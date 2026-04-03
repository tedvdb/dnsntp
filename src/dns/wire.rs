use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_PTR,
    DNS_TYPE_TXT, DnsQuery, RCODE_NO_ERROR, RCODE_REFUSED,
};

fn encode_domain(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if name.is_empty() {
        out.push(0);
        return out;
    }
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        if b.len() > 63 {
            // Invalid for production; truncate is wrong — keep first 63 to stay on wire
            out.push(63);
            out.extend_from_slice(&b[..63]);
        } else {
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
    }
    out.push(0);
    out
}

fn encode_txt_rdata(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = s;
    while rest.len() > 255 {
        out.push(255);
        out.extend_from_slice(rest.as_bytes().split_at(255).0);
        rest = &rest[255..];
    }
    out.push(rest.len() as u8);
    out.extend_from_slice(rest.as_bytes());
    out
}

/// Documentation-only hostnames (RFC 2606 `.invalid`) so name-type RRs are well-formed on the wire.
fn stub_name_rdata() -> Vec<u8> {
    encode_domain("stub.dnsntp.invalid")
}

fn unix_epoch_millis_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn format_unix_rfc3339_from_millis(unix_millis: u128) -> String {
    let secs_i64 = (unix_millis / 1000).min(i64::MAX as u128) as i64;
    let subsec_nanos = ((unix_millis % 1000) * 1_000_000) as u32;
    let dt = match OffsetDateTime::from_unix_timestamp(secs_i64) {
        Ok(t) => t.replace_nanosecond(subsec_nanos).unwrap_or(t),
        Err(_) => OffsetDateTime::UNIX_EPOCH,
    };
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Three TXT RRs: Unix epoch seconds, Unix epoch milliseconds, and RFC 3339 UTC for the same instant.
fn txt_answer_rdatas_at(unix_millis: u128) -> Vec<Vec<u8>> {
    let secs = (unix_millis / 1000) as u64;
    let epoch_sec_txt = encode_txt_rdata(&secs.to_string());
    let epoch_ms_txt = encode_txt_rdata(&unix_millis.to_string());
    let iso_txt = encode_txt_rdata(&format_unix_rfc3339_from_millis(unix_millis));
    vec![epoch_sec_txt, epoch_ms_txt, iso_txt]
}

fn single_rdata_for_query(qtype: u16) -> Vec<u8> {
    match qtype {
        DNS_TYPE_A => Ipv4Addr::new(192, 0, 2, 1).octets().to_vec(),
        DNS_TYPE_NS | DNS_TYPE_CNAME | DNS_TYPE_PTR => stub_name_rdata(),
        DNS_TYPE_MX => {
            let mut v = 0u16.to_be_bytes().to_vec();
            v.extend_from_slice(&encode_domain("mail.dnsntp.invalid"));
            v
        }
        DNS_TYPE_AAAA => Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
            .octets()
            .to_vec(),
        _ => Vec::new(),
    }
}

/// RDATA blobs to place in separate answer RRs (TXT yields three records: epoch s, epoch ms, ISO UTC).
pub fn answer_rdatas_for_query(qtype: u16) -> Vec<Vec<u8>> {
    match qtype {
        DNS_TYPE_TXT => txt_answer_rdatas_at(unix_epoch_millis_now()),
        _ => {
            let one = single_rdata_for_query(qtype);
            if one.is_empty() {
                vec![]
            } else {
                vec![one]
            }
        }
    }
}

fn pack_flags(
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    ad: bool,
    cd: bool,
    rcode: u8,
) -> u16 {
    let mut f = 0u16;
    if qr {
        f |= 1 << 15;
    }
    f |= (opcode as u16 & 0x0F) << 11;
    if aa {
        f |= 1 << 10;
    }
    if tc {
        f |= 1 << 9;
    }
    if rd {
        f |= 1 << 8;
    }
    if ra {
        f |= 1 << 7;
    }
    if ad {
        f |= 1 << 5;
    }
    if cd {
        f |= 1 << 4;
    }
    f | (rcode as u16 & 0x0F)
}

pub fn build_reply(query: &DnsQuery, answer_rdatas: &[Vec<u8>]) -> Vec<u8> {
    let questions = &query.questions;
    let qd = questions.len() as u16;
    let ancount = answer_rdatas.len() as u16;

    let flags = pack_flags(
        true,
        query.opcode,
        true,
        false,
        query.rd,
        true,
        false,
        false,
        RCODE_NO_ERROR,
    );

    let mut out = Vec::new();
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for q in questions {
        out.extend_from_slice(&encode_domain(&q.name));
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
    }

    if ancount > 0 {
        let q0 = &questions[0];
        for rdata in answer_rdatas {
            out.extend_from_slice(&encode_domain(&q0.name));
            out.extend_from_slice(&q0.qtype.to_be_bytes());
            out.extend_from_slice(&q0.qclass.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes()); // TTL
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
    }

    out
}

/// REFUSED response: echoes the question section, no answer RRs (RFC 1035).
pub fn build_refused_reply(query: &DnsQuery) -> Vec<u8> {
    let questions = &query.questions;
    let qd = questions.len() as u16;

    let flags = pack_flags(
        true,
        query.opcode,
        false,
        false,
        query.rd,
        false,
        false,
        false,
        RCODE_REFUSED,
    );

    let mut out = Vec::new();
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for q in questions {
        out.extend_from_slice(&encode_domain(&q.name));
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::parse::parse_dns_packet;
    use crate::dns::{
        DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_TXT,
    };

    #[test]
    fn rdata_a_is_documentation_ip() {
        let v = answer_rdatas_for_query(DNS_TYPE_A);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].as_slice(), [192, 0, 2, 1]);
    }

    #[test]
    fn rdata_aaaa_is_documentation_ipv6() {
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets();
        let v = answer_rdatas_for_query(DNS_TYPE_AAAA);
        assert_eq!(v[0].as_slice(), expected.as_slice());
    }

    #[test]
    fn txt_three_rdatas_epoch_sec_ms_and_rfc3339_utc() {
        let v = txt_answer_rdatas_at(1_700_000_000_123);
        assert_eq!(v.len(), 3);
        assert_eq!(&v[0][1..], b"1700000000");
        assert_eq!(&v[1][1..], b"1700000000123");
        let iso = std::str::from_utf8(&v[2][1..]).unwrap();
        assert!(
            iso.starts_with("2023-11-14T22:13:20") && iso.ends_with('Z'),
            "unexpected RFC 3339: {iso}"
        );
        assert!(iso.contains(".123"), "expected subsecond from ms: {iso}");
    }

    #[test]
    fn answer_rdatas_for_txt_returns_three_records() {
        let v = answer_rdatas_for_query(DNS_TYPE_TXT);
        assert_eq!(v.len(), 3);
        assert!(!v[0].is_empty() && !v[1].is_empty() && !v[2].is_empty());
    }

    #[test]
    fn encode_txt_splits_long_strings() {
        let s = "x".repeat(300);
        let enc = encode_txt_rdata(&s);
        assert_eq!(enc[0], 255);
        assert_eq!(&enc[1..256], &s.as_bytes()[..255]);
        assert_eq!(enc[256], 45);
        assert_eq!(&enc[257..], &s.as_bytes()[255..]);
        let mut decoded = Vec::new();
        let mut i = 0usize;
        while i < enc.len() {
            let len = enc[i] as usize;
            i += 1;
            decoded.extend_from_slice(&enc[i..i + len]);
            i += len;
        }
        assert_eq!(decoded, s.as_bytes());
    }

    #[test]
    fn rdata_unknown_empty() {
        assert!(answer_rdatas_for_query(99).is_empty());
    }

    #[test]
    fn rdata_ns_mx_are_nonempty_wire_domains() {
        let ns = &answer_rdatas_for_query(DNS_TYPE_NS)[0];
        assert!(ns.len() >= 2 && ns.last() == Some(&0));
        let mx = &answer_rdatas_for_query(DNS_TYPE_MX)[0];
        assert!(mx.len() >= 2 + 2);
        assert_eq!(&mx[0..2], &0u16.to_be_bytes());
        assert!(mx.len() > 2 && mx.last() == Some(&0));
    }

    #[test]
    fn build_reply_skips_answer_when_rdata_empty() {
        use crate::dns::DnsQuestion;

        let query = crate::dns::DnsQuery {
            id: 4,
            opcode: 0,
            rd: false,
            questions: vec![DnsQuestion {
                name: "a".to_string(),
                qtype: 42,
                qclass: 1,
            }],
        };
        let reply = build_reply(&query, &[]);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
        assert_eq!(reply.len(), 12 + 3 + 4);
    }

    #[test]
    fn encode_domain_empty_is_root() {
        assert_eq!(encode_domain(""), vec![0]);
    }

    #[test]
    fn encode_domain_skips_empty_labels() {
        let b = encode_domain(".a..b.");
        assert_eq!(b, vec![1, b'a', 1, b'b', 0]);
    }


    #[test]
    fn encode_domain_truncates_oversized_label() {
        let long = "a".repeat(100);
        let b = encode_domain(&long);
        assert_eq!(b[0], 63);
        assert_eq!(b.len(), 1 + 63 + 1);
        assert_eq!(&b[1..1 + 63], &long.as_bytes()[..63]);
    }

    #[test]
    fn build_refused_reply_rcode_and_empty_answer() {
        use crate::dns::DnsQuestion;

        let query = crate::dns::DnsQuery {
            id: 0x55,
            opcode: 0,
            rd: true,
            questions: vec![DnsQuestion {
                name: "x".to_string(),
                qtype: DNS_TYPE_A,
                qclass: 1,
            }],
        };
        let reply = build_refused_reply(&query);
        assert_eq!(&reply[0..2], &[0, 0x55]);
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_eq!(flags & 0x0F, RCODE_REFUSED as u16);
        assert!(flags & (1 << 15) != 0);
        assert!(flags & (1 << 8) != 0);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
        assert_eq!(reply.len(), 12 + 3 + 4);
    }

    #[test]
    fn pack_flags_sets_expected_bits() {
        let f = pack_flags(true, 0x0A, true, true, true, true, true, true, 0x0F);
        assert!(f & (1 << 15) != 0);
        assert_eq!((f >> 11) & 0x0F, 0x0A);
        assert!(f & (1 << 10) != 0);
        assert!(f & (1 << 9) != 0);
        assert!(f & (1 << 8) != 0);
        assert!(f & (1 << 7) != 0);
        assert!(f & (1 << 5) != 0);
        assert!(f & (1 << 4) != 0);
        assert_eq!(f & 0x0F, 0x0F);
    }

    #[test]
    fn build_reply_roundtrip_answer_section() {
        use crate::dns::DnsQuestion;

        let query = crate::dns::DnsQuery {
            id: 0xacef,
            opcode: 0,
            rd: true,
            questions: vec![DnsQuestion {
                name: "example.net".to_string(),
                qtype: DNS_TYPE_A,
                qclass: 1,
            }],
        };
        let answers = answer_rdatas_for_query(DNS_TYPE_A);
        let reply = build_reply(&query, &answers);
        assert!(reply.len() > 12);
        assert_eq!(&reply[0..2], &0xacefu16.to_be_bytes());
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert!(flags & (1 << 15) != 0);
        assert!(flags & (1 << 8) != 0);
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 1);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        let parsed = parse_dns_packet(&reply).expect("reply header + question parses");
        assert_eq!(parsed.id, query.id);
        assert_eq!(parsed.questions.len(), 1);

        let rdata = &answers[0];
        let ttl_off = reply.len() - rdata.len() - 6;
        assert_eq!(
            u32::from_be_bytes([
                reply[ttl_off],
                reply[ttl_off + 1],
                reply[ttl_off + 2],
                reply[ttl_off + 3],
            ]),
            300
        );
        let rdlen = u16::from_be_bytes([reply[ttl_off + 4], reply[ttl_off + 5]]) as usize;
        assert_eq!(rdlen, rdata.len());
        assert_eq!(&reply[ttl_off + 6..], rdata.as_slice());
    }

    #[test]
    fn build_reply_multiple_questions_repeats_all_in_query_section() {
        use crate::dns::DnsQuestion;

        let query = crate::dns::DnsQuery {
            id: 1,
            opcode: 0,
            rd: false,
            questions: vec![
                DnsQuestion {
                    name: "a".to_string(),
                    qtype: 1,
                    qclass: 1,
                },
                DnsQuestion {
                    name: "b".to_string(),
                    qtype: 28,
                    qclass: 1,
                },
            ],
        };
        let reply = build_reply(&query, &[vec![1, 2, 3]]);
        let rest = parse_dns_packet(&reply).unwrap();
        assert_eq!(rest.questions.len(), 2);
        assert_eq!(rest.questions[0].name, "a");
        assert_eq!(rest.questions[1].name, "b");
    }
}
