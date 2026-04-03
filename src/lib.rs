//! DNS query/response helpers used by the UDP server binary.

pub mod dns;

pub use dns::{
    answer_rdatas_for_query, build_refused_reply, build_reply, parse_dns_packet, DnsQuery,
    DnsQuestion, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_PTR,
    DNS_TYPE_TXT, RCODE_NO_ERROR, RCODE_REFUSED,
};

/// Parses a DNS query and builds a reply for the first question (same logic as the server handler).
pub fn process_dns_request(data: &[u8]) -> Option<(DnsQuery, Vec<u8>)> {
    let packet = parse_dns_packet(data).ok()?;
    if packet.questions.is_empty() {
        return None;
    }
    let q0 = &packet.questions[0];
    let reply = if q0.qtype == DNS_TYPE_TXT {
        let answers = answer_rdatas_for_query(q0.qtype);
        build_reply(&packet, &answers)
    } else {
        build_refused_reply(&packet)
    };
    Some((packet, reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_dns_request_preserves_query_id_in_txt_reply() {
        let mut p = vec![0u8; 12];
        p[0..2].copy_from_slice(&0x0102u16.to_be_bytes());
        p[4..6].copy_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(b"\x01z\x00");
        p.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        let (q, reply) = process_dns_request(&p).expect("valid");
        assert_eq!(q.id, 0x0102);
        assert_eq!(reply[0..2], [0x01, 0x02]);
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_eq!(flags & 0x0F, RCODE_NO_ERROR as u16);
    }
}
