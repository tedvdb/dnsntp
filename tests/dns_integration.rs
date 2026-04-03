//! Integration tests for request handling and parse/build consistency.

use dnsntp::{
    build_refused_reply, parse_dns_packet, process_dns_request, DNS_TYPE_A, DNS_TYPE_AAAA,
    DNS_TYPE_NS, DNS_TYPE_TXT, RCODE_REFUSED,
};

fn minimal_query(id: u16, qname: &[u8], qtype: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + qname.len() + 4);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(qname);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p
}

#[test]
fn process_request_none_on_parse_error() {
    assert!(process_dns_request(&[0u8; 4]).is_none());
}

#[test]
fn process_request_none_on_zero_questions() {
    let mut p = vec![0u8; 12];
    p[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert!(process_dns_request(&p).is_none());
}

#[test]
fn non_txt_a_query_returns_refused() {
    let q = minimal_query(0xbeef, b"\x07example\x00", DNS_TYPE_A);
    let (parsed, reply) = process_dns_request(&q).expect("valid query");
    assert_eq!(parsed.id, 0xbeef);
    assert_eq!(&reply[0..2], &0xbeef_u16.to_be_bytes());
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    assert_eq!(flags & 0x0F, RCODE_REFUSED as u16);
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
    let back = parse_dns_packet(&reply).expect("reply re-parses");
    assert_eq!(back.id, 0xbeef);
    assert_eq!(back.questions.len(), 1);
}

#[test]
fn txt_query_noerror_three_answers() {
    let q = minimal_query(0xcafe, b"\x01z\x00", DNS_TYPE_TXT);
    let (parsed, reply) = process_dns_request(&q).unwrap();
    assert_eq!(parsed.id, 0xcafe);
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    assert_eq!(flags & 0x0F, 0);
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 3);
}

#[test]
fn reply_ancount_zero_for_non_txt_txt_has_three_answers() {
    let qa = minimal_query(1, b"\x01x\x00", DNS_TYPE_AAAA);
    let (_, ra) = process_dns_request(&qa).unwrap();
    assert_eq!(u16::from_be_bytes([ra[6], ra[7]]), 0);
    assert_eq!(u16::from_be_bytes([ra[2], ra[3]]) & 0x0F, RCODE_REFUSED as u16);
    let qt = minimal_query(2, b"\x01x\x00", DNS_TYPE_TXT);
    let (_, rt) = process_dns_request(&qt).unwrap();
    assert_eq!(u16::from_be_bytes([rt[6], rt[7]]), 3);
    assert_eq!(u16::from_be_bytes([rt[2], rt[3]]) & 0x0F, 0);
}

#[test]
fn unknown_qtype_returns_refused_empty_answers() {
    let q = minimal_query(3, b"\x01y\x00", 999);
    let (packet, reply) = process_dns_request(&q).unwrap();
    let rebuilt = build_refused_reply(&packet);
    assert_eq!(reply, rebuilt);
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
    assert_eq!(reply.len(), 12 + 3 + 4);
    assert_eq!(u16::from_be_bytes([reply[2], reply[3]]) & 0x0F, RCODE_REFUSED as u16);
}

#[test]
fn ns_query_refused_without_answer_rrs() {
    let q = minimal_query(9, b"\x06google\x03com\x00", DNS_TYPE_NS);
    let (_, reply) = process_dns_request(&q).unwrap();
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
    assert_eq!(u16::from_be_bytes([reply[2], reply[3]]) & 0x0F, RCODE_REFUSED as u16);
    assert_eq!(reply.len(), 12 + (1 + 6 + 1 + 3 + 1) + 4);
}
