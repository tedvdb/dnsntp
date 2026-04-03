//! Minimal DNS query parsing and response construction (RFC 1035 / 3596).

mod parse;
mod wire;

pub use parse::parse_dns_packet;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;

pub const RCODE_NO_ERROR: u8 = 0;
pub const RCODE_REFUSED: u8 = 5;

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
    pub questions: Vec<DnsQuestion>,
}

pub fn build_reply(query: &DnsQuery, answer_rdatas: &[Vec<u8>]) -> Vec<u8> {
    wire::build_reply(query, answer_rdatas)
}

pub fn build_refused_reply(query: &DnsQuery) -> Vec<u8> {
    wire::build_refused_reply(query)
}

pub fn answer_rdatas_for_query(qtype: u16) -> Vec<Vec<u8>> {
    wire::answer_rdatas_for_query(qtype)
}
