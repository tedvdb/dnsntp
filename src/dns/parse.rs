use super::{DnsQuery, DnsQuestion};

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    InvalidOffset,
    TooManyCompressionJumps,
    InvalidLabel,
    Utf8(std::str::Utf8Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "packet too short"),
            ParseError::InvalidOffset => write!(f, "invalid packet offset"),
            ParseError::TooManyCompressionJumps => write!(f, "too many name compression jumps"),
            ParseError::InvalidLabel => write!(f, "invalid label length"),
            ParseError::Utf8(e) => write!(f, "invalid UTF-8 in label: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse_dns_packet(data: &[u8]) -> Result<DnsQuery, ParseError> {
    if data.len() < 12 {
        return Err(ParseError::TooShort);
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rd = flags & 0x0100 != 0;

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

    let mut offset = 12usize;
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (name, next) = read_name(data, offset)?;
        offset = next;
        if offset + 4 > data.len() {
            return Err(ParseError::TooShort);
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
    }

    Ok(DnsQuery {
        id,
        opcode,
        rd,
        questions,
    })
}

fn read_name(packet: &[u8], mut offset: usize) -> Result<(String, usize), ParseError> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jump_end = offset;
    let mut jumps = 0usize;

    loop {
        if offset >= packet.len() {
            return Err(ParseError::InvalidOffset);
        }
        let len = packet[offset];

        if len == 0 {
            offset += 1;
            if !jumped {
                jump_end = offset;
            }
            break;
        }

        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(ParseError::TooShort);
            }
            if jumps > 10 {
                return Err(ParseError::TooManyCompressionJumps);
            }
            let ptr = (((len as usize) & 0x3F) << 8) | (packet[offset + 1] as usize);
            if ptr >= packet.len() {
                return Err(ParseError::InvalidOffset);
            }
            if !jumped {
                jump_end = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            continue;
        }

        let label_len = len as usize;
        offset += 1;
        if offset + label_len > packet.len() {
            return Err(ParseError::InvalidLabel);
        }
        let label =
            std::str::from_utf8(&packet[offset..offset + label_len]).map_err(ParseError::Utf8)?;
        if label.is_empty() {
            return Err(ParseError::InvalidLabel);
        }
        labels.push(label.to_string());
        offset += label_len;
    }

    Ok((labels.join("."), jump_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(id: u16, flags: u16, qdcount: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&id.to_be_bytes());
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qdcount.to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        h.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        h.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        h
    }

    fn append_question(mut pkt: Vec<u8>, qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        pkt.extend_from_slice(qname);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&qclass.to_be_bytes());
        pkt
    }

    #[test]
    fn error_display_messages() {
        assert!(
            ParseError::TooShort
                .to_string()
                .contains("short")
        );
        assert!(ParseError::InvalidOffset.to_string().contains("offset"));
        assert!(
            ParseError::TooManyCompressionJumps
                .to_string()
                .contains("compression")
        );
        assert!(ParseError::InvalidLabel.to_string().contains("label"));
        // Exercise Utf8 arm via a real parse failure (invalid label bytes).
        let mut pkt = header(0, 0, 1);
        pkt.push(2);
        pkt.push(0xfe);
        pkt.push(0xff);
        pkt.push(0);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        let e = parse_dns_packet(&pkt).unwrap_err();
        assert!(matches!(e, ParseError::Utf8(_)));
        assert!(e.to_string().contains("UTF-8"));
        assert!(std::error::Error::source(&ParseError::TooShort).is_none());
    }

    #[test]
    fn too_short_empty() {
        assert!(matches!(
            parse_dns_packet(&[]),
            Err(ParseError::TooShort)
        ));
    }

    #[test]
    fn too_short_header_only() {
        assert!(matches!(
            parse_dns_packet(&[0u8; 11]),
            Err(ParseError::TooShort)
        ));
    }

    #[test]
    fn too_short_truncated_question_tail() {
        let mut pkt = header(0xabcd, 0x0100, 1);
        pkt.extend_from_slice(b"\x01a\x00"); // name
        pkt.extend_from_slice(&1u16.to_be_bytes()); // qtype only — missing qclass + rest
        assert!(matches!(parse_dns_packet(&pkt), Err(ParseError::TooShort)));
    }

    #[test]
    fn parses_id_opcode_rd_and_question() {
        // flags: opcode 5 in bits 11..15, RD set (0x0100)
        let flags: u16 = (5u16 << 11) | 0x0100;
        let pkt = append_question(
            header(0x2468, flags, 1),
            b"\x01z\x00",
            1,
            1,
        );
        let q = parse_dns_packet(&pkt).unwrap();
        assert_eq!(q.id, 0x2468);
        assert_eq!(q.opcode, 5);
        assert!(q.rd);
        assert_eq!(q.questions.len(), 1);
        assert_eq!(q.questions[0].name, "z");
        assert_eq!(q.questions[0].qtype, 1);
        assert_eq!(q.questions[0].qclass, 1);
    }

    #[test]
    fn rd_false_when_not_set() {
        let pkt = append_question(header(9, 0, 1), b"\x03foo\x00", 28, 1);
        let q = parse_dns_packet(&pkt).unwrap();
        assert!(!q.rd);
        assert_eq!(q.questions[0].qtype, 28);
    }

    #[test]
    fn parses_multi_label_name() {
        let pkt = append_question(
            header(1, 0, 1),
            b"\x03www\x07example\x03com\x00",
            16,
            1,
        );
        let q = parse_dns_packet(&pkt).unwrap();
        assert_eq!(q.questions[0].name, "www.example.com");
    }

    #[test]
    fn parses_two_questions() {
        let mut pkt = header(2, 0, 2);
        pkt.extend_from_slice(b"\x01a\x00");
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(b"\x01b\x00");
        pkt.extend_from_slice(&28u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        let q = parse_dns_packet(&pkt).unwrap();
        assert_eq!(q.questions.len(), 2);
        assert_eq!(q.questions[0].name, "a");
        assert_eq!(q.questions[1].name, "b");
        assert_eq!(q.questions[1].qtype, 28);
    }

    #[test]
    fn name_compression_pointer() {
        // Q1: example.com at offset 12; Q2: \x03www + pointer to 12 -> www.example.com
        let mut pkt = header(3, 0, 2);
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(b"\x03www\xc0\x0c");
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        let q = parse_dns_packet(&pkt).unwrap();
        assert_eq!(q.questions[0].name, "example.com");
        assert_eq!(q.questions[1].name, "www.example.com");
    }

    #[test]
    fn compression_pointer_out_of_range() {
        let mut pkt = header(0, 0, 1);
        pkt.extend_from_slice(b"\xc0\xff"); // points past end
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            parse_dns_packet(&pkt),
            Err(ParseError::InvalidOffset)
        ));
    }

    #[test]
    fn compression_second_byte_missing() {
        let mut pkt = header(0, 0, 1);
        pkt.extend_from_slice(b"\xc0");
        assert!(matches!(parse_dns_packet(&pkt), Err(ParseError::TooShort)));
    }

    #[test]
    fn too_many_compression_jumps() {
        // Chain: each pointer jumps to next two-byte pair; after 11 jumps, fails.
        let mut pkt = vec![0u8; 12];
        pkt[0..12].copy_from_slice(&[
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        ]);
        for i in 0..12u16 {
            let off = 12 + i * 2;
            pkt.push(0xc0);
            pkt.push((off + 2) as u8);
        }
        pkt.push(0xc0);
        pkt.push(0x0c);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            parse_dns_packet(&pkt),
            Err(ParseError::TooManyCompressionJumps)
        ));
    }

    #[test]
    fn label_length_overflows_packet() {
        let mut pkt = header(0, 0, 1);
        pkt.push(10); // claims 10 bytes but we only add 2
        pkt.push(b'x');
        pkt.push(b'y');
        assert!(matches!(
            parse_dns_packet(&pkt),
            Err(ParseError::InvalidLabel)
        ));
    }

    #[test]
    fn name_offset_past_end() {
        let mut pkt = header(0, 0, 1);
        pkt.push(5);
        pkt.push(b'x');
        // no terminator, ended by running out of buffer
        assert!(matches!(
            parse_dns_packet(&pkt),
            Err(ParseError::InvalidLabel)
        ));
    }

    #[test]
    fn invalid_utf8_in_label() {
        let mut pkt = header(0, 0, 1);
        pkt.push(2);
        pkt.push(0xc3);
        pkt.push(0x28); // invalid sequence
        pkt.push(0);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        assert!(matches!(parse_dns_packet(&pkt), Err(ParseError::Utf8(_))));
    }

    #[test]
    fn offset_starts_beyond_packet() {
        let pkt = header(0, 0, 1); // QDCOUNT 1 but no question body
        assert!(matches!(
            parse_dns_packet(&pkt),
            Err(ParseError::InvalidOffset)
        ));
    }
}
