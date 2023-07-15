use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_address: Ipv4Addr,
    pub destination_address: Ipv4Addr,
}

pub fn get_checksum(buffer: &[u8]) -> u16 {
    let mut sum: u16 = 0;

    for (index, chunk) in buffer.chunks(2).enumerate() {
        if index == 5 {
            continue;
        }
        let num = ((chunk[0] as u16) << 8) | chunk[1] as u16;
        let (new_sum, is_overflowed) = sum.overflowing_add(num);
        sum = new_sum;
        if is_overflowed {
            sum += 1;
        }
    }
    !sum
}

pub fn parse(bytes: &[u8]) -> IPv4Header {
    IPv4Header {
        version: bytes[0] >> 4,
        ihl: bytes[0] & 0xf,
        type_of_service: bytes[1],
        total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
        identification: u16::from_be_bytes([bytes[4], bytes[5]]),
        flags: bytes[6] >> 5,
        fragment_offset: u16::from_be_bytes([bytes[6] & 0xf1, bytes[7]]),
        time_to_live: bytes[8],
        protocol: bytes[9],
        checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
        source_address: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        destination_address: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
    }
}

pub fn pack(buffer: &mut [u8], ipv4_header: IPv4Header) -> usize {
    buffer[0] = (ipv4_header.version << 4) + ipv4_header.ihl;
    buffer[1] = ipv4_header.type_of_service;
    buffer[2..=3].copy_from_slice(&ipv4_header.total_length.to_be_bytes());
    buffer[4..=5].copy_from_slice(&ipv4_header.identification.to_be_bytes());
    buffer[6] = ipv4_header.flags << 5;
    buffer[7] = ipv4_header.fragment_offset.to_be_bytes()[1];
    buffer[8] = ipv4_header.time_to_live;
    buffer[9] = ipv4_header.protocol;
    buffer[10] = 0;
    buffer[11] = 0;
    buffer[12..=15].copy_from_slice(&ipv4_header.source_address.octets());
    buffer[16..=19].copy_from_slice(&ipv4_header.destination_address.octets());

    let checksum = get_checksum(&buffer).to_be_bytes();
    buffer[10..=11].copy_from_slice(&checksum);
    20
}
