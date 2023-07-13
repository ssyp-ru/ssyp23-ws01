#[derive(Debug)]
pub struct TCPHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    reserved: u8,
    control_bits: u8,
    window: u16,
    checksum: u16,
    urgent_pointer: u16
}

pub fn parse(bytes: &[u8]) -> TCPHeader {
    TCPHeader {
        source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        sequence_number: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        acknowledgment_number: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        data_offset: bytes[12] >> 4,
        reserved: bytes[12] & 0xf,
        control_bits: bytes[13] & 1 << 4,
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
        urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]])
    }
}