#[derive(Debug)]
pub struct TCPHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    reserved: u8,
    cwr_flag: u8,
    ece_flag: u8,
    urg_flag: u8,
    ack_flag: u8,
    psh_flag: u8,
    rst_flag: u8,
    syn_flag: u8,
    fin_flag: u8,
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
        cwr_flag: bytes[13] & 1 << 7,
        ece_flag: bytes[13] & 1 << 6,
        urg_flag: bytes[13] & 1 << 5,
        ack_flag: bytes[13] & 1 << 4,
        psh_flag: bytes[13] & 1 << 3,
        rst_flag: bytes[13] & 1 << 2,
        syn_flag: bytes[13] & 1 << 1,
        fin_flag: bytes[13] & 1,
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
        urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]])
    }
}