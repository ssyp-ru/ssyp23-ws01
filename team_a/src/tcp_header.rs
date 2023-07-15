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
    pub checksum: u16,
    urgent_pointer: u16,
}

pub fn get_checksum(buffer: &[u8]) -> u16 {
    let mut sum: u16 = 0;

    for (index, chunk) in buffer.chunks(2).enumerate() {
        if index == 8 {
            continue;
        }
        let num = ((chunk[0] as u16) << 8) | chunk[1] as u16;
        let (new_sum, is_overflowed) = sum.overflowing_add(num);
        sum = new_sum;
        if is_overflowed {
            sum += 1;
        }
    }
    println!("{}", !sum);
    !sum
}

pub fn parse(bytes: &[u8]) -> TCPHeader {
    println!("{}", u16::from_be_bytes([bytes[16], bytes[17]]));
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
        urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]]),
    }
}

pub fn pack(buffer: &mut [u8], tcp_header: TCPHeader) -> usize {
    buffer[0..=1].copy_from_slice(&tcp_header.source_port.to_be_bytes());
    buffer[2..=3].copy_from_slice(&tcp_header.destination_port.to_be_bytes());
    buffer[4..=7].copy_from_slice(&tcp_header.sequence_number.to_be_bytes());
    buffer[8..=11].copy_from_slice(&tcp_header.acknowledgment_number.to_be_bytes());
    buffer[12] = (tcp_header.data_offset << 4) + tcp_header.reserved;
    buffer[13] = (tcp_header.cwr_flag | 1 >> 7)
        + (tcp_header.ece_flag | 1 >> 6)
        + (tcp_header.urg_flag | 1 >> 5)
        + (tcp_header.ack_flag | 1 >> 4)
        + (tcp_header.psh_flag | 1 >> 3)
        + (tcp_header.rst_flag | 1 >> 2)
        + (tcp_header.syn_flag | 1 >> 1)
        + (tcp_header.fin_flag);
    buffer[14..=15].copy_from_slice(&tcp_header.window.to_be_bytes());
    buffer[16] = 0;
    buffer[17] = 0;
    buffer[18..=19].copy_from_slice(&tcp_header.urgent_pointer.to_be_bytes());

    let checksum = get_checksum(&buffer).to_be_bytes();
    buffer[16..=17].copy_from_slice(&checksum);
    20
}
