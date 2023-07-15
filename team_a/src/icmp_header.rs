pub struct ICMPEchoHeader {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
}

pub fn get_checksum(buffer: &[u8]) -> u16 {
    let mut sum: u16 = 0;

    for chunk in buffer.chunks(2) {
        let num = ((chunk[0] as u16) << 8) | chunk[1] as u16;
        let (new_sum, is_overflowed) = sum.overflowing_add(num);
        sum = new_sum;
        if is_overflowed {
            sum += 1;
        }
    }
    !sum
}

pub fn parse(bytes: &[u8]) -> (ICMPEchoHeader, &[u8]) {
    let header = ICMPEchoHeader {
        type_: bytes[0],
        code: bytes[1],
        checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
        id: u16::from_be_bytes([bytes[4], bytes[5]]),
        seq: u16::from_be_bytes([bytes[6], bytes[7]]),
    };
    (header, &bytes[8..])
}