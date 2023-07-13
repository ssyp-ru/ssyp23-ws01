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