pub fn set_u16_be(arr: &mut [u8], value: u16)
{
    arr.copy_from_slice(&value.to_be_bytes());
}

pub fn set_u32_be(arr: &mut [u8], value: u32)
{
    arr.copy_from_slice(&value.to_be_bytes());
}

pub fn wrapping_between(start: u32, x: u32, end: u32) -> bool
{
    if end >= start
    {
        start <= x && x <= end
    }
    else
    {
        x >= start || x <= end
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId
{
    pub ip_src: u32,
    pub ip_dst: u32,
    pub port_src: u16,
    pub port_dst: u16,
}