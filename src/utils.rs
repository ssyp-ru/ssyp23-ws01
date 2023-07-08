pub fn set_u16_be(arr: &mut [u8], value: u16)
{
    arr.copy_from_slice(&value.to_be_bytes());
}

pub fn set_u32_be(arr: &mut [u8], value: u32)
{
    arr.copy_from_slice(&value.to_be_bytes());
}