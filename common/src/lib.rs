#![no_std]
/// BasicFeatures is a struct collection all traffic data and is 280 bits in size.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BasicFeatures {
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub protocol: u8,
    pub fin_flag: u8,
    pub syn_flag: u8,
    pub rst_flag: u8,
    pub psh_flag: u8,
    pub ack_flag: u8,
    pub urg_flag: u8,
    pub cwe_flag: u8,
    pub ece_flag: u8,
    pub data_length: u32,
    pub header_length: u32,
    pub length: u32,
    pub window_size: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BasicFeatures {}
