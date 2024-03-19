#![no_std]
use network_types::ip::in6_addr;
/// BasicFeaturesIpv4 is a struct collection all ipv4 traffic data and is 280 bits in size.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BasicFeaturesIpv4 {
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
unsafe impl aya::Pod for BasicFeaturesIpv4 {}

/// BasicFeaturesIpv6 is a struct collection all ipv6 traffic data and is 472 bits in size.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BasicFeaturesIpv6 {
    pub ipv6_destination: in6_addr,
    pub ipv6_source: in6_addr,
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
unsafe impl aya::Pod for BasicFeaturesIpv6 {}
