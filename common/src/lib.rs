#![no_std]

/// BasicFeaturesIpv4 is a struct collection all ipv4 traffic data and is 32 bytes in size.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct EbpfEventIpv4 {
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub data_length: u16,
    pub length: u16,
    pub window_size: u16,
    pub combined_flags: u8,
    pub protocol: u8,
    pub header_length: u8,
    pub sequence_number: u32,
    pub sequence_number_ack: u32,
    pub _padding: [u8; 3],
}

impl EbpfEventIpv4 {
    pub fn new(
        ipv4_destination: u32,
        ipv4_source: u32,
        port_destination: u16,
        port_source: u16,
        data_length: u16,
        length: u16,
        window_size: u16,
        combined_flags: u8,
        protocol: u8,
        header_length: u8,
        sequence_number: u32,
        sequence_number_ack: u32,
    ) -> Self {
        EbpfEventIpv4 {
            ipv4_destination,
            ipv4_source,
            port_destination,
            port_source,
            data_length,
            length,
            window_size,
            combined_flags,
            protocol,
            header_length,
            sequence_number,
            sequence_number_ack,
            _padding: [0; 3],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EbpfEventIpv4 {}

/// BasicFeaturesIpv6 is a struct collection all ipv6 traffic data and is 64 bytes in size.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EbpfEventIpv6 {
    pub ipv6_destination: u128,
    pub ipv6_source: u128,
    pub port_destination: u16,
    pub port_source: u16,
    pub data_length: u16,
    pub length: u16,
    pub window_size: u16,
    pub combined_flags: u8,
    pub protocol: u8,
    pub header_length: u8,
    pub sequence_number: u32,
    pub sequence_number_ack: u32,
    pub _padding: [u8; 11],
}

impl EbpfEventIpv6 {
    pub fn new(
        ipv6_destination: u128,
        ipv6_source: u128,
        port_destination: u16,
        port_source: u16,
        data_length: u16,
        length: u16,
        window_size: u16,
        combined_flags: u8,
        protocol: u8,
        header_length: u8,
        sequence_number: u32,
        sequence_number_ack: u32,
    ) -> Self {
        EbpfEventIpv6 {
            ipv6_destination,
            ipv6_source,
            port_destination,
            port_source,
            data_length,
            length,
            window_size,
            combined_flags,
            protocol,
            header_length,
            sequence_number,
            sequence_number_ack,
            _padding: [0; 11],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EbpfEventIpv6 {}
