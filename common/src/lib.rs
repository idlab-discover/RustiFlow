#![no_std]

pub use network_types::{icmp::IcmpHdr, tcp::TcpHdr, udp::UdpHdr};

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
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub _padding: [u8; 1],
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
        icmp_type: u8,
        icmp_code: u8,
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
            icmp_type,
            icmp_code,
            _padding: [0; 1],
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
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub _padding: [u8; 9],
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
        icmp_type: u8,
        icmp_code: u8,
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
            icmp_type,
            icmp_code,
            _padding: [0; 9],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EbpfEventIpv6 {}

pub trait NetworkHeader {
    fn source_port(&self) -> u16;
    fn destination_port(&self) -> u16;
    fn window_size(&self) -> u16;
    fn combined_flags(&self) -> u8;
    fn header_length(&self) -> u8;
    fn sequence_number(&self) -> u32;
    fn sequence_number_ack(&self) -> u32;
    fn icmp_type(&self) -> u8;
    fn icmp_code(&self) -> u8;
}

impl NetworkHeader for TcpHdr {
    fn source_port(&self) -> u16 {
        self.source
    }
    fn destination_port(&self) -> u16 {
        self.dest
    }
    fn window_size(&self) -> u16 {
        self.window as u16
    }
    fn combined_flags(&self) -> u8 {
        ((self.fin() as u8) << 0)
            | ((self.syn() as u8) << 1)
            | ((self.rst() as u8) << 2)
            | ((self.psh() as u8) << 3)
            | ((self.ack() as u8) << 4)
            | ((self.urg() as u8) << 5)
            | ((self.ece() as u8) << 6)
            | ((self.cwr() as u8) << 7)
    }
    fn header_length(&self) -> u8 {
        TcpHdr::LEN as u8
    }
    fn sequence_number(&self) -> u32 {
        self.seq
    }
    fn sequence_number_ack(&self) -> u32 {
        self.ack_seq
    }
    fn icmp_type(&self) -> u8 {
        0
    }
    fn icmp_code(&self) -> u8 {
        0
    }
}

impl NetworkHeader for UdpHdr {
    fn source_port(&self) -> u16 {
        self.source
    }
    fn destination_port(&self) -> u16 {
        self.dest
    }
    fn window_size(&self) -> u16 {
        0
    }
    fn combined_flags(&self) -> u8 {
        0
    }
    fn header_length(&self) -> u8 {
        UdpHdr::LEN as u8
    }
    fn sequence_number(&self) -> u32 {
        0
    }
    fn sequence_number_ack(&self) -> u32 {
        0
    }
    fn icmp_type(&self) -> u8 {
        0
    }
    fn icmp_code(&self) -> u8 {
        0
    }
}

impl NetworkHeader for IcmpHdr {
    fn source_port(&self) -> u16 {
        0
    }
    fn destination_port(&self) -> u16 {
        0
    }
    fn window_size(&self) -> u16 {
        0
    }
    fn combined_flags(&self) -> u8 {
        0
    }
    fn header_length(&self) -> u8 {
        IcmpHdr::LEN as u8
    }
    fn sequence_number(&self) -> u32 {
        0
    }
    fn sequence_number_ack(&self) -> u32 {
        0
    }
    fn icmp_type(&self) -> u8 {
        self.type_
    }

    fn icmp_code(&self) -> u8 {
        self.code
    }
}
