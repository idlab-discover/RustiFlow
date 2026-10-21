#![no_std]

pub mod ipv6_extensions;

pub use network_types::{
    icmp::{Icmpv4Hdr, Icmpv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub const REALTIME_EVENT_QUEUE_COUNT: usize = 8;
pub const REALTIME_EVENT_RINGBUF_BYTES: u32 = 1024 * 1024 * 64;

/// BasicFeaturesIpv4 is a struct collection all ipv4 traffic data.
///
/// Addresses keep the wire byte order in memory (`u32::from_ne_bytes` of the
/// address bytes); every other multi-byte field is in host byte order.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct EbpfEventIpv4 {
    pub timestamp_ns: u64,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_ns: u64,
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
            timestamp_ns,
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

/// BasicFeaturesIpv6 is a struct collection all ipv6 traffic data.
///
/// Addresses keep the wire byte order in memory (`u128::from_ne_bytes` of the
/// address bytes); every other multi-byte field is in host byte order.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EbpfEventIpv6 {
    pub timestamp_ns: u64,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_ns: u64,
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
            timestamp_ns,
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
        u16::from_be_bytes(self.source)
    }
    fn destination_port(&self) -> u16 {
        u16::from_be_bytes(self.dest)
    }
    fn window_size(&self) -> u16 {
        u16::from_be_bytes(self.window)
    }
    fn combined_flags(&self) -> u8 {
        (self.fin() as u8)
            | ((self.syn() as u8) << 1)
            | ((self.rst() as u8) << 2)
            | ((self.psh() as u8) << 3)
            | ((self.ack() as u8) << 4)
            | ((self.urg() as u8) << 5)
            | ((self.ece() as u8) << 6)
            | ((self.cwr() as u8) << 7)
    }
    fn header_length(&self) -> u8 {
        (self.doff() * 4) as u8
    }
    fn sequence_number(&self) -> u32 {
        u32::from_be_bytes(self.seq)
    }
    fn sequence_number_ack(&self) -> u32 {
        u32::from_be_bytes(self.ack_seq)
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
        self.src_port()
    }
    fn destination_port(&self) -> u16 {
        self.dst_port()
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

/// ICMPv4 and ICMPv6 share the type/code layout this crate reads.
macro_rules! impl_icmp_network_header {
    ($header:ty) => {
        impl NetworkHeader for $header {
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
                <$header>::LEN as u8
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
    };
}

impl_icmp_network_header!(Icmpv4Hdr);
impl_icmp_network_header!(Icmpv6Hdr);

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a header from wire bytes the way `TcContext::load` does.
    fn load<T>(bytes: &[u8]) -> T {
        assert_eq!(bytes.len(), core::mem::size_of::<T>());
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) }
    }

    fn fields(header: &impl NetworkHeader) -> (u16, u16, u16, u8, u8, u32, u32, u8, u8) {
        (
            header.source_port(),
            header.destination_port(),
            header.window_size(),
            header.combined_flags(),
            header.header_length(),
            header.sequence_number(),
            header.sequence_number_ack(),
            header.icmp_type(),
            header.icmp_code(),
        )
    }

    #[test]
    fn tcp_header_fields_are_in_host_order() {
        let tcp: TcpHdr = load(&[
            0xc3, 0x50, // source port 50000
            0x01, 0xbb, // destination port 443
            0x01, 0x02, 0x03, 0x04, // sequence number
            0x0a, 0x0b, 0x0c, 0x0d, // acknowledgement number
            0x80, 0x12, // data offset 8 words, SYN and ACK
            0x72, 0x10, // window 29200
            0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
        ]);

        assert_eq!(
            fields(&tcp),
            (
                50000,
                443,
                29200,
                0b0001_0010,
                32,
                0x0102_0304,
                0x0a0b_0c0d,
                0,
                0
            )
        );
    }

    #[test]
    fn udp_header_fields_are_in_host_order() {
        let udp: UdpHdr = load(&[0x00, 0x35, 0xd4, 0x31, 0x00, 0x20, 0x00, 0x00]);

        assert_eq!(fields(&udp), (53, 54321, 0, 0, 8, 0, 0, 0, 0));
    }

    #[test]
    fn icmp_headers_report_type_and_code() {
        let bytes = [3, 4, 0, 0, 0, 0, 0, 0];
        let icmpv4: Icmpv4Hdr = load(&bytes);
        let icmpv6: Icmpv6Hdr = load(&bytes);

        assert_eq!(fields(&icmpv4), (0, 0, 0, 0, 8, 0, 0, 3, 4));
        assert_eq!(fields(&icmpv6), fields(&icmpv4));
    }
}
