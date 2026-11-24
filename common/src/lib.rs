#![no_std]

pub mod ip_protocol;
pub mod ipv6_extensions;
pub mod wire;

use wire::{IcmpMessageHeader, TcpHeader, UdpHeader};

pub const REALTIME_EVENT_QUEUE_COUNT: usize = 8;
pub const REALTIME_EVENT_RINGBUF_BYTES: u32 = 1024 * 1024 * 64;

/// BasicFeaturesIpv4 is a struct collection all ipv4 traffic data.
///
/// Addresses are the wire bytes in network order; every other multi-byte
/// field is in host byte order.
#[repr(C, packed)]
#[derive(
    Copy,
    Clone,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
)]
pub struct EbpfEventIpv4 {
    pub timestamp_ns: u64,
    pub ipv4_destination: [u8; 4],
    pub ipv4_source: [u8; 4],
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
    pub ttl: u8,
}

impl EbpfEventIpv4 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_ns: u64,
        ipv4_destination: [u8; 4],
        ipv4_source: [u8; 4],
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
        ttl: u8,
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
            ttl,
        }
    }
}

// The eBPF programs and userspace exchange this record by size alone.
const _: () = assert!(core::mem::size_of::<EbpfEventIpv4>() == 40);

/// BasicFeaturesIpv6 is a struct collection all ipv6 traffic data.
///
/// Addresses are the wire bytes in network order; every other multi-byte
/// field is in host byte order.
#[repr(C, packed)]
#[derive(
    Copy,
    Clone,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
)]
pub struct EbpfEventIpv6 {
    pub timestamp_ns: u64,
    pub ipv6_destination: [u8; 16],
    pub ipv6_source: [u8; 16],
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
    pub ttl: u8,
    pub _padding: [u8; 8],
}

impl EbpfEventIpv6 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_ns: u64,
        ipv6_destination: [u8; 16],
        ipv6_source: [u8; 16],
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
        ttl: u8,
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
            ttl,
            _padding: [0; 8],
        }
    }
}

// The eBPF programs and userspace exchange this record by size alone.
const _: () = assert!(core::mem::size_of::<EbpfEventIpv6>() == 72);

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

impl NetworkHeader for TcpHeader {
    fn source_port(&self) -> u16 {
        self.source_port.get()
    }
    fn destination_port(&self) -> u16 {
        self.destination_port.get()
    }
    fn window_size(&self) -> u16 {
        self.window.get()
    }
    fn combined_flags(&self) -> u8 {
        self.flags
    }
    fn header_length(&self) -> u8 {
        TcpHeader::header_length(self)
    }
    fn sequence_number(&self) -> u32 {
        self.sequence_number.get()
    }
    fn sequence_number_ack(&self) -> u32 {
        self.acknowledgement_number.get()
    }
    fn icmp_type(&self) -> u8 {
        0
    }
    fn icmp_code(&self) -> u8 {
        0
    }
}

impl NetworkHeader for UdpHeader {
    fn source_port(&self) -> u16 {
        self.source_port.get()
    }
    fn destination_port(&self) -> u16 {
        self.destination_port.get()
    }
    fn window_size(&self) -> u16 {
        0
    }
    fn combined_flags(&self) -> u8 {
        0
    }
    fn header_length(&self) -> u8 {
        core::mem::size_of::<UdpHeader>() as u8
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
impl NetworkHeader for IcmpMessageHeader {
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
        core::mem::size_of::<IcmpMessageHeader>() as u8
    }
    fn sequence_number(&self) -> u32 {
        0
    }
    fn sequence_number_ack(&self) -> u32 {
        0
    }
    fn icmp_type(&self) -> u8 {
        self.header.icmp_type
    }
    fn icmp_code(&self) -> u8 {
        self.header.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromBytes;

    /// Reads a header from wire bytes the way `TcContext::load` does.
    fn load<T: FromBytes>(bytes: &[u8]) -> T {
        T::read_from_bytes(bytes).unwrap()
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
        let tcp: TcpHeader = load(&[
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
        let udp: UdpHeader = load(&[0x00, 0x35, 0xd4, 0x31, 0x00, 0x20, 0x00, 0x00]);

        assert_eq!(fields(&udp), (53, 54321, 0, 0, 8, 0, 0, 0, 0));
    }

    #[test]
    fn icmp_header_reports_type_and_code() {
        let icmp: IcmpMessageHeader = load(&[3, 4, 0, 0, 0, 0, 0, 0]);

        assert_eq!(fields(&icmp), (0, 0, 0, 0, 8, 0, 0, 3, 4));
    }
}
