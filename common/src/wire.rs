//! Wire layouts of the link, network and transport headers RustiFlow reads.
//!
//! Every header is `Unaligned` and accepts any bit pattern, so it can be
//! borrowed from untrusted packet bytes with a single length check, and
//! multi-byte fields carry their network byte order in their type.

use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_IPV6: u16 = 0x86dd;
pub const ETHER_TYPE_VLAN: u16 = 0x8100;

/// Ethernet II header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: U16,
}

/// Linux cooked capture (SLL) header, as written by libpcap.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct LinuxCookedHeader {
    pub packet_type: U16,
    pub arphrd_type: U16,
    pub address_length: U16,
    pub address: [u8; 8],
    pub protocol: U16,
}

/// 802.1Q tag that follows an Ethernet header whose EtherType is VLAN.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct VlanTag {
    pub tag_control: U16,
    pub ether_type: U16,
}

/// IPv4 header without options.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: U16,
    pub identification: U16,
    pub flags_fragment_offset: U16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: U16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

impl Ipv4Header {
    /// Header length in bytes, as declared by the IHL field.
    pub fn header_length(&self) -> usize {
        usize::from(self.version_ihl & 0x0f) * 4
    }

    /// Fragment offset in 8-byte units.
    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment_offset.get() & 0x1fff
    }

    pub fn more_fragments(&self) -> bool {
        self.flags_fragment_offset.get() & 0x2000 != 0
    }
}

/// Fixed IPv6 header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Ipv6Header {
    pub version_class_flow: [u8; 4],
    pub payload_length: U16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

/// TCP header without options.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct TcpHeader {
    pub source_port: U16,
    pub destination_port: U16,
    pub sequence_number: U32,
    pub acknowledgement_number: U32,
    pub data_offset_reserved: u8,
    /// CWR, ECE, URG, ACK, PSH, RST, SYN, FIN from the most significant bit.
    pub flags: u8,
    pub window: U16,
    pub checksum: U16,
    pub urgent_pointer: U16,
}

impl TcpHeader {
    /// Header length in bytes, as declared by the data offset field.
    pub fn header_length(&self) -> u8 {
        (self.data_offset_reserved >> 4) * 4
    }
}

/// UDP header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct UdpHeader {
    pub source_port: U16,
    pub destination_port: U16,
    pub length: U16,
    pub checksum: U16,
}

/// The type, code and checksum shared by every ICMPv4 and ICMPv6 message.
/// The rest of the header depends on the message type.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: U16,
}

const _: () = {
    assert!(core::mem::size_of::<EthernetHeader>() == 14);
    assert!(core::mem::size_of::<LinuxCookedHeader>() == 16);
    assert!(core::mem::size_of::<VlanTag>() == 4);
    assert!(core::mem::size_of::<Ipv4Header>() == 20);
    assert!(core::mem::size_of::<Ipv6Header>() == 40);
    assert!(core::mem::size_of::<TcpHeader>() == 20);
    assert!(core::mem::size_of::<UdpHeader>() == 8);
    assert!(core::mem::size_of::<IcmpHeader>() == 4);
};
