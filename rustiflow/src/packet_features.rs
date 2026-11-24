#[cfg(target_os = "linux")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use common::{
    ip_protocol,
    ipv6_extensions::Ipv6Extension,
    wire::{IcmpHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader},
};
#[cfg(target_os = "linux")]
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::debug;
use zerocopy::FromBytes;

use crate::flow_key::FlowKey;

// Define TCP flags
pub const FIN_FLAG: u8 = 0b00000001;
pub const SYN_FLAG: u8 = 0b00000010;
pub const RST_FLAG: u8 = 0b00000100;
pub const PSH_FLAG: u8 = 0b00001000;
pub const ACK_FLAG: u8 = 0b00010000;
pub const URG_FLAG: u8 = 0b00100000;
pub const ECE_FLAG: u8 = 0b01000000;
pub const CWR_FLAG: u8 = 0b10000000;

impl Default for PacketFeatures {
    fn default() -> Self {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            source_port: 0,
            destination_port: 0,
            protocol: 0,
            timestamp_us: 0,
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwr_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 0,
            length: 0,
            window_size: 0,
            sequence_number: 0,
            sequence_number_ack: 0,
            icmp_type: None,
            icmp_code: None,
            flags: 0,
            ttl: 0,
            tcp_payload: None,
        }
    }
}

pub struct PacketFeatures {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub timestamp_us: i64,
    pub fin_flag: u8,
    pub syn_flag: u8,
    pub rst_flag: u8,
    pub psh_flag: u8,
    pub ack_flag: u8,
    pub urg_flag: u8,
    pub cwr_flag: u8,
    pub ece_flag: u8,
    pub data_length: u16,
    pub header_length: u8,
    pub length: u16,
    pub window_size: u16,
    pub sequence_number: u32,
    pub sequence_number_ack: u32,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub flags: u8,
    /// IPv4 TTL or IPv6 hop limit.
    pub ttl: u8,
    /// Complete TCP segment payload on selected ports, when enabled for pcap.
    pub tcp_payload: Option<Box<[u8]>>,
}

impl PacketFeatures {
    #[cfg(target_os = "linux")]
    // Constructor to create PacketFeatures from EbpfEventIpv4
    pub fn from_ebpf_event_ipv4(event: &EbpfEventIpv4, realtime_offset_us: i64) -> Self {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::from(event.ipv4_source)),
            destination_ip: IpAddr::V4(Ipv4Addr::from(event.ipv4_destination)),
            source_port: event.port_source,
            destination_port: event.port_destination,
            protocol: event.protocol,
            timestamp_us: monotonic_ns_to_epoch_us(event.timestamp_ns, realtime_offset_us),
            fin_flag: get_tcp_flag(event.combined_flags, FIN_FLAG),
            syn_flag: get_tcp_flag(event.combined_flags, SYN_FLAG),
            rst_flag: get_tcp_flag(event.combined_flags, RST_FLAG),
            psh_flag: get_tcp_flag(event.combined_flags, PSH_FLAG),
            ack_flag: get_tcp_flag(event.combined_flags, ACK_FLAG),
            urg_flag: get_tcp_flag(event.combined_flags, URG_FLAG),
            cwr_flag: get_tcp_flag(event.combined_flags, CWR_FLAG),
            ece_flag: get_tcp_flag(event.combined_flags, ECE_FLAG),
            data_length: event.data_length,
            header_length: event.header_length,
            length: event.length,
            window_size: event.window_size,
            sequence_number: event.sequence_number,
            sequence_number_ack: event.sequence_number_ack,
            icmp_type: if event.protocol == ip_protocol::ICMP {
                Some(event.icmp_type)
            } else {
                None
            },
            icmp_code: if event.protocol == ip_protocol::ICMP {
                Some(event.icmp_code)
            } else {
                None
            },
            flags: event.combined_flags,
            ttl: event.ttl,
            tcp_payload: None,
        }
    }

    #[cfg(target_os = "linux")]
    // Constructor to create PacketFeatures from EbpfEventIpv6
    pub fn from_ebpf_event_ipv6(event: &EbpfEventIpv6, realtime_offset_us: i64) -> Self {
        PacketFeatures {
            source_ip: IpAddr::V6(Ipv6Addr::from(event.ipv6_source)),
            destination_ip: IpAddr::V6(Ipv6Addr::from(event.ipv6_destination)),
            source_port: event.port_source,
            destination_port: event.port_destination,
            protocol: event.protocol,
            timestamp_us: monotonic_ns_to_epoch_us(event.timestamp_ns, realtime_offset_us),
            fin_flag: get_tcp_flag(event.combined_flags, FIN_FLAG),
            syn_flag: get_tcp_flag(event.combined_flags, SYN_FLAG),
            rst_flag: get_tcp_flag(event.combined_flags, RST_FLAG),
            psh_flag: get_tcp_flag(event.combined_flags, PSH_FLAG),
            ack_flag: get_tcp_flag(event.combined_flags, ACK_FLAG),
            urg_flag: get_tcp_flag(event.combined_flags, URG_FLAG),
            cwr_flag: get_tcp_flag(event.combined_flags, CWR_FLAG),
            ece_flag: get_tcp_flag(event.combined_flags, ECE_FLAG),
            data_length: event.data_length,
            header_length: event.header_length,
            length: event.length,
            window_size: event.window_size,
            sequence_number: event.sequence_number,
            sequence_number_ack: event.sequence_number_ack,
            icmp_type: if event.protocol == ip_protocol::ICMPV6 {
                Some(event.icmp_type)
            } else {
                None
            },
            icmp_code: if event.protocol == ip_protocol::ICMPV6 {
                Some(event.icmp_code)
            } else {
                None
            },
            flags: event.combined_flags,
            ttl: event.ttl,
            tcp_payload: None,
        }
    }

    /// Decodes an IPv4 packet that starts at `packet`. Bytes past the
    /// declared total length, such as Ethernet padding, are ignored.
    pub fn from_ipv4_packet(
        packet: &[u8],
        timestamp_us: i64,
        capture_tcp_payload: bool,
    ) -> Option<Self> {
        let (header, _) = Ipv4Header::ref_from_prefix(packet).ok()?;
        if header.fragment_offset() > 0 {
            return None;
        }

        let header_length = header.header_length();
        let length = header.total_length.get();
        let transport_length = if capture_tcp_payload && !header.more_fragments() {
            usize::from(length).checked_sub(header_length)
        } else {
            None
        };
        // An IHL below the minimum still leaves the fixed header in front.
        let payload = packet
            .get(header_length.max(size_of::<Ipv4Header>())..)
            .map_or(&[][..], |rest| {
                &rest[..rest
                    .len()
                    .min(usize::from(length).saturating_sub(header_length))]
            });
        extract_packet_features_transport(
            Self {
                source_ip: Ipv4Addr::from(header.source).into(),
                destination_ip: Ipv4Addr::from(header.destination).into(),
                protocol: header.protocol,
                timestamp_us,
                length,
                ttl: header.ttl,
                ..Self::default()
            },
            payload,
            transport_length,
        )
    }

    /// Decodes an IPv6 packet that starts at `packet`. Bytes past the
    /// declared payload length are ignored.
    pub fn from_ipv6_packet(
        packet: &[u8],
        timestamp_us: i64,
        capture_tcp_payload: bool,
    ) -> Option<Self> {
        let (header, rest) = Ipv6Header::ref_from_prefix(packet).ok()?;
        let declared_length = header.payload_length.get();
        let ip_payload = &rest[..rest.len().min(usize::from(declared_length))];
        let (protocol, payload, fragmented) =
            skip_ipv6_extension_headers(header.next_header, ip_payload)?;
        let transport_length = if capture_tcp_payload && !fragmented {
            usize::from(declared_length).checked_sub(ip_payload.len() - payload.len())
        } else {
            None
        };
        extract_packet_features_transport(
            Self {
                source_ip: Ipv6Addr::from(header.source).into(),
                destination_ip: Ipv6Addr::from(header.destination).into(),
                protocol,
                timestamp_us,
                length: if capture_tcp_payload {
                    declared_length.saturating_add(40)
                } else {
                    packet.len() as u16
                },
                ttl: header.hop_limit,
                ..Self::default()
            },
            payload,
            transport_length,
        )
    }

    pub fn flow_key_value(&self) -> FlowKey {
        FlowKey::new(
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol,
        )
    }

    pub fn biflow_key_value(&self) -> FlowKey {
        self.flow_key_value().canonical()
    }
}

fn get_tcp_flag(value: u8, flag: u8) -> u8 {
    ((value & flag) != 0) as u8
}

#[cfg(target_os = "linux")]
fn monotonic_ns_to_epoch_us(timestamp_ns: u64, realtime_offset_us: i64) -> i64 {
    realtime_offset_us + (timestamp_ns / 1_000) as i64
}

fn skip_ipv6_extension_headers(
    mut next_header: u8,
    mut payload: &[u8],
) -> Option<(u8, &[u8], bool)> {
    const MAX_EXTENSION_HEADERS: usize = 8;
    let mut fragmented = false;

    for _ in 0..MAX_EXTENSION_HEADERS {
        let Some(extension) = Ipv6Extension::from_next_header(next_header) else {
            return Some((next_header, payload, fragmented));
        };
        let prefix = *payload.first_chunk::<4>()?;
        let header_len = extension.header_length(prefix)?;
        fragmented |= matches!(extension, Ipv6Extension::Fragment) && prefix[3] & 1 != 0;

        next_header = prefix[0];
        payload = payload.get(header_len..)?;
    }

    Some((next_header, payload, fragmented))
}

fn extract_packet_features_transport(
    mut features: PacketFeatures,
    packet: &[u8],
    declared_transport_length: Option<usize>,
) -> Option<PacketFeatures> {
    match features.protocol {
        ip_protocol::TCP => {
            let (tcp, _) = TcpHeader::ref_from_prefix(packet).ok()?;
            features.source_port = tcp.source_port.get();
            features.destination_port = tcp.destination_port.get();
            features.flags = tcp.flags;
            features.fin_flag = get_tcp_flag(features.flags, FIN_FLAG);
            features.syn_flag = get_tcp_flag(features.flags, SYN_FLAG);
            features.rst_flag = get_tcp_flag(features.flags, RST_FLAG);
            features.psh_flag = get_tcp_flag(features.flags, PSH_FLAG);
            features.ack_flag = get_tcp_flag(features.flags, ACK_FLAG);
            features.urg_flag = get_tcp_flag(features.flags, URG_FLAG);
            features.cwr_flag = get_tcp_flag(features.flags, CWR_FLAG);
            features.ece_flag = get_tcp_flag(features.flags, ECE_FLAG);
            features.header_length = tcp.header_length();
            // A data offset below the minimum still leaves the fixed header in front.
            let payload_start = usize::from(features.header_length).max(size_of::<TcpHeader>());
            features.data_length = packet.len().saturating_sub(payload_start) as u16;
            features.window_size = tcp.window.get();
            features.sequence_number = tcp.sequence_number.get();
            features.sequence_number_ack = tcp.acknowledgement_number.get();
            if let Some(end) = declared_transport_length {
                let start = usize::from(features.header_length);
                if let Some(length) = end.checked_sub(start).filter(|_| start >= 20) {
                    features.data_length = length as u16;
                    if length <= 16 * 1024
                        && crate::flows::features::application::ApplicationProtocol::from_ports(
                            features.source_port,
                            features.destination_port,
                        )
                        .is_some()
                    {
                        features.tcp_payload = packet.get(start..end).map(Box::from);
                    }
                }
            }
        }
        ip_protocol::UDP => {
            let (udp, payload) = UdpHeader::ref_from_prefix(packet).ok()?;
            features.source_port = udp.source_port.get();
            features.destination_port = udp.destination_port.get();
            features.data_length = payload.len() as u16;
            features.header_length = 8;
        }
        ip_protocol::ICMP | ip_protocol::ICMPV6 => {
            // The message-specific rest of the header counts as data here.
            let (icmp, payload) = IcmpHeader::ref_from_prefix(packet).ok()?;
            features.data_length = payload.len() as u16;
            features.header_length = 8;
            features.icmp_type = Some(icmp.icmp_type);
            features.icmp_code = Some(icmp.code);
        }
        _ => {
            debug!("Unsupported protocol in packet!");
            return None;
        }
    }
    Some(features)
}
