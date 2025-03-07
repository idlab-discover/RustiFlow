use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::debug;
use pnet::packet::{
    icmp::IcmpPacket,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};

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
            timestamp_us: Utc::now().timestamp_micros(),
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
}

impl PacketFeatures {
    // Constructor to create PacketFeatures from EbpfEventIpv4
    pub fn from_ebpf_event_ipv4(event: &EbpfEventIpv4) -> Self {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::from(event.ipv4_source.to_be())),
            destination_ip: IpAddr::V4(Ipv4Addr::from(event.ipv4_destination.to_be())),
            source_port: event.port_source,
            destination_port: event.port_destination,
            protocol: event.protocol,
            timestamp_us: chrono::Utc::now().timestamp_micros(),
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
            icmp_type: if event.protocol == IpNextHeaderProtocols::Icmp.0 {
                Some(event.icmp_type)
            } else {
                None
            },
            icmp_code: if event.protocol == IpNextHeaderProtocols::Icmp.0 {
                Some(event.icmp_code)
            } else {
                None
            },
            flags: event.combined_flags,
        }
    }

    // Constructor to create PacketFeatures from EbpfEventIpv6
    pub fn from_ebpf_event_ipv6(event: &EbpfEventIpv6) -> Self {
        PacketFeatures {
            source_ip: IpAddr::V6(Ipv6Addr::from(event.ipv6_source.to_be())),
            destination_ip: IpAddr::V6(Ipv6Addr::from(event.ipv6_destination.to_be())),
            source_port: event.port_source,
            destination_port: event.port_destination,
            protocol: event.protocol,
            timestamp_us: chrono::Utc::now().timestamp_micros(),
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
            icmp_type: if event.protocol == IpNextHeaderProtocols::Icmpv6.0 {
                Some(event.icmp_type)
            } else {
                None
            },
            icmp_code: if event.protocol == IpNextHeaderProtocols::Icmpv6.0 {
                Some(event.icmp_code)
            } else {
                None
            },
            flags: event.combined_flags,
        }
    }

    // Constructor to create PacketFeatures from an IPv4 packet
    pub fn from_ipv4_packet(packet: &Ipv4Packet, timestamp_us: i64) -> Option<Self> {
        extract_packet_features_transport(
            packet.get_source().into(),
            packet.get_destination().into(),
            packet.get_next_level_protocol(),
            timestamp_us,
            packet.get_total_length(),
            packet.payload(),
        )
    }

    // Constructor to create PacketFeatures from an IPv6 packet
    pub fn from_ipv6_packet(packet: &Ipv6Packet, timestamp_us: i64) -> Option<Self> {
        extract_packet_features_transport(
            packet.get_source().into(),
            packet.get_destination().into(),
            packet.get_next_header(),
            timestamp_us,
            packet.packet().len() as u16,
            packet.payload(),
        )
    }

    /// Generates a flow key based on IPs, ports, and protocol
    pub fn flow_key(&self) -> String {
        format!(
            "{}:{}-{}:{}-{}",
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol
        )
    }

    /// Generates a flow key based on IPs, ports, and protocol in the reverse direction
    pub fn flow_key_bwd(&self) -> String {
        format!(
            "{}:{}-{}:{}-{}",
            self.destination_ip,
            self.destination_port,
            self.source_ip,
            self.source_port,
            self.protocol
        )
    }

    /// Generates a biflow key
    pub fn biflow_key(&self) -> String {
        // Create tuples of (IP, port) for comparison
        let src = (&self.source_ip, self.source_port);
        let dst = (&self.destination_ip, self.destination_port);

        // Determine the correct order (src < dst)
        if src < dst {
            format!(
                "{}:{}-{}:{}-{}",
                self.source_ip,
                self.source_port,
                self.destination_ip,
                self.destination_port,
                self.protocol
            )
        } else {
            // If destination IP/port is "smaller", swap the order
            format!(
                "{}:{}-{}:{}-{}",
                self.destination_ip,
                self.destination_port,
                self.source_ip,
                self.source_port,
                self.protocol
            )
        }
    }
}

fn get_tcp_flag(value: u8, flag: u8) -> u8 {
    ((value & flag) != 0) as u8
}

fn extract_packet_features_transport(
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: IpNextHeaderProtocol,
    timestamp_us: i64,
    total_length: u16,
    packet: &[u8],
) -> Option<PacketFeatures> {
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = TcpPacket::new(packet)?;
            Some(PacketFeatures {
                source_ip,
                destination_ip,
                source_port: tcp_packet.get_source(),
                destination_port: tcp_packet.get_destination(),
                protocol: protocol.0,
                timestamp_us,
                fin_flag: get_tcp_flag(tcp_packet.get_flags(), FIN_FLAG),
                syn_flag: get_tcp_flag(tcp_packet.get_flags(), SYN_FLAG),
                rst_flag: get_tcp_flag(tcp_packet.get_flags(), RST_FLAG),
                psh_flag: get_tcp_flag(tcp_packet.get_flags(), PSH_FLAG),
                ack_flag: get_tcp_flag(tcp_packet.get_flags(), ACK_FLAG),
                urg_flag: get_tcp_flag(tcp_packet.get_flags(), URG_FLAG),
                cwr_flag: get_tcp_flag(tcp_packet.get_flags(), CWR_FLAG),
                ece_flag: get_tcp_flag(tcp_packet.get_flags(), ECE_FLAG),
                data_length: tcp_packet.payload().len() as u16,
                header_length: (tcp_packet.get_data_offset() * 4) as u8,
                length: total_length,
                window_size: tcp_packet.get_window(),
                sequence_number: tcp_packet.get_sequence(),
                sequence_number_ack: tcp_packet.get_acknowledgement(),
                icmp_type: None,
                icmp_code: None,
                flags: tcp_packet.get_flags(),
            })
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = UdpPacket::new(packet)?;
            Some(PacketFeatures {
                source_ip,
                destination_ip,
                source_port: udp_packet.get_source(),
                destination_port: udp_packet.get_destination(),
                protocol: protocol.0,
                timestamp_us,
                fin_flag: 0,
                syn_flag: 0,
                rst_flag: 0,
                psh_flag: 0,
                ack_flag: 0,
                urg_flag: 0,
                cwr_flag: 0,
                ece_flag: 0,
                data_length: udp_packet.payload().len() as u16,
                header_length: 8, // Fixed header size for UDP
                length: total_length,
                window_size: 0,         // No window size for UDP
                sequence_number: 0,     // No sequence number for UDP
                sequence_number_ack: 0, // No sequence number ACK for UDP
                icmp_type: None,
                icmp_code: None,
                flags: 0, // No flags for UDP
            })
        }
        IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
            let icmp_packet = IcmpPacket::new(packet)?;
            Some(PacketFeatures {
                source_ip,
                destination_ip,
                source_port: 0,
                destination_port: 0,
                protocol: protocol.0,
                timestamp_us,
                fin_flag: 0,
                syn_flag: 0,
                rst_flag: 0,
                psh_flag: 0,
                ack_flag: 0,
                urg_flag: 0,
                cwr_flag: 0,
                ece_flag: 0,
                data_length: icmp_packet.payload().len() as u16,
                header_length: 8, // Fixed header size for ICMP
                length: total_length,
                window_size: 0,         // No window size for ICMP
                sequence_number: 0,     // No sequence number for ICMP
                sequence_number_ack: 0, // No sequence number ACK for ICMP
                icmp_type: Some(icmp_packet.get_icmp_type().0),
                icmp_code: Some(icmp_packet.get_icmp_code().0),
                flags: 0, // No flags for ICMP
            })
        }
        _ => {
            debug!("Unsupported protocol in packet!");
            None
        }
    }
}
