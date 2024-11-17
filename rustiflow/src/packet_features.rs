use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
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
const FIN_FLAG: u8 = 0b00000001;
const SYN_FLAG: u8 = 0b00000010;
const RST_FLAG: u8 = 0b00000100;
const PSH_FLAG: u8 = 0b00001000;
const ACK_FLAG: u8 = 0b00010000;
const URG_FLAG: u8 = 0b00100000;
const ECE_FLAG: u8 = 0b01000000;
const CWE_FLAG: u8 = 0b10000000;

impl Default for PacketFeatures {
    fn default() -> Self {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            source_port: 0,
            destination_port: 0,
            protocol: 0,
            timestamp: Utc::now(),
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 0,
            length: 0,
            window_size: 0,
            sequence_number: 0,
            sequence_number_ack: 0,
        }
    }
}

pub struct PacketFeatures {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub timestamp: DateTime<Utc>,
    pub fin_flag: u8,
    pub syn_flag: u8,
    pub rst_flag: u8,
    pub psh_flag: u8,
    pub ack_flag: u8,
    pub urg_flag: u8,
    pub cwe_flag: u8,
    pub ece_flag: u8,
    pub data_length: u16,
    pub header_length: u8,
    pub length: u16,
    pub window_size: u16,
    pub sequence_number: u32,
    pub sequence_number_ack: u32,
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
            timestamp: chrono::Utc::now(),
            fin_flag: get_tcp_flag(event.combined_flags, FIN_FLAG),
            syn_flag: get_tcp_flag(event.combined_flags, SYN_FLAG),
            rst_flag: get_tcp_flag(event.combined_flags, RST_FLAG),
            psh_flag: get_tcp_flag(event.combined_flags, PSH_FLAG),
            ack_flag: get_tcp_flag(event.combined_flags, ACK_FLAG),
            urg_flag: get_tcp_flag(event.combined_flags, URG_FLAG),
            cwe_flag: get_tcp_flag(event.combined_flags, CWE_FLAG),
            ece_flag: get_tcp_flag(event.combined_flags, ECE_FLAG),
            data_length: event.data_length,
            header_length: event.header_length,
            length: event.length,
            window_size: event.window_size,
            sequence_number: event.sequence_number,
            sequence_number_ack: event.sequence_number_ack,
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
            timestamp: chrono::Utc::now(),
            fin_flag: get_tcp_flag(event.combined_flags, FIN_FLAG),
            syn_flag: get_tcp_flag(event.combined_flags, SYN_FLAG),
            rst_flag: get_tcp_flag(event.combined_flags, RST_FLAG),
            psh_flag: get_tcp_flag(event.combined_flags, PSH_FLAG),
            ack_flag: get_tcp_flag(event.combined_flags, ACK_FLAG),
            urg_flag: get_tcp_flag(event.combined_flags, URG_FLAG),
            cwe_flag: get_tcp_flag(event.combined_flags, CWE_FLAG),
            ece_flag: get_tcp_flag(event.combined_flags, ECE_FLAG),
            data_length: event.data_length,
            header_length: event.header_length,
            length: event.length,
            window_size: event.window_size,
            sequence_number: event.sequence_number,
            sequence_number_ack: event.sequence_number_ack,
        }
    }

    // Constructor to create PacketFeatures from an IPv4 packet
    pub fn from_ipv4_packet(packet: &Ipv4Packet, timestamp: DateTime<Utc>) -> Option<Self> {
        extract_packet_features_transport(
            packet.get_source().into(),
            packet.get_destination().into(),
            packet.get_next_level_protocol(),
            timestamp,
            packet.get_total_length(),
            packet.payload(),
        )
    }

    // Constructor to create PacketFeatures from an IPv6 packet
    pub fn from_ipv6_packet(packet: &Ipv6Packet, timestamp: DateTime<Utc>) -> Option<Self> {
        extract_packet_features_transport(
            packet.get_source().into(),
            packet.get_destination().into(),
            packet.get_next_header(),
            timestamp,
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
    timestamp: DateTime<Utc>,
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
                timestamp,
                fin_flag: get_tcp_flag(tcp_packet.get_flags(), FIN_FLAG),
                syn_flag: get_tcp_flag(tcp_packet.get_flags(), SYN_FLAG),
                rst_flag: get_tcp_flag(tcp_packet.get_flags(), RST_FLAG),
                psh_flag: get_tcp_flag(tcp_packet.get_flags(), PSH_FLAG),
                ack_flag: get_tcp_flag(tcp_packet.get_flags(), ACK_FLAG),
                urg_flag: get_tcp_flag(tcp_packet.get_flags(), URG_FLAG),
                cwe_flag: get_tcp_flag(tcp_packet.get_flags(), CWE_FLAG),
                ece_flag: get_tcp_flag(tcp_packet.get_flags(), ECE_FLAG),
                data_length: tcp_packet.payload().len() as u16,
                header_length: (tcp_packet.get_data_offset() * 4) as u8,
                length: total_length,
                window_size: tcp_packet.get_window(),
                sequence_number: tcp_packet.get_sequence(),
                sequence_number_ack: tcp_packet.get_acknowledgement(),
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
                timestamp,
                fin_flag: 0,
                syn_flag: 0,
                rst_flag: 0,
                psh_flag: 0,
                ack_flag: 0,
                urg_flag: 0,
                cwe_flag: 0,
                ece_flag: 0,
                data_length: udp_packet.payload().len() as u16,
                header_length: 8, // Fixed header size for UDP
                length: total_length,
                window_size: 0,         // No window size for UDP
                sequence_number: 0,     // No sequence number for UDP
                sequence_number_ack: 0, // No sequence number ACK for UDP
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
                timestamp,
                fin_flag: 0,
                syn_flag: 0,
                rst_flag: 0,
                psh_flag: 0,
                ack_flag: 0,
                urg_flag: 0,
                cwe_flag: 0,
                ece_flag: 0,
                data_length: icmp_packet.payload().len() as u16,
                header_length: 8, // Fixed header size for ICMP
                length: total_length,
                window_size: 0,         // No window size for ICMP
                sequence_number: 0,     // No sequence number for ICMP
                sequence_number_ack: 0, // No sequence number ACK for ICMP
            })
        }
        _ => {
            debug!("Unsupported protocol in packet!");
            None
        }
    }
}
