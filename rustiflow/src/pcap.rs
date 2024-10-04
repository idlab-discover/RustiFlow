use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;

use crate::Flow;
use crate::{flow_table::FlowTable, packet_features::PacketFeatures};
use chrono::{DateTime, Utc};
use log::{debug, error};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    icmp::IcmpPacket,
    icmpv6::Icmpv6Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

// Define constants for Linux cooked capture EtherTypes
const SLL_IPV4: u16 = 0x0800;
const SLL_IPV6: u16 = 0x86DD;

// Define TCP flags
const FIN_FLAG: u8 = 0b00000001;
const SYN_FLAG: u8 = 0b00000010;
const RST_FLAG: u8 = 0b00000100;
const PSH_FLAG: u8 = 0b00001000;
const ACK_FLAG: u8 = 0b00010000;
const URG_FLAG: u8 = 0b00100000;
const ECE_FLAG: u8 = 0b01000000;
const CWE_FLAG: u8 = 0b10000000;

pub async fn read_pcap_file<T>(
    path: &str,
    output_channel: Sender<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
) -> Result<(), anyhow::Error>
where
    T: Flow,
{
    debug!("Opening the pcap file: {:?} ...", path);

    let mut pcap_capture = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            error!("Error opening file: {:?}", e);
            return Err(anyhow::Error::new(e));
        }
    };

    // Create sharded FlowTables each in their own task and returns channels to send packets to the shards
    let buffer_num_packets = 10_000;
    let shard_senders = create_shard_senders::<T>(
        num_threads, 
        buffer_num_packets, 
        output_channel, 
        active_timeout, 
        idle_timeout, 
        early_export,
        expiration_check_interval
    );

    debug!("Reading the pcap file: {:?} ...", path);
    while let Ok(packet) = pcap_capture.next_packet() {
        // Convert TimeVal from packet capture to DateTime<Utc>
        let timestamp = DateTime::from_timestamp(
            packet.header.ts.tv_sec,
            (packet.header.ts.tv_usec * 1000) as u32,
        )
        .unwrap();

        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
                        process_packet::<T, Ipv4Packet>(
                            &packet,
                            timestamp,
                            &shard_senders,
                            num_threads,
                            extract_packet_features_ipv4::<T>,
                        )
                        .await;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(packet) = Ipv6Packet::new(ethernet.payload()) {
                        process_packet::<T, Ipv6Packet>(
                            &packet,
                            timestamp,
                            &shard_senders,
                            num_threads,
                            extract_packet_features_ipv6::<T>,
                        )
                        .await;
                    }
                }
                _ => {
                    // Check if it is a Linux cooked capture
                    let ethertype = u16::from_be_bytes([packet.data[14], packet.data[15]]);
                    match ethertype {
                        SLL_IPV4 => {
                            if let Some(packet) = Ipv4Packet::new(&packet.data[16..]) {
                                process_packet::<T, Ipv4Packet>(
                                    &packet,
                                    timestamp,
                                    &shard_senders,
                                    num_threads,
                                    extract_packet_features_ipv4::<T>,
                                )
                                .await;
                            }
                        }
                        SLL_IPV6 => {
                            if let Some(packet) = Ipv6Packet::new(&packet.data[16..]) {
                                process_packet::<T, Ipv6Packet>(
                                    &packet,
                                    timestamp,
                                    &shard_senders,
                                    num_threads,
                                    extract_packet_features_ipv6::<T>,
                                )
                                .await;
                            }
                        }
                        _ => debug!("Failed to parse packet as IPv4 or IPv6..."),
                    }
                }
            }
        } else {
            error!("Error parsing packet...");
        }
    }
    debug!("Finished reading the pcap file: {:?}", path);
    Ok(())
}

/// Processes and sends packet features to the appropriate shard.
async fn process_packet<T, P>(
    packet: &P,
    timestamp: DateTime<Utc>,
    shard_senders: &Vec<mpsc::Sender<PacketFeatures>>,
    num_shards: u8,
    extractor: fn(&P, DateTime<Utc>) -> Option<PacketFeatures>,
) where
    T: Flow,
    P: Packet,
{
    if let Some(packet_features) = extractor(packet, timestamp) {
        let flow_key = packet_features.biflow_key();
        let shard_index = compute_shard_index(&flow_key, num_shards);

        if let Err(e) = shard_senders[shard_index].send(packet_features).await {
            error!(
                "Failed to send packet_features to shard {}: {}",
                shard_index, e
            );
        }
    }
}

fn extract_packet_features_ipv4<T>(
    packet: &Ipv4Packet,
    timestamp: DateTime<Utc>,
) -> Option<PacketFeatures>
where
    T: Flow,
{
    if let Some(packet_features) = extract_packet_features_transport(
        packet.get_source().into(),
        packet.get_destination().into(),
        packet.get_next_level_protocol(),
        timestamp,
        packet.get_total_length(),
        packet.payload(),
    ) {
        Some(packet_features)
    } else {
        debug!("Failed to extract basic features from IPv4 packet");
        None
    }
}

fn extract_packet_features_ipv6<T>(
    packet: &Ipv6Packet,
    timestamp: DateTime<Utc>,
) -> Option<PacketFeatures>
where
    T: Flow,
{
    if let Some(packet_features) = extract_packet_features_transport(
        packet.get_source().into(),
        packet.get_destination().into(),
        packet.get_next_header(),
        timestamp,
        packet.packet().len() as u16,
        packet.payload(),
    ) {
        Some(packet_features)
    } else {
        debug!("Failed to extract basic features from IPv6 packet");
        None
    }
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
            Some(PacketFeatures::new(
                source_ip.into(),
                destination_ip.into(),
                tcp_packet.get_source(),
                tcp_packet.get_destination(),
                protocol.0,
                timestamp,
                get_tcp_flag(tcp_packet.get_flags(), FIN_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), SYN_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), RST_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), PSH_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), ACK_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), URG_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), CWE_FLAG),
                get_tcp_flag(tcp_packet.get_flags(), ECE_FLAG),
                tcp_packet.payload().len() as u16,
                (tcp_packet.get_data_offset() * 4) as u8,
                total_length,
                tcp_packet.get_window(),
            ))
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = UdpPacket::new(packet)?;
            Some(PacketFeatures::new(
                source_ip.into(),
                destination_ip.into(),
                udp_packet.get_source(),
                udp_packet.get_destination(),
                protocol.0,
                timestamp,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0, // No flags for UDP
                udp_packet.payload().len() as u16,
                8,
                total_length,
                0,
            ))
        }
        IpNextHeaderProtocols::Icmp => {
            let icmp_packet = IcmpPacket::new(packet)?;
            Some(PacketFeatures::new(
                source_ip.into(),
                destination_ip.into(),
                0,
                0,
                protocol.0,
                timestamp,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0, // No flags for ICMP
                icmp_packet.payload().len() as u16,
                8,
                total_length,
                0,
            ))
        }
        IpNextHeaderProtocols::Icmpv6 => {
            let icmpv6_packet = Icmpv6Packet::new(packet)?;
            Some(PacketFeatures::new(
                source_ip.into(),
                destination_ip.into(),
                0,
                0,
                protocol.0,
                timestamp,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0, // No flags for ICMPv6
                icmpv6_packet.payload().len() as u16,
                8,
                total_length,
                0,
            ))
        }
        _ => {
            debug!("Unsupported protocol in packet!");
            return None;
        }
    }
}

fn get_tcp_flag(value: u8, flag: u8) -> u8 {
    ((value & flag) != 0) as u8
}

fn compute_shard_index(flow_key: &str, num_shards: u8) -> usize {
    assert!(num_shards > 0, "num_shards must be greater than 0");
    let mut hasher = DefaultHasher::new();
    flow_key.hash(&mut hasher);
    let hash = hasher.finish();
    (hash % num_shards as u64) as usize
}

/// Creates shard channels to FlowTables and spawns processing tasks for each shard.
fn create_shard_senders<T>(
    num_shards: u8,
    buffer_num_packets: usize,
    output_channel: Sender<T>,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
) -> Vec<mpsc::Sender<PacketFeatures>>
where
    T: Flow,
{
    debug!("Creating {} sharded FlowTables...", num_shards);
    let mut shard_senders = Vec::with_capacity(num_shards as usize);
    for _ in 0..num_shards {
        let (tx, mut rx) = mpsc::channel::<PacketFeatures>(buffer_num_packets);
        let mut flow_table = FlowTable::new(active_timeout, idle_timeout, early_export, output_channel.clone(), expiration_check_interval);
        
        tokio::spawn(async move {
            while let Some(packet_features) = rx.recv().await {
                flow_table.process_packet(&packet_features).await;
            }
            // Handle flow exporting when the receiver is closed
            flow_table.export_all_flows().await;
        });
        shard_senders.push(tx);
    }
    debug!("Sharded FlowTables created");

    shard_senders
}
