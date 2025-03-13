use std::hash::{DefaultHasher, Hash, Hasher};

use crate::Flow;
use crate::{flow_table::FlowTable, packet_features::PacketFeatures};
use chrono::DateTime;
use log::{debug, error};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    Packet,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

// Define constants for Linux cooked capture EtherTypes
const SLL_IPV4: u16 = 0x0800;
const SLL_IPV6: u16 = 0x86DD;
// Define constant for 802.1Q VLAN EtherType
const ETHERTYPE_VLAN: u16 = 0x8100;

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
        expiration_check_interval,
    );

    debug!("Reading the pcap file: {:?} ...", path);
    while let Ok(packet) = pcap_capture.next_packet() {
        // Convert TimeVal from packet capture to DateTime<Utc>
        let timestamp_us = DateTime::from_timestamp(
            packet.header.ts.tv_sec,
            (packet.header.ts.tv_usec * 1000) as u32,
        )
        .unwrap()
        .timestamp_micros();

        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
                        process_packet::<T, Ipv4Packet>(
                            &packet,
                            timestamp_us,
                            &shard_senders,
                            num_threads,
                            PacketFeatures::from_ipv4_packet,
                        )
                        .await;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(packet) = Ipv6Packet::new(ethernet.payload()) {
                        process_packet::<T, Ipv6Packet>(
                            &packet,
                            timestamp_us,
                            &shard_senders,
                            num_threads,
                            PacketFeatures::from_ipv6_packet,
                        )
                        .await;
                    }
                }
                EtherTypes::Vlan => {
                    // Handle 802.1Q VLAN tagged packets
                    // VLAN header is 4 bytes: 2 bytes for VLAN tag and 2 bytes for inner EtherType
                    if ethernet.payload().len() >= 4 {
                        let inner_ethertype =
                            u16::from_be_bytes([ethernet.payload()[2], ethernet.payload()[3]]);

                        match inner_ethertype {
                            SLL_IPV4 => {
                                if let Some(packet) = Ipv4Packet::new(&ethernet.payload()[4..]) {
                                    process_packet::<T, Ipv4Packet>(
                                        &packet,
                                        timestamp_us,
                                        &shard_senders,
                                        num_threads,
                                        PacketFeatures::from_ipv4_packet,
                                    )
                                    .await;
                                }
                            }
                            SLL_IPV6 => {
                                if let Some(packet) = Ipv6Packet::new(&ethernet.payload()[4..]) {
                                    process_packet::<T, Ipv6Packet>(
                                        &packet,
                                        timestamp_us,
                                        &shard_senders,
                                        num_threads,
                                        PacketFeatures::from_ipv6_packet,
                                    )
                                    .await;
                                }
                            }
                            _ => debug!(
                                "Unsupported inner EtherType in VLAN packet: 0x{:04x}",
                                inner_ethertype
                            ),
                        }
                    } else {
                        debug!("VLAN packet too short to contain inner EtherType");
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
                                    timestamp_us,
                                    &shard_senders,
                                    num_threads,
                                    PacketFeatures::from_ipv4_packet,
                                )
                                .await;
                            }
                        }
                        SLL_IPV6 => {
                            if let Some(packet) = Ipv6Packet::new(&packet.data[16..]) {
                                process_packet::<T, Ipv6Packet>(
                                    &packet,
                                    timestamp_us,
                                    &shard_senders,
                                    num_threads,
                                    PacketFeatures::from_ipv6_packet,
                                )
                                .await;
                            }
                        }
                        ETHERTYPE_VLAN => {
                            // Handle VLAN in Linux cooked capture
                            if packet.data.len() >= 20 {
                                // 16 bytes SLL header + 4 bytes VLAN header
                                let inner_ethertype =
                                    u16::from_be_bytes([packet.data[18], packet.data[19]]);

                                match inner_ethertype {
                                    SLL_IPV4 => {
                                        if let Some(packet) = Ipv4Packet::new(&packet.data[20..]) {
                                            process_packet::<T, Ipv4Packet>(
                                                &packet,
                                                timestamp_us,
                                                &shard_senders,
                                                num_threads,
                                                PacketFeatures::from_ipv4_packet,
                                            )
                                            .await;
                                        }
                                    }
                                    SLL_IPV6 => {
                                        if let Some(packet) = Ipv6Packet::new(&packet.data[20..]) {
                                            process_packet::<T, Ipv6Packet>(
                                                &packet,
                                                timestamp_us,
                                                &shard_senders,
                                                num_threads,
                                                PacketFeatures::from_ipv6_packet,
                                            )
                                            .await;
                                        }
                                    }
                                    _ => debug!(
                                        "Unsupported inner EtherType in VLAN packet: 0x{:04x}",
                                        inner_ethertype
                                    ),
                                }
                            } else {
                                debug!("VLAN packet in Linux cooked capture too short");
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
    timestamp_us: i64,
    shard_senders: &Vec<mpsc::Sender<PacketFeatures>>,
    num_shards: u8,
    extractor: fn(&P, i64) -> Option<PacketFeatures>,
) where
    T: Flow,
    P: Packet,
{
    if let Some(packet_features) = extractor(packet, timestamp_us) {
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
        let mut flow_table = FlowTable::new(
            active_timeout,
            idle_timeout,
            early_export,
            output_channel.clone(),
            expiration_check_interval,
        );

        tokio::spawn(async move {
            let mut last_timestamp = None;
            while let Some(packet_features) = rx.recv().await {
                last_timestamp = Some(packet_features.timestamp_us);
                flow_table.process_packet(&packet_features).await;
            }
            // Handle flow exporting when the receiver is closed
            if let Some(timestamp) = last_timestamp {
                flow_table.export_all_flows(timestamp).await;
            }
        });
        shard_senders.push(tx);
    }
    debug!("Sharded FlowTables created");

    shard_senders
}
