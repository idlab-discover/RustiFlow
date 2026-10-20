use std::num::NonZeroUsize;

use crate::flow_key::ShardSelector;
use crate::output::FlowSink;
use crate::Flow;
use crate::{flow_table::FlowTable, packet_features::PacketFeatures};
use anyhow::Context;
use chrono::DateTime;
use log::{debug, error};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    Packet,
};
use tokio::sync::mpsc;

// Define constants for Linux cooked capture EtherTypes
const SLL_IPV4: u16 = 0x0800;
const SLL_IPV6: u16 = 0x86DD;
// Define constant for 802.1Q VLAN EtherType
const ETHERTYPE_VLAN: u16 = 0x8100;

pub async fn read_pcap_file<T>(
    path: &str,
    exporter: impl FlowSink<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
) -> Result<(), anyhow::Error>
where
    T: Flow,
{
    let shard_count =
        NonZeroUsize::new(usize::from(num_threads)).context("thread count must be at least 1")?;

    debug!("Opening the pcap file: {:?} ...", path);

    let mut pcap_capture = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            error!("Error opening file: {:?}", e);
            return Err(anyhow::Error::new(e));
        }
    };

    // Create sharded FlowTables each in their own task and route packets to them in batches
    let mut dispatcher = ShardDispatcher::new(
        shard_count,
        create_shard_senders::<T>(
            num_threads,
            exporter,
            active_timeout,
            idle_timeout,
            early_export,
            expiration_check_interval,
        ),
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
                            &mut dispatcher,
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
                            &mut dispatcher,
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
                                        &mut dispatcher,
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
                                        &mut dispatcher,
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
                    if packet.data.len() < 16 {
                        debug!("Packet too short for Linux cooked capture header");
                        continue;
                    }

                    let ethertype = u16::from_be_bytes([packet.data[14], packet.data[15]]);
                    match ethertype {
                        SLL_IPV4 => {
                            if let Some(packet) = Ipv4Packet::new(&packet.data[16..]) {
                                process_packet::<T, Ipv4Packet>(
                                    &packet,
                                    timestamp_us,
                                    &mut dispatcher,
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
                                    &mut dispatcher,
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
                                                &mut dispatcher,
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
                                                &mut dispatcher,
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
    dispatcher.flush().await;
    debug!("Finished reading the pcap file: {:?}", path);
    Ok(())
}

/// Packets routed to a shard per channel send.
const SHARD_BATCH_SIZE: usize = 128;
/// Batches that may wait for a shard (about 10k packets).
const SHARD_QUEUE_CAPACITY: usize = 10_000 / SHARD_BATCH_SIZE;

/// Routes packets to shard tasks in per-shard batches, preserving each shard's
/// packet order while amortizing channel sends and wakeups.
struct ShardDispatcher {
    selector: ShardSelector,
    senders: Vec<mpsc::Sender<Vec<PacketFeatures>>>,
    pending: Vec<Vec<PacketFeatures>>,
}

impl ShardDispatcher {
    fn new(shard_count: NonZeroUsize, senders: Vec<mpsc::Sender<Vec<PacketFeatures>>>) -> Self {
        Self {
            selector: ShardSelector::new(shard_count),
            pending: senders
                .iter()
                .map(|_| Vec::with_capacity(SHARD_BATCH_SIZE))
                .collect(),
            senders,
        }
    }

    async fn dispatch(&mut self, packet_features: PacketFeatures) {
        let shard_index = self
            .selector
            .shard_index(&packet_features.biflow_key_value());
        self.pending[shard_index].push(packet_features);
        if self.pending[shard_index].len() >= SHARD_BATCH_SIZE {
            self.send_pending(shard_index).await;
        }
    }

    /// Sends every partially filled batch.
    async fn flush(&mut self) {
        for shard_index in 0..self.pending.len() {
            if !self.pending[shard_index].is_empty() {
                self.send_pending(shard_index).await;
            }
        }
    }

    async fn send_pending(&mut self, shard_index: usize) {
        let batch = std::mem::replace(
            &mut self.pending[shard_index],
            Vec::with_capacity(SHARD_BATCH_SIZE),
        );
        if let Err(e) = self.senders[shard_index].send(batch).await {
            error!(
                "Failed to send packet batch to shard {}: {}",
                shard_index, e
            );
        }
    }
}

/// Extracts packet features and routes them to the appropriate shard.
async fn process_packet<T, P>(
    packet: &P,
    timestamp_us: i64,
    dispatcher: &mut ShardDispatcher,
    extractor: fn(&P, i64) -> Option<PacketFeatures>,
) where
    T: Flow,
    P: Packet,
{
    if let Some(packet_features) = extractor(packet, timestamp_us) {
        dispatcher.dispatch(packet_features).await;
    }
}

/// Creates shard channels to FlowTables and spawns processing tasks for each shard.
fn create_shard_senders<T>(
    num_shards: u8,
    exporter: impl FlowSink<T>,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
) -> Vec<mpsc::Sender<Vec<PacketFeatures>>>
where
    T: Flow,
{
    debug!("Creating {} sharded FlowTables...", num_shards);
    let mut shard_senders = Vec::with_capacity(num_shards as usize);
    for _ in 0..num_shards {
        let (tx, mut rx) = mpsc::channel::<Vec<PacketFeatures>>(SHARD_QUEUE_CAPACITY);
        let mut flow_table = FlowTable::new(
            active_timeout,
            idle_timeout,
            early_export,
            exporter.shard_sender(),
            expiration_check_interval,
        );

        tokio::spawn(async move {
            let mut last_timestamp = None;
            while let Some(packet_batch) = rx.recv().await {
                for packet_features in packet_batch {
                    last_timestamp = Some(packet_features.timestamp_us);
                    flow_table.process_packet(&packet_features).await;
                }
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
