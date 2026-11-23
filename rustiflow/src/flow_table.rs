#[cfg(target_os = "linux")]
mod batch_keys;
#[cfg(not(feature = "staged-flow-lookup"))]
use std::collections::{hash_map::Entry, HashMap};
#[cfg(feature = "staged-flow-lookup")]
use std::hash::BuildHasher;
use std::{num::NonZeroU64, time::Instant};

use crate::{
    export_profile,
    flow_key::{FlowKey, FlowKeyHashBuilder, KeyOrientation},
    flows::util::FlowExpireCause,
    output::ShardOutput,
    packet_features::PacketFeatures,
    Flow,
};
#[cfg(feature = "staged-flow-lookup")]
use hashbrown::HashTable;
use log::debug;

#[cfg(all(
    feature = "staged-flow-lookup",
    target_os = "linux",
    target_arch = "x86_64"
))]
mod staged_lookup;

enum FlowUpdate<T> {
    Active,
    EarlyExport(T),
    Terminated,
}

/// A tracked flow, stored under its canonical biflow key.
struct FlowEntry<T> {
    #[cfg(feature = "staged-flow-lookup")]
    key: FlowKey,
    flow: T,
    /// Orientation of the initiator inferred at creation; packets with the same
    /// orientation travel in the flow's forward direction.
    forward_orientation: KeyOrientation,
    /// Next early-export boundary, at first packet + k * interval. Unused when
    /// early export is disabled.
    next_early_export_us: i64,
}

pub struct FlowTable<T> {
    #[cfg(not(feature = "staged-flow-lookup"))]
    flow_map: HashMap<FlowKey, FlowEntry<T>, FlowKeyHashBuilder>,
    #[cfg(feature = "staged-flow-lookup")]
    flow_map: HashTable<FlowEntry<T>>,
    #[cfg(feature = "staged-flow-lookup")]
    hash_builder: FlowKeyHashBuilder,
    #[cfg(all(
        feature = "staged-flow-lookup",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    staged_lookup: bool,
    #[cfg(target_os = "linux")]
    canonicalizer: batch_keys::BatchCanonicalizer,
    active_timeout: u64,
    idle_timeout: u64,
    early_export_us: Option<i64>,
    output: ShardOutput<T>,
    next_check_time_us: Option<i64>, // Track the next time we check for flow expirations
    expiration_check_interval_us: i64, // Check for expired flows every x seconds
}

impl<T> FlowTable<T>
where
    T: Flow,
{
    pub fn new(
        active_timeout: u64,
        idle_timeout: u64,
        early_export: Option<NonZeroU64>,
        output: impl Into<ShardOutput<T>>,
        expiration_check_interval: u64,
    ) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            canonicalizer: batch_keys::BatchCanonicalizer::from_env(),
            #[cfg(not(feature = "staged-flow-lookup"))]
            flow_map: HashMap::default(),
            #[cfg(feature = "staged-flow-lookup")]
            flow_map: HashTable::new(),
            #[cfg(feature = "staged-flow-lookup")]
            hash_builder: FlowKeyHashBuilder::default(),
            #[cfg(all(
                feature = "staged-flow-lookup",
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            staged_lookup: std::env::var_os("RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP")
                .is_some_and(|value| value == "1"),
            active_timeout,
            idle_timeout,
            early_export_us: early_export.map(|seconds| (seconds.get() * 1_000_000) as i64),
            output: output.into(),
            next_check_time_us: None,
            expiration_check_interval_us: (expiration_check_interval * 1_000_000) as i64,
        }
    }

    /// Processes a packet (either IPv4 or IPv6) and updates the flow map.
    ///
    /// Both directions of a biflow share one canonical map entry.
    pub async fn process_packet(&mut self, packet: &PacketFeatures) {
        // Check if enough virtual time has passed to trigger flow expiration checks
        self.check_and_export_expired_flows(packet.timestamp_us)
            .await;
        self.process_packet_without_expiration_scan(packet).await;
    }

    /// Processes a packet when the caller schedules expiration scans separately.
    pub(crate) async fn process_packet_without_expiration_scan(&mut self, packet: &PacketFeatures) {
        let lookup = self.packet_lookup(packet);
        self.apply_lookup(packet, lookup).await;
    }

    fn packet_lookup(&self, packet: &PacketFeatures) -> PacketLookup {
        let (key, orientation) = packet.flow_key_value().canonicalize();
        PacketLookup {
            key,
            orientation,
            #[cfg(feature = "staged-flow-lookup")]
            hash: self.hash_builder.hash_one(key),
            #[cfg(feature = "staged-flow-lookup")]
            bucket_hint: None,
        }
    }

    /// Processes one already ordered realtime shard batch.
    #[cfg(target_os = "linux")]
    pub(crate) async fn process_batch(&mut self, packets: &[PacketFeatures]) {
        #[cfg(all(feature = "staged-flow-lookup", target_arch = "x86_64"))]
        if self.staged_lookup {
            self.process_staged_batch(packets).await;
            return;
        }
        if let Some(orientations) = self.canonicalizer.prepare(packets) {
            let orientations = std::mem::take(orientations);
            for (packet, &orientation) in packets.iter().zip(&orientations) {
                self.check_and_export_expired_flows(packet.timestamp_us)
                    .await;
                let key = packet.flow_key_value();
                let key = match orientation {
                    KeyOrientation::Canonical => key,
                    KeyOrientation::Reversed => key.reverse(),
                };
                let lookup = PacketLookup {
                    key,
                    orientation,
                    #[cfg(feature = "staged-flow-lookup")]
                    hash: self.hash_builder.hash_one(key),
                    #[cfg(feature = "staged-flow-lookup")]
                    bucket_hint: None,
                };
                self.apply_lookup(packet, lookup).await;
            }
            self.canonicalizer.restore(orientations);
            return;
        }
        for packet in packets {
            self.process_packet(packet).await;
        }
    }

    async fn apply_lookup(&mut self, packet: &PacketFeatures, lookup: PacketLookup) {
        let PacketLookup {
            key: biflow_key,
            orientation,
            #[cfg(feature = "staged-flow-lookup")]
            hash,
            #[cfg(feature = "staged-flow-lookup")]
            bucket_hint,
        } = lookup;
        // An earlier packet or expiration sweep may have moved or removed the
        // entry. Validate the hinted slot against the full key before using it.
        #[cfg(feature = "staged-flow-lookup")]
        let valid_hint = bucket_hint.filter(|&index| {
            self.flow_map
                .get_bucket(index)
                .is_some_and(|entry| entry.key == biflow_key)
        });
        #[cfg(feature = "staged-flow-lookup")]
        let occupied = match valid_hint {
            Some(index) => self.flow_map.get_bucket_entry(index),
            None => self
                .flow_map
                .find_entry(hash, |entry| entry.key == biflow_key),
        };
        #[cfg(not(feature = "staged-flow-lookup"))]
        let occupied = match self.flow_map.entry(biflow_key) {
            Entry::Occupied(entry) => Ok(entry),
            Entry::Vacant(_) => Err(()),
        };
        match occupied {
            Ok(mut occupied) => {
                let entry = occupied.get_mut();
                let (is_expired, cause) = entry.flow.is_expired(
                    packet.timestamp_us,
                    self.active_timeout,
                    self.idle_timeout,
                );

                if is_expired {
                    #[cfg(not(feature = "staged-flow-lookup"))]
                    let mut expired_flow = occupied.remove().flow;
                    #[cfg(feature = "staged-flow-lookup")]
                    let mut expired_flow = occupied.remove().0.flow;
                    expired_flow.close_flow(packet.timestamp_us, cause);
                    self.output.export(expired_flow).await;
                    self.create_and_insert_flow(packet, lookup).await;
                    return;
                }

                let is_forward = entry.forward_orientation == orientation;
                match Self::apply_packet_to_flow(entry, packet, is_forward, self.early_export_us) {
                    FlowUpdate::Active => {}
                    FlowUpdate::EarlyExport(snapshot) => {
                        self.output.export(snapshot).await;
                    }
                    FlowUpdate::Terminated => {
                        #[cfg(not(feature = "staged-flow-lookup"))]
                        let terminated_flow = occupied.remove().flow;
                        #[cfg(feature = "staged-flow-lookup")]
                        let terminated_flow = occupied.remove().0.flow;
                        self.output.export(terminated_flow).await;
                    }
                }
            }
            Err(_) => {
                self.create_and_insert_flow(packet, lookup).await;
            }
        }
    }

    /// Create a flow for the given packet and insert it unless it terminated immediately.
    async fn create_and_insert_flow(&mut self, packet: &PacketFeatures, lookup: PacketLookup) {
        let PacketLookup {
            key: biflow_key,
            orientation,
            ..
        } = lookup;
        // A first SYN-ACK identifies the responder even if its SYN is still queued.
        let packet_key = packet.flow_key_value();
        let is_forward = !(packet.protocol == 6 && packet.syn_flag > 0 && packet.ack_flag > 0);
        let forward_key = if is_forward {
            packet_key
        } else {
            packet_key.reverse()
        };
        let forward_orientation = if is_forward {
            orientation
        } else {
            forward_key.canonicalize().1
        };
        let new_flow = T::new(
            forward_key.to_string(),
            forward_key.source.ip,
            forward_key.source.port,
            forward_key.destination.ip,
            forward_key.destination.port,
            packet.protocol,
            packet.timestamp_us,
        );
        let mut entry = FlowEntry {
            #[cfg(feature = "staged-flow-lookup")]
            key: biflow_key,
            flow: new_flow,
            forward_orientation,
            next_early_export_us: packet.timestamp_us + self.early_export_us.unwrap_or(0),
        };
        let snapshot = match Self::apply_packet_to_flow(
            &mut entry,
            packet,
            is_forward,
            self.early_export_us,
        ) {
            FlowUpdate::Active => None,
            FlowUpdate::EarlyExport(snapshot) => Some(snapshot),
            FlowUpdate::Terminated => {
                self.output.export(entry.flow).await;
                return;
            }
        };

        // The authoritative lookup found a miss or removed the expired entry.
        #[cfg(not(feature = "staged-flow-lookup"))]
        self.flow_map.insert(biflow_key, entry);
        #[cfg(feature = "staged-flow-lookup")]
        self.flow_map.insert_unique(lookup.hash, entry, |entry| {
            self.hash_builder.hash_one(entry.key)
        });
        if let Some(snapshot) = snapshot {
            self.output.export(snapshot).await;
        }
    }

    /// Applies a packet to a flow and decides whether it terminated the flow or
    /// reached the flow's next early-export boundary.
    ///
    /// Early exports are cumulative snapshots of the flow so far, closed like a
    /// final export but with cause `None`. Only packets trigger them, so a flow
    /// that goes quiet gets no further snapshots until it expires.
    fn apply_packet_to_flow(
        entry: &mut FlowEntry<T>,
        packet: &PacketFeatures,
        is_forward: bool,
        early_export_us: Option<i64>,
    ) -> FlowUpdate<T> {
        if entry.flow.update_flow(packet, is_forward) {
            return FlowUpdate::Terminated;
        }
        let Some(interval_us) = early_export_us else {
            return FlowUpdate::Active;
        };
        if packet.timestamp_us < entry.next_early_export_us {
            return FlowUpdate::Active;
        }

        // Stay on the first packet + k * interval grid, skipping boundaries that
        // passed without packets, so one packet yields at most one snapshot.
        let first_timestamp_us = entry.flow.get_first_timestamp_us();
        let elapsed_intervals = (packet.timestamp_us - first_timestamp_us) / interval_us;
        entry.next_early_export_us = first_timestamp_us + (elapsed_intervals + 1) * interval_us;

        let clone_start = Instant::now();
        let mut snapshot = entry.flow.clone();
        export_profile::record_clone(clone_start.elapsed());
        snapshot.close_flow(packet.timestamp_us, FlowExpireCause::None);
        FlowUpdate::EarlyExport(snapshot)
    }

    /// Export all flows in the flow map in order of first packet arrival.
    pub async fn export_all_flows(&mut self, timestamp_us: i64) {
        // Sort small (timestamp, key) pairs rather than the flows themselves, so
        // each flow is moved exactly once, out of the map for export.
        let mut export_order: Vec<_> = self
            .entries()
            .map(|(key, entry)| (entry.flow.get_first_timestamp_us(), key))
            .collect();
        export_order.sort_by_key(|&(first_timestamp_us, _)| first_timestamp_us);

        for (_, key) in export_order {
            if let Some(FlowEntry { mut flow, .. }) = self.remove(&key) {
                flow.close_flow(timestamp_us, FlowExpireCause::ExporterShutdown);
                self.output.export(flow).await;
            }
        }
        self.output.flush().await;
    }

    /// Checks if enough time has passed to trigger flow expiration checks and exports expired flows.
    async fn check_and_export_expired_flows(&mut self, current_time_us: i64) {
        if self
            .next_check_time_us
            .is_none_or(|next_check| current_time_us >= next_check)
        {
            self.export_expired_flows(current_time_us).await;
            self.next_check_time_us = Some(current_time_us + self.expiration_check_interval_us);
            debug!(
                "Next flow expiration check scheduled at: {:?}",
                self.next_check_time_us
            );
        }
    }

    /// Export all expired flows.
    pub async fn export_expired_flows(&mut self, timestamp_us: i64) {
        // Export all expired flows
        let expired_flows: Vec<_> = self
            .entries()
            .filter_map(|(key, entry)| {
                let (is_expired, cause) =
                    entry
                        .flow
                        .is_expired(timestamp_us, self.active_timeout, self.idle_timeout);
                if is_expired {
                    Some((key, cause))
                } else {
                    None
                }
            })
            .collect();

        debug!("Exporting {} expired flows", expired_flows.len());
        for (key, cause) in expired_flows {
            if let Some(FlowEntry { mut flow, .. }) = self.remove(&key) {
                flow.close_flow(timestamp_us, cause);
                self.output.export(flow).await;
            }
        }
    }

    fn entries(&self) -> impl Iterator<Item = (FlowKey, &FlowEntry<T>)> {
        #[cfg(feature = "staged-flow-lookup")]
        {
            self.flow_map.iter().map(|entry| (entry.key, entry))
        }
        #[cfg(not(feature = "staged-flow-lookup"))]
        {
            self.flow_map.iter().map(|(key, entry)| (*key, entry))
        }
    }

    #[cfg(not(feature = "staged-flow-lookup"))]
    fn remove(&mut self, key: &FlowKey) -> Option<FlowEntry<T>> {
        self.flow_map.remove(key)
    }
    #[cfg(feature = "staged-flow-lookup")]
    fn remove(&mut self, key: &FlowKey) -> Option<FlowEntry<T>> {
        let hash = self.hash_builder.hash_one(key);
        let (entry, _) = self
            .flow_map
            .find_entry(hash, |entry| entry.key == *key)
            .ok()?
            .remove();
        Some(entry)
    }
}

struct PacketLookup {
    key: FlowKey,
    orientation: KeyOrientation,
    #[cfg(feature = "staged-flow-lookup")]
    hash: u64,
    #[cfg(feature = "staged-flow-lookup")]
    bucket_hint: Option<usize>,
}
