use std::{
    collections::{hash_map::Entry, HashMap},
    time::Instant,
};

use crate::{
    export_profile,
    flow_key::{FlowKey, KeyOrientation},
    flows::util::FlowExpireCause,
    packet_features::PacketFeatures,
    Flow,
};
use log::{debug, error};
use tokio::sync::mpsc;

enum FlowUpdate<T> {
    Active,
    EarlyExport(T),
    Terminated,
}

/// A tracked flow, stored under its canonical biflow key.
struct FlowEntry<T> {
    flow: T,
    /// Orientation of the packet that created the flow; packets with the same
    /// orientation travel in the flow's forward direction.
    forward_orientation: KeyOrientation,
}

pub struct FlowTable<T> {
    flow_map: HashMap<FlowKey, FlowEntry<T>>, // Keyed by canonical biflow key
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    export_channel: mpsc::Sender<T>,
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
        early_export: Option<u64>,
        export_channel: mpsc::Sender<T>,
        expiration_check_interval: u64,
    ) -> Self {
        Self {
            flow_map: HashMap::new(),
            active_timeout,
            idle_timeout,
            early_export,
            export_channel,
            next_check_time_us: None,
            expiration_check_interval_us: (expiration_check_interval * 1_000_000) as i64,
        }
    }

    /// Processes a packet (either IPv4 or IPv6) and updates the flow map.
    ///
    /// Both directions of a biflow share one canonical map entry, so each packet
    /// costs a single hash-table lookup.
    pub async fn process_packet(&mut self, packet: &PacketFeatures) {
        // Check if enough virtual time has passed to trigger flow expiration checks
        self.check_and_export_expired_flows(packet.timestamp_us)
            .await;

        let (biflow_key, orientation) = packet.flow_key_value().canonicalize();
        match self.flow_map.entry(biflow_key) {
            Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                let (is_expired, cause) = entry.flow.is_expired(
                    packet.timestamp_us,
                    self.active_timeout,
                    self.idle_timeout,
                );

                if is_expired {
                    let mut expired_flow = occupied.remove().flow;
                    expired_flow.close_flow(packet.timestamp_us, cause);
                    Self::export(&self.export_channel, expired_flow).await;
                    self.create_and_insert_flow(packet, biflow_key, orientation)
                        .await;
                    return;
                }

                let is_forward = entry.forward_orientation == orientation;
                match Self::apply_packet_to_flow(
                    &mut entry.flow,
                    packet,
                    is_forward,
                    self.early_export,
                ) {
                    FlowUpdate::Active => {}
                    FlowUpdate::EarlyExport(snapshot) => {
                        Self::export(&self.export_channel, snapshot).await;
                    }
                    FlowUpdate::Terminated => {
                        let terminated_flow = occupied.remove().flow;
                        Self::export(&self.export_channel, terminated_flow).await;
                    }
                }
            }
            Entry::Vacant(_) => {
                self.create_and_insert_flow(packet, biflow_key, orientation)
                    .await;
            }
        }
    }

    /// Create a flow for the given packet and insert it unless it terminated immediately.
    async fn create_and_insert_flow(
        &mut self,
        packet: &PacketFeatures,
        biflow_key: FlowKey,
        orientation: KeyOrientation,
    ) {
        let mut new_flow = T::new(
            packet.flow_key_value().to_string(),
            packet.source_ip,
            packet.source_port,
            packet.destination_ip,
            packet.destination_port,
            packet.protocol,
            packet.timestamp_us,
        );
        let snapshot =
            match Self::apply_packet_to_flow(&mut new_flow, packet, true, self.early_export) {
                FlowUpdate::Active => None,
                FlowUpdate::EarlyExport(snapshot) => Some(snapshot),
                FlowUpdate::Terminated => {
                    Self::export(&self.export_channel, new_flow).await;
                    return;
                }
            };

        self.flow_map.insert(
            biflow_key,
            FlowEntry {
                flow: new_flow,
                forward_orientation: orientation,
            },
        );
        if let Some(snapshot) = snapshot {
            Self::export(&self.export_channel, snapshot).await;
        }
    }

    fn apply_packet_to_flow(
        flow: &mut T,
        packet: &PacketFeatures,
        is_forward: bool,
        early_export: Option<u64>,
    ) -> FlowUpdate<T> {
        if flow.update_flow(packet, is_forward) {
            FlowUpdate::Terminated
        } else if early_export.is_some_and(|early_export| {
            ((packet.timestamp_us - flow.get_first_timestamp_us()) / 1_000_000) as u64
                > early_export
        }) {
            let clone_start = Instant::now();
            let snapshot = flow.clone();
            export_profile::record_clone(clone_start.elapsed());
            FlowUpdate::EarlyExport(snapshot)
        } else {
            FlowUpdate::Active
        }
    }

    /// Export all flows in the flow map in order of first packet arrival.
    pub async fn export_all_flows(&mut self, timestamp_us: i64) {
        let mut flows_to_export: Vec<_> = self
            .flow_map
            .drain() // Drain all entries from the map
            .map(|(_, entry)| entry.flow) // Collect all flows
            .collect();

        // Sort flows by `first_timestamp`
        flows_to_export.sort_by_key(|flow| flow.get_first_timestamp_us());

        // Export each flow in order of `first_timestamp`
        for mut flow in flows_to_export {
            flow.close_flow(timestamp_us, FlowExpireCause::ExporterShutdown);
            Self::export(&self.export_channel, flow).await;
        }
    }

    /// Exports a single flow.
    async fn export(export_channel: &mpsc::Sender<T>, flow: T) {
        if export_channel.is_closed() {
            error!("Failed to send flow: export channel is closed");
        } else if let Err(e) = export_channel.send(flow).await {
            error!("Failed to send flow: {}", e);
        }
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
            .flow_map
            .iter()
            .filter_map(|(key, entry)| {
                let (is_expired, cause) =
                    entry
                        .flow
                        .is_expired(timestamp_us, self.active_timeout, self.idle_timeout);
                if is_expired {
                    Some((*key, cause))
                } else {
                    None
                }
            })
            .collect();

        debug!("Exporting {} expired flows", expired_flows.len());
        for (key, cause) in expired_flows {
            if let Some(FlowEntry { mut flow, .. }) = self.flow_map.remove(&key) {
                flow.close_flow(timestamp_us, cause);
                Self::export(&self.export_channel, flow).await;
            }
        }
    }
}
