use std::collections::HashMap;

use crate::{packet_features::PacketFeatures, Flow};
use chrono::{DateTime, TimeDelta, Utc};
use log::{debug, error};
use tokio::sync::mpsc;

pub struct FlowTable<T> {
    flow_map: HashMap<String, T>, // HashMap for fast flow access by key
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    export_channel: mpsc::Sender<T>,
    next_check_time: Option<DateTime<Utc>>, // Track the next time we check for flow expirations
    expiration_check_interval: TimeDelta,   // Check for expired flows every x seconds
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
            next_check_time: None,
            expiration_check_interval: TimeDelta::seconds(expiration_check_interval as i64),
        }
    }

    /// Processes a packet (either IPv4 or IPv6) and updates the flow map.
    pub async fn process_packet(&mut self, packet: &PacketFeatures) {
        debug!("Processing packet: {:?}", packet.flow_key());

        // Check if enough virtual time has passed to trigger flow expiration checks
        self.check_and_export_expired_flows(packet.timestamp).await;

        // Determine the flow direction and key
        let flow_key = if self.flow_map.contains_key(&packet.flow_key_bwd()) {
            packet.flow_key_bwd()
        } else {
            packet.flow_key()
        };

        // Update the flow if it exists, otherwise create a new flow
        if let Some(mut flow) = self.flow_map.remove(&flow_key) {
            if flow.is_expired(packet.timestamp, self.active_timeout, self.idle_timeout) {
                debug!("Flow expired: {:?}, Creating new Flow", flow.flow_key());
                self.export_flow(flow).await;
                self.create_and_insert_flow(packet).await;
            } else {
                debug!("Updating flow: {:?}", flow.flow_key());
                let is_terminated = self.update_flow_with_packet(&mut flow, packet).await;
                if !is_terminated {
                    self.flow_map.insert(flow_key, flow);
                }
            }
        } else {
            debug!("Creating new Flow: {:?}", packet.flow_key());
            self.create_and_insert_flow(packet).await;
        }
    }

    /// Create and insert a new flow for the given packet.
    async fn create_and_insert_flow(&mut self, packet: &PacketFeatures) {
        let mut new_flow = T::new(
            packet.flow_key(),
            packet.source_ip,
            packet.source_port,
            packet.destination_ip,
            packet.destination_port,
            packet.protocol,
            packet.timestamp,
        );
        self.update_flow_with_packet(&mut new_flow, packet).await;
        self.flow_map.insert(packet.flow_key(), new_flow);
    }

    /// Updates a flow with a packet and exports flow if terminated.
    ///
    /// Returns a boolean indicating if the flow is terminated.
    async fn update_flow_with_packet(&mut self, flow: &mut T, packet: &PacketFeatures) -> bool {
        let is_forward = *flow.flow_key() == packet.flow_key();
        let flow_terminated = flow.update_flow(&packet, is_forward);

        if flow_terminated {
            // If terminated, export the flow
            self.export_flow(flow.clone()).await;
        } else if let Some(early_export) = self.early_export {
            // If flow duration is greater than early export, export the flow immediately (without deletion from the flow table)
            if (packet.timestamp - flow.get_first_timestamp()).num_seconds() as u64 > early_export {
                self.export_flow(flow.clone()).await;
            }
        }
        flow_terminated
    }

    /// Export all flows in the flow map in order of first packet arrival.
    pub async fn export_all_flows(&mut self) {
        let mut flows_to_export: Vec<_> = self
            .flow_map
            .drain() // Drain all entries from the map
            .map(|(_, flow)| flow) // Collect all flows
            .collect();

        // Sort flows by `first_timestamp`
        flows_to_export.sort_by_key(|flow| flow.get_first_timestamp());

        // Export each flow in order of `first_timestamp`
        for flow in flows_to_export {
            self.export_flow(flow).await;
        }
    }

    /// Exports a single flow.
    pub async fn export_flow(&self, flow: T) {
        if self.export_channel.is_closed() {
            error!("Failed to send flow: export channel is closed");
        } else if let Err(e) = self.export_channel.send(flow).await {
            error!("Failed to send flow: {}", e);
        }
    }

    /// Checks if enough time has passed to trigger flow expiration checks and exports expired flows.
    async fn check_and_export_expired_flows(&mut self, current_time: DateTime<Utc>) {
        if self
            .next_check_time
            .map_or(true, |next_check| current_time >= next_check)
        {
            self.export_expired_flows(current_time).await;
            self.next_check_time = Some(current_time + self.expiration_check_interval);
            debug!(
                "Next flow expiration check scheduled at: {:?}",
                self.next_check_time
            );
        }
    }

    /// Export all expired flows.
    pub async fn export_expired_flows(&mut self, timestamp: DateTime<Utc>) {
        // Export all expired flows
        let expired_flows: Vec<_> = self
            .flow_map
            .iter()
            .filter_map(|(key, flow)| {
                if flow.is_expired(timestamp, self.active_timeout, self.idle_timeout) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        debug!("Exporting {} expired flows", expired_flows.len());
        for key in expired_flows {
            if let Some(flow) = self.flow_map.remove(&key) {
                self.export_flow(flow).await;
            }
        }
    }
}
