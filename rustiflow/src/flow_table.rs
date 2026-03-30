use std::collections::HashMap;

use crate::{
    flow_key::FlowKey, flows::util::FlowExpireCause, packet_features::PacketFeatures, Flow,
};
use log::{debug, error};
use tokio::sync::mpsc;

enum ExistingFlowUpdate<T> {
    Updated,
    EarlyExport(T),
    Terminated(T),
    Expired(FlowExpireCause),
}

enum FlowUpdate<T> {
    Active,
    EarlyExport(T),
    Terminated(T),
}

pub struct FlowTable<T> {
    flow_map: HashMap<FlowKey, T>, // HashMap for fast flow access by key
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
    pub async fn process_packet(&mut self, packet: &PacketFeatures) {
        // Check if enough virtual time has passed to trigger flow expiration checks
        self.check_and_export_expired_flows(packet.timestamp_us)
            .await;

        let flow_key = packet.flow_key_value();
        let reverse_flow_key = flow_key.reverse();

        if self.process_existing_flow(packet, flow_key, true).await
            || self
                .process_existing_flow(packet, reverse_flow_key, false)
                .await
        {
            return;
        }

        self.create_and_insert_flow(packet).await;
    }

    /// Create and insert a new flow for the given packet.
    async fn create_and_insert_flow(&mut self, packet: &PacketFeatures) {
        let flow_key = packet.flow_key_value();
        let mut new_flow = T::new(
            flow_key.to_string(),
            packet.source_ip,
            packet.source_port,
            packet.destination_ip,
            packet.destination_port,
            packet.protocol,
            packet.timestamp_us,
        );
        match Self::apply_packet_to_flow(&mut new_flow, packet, true, self.early_export) {
            FlowUpdate::Active => {
                self.flow_map.insert(flow_key, new_flow);
            }
            FlowUpdate::EarlyExport(flow) => {
                self.export_flow(flow).await;
                self.flow_map.insert(flow_key, new_flow);
            }
            FlowUpdate::Terminated(flow) => {
                self.export_flow(flow).await;
            }
        }
    }

    async fn process_existing_flow(
        &mut self,
        packet: &PacketFeatures,
        flow_key: FlowKey,
        is_forward: bool,
    ) -> bool {
        let Some(update) = self.inspect_existing_flow(&flow_key, packet, is_forward) else {
            return false;
        };

        match update {
            ExistingFlowUpdate::Updated => {}
            ExistingFlowUpdate::EarlyExport(flow) => {
                self.export_flow(flow).await;
            }
            ExistingFlowUpdate::Terminated(flow) => {
                self.flow_map.remove(&flow_key);
                self.export_flow(flow).await;
            }
            ExistingFlowUpdate::Expired(cause) => {
                if let Some(mut flow) = self.flow_map.remove(&flow_key) {
                    flow.close_flow(packet.timestamp_us, cause);
                    self.export_flow(flow).await;
                }
                self.create_and_insert_flow(packet).await;
            }
        }

        true
    }

    fn inspect_existing_flow(
        &mut self,
        flow_key: &FlowKey,
        packet: &PacketFeatures,
        is_forward: bool,
    ) -> Option<ExistingFlowUpdate<T>> {
        let flow = self.flow_map.get_mut(flow_key)?;
        let (is_expired, cause) =
            flow.is_expired(packet.timestamp_us, self.active_timeout, self.idle_timeout);

        if is_expired {
            Some(ExistingFlowUpdate::Expired(cause))
        } else {
            Some(
                match Self::apply_packet_to_flow(flow, packet, is_forward, self.early_export) {
                    FlowUpdate::Active => ExistingFlowUpdate::Updated,
                    FlowUpdate::EarlyExport(flow) => ExistingFlowUpdate::EarlyExport(flow),
                    FlowUpdate::Terminated(flow) => ExistingFlowUpdate::Terminated(flow),
                },
            )
        }
    }

    fn apply_packet_to_flow(
        flow: &mut T,
        packet: &PacketFeatures,
        is_forward: bool,
        early_export: Option<u64>,
    ) -> FlowUpdate<T> {
        if flow.update_flow(packet, is_forward) {
            FlowUpdate::Terminated(flow.clone())
        } else if early_export.is_some_and(|early_export| {
            ((packet.timestamp_us - flow.get_first_timestamp_us()) / 1_000_000) as u64
                > early_export
        }) {
            FlowUpdate::EarlyExport(flow.clone())
        } else {
            FlowUpdate::Active
        }
    }

    /// Export all flows in the flow map in order of first packet arrival.
    pub async fn export_all_flows(&mut self, timestamp_us: i64) {
        let mut flows_to_export: Vec<_> = self
            .flow_map
            .drain() // Drain all entries from the map
            .map(|(_, flow)| flow) // Collect all flows
            .collect();

        // Sort flows by `first_timestamp`
        flows_to_export.sort_by_key(|flow| flow.get_first_timestamp_us());

        // Export each flow in order of `first_timestamp`
        for mut flow in flows_to_export {
            flow.close_flow(timestamp_us, FlowExpireCause::ExporterShutdown);
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
            .filter_map(|(key, flow)| {
                let (is_expired, cause) =
                    flow.is_expired(timestamp_us, self.active_timeout, self.idle_timeout);
                if is_expired {
                    Some((*key, cause))
                } else {
                    None
                }
            })
            .collect();

        debug!("Exporting {} expired flows", expired_flows.len());
        for (key, cause) in expired_flows {
            if let Some(mut flow) = self.flow_map.remove(&key) {
                flow.close_flow(timestamp_us, cause);
                self.export_flow(flow).await;
            }
        }
    }
}
