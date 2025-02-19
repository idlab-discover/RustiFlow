use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{
    basic_flow::BasicFlow,
    features::{icmp_stats::IcmpStats, util::FlowFeature},
    flow::Flow,
    util::FlowExpireCause,
};

/// Represents a Custom Flow, encapsulating various metrics and states of a network flow.
///
/// As an example, this flow has one feature that represents the sum of the inter arrival times of the first 10 packets for both egress and ingress direction.
///
/// This struct is made so you can define your own features.
#[derive(Clone)]
pub struct CustomFlow {
    /// Choose here for an existing flow type or leave the basic flow.
    pub basic_flow: BasicFlow,
    /// Add here the additional features.
    pub icmp_stats: IcmpStats,
}

impl Flow for CustomFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self {
        CustomFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp_us,
            ),
            // Add here the initialization of the additional features, e.g. icmp stats.
            icmp_stats: IcmpStats::new(),
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        // Update the basic flow and returns true if the flow is terminated.
        let last_timestamp_us = self.basic_flow.last_timestamp_us;
        let is_terminated = self.basic_flow.update_flow(packet, fwd);

        // Add here the update of the additional features.
        self.icmp_stats.update(packet, fwd, last_timestamp_us);

        // Return the termination status of the flow.
        is_terminated
    }

    fn close_flow(&mut self, timestamp_us: i64, cause: FlowExpireCause) {
        self.basic_flow.close_flow(timestamp_us, cause);

        self.icmp_stats.close(timestamp_us, cause);
    }

    fn dump(&self) -> String {
        // Add here the dump of the custom flow.
        format!(
            "{},{},{}",
            self.basic_flow.flow_key,
            self.icmp_stats.get_type(),
            self.icmp_stats.get_code()
        )
    }

    fn get_features() -> String {
        // Add here the features of the custom flow.
        format!("flow_id,icmp_type,icmp_code")
    }

    fn dump_without_contamination(&self) -> String {
        // Add here the dump of the custom flow without contaminant features.
        format!(
            "{},{}",
            self.icmp_stats.get_type(),
            self.icmp_stats.get_code()
        )
    }

    fn get_features_without_contamination() -> String {
        // Add here the features of the custom flow without contaminant features.
        format!("icmp_type,icmp_code")
    }

    fn get_first_timestamp_us(&self) -> i64 {
        self.basic_flow.first_timestamp_us
    }

    fn is_expired(
        &self,
        timestamp_us: i64,
        active_timeout: u64,
        idle_timeout: u64,
    ) -> (bool, FlowExpireCause) {
        self.basic_flow
            .is_expired(timestamp_us, active_timeout, idle_timeout)
    }

    fn flow_key(&self) -> &String {
        &self.basic_flow.flow_key
    }
}
