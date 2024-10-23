use chrono::{DateTime, Utc};
use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{basic_flow::BasicFlow, flow::Flow};

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
    pub inter_arrival_time_total: f64,
}

impl CustomFlow {
    // Define here the custom flow functions that calculate the additional features.
    fn update_inter_arrival_time_total(&mut self, packet: &PacketFeatures) {
        if (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) > 10 {
            let iat = packet
                .timestamp
                .signed_duration_since(self.basic_flow.last_timestamp)
                .num_nanoseconds()
                .unwrap() as f64
                / 1000.0;

            self.inter_arrival_time_total += iat;
        }
    }
}

impl Flow for CustomFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self {
        CustomFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                ts_date,
            ),
            // Add here the initialization of the additional features.
            inter_arrival_time_total: 0.0,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        // Add here the update of the additional features.
        self.update_inter_arrival_time_total(packet);

        // Update the basic flow and returns true if the flow is terminated.
        let is_terminated = self.basic_flow.update_flow(packet, fwd);

        // Add here the update of the additional features that depend on the basic flow to be updated first.

        // Return the termination status of the flow.
        is_terminated
    }

    fn dump(&self) -> String {
        // Add here the dump of the custom flow.
        format!(
            "{},{}",
            self.basic_flow.flow_key, self.inter_arrival_time_total
        )
    }

    fn get_features() -> String {
        // Add here the features of the custom flow.
        format!("FLOW_KEY,INTER_ARRIVAL_TIME_TOTAL")
    }

    fn dump_without_contamination(&self) -> String {
        // Add here the dump of the custom flow without contaminant features.
        format!("{}", self.inter_arrival_time_total)
    }

    fn get_features_without_contamination() -> String {
        // Add here the features of the custom flow without contaminant features.
        format!("INTER_ARRIVAL_TIME_TOTAL")
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.basic_flow.get_first_timestamp()
    }

    fn is_expired(&self, timestamp: DateTime<Utc>, active_timeout: u64, idle_timeout: u64) -> bool {
        self.basic_flow
            .is_expired(timestamp, active_timeout, idle_timeout)
    }

    fn flow_key(&self) -> &String {
        &self.basic_flow.flow_key
    }
}
