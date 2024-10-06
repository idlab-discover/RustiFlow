use chrono::{DateTime, Utc};
use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{basic_flow::BasicFlow, flow::Flow};

/// Represents a Custom Flow, encapsulating various metrics and states of a network flow.
///
/// This struct is made so you can define your own features.
#[derive(Clone)]
pub struct CustomFlow {
    /// Choose here for an existing flow type or leave the basic flow.
    pub basic_flow: BasicFlow,
}

impl CustomFlow {
    // Define here the custom flow functions that calculate the additional features.
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
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        // Update the basic flow and returns true if the flow is terminated.
        let is_terminated = self.basic_flow.update_flow(packet, fwd);
        // Add here the update of the additional features.

        // Return the termination status of the flow.
        is_terminated
    }

    fn dump(&self) -> String {
        // Add here the dump of the custom flow.
        format!("")
    }

    fn get_features() -> String {
        // Add here the features of the custom flow.
        format!("")
    }

    fn dump_without_contamination(&self) -> String {
        // Add here the dump of the custom flow without contaminant features.
        format!("")
    }

    fn get_features_without_contamination() -> String {
        // Add here the features of the custom flow without contaminant features.
        format!("")
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

#[cfg(test)]
mod tests {
    // use std::net::{IpAddr, Ipv4Addr};

    // use crate::flows::flow::Flow;

    // use super::CustomFlow;

    // fn setup_customflow() -> CustomFlow {
    //     CustomFlow::new(
    //         "".to_string(),
    //         IpAddr::V4(Ipv4Addr::from(1)),
    //         80,
    //         IpAddr::V4(Ipv4Addr::from(2)),
    //         8080,
    //         6,
    //     )
    // }

    // Add here the tests for the custom flow, if you want to test the custom flow.
}
