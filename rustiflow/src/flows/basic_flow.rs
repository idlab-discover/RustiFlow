use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::{flows::util::iana_port_mapping, packet_features::PacketFeatures};

use super::flow::Flow;

#[derive(Clone, PartialEq, Debug)]
pub(crate) enum FlowState {
    Established,
    FinSent,
    FinAcked,
}

/// A basic flow that stores the basic features of a flow.
#[derive(Clone)]
pub struct BasicFlow {
    /// The unique identifier of the flow.
    pub flow_key: String,
    /// The destination IP address of the flow.
    pub ip_destination: IpAddr,
    /// The source IP address of the flow.
    pub ip_source: IpAddr,
    /// The destination port of the flow.
    pub port_destination: u16,
    /// The source port of the flow.
    pub port_source: u16,
    /// The protocol of the flow.
    pub protocol: u8,
    /// The first timestamp of the flow.
    pub first_timestamp: DateTime<Utc>,
    /// The last timestamp of the flow.
    pub last_timestamp: DateTime<Utc>,
    /// The last ACK of the flow.
    pub tcp_normal_termination: u8,

    // Tracking TCP Flow Termination
    pub(crate) state_fwd: FlowState,
    pub(crate) state_bwd: FlowState,
    expected_ack_seq_fwd: Option<u32>,
    expected_ack_seq_bwd: Option<u32>,
}

impl BasicFlow {
    /// Checks if the flow is finished.
    ///
    /// A flow is considered finished when both FIN flags are set and the last ACK is received,
    /// and the sequence numbers have been acknowledged by both parties.
    ///
    /// ### Arguments
    ///
    /// * `packet` - The packet to be checked.
    ///
    /// ### Returns
    ///
    /// A boolean indicating if the flow is finished.
    pub fn is_tcp_finished(&mut self, packet: &PacketFeatures, forward: bool) -> bool {
        // Update state when receiving FIN flag
        if packet.fin_flag > 0 {
            if forward {
                self.state_fwd = FlowState::FinSent;
                self.expected_ack_seq_bwd =
                    Some(packet.sequence_number + packet.data_length as u32 + 1);
            } else {
                self.state_bwd = FlowState::FinSent;
                self.expected_ack_seq_fwd =
                    Some(packet.sequence_number + packet.data_length as u32 + 1);
            }
        }

        if self.state_bwd == FlowState::FinSent
            && forward
            && Some(packet.sequence_number_ack) == self.expected_ack_seq_fwd
        {
            self.state_bwd = FlowState::FinAcked;
        } else if self.state_fwd == FlowState::FinSent
            && !forward
            && Some(packet.sequence_number_ack) == self.expected_ack_seq_bwd
        {
            self.state_fwd = FlowState::FinAcked;
        }

        // Return true if both sides are finished and acknowledged the termination
        self.state_fwd == FlowState::FinAcked && self.state_bwd == FlowState::FinAcked
    }

    /// Calculates the flow duration in microseconds.
    ///
    /// Returns the difference between the last and first packet timestamps in microseconds.
    ///
    /// ### Returns
    ///
    /// The duration of the flow in microseconds.
    pub fn get_flow_duration_usec(&self) -> f64 {
        (self.last_timestamp - self.first_timestamp)
            .num_microseconds()
            .unwrap() as f64
    }

    /// Calculates the flow duration in milliseconds.
    ///
    /// Returns the difference between the last and first packet timestamps in milliseconds.
    ///
    /// ### Returns
    ///
    /// The duration of the flow in milliseconds.
    pub fn get_flow_duration_msec(&self) -> f64 {
        self.last_timestamp
            .signed_duration_since(self.first_timestamp)
            .num_milliseconds() as f64
    }
}

impl Flow for BasicFlow {
    fn new(
        flow_id: String,
        ip_source: IpAddr,
        port_source: u16,
        ip_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        first_timestamp: DateTime<Utc>,
    ) -> Self {
        BasicFlow {
            flow_key: flow_id,
            ip_destination,
            ip_source,
            port_destination,
            port_source,
            protocol,
            first_timestamp,
            last_timestamp: first_timestamp,
            tcp_normal_termination: 0,
            state_fwd: FlowState::Established,
            state_bwd: FlowState::Established,
            expected_ack_seq_fwd: None,
            expected_ack_seq_bwd: None,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        self.last_timestamp = packet.timestamp;

        if self.is_tcp_finished(packet, fwd) {
            self.tcp_normal_termination = 1;
        }

        if self.tcp_normal_termination > 0 || packet.rst_flag > 0 {
            return true;
        }

        false
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            self.flow_key,
            self.ip_source,
            self.port_source,
            self.ip_destination,
            self.port_destination,
            self.protocol,
            self.first_timestamp,
            self.last_timestamp,
            self.get_flow_duration_usec(),
            self.tcp_normal_termination
        )
    }

    fn get_features() -> String {
        format!(
            "flow_id,source_ip,source_port,destination_ip,destination_port,protocol,\
            first_timestamp,last_timestamp,duration,normal_tcp_termination"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{}",
            iana_port_mapping(self.port_source),
            iana_port_mapping(self.port_destination),
            self.protocol,
            self.get_flow_duration_usec(),
            self.tcp_normal_termination,
        )
    }

    fn get_features_without_contamination() -> String {
        format!("src_port_iana,dst_port_iana,protocol,duration,normal_tcp_termination")
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.first_timestamp
    }

    fn is_expired(&self, timestamp: DateTime<Utc>, active_timeout: u64, idle_timeout: u64) -> bool {
        if (timestamp - self.first_timestamp).num_seconds() as u64 > active_timeout {
            return true;
        }

        if (timestamp - self.last_timestamp).num_seconds() as u64 > idle_timeout {
            return true;
        }

        false
    }

    fn flow_key(&self) -> &String {
        &self.flow_key
    }
}
