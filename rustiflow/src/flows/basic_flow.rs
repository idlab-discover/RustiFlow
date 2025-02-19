use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::{flows::util::iana_port_mapping, packet_features::PacketFeatures};

use super::{flow::Flow, util::FlowExpireCause};

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
    pub first_timestamp_us: i64, // Microseconds since epoch
    /// The last timestamp of the flow.
    pub last_timestamp_us: i64,
    /// The reason this flow expired
    pub flow_expire_cause: FlowExpireCause,

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
    pub fn get_flow_duration_usec(&self) -> i64 {
        self.last_timestamp_us - self.first_timestamp_us
    }

    /// Calculates the flow duration in milliseconds.
    ///
    /// Returns the difference between the last and first packet timestamps in milliseconds.
    ///
    /// ### Returns
    ///
    /// The duration of the flow in milliseconds.
    pub fn get_flow_duration_msec(&self) -> i64 {
        (self.last_timestamp_us - self.first_timestamp_us) / 1_000
    }

    pub fn get_last_timestamp(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_micros(self.last_timestamp_us).unwrap()
    }

    pub fn get_first_timestamp(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_micros(self.first_timestamp_us).unwrap()
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
        first_timestamp_us: i64,
    ) -> Self {
        BasicFlow {
            flow_key: flow_id,
            ip_destination,
            ip_source,
            port_destination,
            port_source,
            protocol,
            first_timestamp_us,
            last_timestamp_us: first_timestamp_us,
            flow_expire_cause: FlowExpireCause::None,
            state_fwd: FlowState::Established,
            state_bwd: FlowState::Established,
            expected_ack_seq_fwd: None,
            expected_ack_seq_bwd: None,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        self.last_timestamp_us = packet.timestamp_us;

        if self.is_tcp_finished(packet, fwd) {
            self.flow_expire_cause = FlowExpireCause::TcpTermination;
            return true;
        }

        if packet.rst_flag > 0 {
            self.flow_expire_cause = FlowExpireCause::TcpReset;
            return true;
        }

        false
    }

    fn close_flow(&mut self, _timestamp_us: i64, _cause: FlowExpireCause) -> () {
        // No active state to close
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
            self.get_first_timestamp(),
            self.get_last_timestamp(),
            self.get_flow_duration_usec(),
            self.flow_expire_cause.as_str()
        )
    }

    fn get_features() -> String {
        format!(
            "flow_id,source_ip,source_port,destination_ip,destination_port,protocol,\
            first_timestamp,last_timestamp,duration,flow_expire_cause"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{}",
            iana_port_mapping(self.port_source),
            iana_port_mapping(self.port_destination),
            self.protocol,
            self.get_flow_duration_usec(),
            self.flow_expire_cause.as_str(),
        )
    }

    fn get_features_without_contamination() -> String {
        format!("src_port_iana,dst_port_iana,protocol,duration,flow_expire_cause")
    }

    fn get_first_timestamp_us(&self) -> i64 {
        self.first_timestamp_us
    }

    fn is_expired(
        &self,
        timestamp_us: i64,
        active_timeout: u64,
        idle_timeout: u64,
    ) -> (bool, FlowExpireCause) {
        if self.flow_expire_cause != FlowExpireCause::None {
            return (true, self.flow_expire_cause);
        }

        if ((timestamp_us - self.first_timestamp_us) / 1_000_000) as u64 > active_timeout {
            return (true, FlowExpireCause::ActiveTimeout);
        }

        if ((timestamp_us - self.last_timestamp_us) / 1_000_000) as u64 > idle_timeout {
            return (true, FlowExpireCause::IdleTimeout);
        }

        (false, FlowExpireCause::None)
    }

    fn flow_key(&self) -> &String {
        &self.flow_key
    }
}
