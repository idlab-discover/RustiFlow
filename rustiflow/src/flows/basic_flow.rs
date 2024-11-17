use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::packet_features::PacketFeatures;

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
    pub flow_end_of_flow_ack: u8,
    /// The number of FIN flags in the forward direction.
    pub fwd_fin_flag_count: u32,
    /// The number of SYN flags in the forward direction.
    pub fwd_syn_flag_count: u32,
    /// The number of RST flags in the forward direction.
    pub fwd_rst_flag_count: u32,
    /// The number of PSH flags in the forward direction.
    pub fwd_psh_flag_count: u32,
    /// The number of ACK flags in the forward direction.
    pub fwd_ack_flag_count: u32,
    /// The number of URG flags in the forward direction.
    pub fwd_urg_flag_count: u32,
    /// The number of CWE flags in the forward direction.
    pub fwd_cwe_flag_count: u32,
    /// The number of ECE flags in the forward direction.
    pub fwd_ece_flag_count: u32,
    /// The number of packets in the forward direction.
    pub fwd_packet_count: u32,
    /// The number of FIN flags in the backward direction.
    pub bwd_fin_flag_count: u32,
    /// The number of SYN flags in the backward direction.
    pub bwd_syn_flag_count: u32,
    /// The number of RST flags in the backward direction.
    pub bwd_rst_flag_count: u32,
    /// The number of PSH flags in the backward direction.
    pub bwd_psh_flag_count: u32,
    /// The number of ACK flags in the backward direction.
    pub bwd_ack_flag_count: u32,
    /// The number of URG flags in the backward direction.
    pub bwd_urg_flag_count: u32,
    /// The number of CWE flags in the backward direction.
    pub bwd_cwe_flag_count: u32,
    /// The number of ECE flags in the backward direction.
    pub bwd_ece_flag_count: u32,
    /// The number of packets in the backward direction.
    pub bwd_packet_count: u32,
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
            flow_end_of_flow_ack: 0,
            fwd_fin_flag_count: 0,
            fwd_syn_flag_count: 0,
            fwd_rst_flag_count: 0,
            fwd_psh_flag_count: 0,
            fwd_ack_flag_count: 0,
            fwd_urg_flag_count: 0,
            fwd_cwe_flag_count: 0,
            fwd_ece_flag_count: 0,
            fwd_packet_count: 0,
            bwd_fin_flag_count: 0,
            bwd_syn_flag_count: 0,
            bwd_rst_flag_count: 0,
            bwd_psh_flag_count: 0,
            bwd_ack_flag_count: 0,
            bwd_urg_flag_count: 0,
            bwd_cwe_flag_count: 0,
            bwd_ece_flag_count: 0,
            bwd_packet_count: 0,
            state_fwd: FlowState::Established,
            state_bwd: FlowState::Established,
            expected_ack_seq_fwd: None,
            expected_ack_seq_bwd: None,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        self.last_timestamp = packet.timestamp;

        if self.is_tcp_finished(packet, fwd) {
            self.flow_end_of_flow_ack = 1;
        }

        if fwd {
            self.fwd_packet_count += 1;
            self.fwd_fin_flag_count += u32::from(packet.fin_flag);
            self.fwd_syn_flag_count += u32::from(packet.syn_flag);
            self.fwd_rst_flag_count += u32::from(packet.rst_flag);
            self.fwd_psh_flag_count += u32::from(packet.psh_flag);
            self.fwd_ack_flag_count += u32::from(packet.ack_flag);
            self.fwd_urg_flag_count += u32::from(packet.urg_flag);
            self.fwd_cwe_flag_count += u32::from(packet.cwe_flag);
            self.fwd_ece_flag_count += u32::from(packet.ece_flag);
        } else {
            self.bwd_packet_count += 1;
            self.bwd_fin_flag_count += u32::from(packet.fin_flag);
            self.bwd_syn_flag_count += u32::from(packet.syn_flag);
            self.bwd_rst_flag_count += u32::from(packet.rst_flag);
            self.bwd_psh_flag_count += u32::from(packet.psh_flag);
            self.bwd_ack_flag_count += u32::from(packet.ack_flag);
            self.bwd_urg_flag_count += u32::from(packet.urg_flag);
            self.bwd_cwe_flag_count += u32::from(packet.cwe_flag);
            self.bwd_ece_flag_count += u32::from(packet.ece_flag);
        }

        if self.flow_end_of_flow_ack > 0
            || self.fwd_rst_flag_count > 0
            || self.bwd_rst_flag_count > 0
        {
            return true;
        }

        false
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.flow_key,
            self.ip_source,
            self.port_source,
            self.ip_destination,
            self.port_destination,
            self.protocol,
            self.first_timestamp,
            self.last_timestamp,
            self.get_flow_duration_usec(),
            self.flow_end_of_flow_ack,
            self.fwd_fin_flag_count,
            self.fwd_syn_flag_count,
            self.fwd_rst_flag_count,
            self.fwd_psh_flag_count,
            self.fwd_ack_flag_count,
            self.fwd_urg_flag_count,
            self.fwd_cwe_flag_count,
            self.fwd_ece_flag_count,
            self.fwd_packet_count,
            self.bwd_fin_flag_count,
            self.bwd_syn_flag_count,
            self.bwd_rst_flag_count,
            self.bwd_psh_flag_count,
            self.bwd_ack_flag_count,
            self.bwd_urg_flag_count,
            self.bwd_cwe_flag_count,
            self.bwd_ece_flag_count,
            self.bwd_packet_count
        )
    }

    fn get_features() -> String {
        format!(
            "FLOW_ID,IP_SOURCE,PORT_SOURCE,IP_DESTINATION,PORT_DESTINATION,PROTOCOL,\
            FIRST_TIMESTAMP,LAST_TIMESTAMP,DURATION,FLOW_END_OF_FLOW_ACK,\
            FWD_FIN_FLAG_COUNT,FWD_SYN_FLAG_COUNT,FWD_RST_FLAG_COUNT,FWD_PSH_FLAG_COUNT,\
            FWD_ACK_FLAG_COUNT,FWD_URG_FLAG_COUNT,FWD_CWE_FLAG_COUNT,FWD_ECE_FLAG_COUNT,\
            FWD_PACKET_COUNT,BWD_FIN_FLAG_COUNT,BWD_SYN_FLAG_COUNT,BWD_RST_FLAG_COUNT,\
            BWD_PSH_FLAG_COUNT,BWD_ACK_FLAG_COUNT,BWD_URG_FLAG_COUNT,BWD_CWE_FLAG_COUNT,\
            BWD_ECE_FLAG_COUNT,BWD_PACKET_COUNT"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{}",
            self.protocol,
            self.get_flow_duration_usec(),
            self.flow_end_of_flow_ack,
            self.fwd_fin_flag_count,
            self.fwd_syn_flag_count,
            self.fwd_rst_flag_count,
            self.fwd_psh_flag_count,
            self.fwd_ack_flag_count,
            self.fwd_urg_flag_count,
            self.fwd_cwe_flag_count,
            self.fwd_ece_flag_count,
            self.fwd_packet_count,
            self.bwd_fin_flag_count,
            self.bwd_syn_flag_count,
            self.bwd_rst_flag_count,
            self.bwd_psh_flag_count,
            self.bwd_ack_flag_count,
            self.bwd_urg_flag_count,
            self.bwd_cwe_flag_count,
            self.bwd_ece_flag_count,
            self.bwd_packet_count
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "PROTOCOL,DURATION,FLOW_END_OF_FLOW_ACK,\
            FWD_FIN_FLAG_COUNT,FWD_SYN_FLAG_COUNT,FWD_RST_FLAG_COUNT,FWD_PSH_FLAG_COUNT,\
            FWD_ACK_FLAG_COUNT,FWD_URG_FLAG_COUNT,FWD_CWE_FLAG_COUNT,FWD_ECE_FLAG_COUNT,\
            FWD_PACKET_COUNT,BWD_FIN_FLAG_COUNT,BWD_SYN_FLAG_COUNT,BWD_RST_FLAG_COUNT,\
            BWD_PSH_FLAG_COUNT,BWD_ACK_FLAG_COUNT,BWD_URG_FLAG_COUNT,BWD_CWE_FLAG_COUNT,\
            BWD_ECE_FLAG_COUNT,BWD_PACKET_COUNT"
        )
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
