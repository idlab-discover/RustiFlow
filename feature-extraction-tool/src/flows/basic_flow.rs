use std::time::Instant;

use chrono::{DateTime, Utc};
use common::BasicFeatures;

use super::flow::Flow;

/// A basic flow that stores the basic features of a flow.
pub struct BasicFlow {
    /// The unique identifier of the flow.
    pub flow_id: String,
    /// The destination IP address of the flow.
    pub ipv4_destination: u32,
    /// The source IP address of the flow.
    pub ipv4_source: u32,
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
}

impl BasicFlow {
    pub fn new(
        flow_id: String,
        ipv4_source: u32,
        port_source: u16,
        ipv4_destination: u32,
        port_destination: u16,
        protocol: u8,
    ) -> Self {
        BasicFlow {
            flow_id,
            ipv4_destination,
            ipv4_source,
            port_destination,
            port_source,
            protocol,
            first_timestamp: Utc::now(),
            last_timestamp: Utc::now(),
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
        }
    }
}

impl Flow for BasicFlow {
    fn update_flow(&mut self, packet: &BasicFeatures, _timestamp: &Instant, fwd: bool) -> Option<String>{
        self.last_timestamp = Utc::now();

        // when both FIN flags are set, the flow can be finished when the last ACK is received
        if self.fwd_fin_flag_count > 0 && self.bwd_fin_flag_count > 0 {
            self.flow_end_of_flow_ack = packet.ack_flag;
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
        None
    }

    fn dump(&self) -> String {
        format!("{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{}", 
        self.flow_id, 
        self.ipv4_source, 
        self.port_source, 
        self.ipv4_destination, 
        self.port_destination, 
        self.protocol, 
        self.first_timestamp, 
        self.last_timestamp, 
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
        self.bwd_packet_count)
    }
}
