use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::packet_features::PacketFeatures;

use super::{cic_flow::CicFlow, flow::Flow};

/// Represents a Nfstream inspired Flow, encapsulating various metrics and states of a network flow.
///
/// This struct includes detailed information about both forward and backward
#[derive(Clone)]
pub struct NfFlow {
    pub cic_flow: CicFlow,
    pub first_timestamp: DateTime<Utc>,
    pub last_timestamp: DateTime<Utc>,
    pub fwd_first_timestamp: DateTime<Utc>,
    pub fwd_last_timestamp: DateTime<Utc>,
    pub bwd_first_timestamp: Option<DateTime<Utc>>,
    pub bwd_last_timestamp: Option<DateTime<Utc>>,
}

impl NfFlow {
    pub(crate) fn get_bwd_duration(&self) -> i64 {
        if self.bwd_first_timestamp.is_none() || self.bwd_last_timestamp.is_none() {
            return 0;
        }

        (self
            .bwd_last_timestamp
            .unwrap()
            .signed_duration_since(self.bwd_first_timestamp.unwrap()))
        .num_milliseconds()
    }

    pub(crate) fn get_first_bwd_timestamp(&self) -> i64 {
        if self.bwd_first_timestamp.is_none() {
            return 0;
        }

        self.bwd_first_timestamp.unwrap().timestamp_millis()
    }

    fn get_bwd_last_timestamp(&self) -> i64 {
        if self.bwd_last_timestamp.is_none() {
            return 0;
        }

        self.bwd_last_timestamp.unwrap().timestamp_millis()
    }
}

impl Flow for NfFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp: DateTime<Utc>,
    ) -> Self {
        NfFlow {
            cic_flow: CicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp,
            ),
            first_timestamp: timestamp,
            last_timestamp: timestamp,
            fwd_first_timestamp: timestamp,
            fwd_last_timestamp: timestamp,
            bwd_first_timestamp: None,
            bwd_last_timestamp: None,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        let is_terminated = self.cic_flow.update_flow(packet, fwd);
        if fwd {
            self.fwd_last_timestamp = packet.timestamp;
        } else {
            if self.bwd_first_timestamp.is_none() {
                self.bwd_first_timestamp = Some(packet.timestamp);
            }
            self.bwd_last_timestamp = Some(packet.timestamp);
        }
        is_terminated
    }

    fn dump(&self) -> String {
        format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.flow_key,
            self.cic_flow.basic_flow.ip_source,
            self.cic_flow.basic_flow.port_source,
            self.cic_flow.basic_flow.ip_destination,
            self.cic_flow.basic_flow.port_destination,
            self.cic_flow.basic_flow.protocol,
            self.first_timestamp.timestamp_millis(),
            self.last_timestamp.timestamp_millis(),
            self.last_timestamp.signed_duration_since(self.first_timestamp).num_milliseconds(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.fwd_first_timestamp.timestamp_millis(),
            self.fwd_last_timestamp.timestamp_millis(),
            self.fwd_last_timestamp.signed_duration_since(self.fwd_first_timestamp).num_milliseconds(),
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot,
            self.get_first_bwd_timestamp(),
            self.get_bwd_last_timestamp(),
            self.get_bwd_duration(),
            self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.get_flow_packet_length_min(),
            self.cic_flow.get_flow_packet_length_mean(),
            self.cic_flow.get_flow_packet_length_std(),
            self.cic_flow.get_flow_packet_length_max(),
            self.cic_flow.get_fwd_packet_length_min(),
            self.cic_flow.fwd_pkt_len_mean,
            self.cic_flow.fwd_pkt_len_std,
            self.cic_flow.fwd_pkt_len_max,
            self.cic_flow.get_bwd_packet_length_min(),
            self.cic_flow.bwd_pkt_len_mean,
            self.cic_flow.bwd_pkt_len_std,
            self.cic_flow.bwd_pkt_len_max,
            self.cic_flow.get_flow_iat_min() / 1000.0,
            self.cic_flow.get_flow_iat_mean() / 1000.0,
            self.cic_flow.get_flow_iat_std() / 1000.0,
            self.cic_flow.get_flow_iat_max() / 1000.0,
            self.cic_flow.get_fwd_iat_min() / 1000.0,
            self.cic_flow.fwd_iat_mean / 1000.0,
            self.cic_flow.fwd_iat_std / 1000.0,
            self.cic_flow.fwd_iat_max / 1000.0,
            self.cic_flow.get_bwd_iat_min() / 1000.0,
            self.cic_flow.bwd_iat_mean / 1000.0,
            self.cic_flow.bwd_iat_std / 1000.0,
            self.cic_flow.bwd_iat_max / 1000.0,
            self.cic_flow.basic_flow.fwd_syn_flag_count + self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count + self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count + self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count + self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count + self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count + self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count + self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count + self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count,
            self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.bwd_fin_flag_count,
        )
    }

    fn get_features() -> String {
        format!(
            "FLOW_ID,IP_SRC,PORT_SRC,IP_DST,PORT_DST,PROTOCOL,FIRST_TS,LAST_TS,\
            DURATION,FLOW_PKTS,FLOW_BYTES,FWD_FIRST_TS,FWD_LAST_TS,FWD_DURATION,FWD_PKTS,\
            FWD_BYTES,BWD_FIRST_TS,BWD_LAST_TS,BWD_DURATION,BWD_PKTS,BWD_BYTES,FLOW_PKT_LEN_MIN,\
            FLOW_PKT_LEN_MEAN,FLOW_PKT_LEN_STD,FLOW_PKT_LEN_MAX,FWD_PKT_LEN_MIN,FWD_PKT_LEN_MEAN,\
            FWD_PKT_LEN_STD,FWD_PKT_LEN_MAX,BWD_PKT_LEN_MIN,BWD_PKT_LEN_MEAN,BWD_PKT_LEN_STD,\
            BWD_PKT_LEN_MAX,FLOW_IAT_MIN,FLOW_IAT_MEAN,FLOW_IAT_STD,FLOW_IAT_MAX,FWD_IAT_MIN,\
            FWD_IAT_MEAN,FWD_IAT_STD,FWD_IAT_MAX,BWD_IAT_MIN,BWD_IAT_MEAN,BWD_IAT_STD,\
            BWD_IAT_MAX,FLOW_SYN,FLOW_CWE,FLOW_ECE,FLOW_URG,FLOW_ACK,FLOW_PSH,FLOW_RST,\
            FLOW_FIN,FWD_SYN,FWD_CWE,FWD_ECE,FWD_URG,FWD_ACK,FWD_PSH,FWD_RST,FWD_FIN,\
            BWD_SYN,BWD_CWE,BWD_ECE,BWD_URG,BWD_ACK,BWD_PSH,BWD_RST,BWD_FIN"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.protocol,
            self.last_timestamp
                .signed_duration_since(self.first_timestamp)
                .num_milliseconds(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.fwd_last_timestamp
                .signed_duration_since(self.fwd_first_timestamp)
                .num_milliseconds(),
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot,
            self.get_bwd_duration(),
            self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.get_flow_packet_length_min(),
            self.cic_flow.get_flow_packet_length_mean(),
            self.cic_flow.get_flow_packet_length_std(),
            self.cic_flow.get_flow_packet_length_max(),
            self.cic_flow.get_fwd_packet_length_min(),
            self.cic_flow.fwd_pkt_len_mean,
            self.cic_flow.fwd_pkt_len_std,
            self.cic_flow.fwd_pkt_len_max,
            self.cic_flow.get_bwd_packet_length_min(),
            self.cic_flow.bwd_pkt_len_mean,
            self.cic_flow.bwd_pkt_len_std,
            self.cic_flow.bwd_pkt_len_max,
            self.cic_flow.get_flow_iat_min() / 1000.0,
            self.cic_flow.get_flow_iat_mean() / 1000.0,
            self.cic_flow.get_flow_iat_std() / 1000.0,
            self.cic_flow.get_flow_iat_max() / 1000.0,
            self.cic_flow.get_fwd_iat_min() / 1000.0,
            self.cic_flow.fwd_iat_mean / 1000.0,
            self.cic_flow.fwd_iat_std / 1000.0,
            self.cic_flow.fwd_iat_max / 1000.0,
            self.cic_flow.get_bwd_iat_min() / 1000.0,
            self.cic_flow.bwd_iat_mean / 1000.0,
            self.cic_flow.bwd_iat_std / 1000.0,
            self.cic_flow.bwd_iat_max / 1000.0,
            self.cic_flow.basic_flow.fwd_syn_flag_count
                + self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count
                + self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count
                + self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count
                + self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count
                + self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count
                + self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count
                + self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count
                + self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count,
            self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.bwd_fin_flag_count,
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "PROTOCOL,DURATION,FLOW_PKTS,FLOW_BYTES,FWD_DURATION,FWD_PKTS,FWD_BYTES,\
            BWD_DURATION,BWD_PKTS,BWD_BYTES,FLOW_PKT_LEN_MIN,FLOW_PKT_LEN_MEAN,FLOW_PKT_LEN_STD,\
            FLOW_PKT_LEN_MAX,FWD_PKT_LEN_MIN,FWD_PKT_LEN_MEAN,FWD_PKT_LEN_STD,FWD_PKT_LEN_MAX,\
            BWD_PKT_LEN_MIN,BWD_PKT_LEN_MEAN,BWD_PKT_LEN_STD,BWD_PKT_LEN_MAX,FLOW_IAT_MIN,\
            FLOW_IAT_MEAN,FLOW_IAT_STD,FLOW_IAT_MAX,FWD_IAT_MIN,FWD_IAT_MEAN,FWD_IAT_STD,\
            FWD_IAT_MAX,BWD_IAT_MIN,BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,FLOW_SYN,FLOW_CWE,\
            FLOW_ECE,FLOW_URG,FLOW_ACK,FLOW_PSH,FLOW_RST,FLOW_FIN,FWD_SYN,FWD_CWE,FWD_ECE,\
            FWD_URG,FWD_ACK,FWD_PSH,FWD_RST,FWD_FIN,BWD_SYN,BWD_CWE,BWD_ECE,BWD_URG,BWD_ACK,\
            BWD_PSH,BWD_RST,BWD_FIN"
        )
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.cic_flow.get_first_timestamp()
    }

    fn is_expired(&self, timestamp: DateTime<Utc>, active_timeout: u64, idle_timeout: u64) -> bool {
        self.cic_flow
            .is_expired(timestamp, active_timeout, idle_timeout)
    }

    fn flow_key(&self) -> &String {
        &self.cic_flow.basic_flow.flow_key
    }
}
