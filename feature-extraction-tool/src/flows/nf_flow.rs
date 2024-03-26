use std::{
    net::IpAddr, ops::Deref, time::{Instant, SystemTime, UNIX_EPOCH}
};

use chrono::{DateTime, Utc};

use crate::{utils::utils::BasicFeatures, NO_CONTAMINANT_FEATURES};

use super::{cic_flow::CicFlow, flow::Flow};

/// Represents a Nfstream inspired Flow, encapsulating various metrics and states of a network flow.
///
/// This struct includes detailed information about both forward and backward
pub struct NfFlow {
    pub cic_flow: CicFlow,
    pub first_timestamp: SystemTime,
    pub last_timestamp: SystemTime,
    pub fwd_first_timestamp: SystemTime,
    pub fwd_last_timestamp: SystemTime,
    pub bwd_first_timestamp: SystemTime,
    pub bwd_last_timestamp: SystemTime,
}

impl Flow for NfFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
    ) -> Self {
        NfFlow {
            cic_flow: CicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
            ),
            first_timestamp: SystemTime::now(),
            last_timestamp: SystemTime::now(),
            fwd_first_timestamp: SystemTime::now(),
            fwd_last_timestamp: SystemTime::now(),
            bwd_first_timestamp: SystemTime::now(),
            bwd_last_timestamp: SystemTime::now(),
        }
    }

    fn update_flow(
        &mut self,
        packet: &BasicFeatures,
        timestamp: &Instant,
        fwd: bool,
    ) -> Option<String> {
        if fwd {
            self.fwd_last_timestamp = SystemTime::now();
        } else {
            self.bwd_last_timestamp = SystemTime::now();
        }

        let end = self.cic_flow.update_flow(packet, timestamp, fwd);
        if end.is_some() {
            if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                return Some(self.dump_without_contamination());
            } else {
                return Some(self.dump());
            }
        }

        None
    }

    fn dump(&self) -> String {
        format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.flow_id,
            self.cic_flow.basic_flow.ip_source,
            self.cic_flow.basic_flow.port_source,
            self.cic_flow.basic_flow.ip_destination,
            self.cic_flow.basic_flow.port_destination,
            self.cic_flow.basic_flow.protocol,
            self.first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.fwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.fwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.fwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.fwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot,
            self.bwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.bwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.bwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.bwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
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

    fn dump_without_contamination(&self) -> String {
        format!("{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
        {},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.protocol,
            self.last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.fwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.fwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot,
            self.bwd_last_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis() - self.bwd_first_timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis(),
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

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.cic_flow.get_first_timestamp()
    }
}
