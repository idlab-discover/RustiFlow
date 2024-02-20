use super::print::Print;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CicRecord {
    #[serde(rename = "Flow ID")]
    pub flow_id: String,
    #[serde(rename = "Source IP")]
    pub src_ip: String,
    #[serde(rename = "Source Port")]
    pub src_port: u16,
    #[serde(rename = "Destination IP")]
    pub dst_ip: String,
    #[serde(rename = "Destination Port")]
    pub dst_port: u16,
    #[serde(rename = "Protocol")]
    pub protocol: u8,
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
    #[serde(rename = "Flow Duration")]
    pub flow_duration: f64,
    #[serde(rename = "Total Fwd Packets")]
    pub tot_fwd_pkts: u32,
    #[serde(rename = "Total Backward Packets")]
    pub tot_bwd_pkts: u32,
    #[serde(rename = "Total Length of Fwd Packets")]
    pub totlen_fwd_pkts: f64,
    #[serde(rename = "Total Length of Bwd Packets")]
    pub totlen_bwd_pkts: f64,
    #[serde(rename = "Fwd Packet Length Max")]
    pub fwd_pkt_len_max: f64,
    #[serde(rename = "Fwd Packet Length Min")]
    pub fwd_pkt_len_min: f64,
    #[serde(rename = "Fwd Packet Length Mean")]
    pub fwd_pkt_len_mean: f64,
    #[serde(rename = "Fwd Packet Length Std")]
    pub fwd_pkt_len_std: f64,
    #[serde(rename = "Bwd Packet Length Max")]
    pub bwd_pkt_len_max: f64,
    #[serde(rename = "Bwd Packet Length Min")]
    pub bwd_pkt_len_min: f64,
    #[serde(rename = "Bwd Packet Length Mean")]
    pub bwd_pkt_len_mean: f64,
    #[serde(rename = "Bwd Packet Length Std")]
    pub bwd_pkt_len_std: f64,
    #[serde(rename = "Flow Bytes/s")]
    pub flow_bytes_s: f64,
    #[serde(rename = "Flow Packets/s")]
    pub flow_packets_s: f64,
    #[serde(rename = "Flow IAT Mean")]
    pub flow_iat_mean: f64,
    #[serde(rename = "Flow IAT Std")]
    pub flow_iat_std: f64,
    #[serde(rename = "Flow IAT Max")]
    pub flow_iat_max: f64,
    #[serde(rename = "Flow IAT Min")]
    pub flow_iat_min: f64,
    #[serde(rename = "Fwd IAT Total")]
    pub fwd_iat_total: f64,
    #[serde(rename = "Fwd IAT Mean")]
    pub fwd_iat_mean: f64,
    #[serde(rename = "Fwd IAT Std")]
    pub fwd_iat_std: f64,
    #[serde(rename = "Fwd IAT Max")]
    pub fwd_iat_max: f64,
    #[serde(rename = "Fwd IAT Min")]
    pub fwd_iat_min: f64,
    #[serde(rename = "Bwd IAT Total")]
    pub bwd_iat_total: f64,
    #[serde(rename = "Bwd IAT Mean")]
    pub bwd_iat_mean: f64,
    #[serde(rename = "Bwd IAT Std")]
    pub bwd_iat_std: f64,
    #[serde(rename = "Bwd IAT Max")]
    pub bwd_iat_max: f64,
    #[serde(rename = "Bwd IAT Min")]
    pub bwd_iat_min: f64,
    #[serde(rename = "Fwd PSH Flags")]
    pub fwd_psh_flags: u32,
    #[serde(rename = "Bwd PSH Flags")]
    pub bwd_psh_flags: u32,
    #[serde(rename = "Fwd URG Flags")]
    pub fwd_urg_flags: u32,
    #[serde(rename = "Bwd URG Flags")]
    pub bwd_urg_flags: u32,
    #[serde(rename = "Fwd Header Length")]
    pub fwd_header_length: f64,
    #[serde(rename = "Bwd Header Length")]
    pub bwd_header_length: f64,
    #[serde(rename = "Fwd Packets/s")]
    pub fwd_packets_s: f64,
    #[serde(rename = "Bwd Packets/s")]
    pub bwd_packets_s: f64,
    #[serde(rename = "Min Packet Length")]
    pub min_packet_length: f64,
    #[serde(rename = "Max Packet Length")]
    pub max_packet_length: f64,
    #[serde(rename = "Packet Length Mean")]
    pub packet_length_mean: f64,
    #[serde(rename = "Packet Length Std")]
    pub packet_length_std: f64,
    #[serde(rename = "Packet Length Variance")]
    pub packet_length_variance: f64,
    #[serde(rename = "FIN Flag Count")]
    pub fin_flag_count: u32,
    #[serde(rename = "SYN Flag Count")]
    pub syn_flag_count: u32,
    #[serde(rename = "RST Flag Count")]
    pub rst_flag_count: u32,
    #[serde(rename = "PSH Flag Count")]
    pub psh_flag_count: u32,
    #[serde(rename = "ACK Flag Count")]
    pub ack_flag_count: u32,
    #[serde(rename = "URG Flag Count")]
    pub urg_flag_count: u32,
    #[serde(rename = "CWE Flag Count")]
    pub cwe_flag_count: u32,
    #[serde(rename = "ECE Flag Count")]
    pub ece_flag_count: u32,
    #[serde(rename = "Down/Up Ratio")]
    pub down_up_ratio: f64,
    #[serde(rename = "Average Packet Size")]
    pub average_packet_size: f64,
    #[serde(rename = "Avg Fwd Segment Size")]
    pub avg_fwd_segment_size: f64,
    #[serde(rename = "Avg Bwd Segment Size")]
    pub avg_bwd_segment_size: f64,
    #[serde(rename = "Fwd Avg Bytes/Bulk")]
    pub fwd_avg_bytes_bulk: u64,
    #[serde(rename = "Fwd Avg Packets/Bulk")]
    pub fwd_avg_packets_bulk: u64,
    #[serde(rename = "Fwd Avg Bulk Rate")]
    pub fwd_avg_bulk_rate: f64,
    #[serde(rename = "Bwd Avg Bytes/Bulk")]
    pub bwd_avg_bytes_bulk: u64,
    #[serde(rename = "Bwd Avg Packets/Bulk")]
    pub bwd_avg_packets_bulk: u64,
    #[serde(rename = "Bwd Avg Bulk Rate")]
    pub bwd_avg_bulk_rate: f64,
    #[serde(rename = "Subflow Fwd Packets")]
    pub subflow_fwd_packets: u32,
    #[serde(rename = "Subflow Fwd Bytes")]
    pub subflow_fwd_bytes: u64,
    #[serde(rename = "Subflow Bwd Packets")]
    pub subflow_bwd_packets: u32,
    #[serde(rename = "Subflow Bwd Bytes")]
    pub subflow_bwd_bytes: u64,
    #[serde(rename = "Init_Win_bytes_forward")]
    pub init_win_bytes_forward: i64,
    #[serde(rename = "Init_Win_bytes_backward")]
    pub init_win_bytes_backward: i64,
    #[serde(rename = "act_data_pkt_fwd")]
    pub act_data_pkt_fwd: f64,
    #[serde(rename = "min_seg_size_forward")]
    pub min_seg_size_forward: u32,
    #[serde(rename = "Active Mean")]
    pub active_mean: f64,
    #[serde(rename = "Active Std")]
    pub active_std: f64,
    #[serde(rename = "Active Max")]
    pub active_max: f64,
    #[serde(rename = "Active Min")]
    pub active_min: f64,
    #[serde(rename = "Idle Mean")]
    pub idle_mean: f64,
    #[serde(rename = "Idle Std")]
    pub idle_std: f64,
    #[serde(rename = "Idle Max")]
    pub idle_max: f64,
    #[serde(rename = "Idle Min")]
    pub idle_min: f64,
    #[serde(rename = "Label")]
    pub label: String,
}

impl Print for CicRecord {
    fn print(&self) {
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{}",
            self.flow_id,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.timestamp,
            self.flow_duration,
            self.tot_fwd_pkts,
            self.tot_bwd_pkts,
            self.totlen_fwd_pkts,
            self.totlen_bwd_pkts,
            self.fwd_pkt_len_max,
            self.fwd_pkt_len_min,
            self.fwd_pkt_len_mean,
            self.fwd_pkt_len_std,
            self.bwd_pkt_len_max,
            self.bwd_pkt_len_min,
            self.bwd_pkt_len_mean,
            self.bwd_pkt_len_std,
            self.flow_bytes_s,
            self.flow_packets_s,
            self.flow_iat_mean,
            self.flow_iat_std,
            self.flow_iat_max,
            self.flow_iat_min,
            self.fwd_iat_total,
            self.fwd_iat_mean,
            self.fwd_iat_std,
            self.fwd_iat_max,
            self.fwd_iat_min,
            self.bwd_iat_total,
            self.bwd_iat_mean,
            self.bwd_iat_std,
            self.bwd_iat_max,
            self.bwd_iat_min,
            self.fwd_psh_flags,
            self.bwd_psh_flags,
            self.fwd_urg_flags,
            self.bwd_urg_flags,
            self.fwd_header_length,
            self.bwd_header_length,
            self.fwd_packets_s,
            self.bwd_packets_s,
            self.min_packet_length,
            self.max_packet_length,
            self.packet_length_mean,
            self.packet_length_std,
            self.packet_length_variance,
            self.fin_flag_count,
            self.syn_flag_count,
            self.rst_flag_count,
            self.psh_flag_count,
            self.ack_flag_count,
            self.urg_flag_count,
            self.cwe_flag_count,
            self.ece_flag_count,
            self.down_up_ratio,
            self.average_packet_size,
            self.avg_fwd_segment_size,
            self.avg_bwd_segment_size,
            self.fwd_avg_bytes_bulk,
            self.fwd_avg_packets_bulk,
            self.fwd_avg_bulk_rate,
            self.bwd_avg_bytes_bulk,
            self.bwd_avg_packets_bulk,
            self.bwd_avg_bulk_rate,
            self.subflow_fwd_packets,
            self.subflow_fwd_bytes,
            self.subflow_bwd_packets,
            self.subflow_bwd_bytes,
            self.init_win_bytes_forward,
            self.init_win_bytes_backward,
            self.act_data_pkt_fwd,
            self.min_seg_size_forward,
            self.active_mean,
            self.active_std,
            self.active_max,
            self.active_min,
            self.idle_mean,
            self.idle_std,
            self.idle_max,
            self.idle_min,
            self.label
        );
    }
}
