use std::net::IpAddr;

use crate::{
    flows::{
        features::util::{safe_div, safe_div_int, safe_per_second_rate},
        util::iana_port_mapping,
    },
    packet_features::PacketFeatures,
};

use super::{
    basic_flow::BasicFlow,
    features::{
        active_idle_stats::ActiveIdleStats, bulk_stats::BulkStats, header_stats::HeaderLengthStats,
        iat_stats::IATStats, icmp_stats::IcmpStats, packet_stats::PacketLengthStats,
        payload_stats::PayloadLengthStats, retransmission_stats::RetransmissionStats,
        subflow_stats::SubflowStats, tcp_flag_stats::TcpFlagStats, util::FlowFeature,
        window_size_stats::WindowSizeStats,
    },
    flow::Flow,
    util::FlowExpireCause,
};

/// Represents a Flow as exported by CICFlowMeter.
#[derive(Clone)]
pub struct CicFlow {
    pub basic_flow: BasicFlow,
    pub packet_len_stats: PacketLengthStats,
    pub iat_stats: IATStats,
    pub tcp_flags_stats: TcpFlagStats,
    pub header_len_stats: HeaderLengthStats,
    pub payload_len_stats: PayloadLengthStats,
    pub bulk_stats: BulkStats,
    pub subflow_stats: SubflowStats,
    pub active_idle_stats: ActiveIdleStats,
    pub icmp_stats: IcmpStats,
    pub retransmission_stats: RetransmissionStats,
    pub window_size_stats: WindowSizeStats,
}

impl Flow for CicFlow {
    fn new(
        flow_key: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self {
        CicFlow {
            basic_flow: BasicFlow::new(
                flow_key,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp_us,
            ),
            packet_len_stats: PacketLengthStats::new(),
            iat_stats: IATStats::new(),
            tcp_flags_stats: TcpFlagStats::new(),
            header_len_stats: HeaderLengthStats::new(),
            payload_len_stats: PayloadLengthStats::new(),
            bulk_stats: BulkStats::new(),
            subflow_stats: SubflowStats::new(),
            active_idle_stats: ActiveIdleStats::new(timestamp_us),
            icmp_stats: IcmpStats::new(),
            retransmission_stats: RetransmissionStats::new(),
            window_size_stats: WindowSizeStats::new(),
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        let last_timestamp_us = self.basic_flow.last_timestamp_us;
        let is_terminated = self.basic_flow.update_flow(packet, fwd);

        self.packet_len_stats.update(packet, fwd, last_timestamp_us);
        self.iat_stats.update(packet, fwd, last_timestamp_us);
        self.tcp_flags_stats.update(packet, fwd, last_timestamp_us);
        self.header_len_stats.update(packet, fwd, last_timestamp_us);
        self.payload_len_stats
            .update(packet, fwd, last_timestamp_us);
        self.bulk_stats.update(packet, fwd, last_timestamp_us);
        self.subflow_stats.update(packet, fwd, last_timestamp_us);
        self.active_idle_stats
            .update(packet, fwd, last_timestamp_us);
        self.icmp_stats.update(packet, fwd, last_timestamp_us);
        self.retransmission_stats
            .update(packet, fwd, last_timestamp_us);
        self.window_size_stats
            .update(packet, fwd, last_timestamp_us);

        is_terminated
    }

    fn close_flow(&mut self, timestamp_us: i64, cause: FlowExpireCause) {
        self.basic_flow.close_flow(timestamp_us, cause);

        self.packet_len_stats.close(timestamp_us, cause);
        self.iat_stats.close(timestamp_us, cause);
        self.tcp_flags_stats.close(timestamp_us, cause);
        self.header_len_stats.close(timestamp_us, cause);
        self.payload_len_stats.close(timestamp_us, cause);
        self.bulk_stats.close(timestamp_us, cause);
        self.subflow_stats.close(timestamp_us, cause);
        self.active_idle_stats.close(timestamp_us, cause);
        self.icmp_stats.close(timestamp_us, cause);
        self.retransmission_stats.close(timestamp_us, cause);
        self.window_size_stats.close(timestamp_us, cause);
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{}",
            // Basic Info
            self.basic_flow.flow_key,
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            self.basic_flow.protocol,
            self.basic_flow.get_first_timestamp(),
            self.basic_flow.get_flow_duration_usec(),
            // Packet Length Stats (fwd & bwd)
            self.packet_len_stats.fwd_packet_len.get_count(),
            self.packet_len_stats.bwd_packet_len.get_count(),
            self.packet_len_stats.fwd_packet_len.get_total(),
            self.packet_len_stats.bwd_packet_len.get_total(),
            self.packet_len_stats.fwd_packet_len.get_max(),
            self.packet_len_stats.fwd_packet_len.get_min(),
            self.packet_len_stats.fwd_packet_len.get_mean(),
            self.packet_len_stats.fwd_packet_len.get_std(),
            self.packet_len_stats.bwd_packet_len.get_max(),
            self.packet_len_stats.bwd_packet_len.get_min(),
            self.packet_len_stats.bwd_packet_len.get_mean(),
            self.packet_len_stats.bwd_packet_len.get_std(),
            // Rate Stats (Flow)
            safe_per_second_rate(
                self.packet_len_stats.flow_total(),
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.flow_count() as f64,
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            // IAT Stats
            self.iat_stats.iat.get_mean(),
            self.iat_stats.iat.get_std(),
            self.iat_stats.iat.get_max(),
            self.iat_stats.iat.get_min(),
            self.iat_stats.fwd_iat.get_total(),
            self.iat_stats.fwd_iat.get_mean(),
            self.iat_stats.fwd_iat.get_std(),
            self.iat_stats.fwd_iat.get_max(),
            self.iat_stats.fwd_iat.get_min(),
            self.iat_stats.bwd_iat.get_total(),
            self.iat_stats.bwd_iat.get_mean(),
            self.iat_stats.bwd_iat.get_std(),
            self.iat_stats.bwd_iat.get_max(),
            self.iat_stats.bwd_iat.get_min(),
            // TCP Flags Stats (fwd & bwd)
            self.tcp_flags_stats.fwd_psh_flag_count,
            self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count,
            self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count,
            self.tcp_flags_stats.bwd_rst_flag_count,
            // Header Length Stats
            self.header_len_stats.fwd_header_len.get_total(),
            self.header_len_stats.bwd_header_len.get_total(),
            // Rate Stats (fwd & bwd packets)
            safe_per_second_rate(
                self.packet_len_stats.fwd_packet_len.get_count() as f64,
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.bwd_packet_len.get_count() as f64,
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            // Packet Length Stats (Flow)
            self.packet_len_stats.flow_min(),
            self.packet_len_stats.flow_max(),
            self.packet_len_stats.flow_mean(),
            self.packet_len_stats.flow_std(),
            self.packet_len_stats.flow_variance(),
            // TCP Flags Stats (Flow)
            self.tcp_flags_stats.fwd_fin_flag_count + self.tcp_flags_stats.bwd_fin_flag_count,
            self.tcp_flags_stats.fwd_syn_flag_count + self.tcp_flags_stats.bwd_syn_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count + self.tcp_flags_stats.bwd_rst_flag_count,
            self.tcp_flags_stats.fwd_psh_flag_count + self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.fwd_ack_flag_count + self.tcp_flags_stats.bwd_ack_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count + self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.fwd_cwr_flag_count + self.tcp_flags_stats.bwd_cwr_flag_count,
            self.tcp_flags_stats.fwd_ece_flag_count + self.tcp_flags_stats.bwd_ece_flag_count,
            // UP/DOWN Ratio
            safe_div_int(
                self.packet_len_stats.bwd_packet_len.get_count(),
                self.packet_len_stats.fwd_packet_len.get_count()
            ),
            // Payload Length Stats
            self.payload_len_stats.payload_len.get_mean(),
            self.payload_len_stats.fwd_payload_len.get_mean(),
            self.payload_len_stats.bwd_payload_len.get_mean(),
            // Bulk Stats
            self.bulk_stats.fwd_bulk_payload_size.get_mean(),
            self.bulk_stats.fwd_bulk_packets.get_mean(),
            self.bulk_stats.fwd_bulk_rate(),
            self.bulk_stats.bwd_bulk_payload_size.get_mean(),
            self.bulk_stats.bwd_bulk_packets.get_mean(),
            self.bulk_stats.bwd_bulk_rate(),
            // Subflow Stats
            safe_div_int(
                self.packet_len_stats.fwd_packet_len.get_count(),
                self.subflow_stats.subflow_count
            ),
            safe_div(
                self.packet_len_stats.fwd_packet_len.get_total(),
                self.subflow_stats.subflow_count as f64
            ),
            safe_div_int(
                self.packet_len_stats.bwd_packet_len.get_count(),
                self.subflow_stats.subflow_count
            ),
            safe_div(
                self.packet_len_stats.bwd_packet_len.get_total(),
                self.subflow_stats.subflow_count as f64
            ),
            // Window Size Stats
            self.window_size_stats.fwd_init_window_size,
            self.window_size_stats.bwd_init_window_size,
            // Non Zero Payload Packets
            self.payload_len_stats.fwd_non_zero_payload_packets,
            self.payload_len_stats.bwd_non_zero_payload_packets,
            // Segment Length Stats
            self.header_len_stats.fwd_header_len.get_min(),
            self.header_len_stats.bwd_header_len.get_min(),
            // Active/Idle Stats
            self.active_idle_stats.active_stats.get_mean(),
            self.active_idle_stats.active_stats.get_std(),
            self.active_idle_stats.active_stats.get_max(),
            self.active_idle_stats.active_stats.get_min(),
            self.active_idle_stats.idle_stats.get_mean(),
            self.active_idle_stats.idle_stats.get_std(),
            self.active_idle_stats.idle_stats.get_max(),
            self.active_idle_stats.idle_stats.get_min(),
            // ICMP Stats
            self.icmp_stats.get_code(),
            self.icmp_stats.get_type(),
            // Retransmission Stats
            self.retransmission_stats.fwd_retransmission_count,
            self.retransmission_stats.bwd_retransmission_count,
            self.retransmission_stats.fwd_retransmission_count
                + self.retransmission_stats.bwd_retransmission_count,
            // Connection Duration
            // Duplicate of duration. Configure active and idle timeouts for specific use case of (very) long runnning flows.
            self.basic_flow.get_flow_duration_usec(),
        )
    }

    fn get_features() -> String {
        [
            "Flow ID",
            "Src IP",
            "Src Port",
            "Dst IP",
            "Dst Port",
            "Protocol",
            "Timestamp",
            "Flow Duration",
            "Total Fwd Packet",
            "Total Bwd packets",
            "Total Length of Fwd Packet",
            "Total Length of Bwd Packet",
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Fwd Packet Length Mean",
            "Fwd Packet Length Std",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Fwd PSH Flags",
            "Bwd PSH Flags",
            "Fwd URG Flags",
            "Bwd URG Flags",
            "Fwd RST Flags",
            "Bwd RST Flags",
            "Fwd Header Length",
            "Bwd Header Length",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Packet Length Min",
            "Packet Length Max",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
            "CWR Flag Count",
            "ECE Flag Count",
            "Down/Up Ratio",
            "Average Packet Size",
            "Fwd Segment Size Avg",
            "Bwd Segment Size Avg",
            "Fwd Bytes/Bulk Avg",
            "Fwd Packet/Bulk Avg",
            "Fwd Bulk Rate Avg",
            "Bwd Bytes/Bulk Avg",
            "Bwd Packet/Bulk Avg",
            "Bwd Bulk Rate Avg",
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "FWD Init Win Bytes",
            "Bwd Init Win Bytes",
            "Fwd Act Data Pkts",
            "Bwd Act Data Pkts",
            "Fwd Seg Size Min",
            "Bwd Seg Size Min",
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min",
            "ICMP Code",
            "ICMP Type",
            "Fwd TCP Retrans. Count",
            "Bwd TCP Retrans. Count",
            "Total TCP Retrans. Count",
            "Total Connection Flow Time",
        ]
        .join(",")
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{}",
            // Basic Info
            iana_port_mapping(self.basic_flow.port_source),
            iana_port_mapping(self.basic_flow.port_destination),
            self.basic_flow.protocol,
            self.basic_flow.get_flow_duration_usec(),
            // Packet Length Stats (fwd & bwd)
            self.packet_len_stats.fwd_packet_len.get_count(),
            self.packet_len_stats.bwd_packet_len.get_count(),
            self.packet_len_stats.fwd_packet_len.get_total(),
            self.packet_len_stats.bwd_packet_len.get_total(),
            self.packet_len_stats.fwd_packet_len.get_max(),
            self.packet_len_stats.fwd_packet_len.get_min(),
            self.packet_len_stats.fwd_packet_len.get_mean(),
            self.packet_len_stats.fwd_packet_len.get_std(),
            self.packet_len_stats.bwd_packet_len.get_max(),
            self.packet_len_stats.bwd_packet_len.get_min(),
            self.packet_len_stats.bwd_packet_len.get_mean(),
            self.packet_len_stats.bwd_packet_len.get_std(),
            // Rate Stats (Flow)
            safe_per_second_rate(
                self.packet_len_stats.flow_total(),
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.flow_count() as f64,
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            // IAT Stats
            self.iat_stats.iat.get_mean(),
            self.iat_stats.iat.get_std(),
            self.iat_stats.iat.get_max(),
            self.iat_stats.iat.get_min(),
            self.iat_stats.fwd_iat.get_total(),
            self.iat_stats.fwd_iat.get_mean(),
            self.iat_stats.fwd_iat.get_std(),
            self.iat_stats.fwd_iat.get_max(),
            self.iat_stats.fwd_iat.get_min(),
            self.iat_stats.bwd_iat.get_total(),
            self.iat_stats.bwd_iat.get_mean(),
            self.iat_stats.bwd_iat.get_std(),
            self.iat_stats.bwd_iat.get_max(),
            self.iat_stats.bwd_iat.get_min(),
            // TCP Flags Stats (fwd & bwd)
            self.tcp_flags_stats.fwd_psh_flag_count,
            self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count,
            self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count,
            self.tcp_flags_stats.bwd_rst_flag_count,
            // Header Length Stats
            self.header_len_stats.fwd_header_len.get_total(),
            self.header_len_stats.bwd_header_len.get_total(),
            // Rate Stats (fwd & bwd packets)
            safe_per_second_rate(
                self.packet_len_stats.fwd_packet_len.get_count() as f64,
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.bwd_packet_len.get_count() as f64,
                self.basic_flow.get_flow_duration_usec() as f64
            ),
            // Packet Length Stats (Flow)
            self.packet_len_stats.flow_min(),
            self.packet_len_stats.flow_max(),
            self.packet_len_stats.flow_mean(),
            self.packet_len_stats.flow_std(),
            self.packet_len_stats.flow_variance(),
            // TCP Flags Stats (Flow)
            self.tcp_flags_stats.fwd_fin_flag_count + self.tcp_flags_stats.bwd_fin_flag_count,
            self.tcp_flags_stats.fwd_syn_flag_count + self.tcp_flags_stats.bwd_syn_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count + self.tcp_flags_stats.bwd_rst_flag_count,
            self.tcp_flags_stats.fwd_psh_flag_count + self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.fwd_ack_flag_count + self.tcp_flags_stats.bwd_ack_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count + self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.fwd_cwr_flag_count + self.tcp_flags_stats.bwd_cwr_flag_count,
            self.tcp_flags_stats.fwd_ece_flag_count + self.tcp_flags_stats.bwd_ece_flag_count,
            // UP/DOWN Ratio
            self.packet_len_stats.bwd_packet_len.get_count() as f64
                / self.packet_len_stats.fwd_packet_len.get_count() as f64,
            // Payload Length Stats
            self.payload_len_stats.payload_len.get_mean(),
            self.payload_len_stats.fwd_payload_len.get_mean(),
            self.payload_len_stats.bwd_payload_len.get_mean(),
            // Bulk Stats
            self.bulk_stats.fwd_bulk_payload_size.get_mean(),
            self.bulk_stats.fwd_bulk_packets.get_mean(),
            self.bulk_stats.fwd_bulk_rate(),
            self.bulk_stats.bwd_bulk_payload_size.get_mean(),
            self.bulk_stats.bwd_bulk_packets.get_mean(),
            self.bulk_stats.bwd_bulk_rate(),
            // Subflow Stats
            self.packet_len_stats.fwd_packet_len.get_count() as f64
                / self.subflow_stats.subflow_count as f64,
            self.packet_len_stats.fwd_packet_len.get_total()
                / self.subflow_stats.subflow_count as f64,
            self.packet_len_stats.bwd_packet_len.get_count() as f64
                / self.subflow_stats.subflow_count as f64,
            self.packet_len_stats.bwd_packet_len.get_total()
                / self.subflow_stats.subflow_count as f64,
            // Window Size Stats
            self.window_size_stats.fwd_init_window_size,
            self.window_size_stats.bwd_init_window_size,
            // Non Zero Payload Packets
            self.payload_len_stats.fwd_non_zero_payload_packets,
            self.payload_len_stats.bwd_non_zero_payload_packets,
            // Segment Length Stats
            self.header_len_stats.fwd_header_len.get_min(),
            self.header_len_stats.bwd_header_len.get_min(),
            // Active/Idle Stats
            self.active_idle_stats.active_stats.get_mean(),
            self.active_idle_stats.active_stats.get_std(),
            self.active_idle_stats.active_stats.get_max(),
            self.active_idle_stats.active_stats.get_min(),
            self.active_idle_stats.idle_stats.get_mean(),
            self.active_idle_stats.idle_stats.get_std(),
            self.active_idle_stats.idle_stats.get_max(),
            self.active_idle_stats.idle_stats.get_min(),
            // ICMP Stats
            self.icmp_stats.get_code(),
            self.icmp_stats.get_type(),
            // Retransmission Stats
            self.retransmission_stats.fwd_retransmission_count,
            self.retransmission_stats.bwd_retransmission_count,
            self.retransmission_stats.fwd_retransmission_count
                + self.retransmission_stats.bwd_retransmission_count,
            // Connection Duration
            // Duplicate of duration. Configure active and idle timeouts for specific use case of (very) long runnning flows.
            self.basic_flow.get_flow_duration_usec(),
        )
    }

    fn get_features_without_contamination() -> String {
        [
            "Src Port (IANA)",
            "Dst Port (IANA)",
            "Protocol",
            "Flow Duration",
            "Total Fwd Packet",
            "Total Bwd packets",
            "Total Length of Fwd Packet",
            "Total Length of Bwd Packet",
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Fwd Packet Length Mean",
            "Fwd Packet Length Std",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Fwd PSH Flags",
            "Bwd PSH Flags",
            "Fwd URG Flags",
            "Bwd URG Flags",
            "Fwd RST Flags",
            "Bwd RST Flags",
            "Fwd Header Length",
            "Bwd Header Length",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Packet Length Min",
            "Packet Length Max",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
            "CWR Flag Count",
            "ECE Flag Count",
            "Down/Up Ratio",
            "Average Packet Size",
            "Fwd Segment Size Avg",
            "Bwd Segment Size Avg",
            "Fwd Bytes/Bulk Avg",
            "Fwd Packet/Bulk Avg",
            "Fwd Bulk Rate Avg",
            "Bwd Bytes/Bulk Avg",
            "Bwd Packet/Bulk Avg",
            "Bwd Bulk Rate Avg",
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "FWD Init Win Bytes",
            "Bwd Init Win Bytes",
            "Fwd Act Data Pkts",
            "Bwd Act Data Pkts",
            "Fwd Seg Size Min",
            "Bwd Seg Size Min",
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min",
            "ICMP Code",
            "ICMP Type",
            "Fwd TCP Retrans. Count",
            "Bwd TCP Retrans. Count",
            "Total TCP Retrans. Count",
            "Total Connection Flow Time",
        ]
        .join(",")
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
