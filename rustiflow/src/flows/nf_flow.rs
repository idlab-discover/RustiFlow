use std::net::IpAddr;

use crate::flows::{features::timing_stats::TimingStats, util::iana_port_mapping};
use crate::packet_features::PacketFeatures;

use super::features::util::FlowFeature;
use super::util::FlowExpireCause;
use super::{
    basic_flow::BasicFlow,
    features::{
        active_idle_stats::ActiveIdleStats, bulk_stats::BulkStats, header_stats::HeaderLengthStats,
        iat_stats::IATStats, icmp_stats::IcmpStats, packet_stats::PacketLengthStats,
        payload_stats::PayloadLengthStats, retransmission_stats::RetransmissionStats,
        subflow_stats::SubflowStats, tcp_flag_stats::TcpFlagStats,
        window_size_stats::WindowSizeStats,
    },
    flow::Flow,
};

/// Represents a Nfstream inspired Flow by the popular nfstream python library.
#[derive(Clone)]
pub struct NfFlow {
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
    pub timing_stats: TimingStats,
}

impl NfFlow {
    pub fn get_expiration_id(&self) -> i8 {
        match self.basic_flow.flow_expire_cause {
            FlowExpireCause::ActiveTimeout => 1,
            FlowExpireCause::IdleTimeout => 0,
            _ => -1,
        }
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
        timestamp_us: i64,
    ) -> Self {
        NfFlow {
            basic_flow: BasicFlow::new(
                flow_id,
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
            timing_stats: TimingStats::new(),
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
        self.timing_stats.update(packet, fwd, last_timestamp_us);

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
        self.timing_stats.close(timestamp_us, cause);
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}",
            // NFlow Core Features
            // 7 features are missing: src_mac, src_oui, dst_mac, dst_oui, ip_version, vlan_id, tunner_id
            self.basic_flow.flow_key,
            self.get_expiration_id(),
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            self.basic_flow.protocol,
            self.basic_flow.first_timestamp_us / 1000,
            self.basic_flow.last_timestamp_us / 1000,
            self.basic_flow.get_flow_duration_msec(),
            self.packet_len_stats.flow_count(),
            self.packet_len_stats.flow_total(),
            self.timing_stats
                .first_timestamp_fwd
                .map(|t| t / 1000)
                .unwrap_or_else(|| 0),
            self.timing_stats
                .last_timestamp_fwd
                .map(|t| t / 1000)
                .unwrap_or_else(|| 0),
            self.timing_stats.get_fwd_duration(),
            self.packet_len_stats.fwd_packet_len.get_count(),
            self.packet_len_stats.fwd_packet_len.get_total(),
            self.timing_stats
                .first_timestamp_bwd
                .map(|t| t / 1000)
                .unwrap_or_else(|| 0),
            self.timing_stats
                .last_timestamp_bwd
                .map(|t| t / 1000)
                .unwrap_or_else(|| 0),
            self.timing_stats.get_bwd_duration(),
            self.packet_len_stats.bwd_packet_len.get_count(),
            self.packet_len_stats.bwd_packet_len.get_total(),
            // Post-Mortem Statistical Features
            self.packet_len_stats.flow_min(),
            self.packet_len_stats.flow_mean(),
            self.packet_len_stats.flow_std(),
            self.packet_len_stats.flow_max(),
            self.packet_len_stats.fwd_packet_len.get_min(),
            self.packet_len_stats.fwd_packet_len.get_mean(),
            self.packet_len_stats.fwd_packet_len.get_std(),
            self.packet_len_stats.fwd_packet_len.get_max(),
            self.packet_len_stats.bwd_packet_len.get_min(),
            self.packet_len_stats.bwd_packet_len.get_mean(),
            self.packet_len_stats.bwd_packet_len.get_std(),
            self.packet_len_stats.bwd_packet_len.get_max(),
            self.iat_stats.iat.get_min() / 1000.0,
            self.iat_stats.iat.get_mean() / 1000.0,
            self.iat_stats.iat.get_std() / 1000.0,
            self.iat_stats.iat.get_max() / 1000.0,
            self.iat_stats.fwd_iat.get_min() / 1000.0,
            self.iat_stats.fwd_iat.get_mean() / 1000.0,
            self.iat_stats.fwd_iat.get_std() / 1000.0,
            self.iat_stats.fwd_iat.get_max() / 1000.0,
            self.iat_stats.bwd_iat.get_min() / 1000.0,
            self.iat_stats.bwd_iat.get_mean() / 1000.0,
            self.iat_stats.bwd_iat.get_std() / 1000.0,
            self.iat_stats.bwd_iat.get_max() / 1000.0,
            self.tcp_flags_stats.fwd_syn_flag_count + self.tcp_flags_stats.bwd_syn_flag_count,
            self.tcp_flags_stats.fwd_cwr_flag_count + self.tcp_flags_stats.bwd_cwr_flag_count,
            self.tcp_flags_stats.fwd_ece_flag_count + self.tcp_flags_stats.bwd_ece_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count + self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.fwd_ack_flag_count + self.tcp_flags_stats.bwd_ack_flag_count,
            self.tcp_flags_stats.fwd_psh_flag_count + self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count + self.tcp_flags_stats.bwd_rst_flag_count,
            self.tcp_flags_stats.fwd_fin_flag_count + self.tcp_flags_stats.bwd_fin_flag_count,
            self.tcp_flags_stats.fwd_syn_flag_count,
            self.tcp_flags_stats.fwd_cwr_flag_count,
            self.tcp_flags_stats.fwd_ece_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count,
            self.tcp_flags_stats.fwd_ack_flag_count,
            self.tcp_flags_stats.fwd_psh_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count,
            self.tcp_flags_stats.fwd_fin_flag_count,
            self.tcp_flags_stats.bwd_syn_flag_count,
            self.tcp_flags_stats.bwd_cwr_flag_count,
            self.tcp_flags_stats.bwd_ece_flag_count,
            self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.bwd_ack_flag_count,
            self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.bwd_rst_flag_count,
            self.tcp_flags_stats.bwd_fin_flag_count,
        )
    }

    fn get_features() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}",
            "id",
            "expiration_id",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "bidirectional_first_seen_ms",
            "bidirectional_last_seen_ms",
            "bidirectional_duration_ms",
            "bidirectional_packets",
            "bidirectional_bytes",
            "src2dst_first_seen_ms",
            "src2dst_last_seen_ms",
            "src2dst_duration_ms",
            "src2dst_packets",
            "src2dst_bytes",
            "dst2src_first_seen_ms",
            "dst2src_last_seen_ms",
            "dst2src_duration_ms",
            "dst2src_packets",
            "dst2src_bytes",
            "bidirectional_min_ps",
            "bidirectional_mean_ps",
            "bidirectional_stddev_ps",
            "bidirectional_max_ps",
            "src2dst_min_ps",
            "src2dst_mean_ps",
            "src2dst_stddev_ps",
            "src2dst_max_ps",
            "dst2src_min_ps",
            "dst2src_mean_ps",
            "dst2src_stddev_ps",
            "dst2src_max_ps",
            "bidirectional_min_piat_ms",
            "bidirectional_mean_piat_ms",
            "bidirectional_stddev_piat_ms",
            "bidirectional_max_piat_ms",
            "src2dst_min_piat_ms",
            "src2dst_mean_piat_ms",
            "src2dst_stddev_piat_ms",
            "src2dst_max_piat_ms",
            "dst2src_min_piat_ms",
            "dst2src_mean_piat_ms",
            "dst2src_stddev_piat_ms",
            "dst2src_max_piat_ms",
            "bidirectional_syn_packets",
            "bidirectional_cwr_packets",
            "bidirectional_ece_packets",
            "bidirectional_urg_packets",
            "bidirectional_ack_packets",
            "bidirectional_psh_packets",
            "bidirectional_rst_packets",
            "bidirectional_fin_packets",
            "src2dst_syn_packets",
            "src2dst_cwr_packets",
            "src2dst_ece_packets",
            "src2dst_urg_packets",
            "src2dst_ack_packets",
            "src2dst_psh_packets",
            "src2dst_rst_packets",
            "src2dst_fin_packets",
            "dst2src_syn_packets",
            "dst2src_cwr_packets",
            "dst2src_ece_packets",
            "dst2src_urg_packets",
            "dst2src_ack_packets",
            "dst2src_psh_packets",
            "dst2src_rst_packets",
            "dst2src_fin_packets",
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}",
            // NFlow Core Features
            iana_port_mapping(self.basic_flow.port_source),
            iana_port_mapping(self.basic_flow.port_destination),
            self.basic_flow.protocol,
            self.basic_flow.get_flow_duration_msec(),
            self.packet_len_stats.flow_count(),
            self.packet_len_stats.flow_total(),
            self.timing_stats.get_fwd_duration(),
            self.packet_len_stats.fwd_packet_len.get_count(),
            self.packet_len_stats.fwd_packet_len.get_total(),
            self.timing_stats.get_bwd_duration(),
            self.packet_len_stats.bwd_packet_len.get_count(),
            self.packet_len_stats.bwd_packet_len.get_total(),
            // Post-Mortem Statistical Features
            self.packet_len_stats.flow_min(),
            self.packet_len_stats.flow_mean(),
            self.packet_len_stats.flow_std(),
            self.packet_len_stats.flow_max(),
            self.packet_len_stats.fwd_packet_len.get_min(),
            self.packet_len_stats.fwd_packet_len.get_mean(),
            self.packet_len_stats.fwd_packet_len.get_std(),
            self.packet_len_stats.fwd_packet_len.get_max(),
            self.packet_len_stats.bwd_packet_len.get_min(),
            self.packet_len_stats.bwd_packet_len.get_mean(),
            self.packet_len_stats.bwd_packet_len.get_std(),
            self.packet_len_stats.bwd_packet_len.get_max(),
            self.iat_stats.iat.get_min() / 1000.0,
            self.iat_stats.iat.get_mean() / 1000.0,
            self.iat_stats.iat.get_std() / 1000.0,
            self.iat_stats.iat.get_max() / 1000.0,
            self.iat_stats.fwd_iat.get_min() / 1000.0,
            self.iat_stats.fwd_iat.get_mean() / 1000.0,
            self.iat_stats.fwd_iat.get_std() / 1000.0,
            self.iat_stats.fwd_iat.get_max() / 1000.0,
            self.iat_stats.bwd_iat.get_min() / 1000.0,
            self.iat_stats.bwd_iat.get_mean() / 1000.0,
            self.iat_stats.bwd_iat.get_std() / 1000.0,
            self.iat_stats.bwd_iat.get_max() / 1000.0,
            self.tcp_flags_stats.fwd_syn_flag_count + self.tcp_flags_stats.bwd_syn_flag_count,
            self.tcp_flags_stats.fwd_cwr_flag_count + self.tcp_flags_stats.bwd_cwr_flag_count,
            self.tcp_flags_stats.fwd_ece_flag_count + self.tcp_flags_stats.bwd_ece_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count + self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.fwd_ack_flag_count + self.tcp_flags_stats.bwd_ack_flag_count,
            self.tcp_flags_stats.fwd_psh_flag_count + self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count + self.tcp_flags_stats.bwd_rst_flag_count,
            self.tcp_flags_stats.fwd_fin_flag_count + self.tcp_flags_stats.bwd_fin_flag_count,
            self.tcp_flags_stats.fwd_syn_flag_count,
            self.tcp_flags_stats.fwd_cwr_flag_count,
            self.tcp_flags_stats.fwd_ece_flag_count,
            self.tcp_flags_stats.fwd_urg_flag_count,
            self.tcp_flags_stats.fwd_ack_flag_count,
            self.tcp_flags_stats.fwd_psh_flag_count,
            self.tcp_flags_stats.fwd_rst_flag_count,
            self.tcp_flags_stats.fwd_fin_flag_count,
            self.tcp_flags_stats.bwd_syn_flag_count,
            self.tcp_flags_stats.bwd_cwr_flag_count,
            self.tcp_flags_stats.bwd_ece_flag_count,
            self.tcp_flags_stats.bwd_urg_flag_count,
            self.tcp_flags_stats.bwd_ack_flag_count,
            self.tcp_flags_stats.bwd_psh_flag_count,
            self.tcp_flags_stats.bwd_rst_flag_count,
            self.tcp_flags_stats.bwd_fin_flag_count,
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}",
            "src_port_iana",
            "dst_port_iana",
            "protocol",
            "bidirectional_duration_ms",
            "bidirectional_packets",
            "bidirectional_bytes",
            "src2dst_duration_ms",
            "src2dst_packets",
            "src2dst_bytes",
            "dst2src_duration_ms",
            "dst2src_packets",
            "dst2src_bytes",
            "bidirectional_min_ps",
            "bidirectional_mean_ps",
            "bidirectional_stddev_ps",
            "bidirectional_max_ps",
            "src2dst_min_ps",
            "src2dst_mean_ps",
            "src2dst_stddev_ps",
            "src2dst_max_ps",
            "dst2src_min_ps",
            "dst2src_mean_ps",
            "dst2src_stddev_ps",
            "dst2src_max_ps",
            "bidirectional_min_piat_ms",
            "bidirectional_mean_piat_ms",
            "bidirectional_stddev_piat_ms",
            "bidirectional_max_piat_ms",
            "src2dst_min_piat_ms",
            "src2dst_mean_piat_ms",
            "src2dst_stddev_piat_ms",
            "src2dst_max_piat_ms",
            "dst2src_min_piat_ms",
            "dst2src_mean_piat_ms",
            "dst2src_stddev_piat_ms",
            "dst2src_max_piat_ms",
            "bidirectional_syn_packets",
            "bidirectional_cwr_packets",
            "bidirectional_ece_packets",
            "bidirectional_urg_packets",
            "bidirectional_ack_packets",
            "bidirectional_psh_packets",
            "bidirectional_rst_packets",
            "bidirectional_fin_packets",
            "src2dst_syn_packets",
            "src2dst_cwr_packets",
            "src2dst_ece_packets",
            "src2dst_urg_packets",
            "src2dst_ack_packets",
            "src2dst_psh_packets",
            "src2dst_rst_packets",
            "src2dst_fin_packets",
            "dst2src_syn_packets",
            "dst2src_cwr_packets",
            "dst2src_ece_packets",
            "dst2src_urg_packets",
            "dst2src_ack_packets",
            "dst2src_psh_packets",
            "dst2src_rst_packets",
            "dst2src_fin_packets",
        )
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
