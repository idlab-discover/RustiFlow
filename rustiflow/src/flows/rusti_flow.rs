use chrono::{DateTime, Utc};
use std::net::IpAddr;

use crate::{flows::util::iana_port_mapping, packet_features::PacketFeatures};

use super::{
    basic_flow::BasicFlow,
    features::{
        active_idle_stats::ActiveIdleStats, bulk_stats::BulkStats, header_stats::HeaderLengthStats,
        iat_stats::IATStats, icmp_stats::IcmpStats, packet_stats::PacketLengthStats,
        payload_stats::PayloadLengthStats, retransmission_stats::RetransmissionStats,
        subflow_stats::SubflowStats, tcp_flag_stats::TcpFlagStats, timing_stats::TimingStats,
        window_size_stats::WindowSizeStats,
    },
    flow::Flow,
};

/// Represents a Rusti Flow, a super-set of features from CICFlowMeter, CIDDS, NFStream and more.
#[derive(Clone)]
pub struct RustiFlow {
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

impl Flow for RustiFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp: DateTime<Utc>,
    ) -> Self {
        RustiFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp,
            ),
            packet_len_stats: PacketLengthStats::new(),
            iat_stats: IATStats::new(),
            tcp_flags_stats: TcpFlagStats::new(),
            header_len_stats: HeaderLengthStats::new(),
            payload_len_stats: PayloadLengthStats::new(),
            bulk_stats: BulkStats::new(),
            subflow_stats: SubflowStats::new(),
            active_idle_stats: ActiveIdleStats::new(&timestamp),
            icmp_stats: IcmpStats::new(),
            retransmission_stats: RetransmissionStats::new(),
            window_size_stats: WindowSizeStats::new(),
            timing_stats: TimingStats::new(),
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        let last_timestamp = self.basic_flow.last_timestamp;
        let is_terminated = self.basic_flow.update_flow(packet, fwd);

        self.packet_len_stats.update(packet, fwd);
        self.iat_stats.update(packet, fwd);
        self.tcp_flags_stats.update(packet, fwd);
        self.header_len_stats.update(packet, fwd);
        self.payload_len_stats.update(packet, fwd);
        self.bulk_stats.update(packet, fwd);
        self.subflow_stats.update(packet, &last_timestamp);
        self.active_idle_stats.update(packet);
        self.icmp_stats.update(packet);
        self.retransmission_stats.update(packet, fwd);
        self.window_size_stats.update(packet, fwd);
        self.timing_stats.update(packet, fwd);

        is_terminated
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{}",
            // Basic Info
            self.basic_flow.flow_key,
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            self.basic_flow.protocol,
            self.basic_flow.first_timestamp,
            self.basic_flow.last_timestamp,
            self.basic_flow.get_flow_duration_usec(),
            self.basic_flow.tcp_normal_termination,
            // Timing Stats
            self.timing_stats.dump(),
            // IAT Stats
            self.iat_stats.dump(),
            // Packet Length Stats
            self.packet_len_stats.dump(),
            // Packet Header Length Stats
            self.header_len_stats.dump(),
            // Payload Length Stats
            self.payload_len_stats.dump(),
            // Bulk Stats
            self.bulk_stats.dump(),
            // Subflow Stats
            self.subflow_stats.dump(),
            // Active Idle Stats
            self.active_idle_stats.dump(),
            // ICMP Stats
            self.icmp_stats.dump(),
            // Retransmission Stats
            self.retransmission_stats.dump(),
            // Window Size Stats
            self.window_size_stats.dump(),
            // TCP Flag Stats
            self.tcp_flags_stats.dump(),
            // Rate Stats (per second)
            self.packet_len_stats.flow_total()
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.flow_count() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.fwd_packet_len.get_total() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.fwd_packet_len.get_count() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.bwd_packet_len.get_total() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.bwd_packet_len.get_count() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            // UP/DOWN Ratio
            self.packet_len_stats.bwd_packet_len.get_count() as f64
                / self.packet_len_stats.fwd_packet_len.get_count() as f64,
        )
    }

    fn get_features() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{}",
            // Basic Info
            "flow_id",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "timestamp_first",
            "timestamp_last",
            "flow_duration_us",
            "normal_tcp_termination",
            // Timing Stats
            TimingStats::header(),
            // IAT Stats
            IATStats::header(),
            // Packet Length Stats
            PacketLengthStats::header(),
            // Packet Header Length Stats
            HeaderLengthStats::header(),
            // Payload Length Stats
            PayloadLengthStats::header(),
            // Bulk Stats
            BulkStats::header(),
            // Subflow Stats
            SubflowStats::header(),
            // Active Idle Stats
            ActiveIdleStats::header(),
            // ICMP Stats
            IcmpStats::header(),
            // Retransmission Stats
            RetransmissionStats::header(),
            // Window Size Stats
            WindowSizeStats::header(),
            // TCP Flag Stats
            TcpFlagStats::header(),
            // Rate Stats (per second)
            "flow_bytes_s",
            "flow_packets_s",
            "fwd_bytes_s",
            "fwd_packets_s",
            "bwd_bytes_s",
            "bwd_packets_s",
            // UP/DOWN Ratio
            "up_down_ratio",
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{}",
            // Basic Info
            iana_port_mapping(self.basic_flow.port_source),
            iana_port_mapping(self.basic_flow.port_destination),
            self.basic_flow.protocol,
            self.basic_flow.get_flow_duration_usec(),
            self.basic_flow.tcp_normal_termination,
            // Timing Stats
            self.timing_stats.dump(),
            // IAT Stats
            self.iat_stats.dump(),
            // Packet Length Stats
            self.packet_len_stats.dump(),
            // Packet Header Length Stats
            self.header_len_stats.dump(),
            // Payload Length Stats
            self.payload_len_stats.dump(),
            // Bulk Stats
            self.bulk_stats.dump(),
            // Subflow Stats
            self.subflow_stats.dump(),
            // Active Idle Stats
            self.active_idle_stats.dump(),
            // ICMP Stats
            self.icmp_stats.dump(),
            // Retransmission Stats
            self.retransmission_stats.dump(),
            // Window Size Stats
            self.window_size_stats.dump(),
            // TCP Flag Stats
            self.tcp_flags_stats.dump(),
            // Rate Stats (per second)
            self.packet_len_stats.flow_total()
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.flow_count() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.fwd_packet_len.get_total() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.fwd_packet_len.get_count() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.bwd_packet_len.get_total() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            self.packet_len_stats.bwd_packet_len.get_count() as f64
                / (self.basic_flow.get_flow_duration_usec() / 1_000_000.0),
            // UP/DOWN Ratio
            self.packet_len_stats.bwd_packet_len.get_count() as f64
                / self.packet_len_stats.fwd_packet_len.get_count() as f64,
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{}",
            // Basic Info
            "source_port_iana",
            "destination_port_iana",
            "protocol",
            "flow_duration_us",
            "normal_tcp_termination",
            // Timing Stats
            TimingStats::header(),
            // IAT Stats
            IATStats::header(),
            // Packet Length Stats
            PacketLengthStats::header(),
            // Packet Header Length Stats
            HeaderLengthStats::header(),
            // Payload Length Stats
            PayloadLengthStats::header(),
            // Bulk Stats
            BulkStats::header(),
            // Subflow Stats
            SubflowStats::header(),
            // Active Idle Stats
            ActiveIdleStats::header(),
            // ICMP Stats
            IcmpStats::header(),
            // Retransmission Stats
            RetransmissionStats::header(),
            // Window Size Stats
            WindowSizeStats::header(),
            // TCP Flag Stats
            TcpFlagStats::header(),
            // Rate Stats (per second)
            "flow_bytes_s",
            "flow_packets_s",
            "fwd_bytes_s",
            "fwd_packets_s",
            "bwd_bytes_s",
            "bwd_packets_s",
            // UP/DOWN Ratio
            "up_down_ratio",
        )
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
