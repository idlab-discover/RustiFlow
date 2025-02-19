use std::net::IpAddr;

use crate::{
    flows::{
        features::util::{safe_div_int, safe_per_second_rate},
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
        subflow_stats::SubflowStats, tcp_flag_stats::TcpFlagStats, timing_stats::TimingStats,
        util::FlowFeature, window_size_stats::WindowSizeStats,
    },
    flow::Flow,
    util::FlowExpireCause,
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
        timestamp_us: i64,
    ) -> Self {
        RustiFlow {
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
        let duration_us = self.basic_flow.get_flow_duration_usec();
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
            self.basic_flow.get_first_timestamp(),
            self.basic_flow.get_last_timestamp(),
            duration_us,
            self.basic_flow.flow_expire_cause.as_str(),
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
            safe_per_second_rate(self.packet_len_stats.flow_total(), duration_us as f64),
            safe_per_second_rate(
                self.packet_len_stats.flow_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.fwd_packet_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.fwd_packet_len.get_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.bwd_packet_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.bwd_packet_len.get_count() as f64,
                duration_us as f64
            ),
            // UP/DOWN Ratio
            safe_div_int(
                self.packet_len_stats.bwd_packet_len.get_count(),
                self.packet_len_stats.fwd_packet_len.get_count()
            ),
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
            "flow_expire_cause",
            // Timing Stats
            TimingStats::headers(),
            // IAT Stats
            IATStats::headers(),
            // Packet Length Stats
            PacketLengthStats::headers(),
            // Packet Header Length Stats
            HeaderLengthStats::headers(),
            // Payload Length Stats
            PayloadLengthStats::headers(),
            // Bulk Stats
            BulkStats::headers(),
            // Subflow Stats
            SubflowStats::headers(),
            // Active Idle Stats
            ActiveIdleStats::headers(),
            // ICMP Stats
            IcmpStats::headers(),
            // Retransmission Stats
            RetransmissionStats::headers(),
            // Window Size Stats
            WindowSizeStats::headers(),
            // TCP Flag Stats
            TcpFlagStats::headers(),
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
        let duration_us = self.basic_flow.get_flow_duration_usec();
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{},{}",
            // Basic Info
            iana_port_mapping(self.basic_flow.port_source),
            iana_port_mapping(self.basic_flow.port_destination),
            self.basic_flow.protocol,
            duration_us,
            self.basic_flow.flow_expire_cause.as_str(),
            // Timing Stats
            self.timing_stats.get_fwd_duration(),
            self.timing_stats.get_bwd_duration(),
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
            safe_per_second_rate(self.packet_len_stats.flow_total(), duration_us as f64),
            safe_per_second_rate(
                self.packet_len_stats.flow_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.fwd_packet_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.fwd_packet_len.get_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.bwd_packet_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.packet_len_stats.bwd_packet_len.get_count() as f64,
                duration_us as f64
            ),
            // UP/DOWN Ratio
            safe_div_int(
                self.packet_len_stats.bwd_packet_len.get_count(),
                self.packet_len_stats.fwd_packet_len.get_count()
            ),
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{},{}",
            // Basic Info
            "source_port_iana",
            "destination_port_iana",
            "protocol",
            "flow_duration_us",
            "flow_expire_cause",
            // Timing Stats
            "fwd_duration_ms",
            "bwd_duration_ms",
            // IAT Stats
            IATStats::headers(),
            // Packet Length Stats
            PacketLengthStats::headers(),
            // Packet Header Length Stats
            HeaderLengthStats::headers(),
            // Payload Length Stats
            PayloadLengthStats::headers(),
            // Bulk Stats
            BulkStats::headers(),
            // Subflow Stats
            SubflowStats::headers(),
            // Active Idle Stats
            ActiveIdleStats::headers(),
            // ICMP Stats
            IcmpStats::headers(),
            // Retransmission Stats
            RetransmissionStats::headers(),
            // Window Size Stats
            WindowSizeStats::headers(),
            // TCP Flag Stats
            TcpFlagStats::headers(),
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
