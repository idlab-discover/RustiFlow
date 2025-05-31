use std::net::IpAddr;
use polars::prelude::AnyValue;

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
            safe_per_second_rate(
                self.payload_len_stats.payload_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.payload_len.get_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.fwd_payload_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.fwd_payload_len.get_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.bwd_payload_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.bwd_payload_len.get_count() as f64,
                duration_us as f64
            ),
            safe_div_int(
                self.payload_len_stats.fwd_payload_len.get_count(),
                self.subflow_stats.subflow_count
            ),
            safe_div(
                self.payload_len_stats.fwd_payload_len.get_total(),
                self.subflow_stats.subflow_count as f64
            ),
            safe_div_int(
                self.payload_len_stats.bwd_payload_len.get_count(),
                self.subflow_stats.subflow_count
            ),
            safe_div(
                self.payload_len_stats.bwd_payload_len.get_total(),
                self.subflow_stats.subflow_count as f64
            ),
            // UP/DOWN Ratio
            safe_div_int(
                self.payload_len_stats.bwd_payload_len.get_count(),
                self.payload_len_stats.fwd_payload_len.get_count()
            ),
        )
    }

    fn get_features() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},\
            {},{},{}",
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
            "fwd_subflow_packets_mean",
            "fwd_subflow_bytes_mean",
            "bwd_subflow_packets_mean",
            "bwd_subflow_bytes_mean",
            // UP/DOWN Ratio
            "up_down_ratio",
        )
    }

    fn dump_without_contamination(&self) -> String {
        let duration_us = self.basic_flow.get_flow_duration_usec();
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{},{},{},{},{},{}",
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
            safe_per_second_rate(
                self.payload_len_stats.payload_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.payload_len.get_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.fwd_payload_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.fwd_payload_len.get_count() as f64,
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.bwd_payload_len.get_total(),
                duration_us as f64
            ),
            safe_per_second_rate(
                self.payload_len_stats.bwd_payload_len.get_count() as f64,
                duration_us as f64
            ),
            safe_div_int(
                self.payload_len_stats.fwd_payload_len.get_count(),
                self.subflow_stats.subflow_count
            ),
            safe_div(
                self.payload_len_stats.fwd_payload_len.get_total(),
                self.subflow_stats.subflow_count as f64
            ),
            safe_div_int(
                self.payload_len_stats.bwd_payload_len.get_count(),
                self.subflow_stats.subflow_count
            ),
            safe_div(
                self.payload_len_stats.bwd_payload_len.get_total(),
                self.subflow_stats.subflow_count as f64
            ),
            // UP/DOWN Ratio
            safe_div_int(
                self.payload_len_stats.bwd_payload_len.get_count(),
                self.payload_len_stats.fwd_payload_len.get_count()
            ),
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{},{},{},{},{},{}",
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
            "fwd_subflow_packets_mean",
            "fwd_subflow_bytes_mean",
            "bwd_subflow_packets_mean",
            "bwd_subflow_bytes_mean",
            // UP/DOWN Ratio
            "up_down_ratio",
        )
    }

    fn get_first_timestamp_us(&self) -> i64 {
        self.basic_flow.first_timestamp_us
    }

    fn get_flow_duration_usec(&self) -> i64 {
        self.basic_flow.get_flow_duration_usec()
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

    fn to_polars_row(&self) -> Vec<AnyValue<'static>> {
        let mut row = self.basic_flow.to_polars_row();
        // BasicFlow::to_polars_row() returns 11 fields. RustiFlow's first 10 match BasicFlow's first 10.
        // The 11th field from BasicFlow (packet_sizes List) is not part of RustiFlow's get_features() header here.
        row.truncate(10);

        // TimingStats: fwd_ts_first_ms, fwd_ts_last_ms, fwd_duration_ms, bwd_ts_first_ms, bwd_ts_last_ms, bwd_duration_ms
        row.push(AnyValue::Int64(self.timing_stats.first_timestamp_fwd_ms.unwrap_or(0)));
        row.push(AnyValue::Int64(self.timing_stats.last_timestamp_fwd_ms.unwrap_or(0)));
        row.push(AnyValue::Int64(self.timing_stats.get_fwd_duration()));
        row.push(AnyValue::Int64(self.timing_stats.first_timestamp_bwd_ms.unwrap_or(0)));
        row.push(AnyValue::Int64(self.timing_stats.last_timestamp_bwd_ms.unwrap_or(0)));
        row.push(AnyValue::Int64(self.timing_stats.get_bwd_duration()));

        // IATStats: (many fields, all f64 as per IATStats::dump format and BasicStats<f64> usage)
        // Example for a few: iat_mean, iat_std, iat_max, iat_min, iat_count (though count might be u64)
        // Headers: "iat_mean,iat_std,iat_max,iat_min,iat_count,fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,fwd_iat_count,bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,bwd_iat_count,flow_iat_total"
        row.push(AnyValue::Float64(self.iat_stats.iat.get_mean()));
        row.push(AnyValue::Float64(self.iat_stats.iat.get_std()));
        row.push(AnyValue::Float64(self.iat_stats.iat.get_max()));
        row.push(AnyValue::Float64(self.iat_stats.iat.get_min()));
        row.push(AnyValue::UInt64(self.iat_stats.iat.get_count())); // count is u64
        row.push(AnyValue::Float64(self.iat_stats.fwd_iat.get_total()));
        row.push(AnyValue::Float64(self.iat_stats.fwd_iat.get_mean()));
        row.push(AnyValue::Float64(self.iat_stats.fwd_iat.get_std()));
        row.push(AnyValue::Float64(self.iat_stats.fwd_iat.get_max()));
        row.push(AnyValue::Float64(self.iat_stats.fwd_iat.get_min()));
        row.push(AnyValue::UInt64(self.iat_stats.fwd_iat.get_count()));
        row.push(AnyValue::Float64(self.iat_stats.bwd_iat.get_total()));
        row.push(AnyValue::Float64(self.iat_stats.bwd_iat.get_mean()));
        row.push(AnyValue::Float64(self.iat_stats.bwd_iat.get_std()));
        row.push(AnyValue::Float64(self.iat_stats.bwd_iat.get_max()));
        row.push(AnyValue::Float64(self.iat_stats.bwd_iat.get_min()));
        row.push(AnyValue::UInt64(self.iat_stats.bwd_iat.get_count()));
        row.push(AnyValue::Float64(self.iat_stats.flow_iat_total));


        // Placeholder for PacketLengthStats, HeaderLengthStats, PayloadLengthStats, etc.
        // Each of these would require iterating through their own headers() and providing AnyValue::xxx for each field.
        // For PacketLengthStats (example fields from its headers like "flow_pkt_len_tot", "flow_pkt_len_mean", etc.)
        // These are typically u64 for totals/counts, f64 for mean/std/min/max.
        // Example for one field:
        // row.push(AnyValue::UInt64(self.packet_len_stats.flow_total_len.get_total())); // Assuming flow_total_len matches a header like "flow_pkt_len_tot"
        // THIS SECTION NEEDS TO BE FILLED OUT COMPLETELY FOR ALL Stats STRUCTS
        // For now, I'll add nulls as placeholders to match a hypothetical number of fields for remaining structs
        // to avoid panic if column/data length mismatch occurs in Polars later.
        // This is a temporary measure for this step.

        let num_packet_len_stats_fields = super::features::packet_stats::PacketLengthStats::headers().matches(',').count() + 1;
        for _ in 0..num_packet_len_stats_fields { row.push(AnyValue::Null); }

        let num_header_len_stats_fields = super::features::header_stats::HeaderLengthStats::headers().matches(',').count() + 1;
        for _ in 0..num_header_len_stats_fields { row.push(AnyValue::Null); }

        let num_payload_len_stats_fields = super::features::payload_stats::PayloadLengthStats::headers().matches(',').count() + 1;
        for _ in 0..num_payload_len_stats_fields { row.push(AnyValue::Null); }

        let num_bulk_stats_fields = super::features::bulk_stats::BulkStats::headers().matches(',').count() + 1;
        for _ in 0..num_bulk_stats_fields { row.push(AnyValue::Null); }

        let num_subflow_stats_fields = super::features::subflow_stats::SubflowStats::headers().matches(',').count() + 1;
        for _ in 0..num_subflow_stats_fields { row.push(AnyValue::Null); }

        let num_active_idle_stats_fields = super::features::active_idle_stats::ActiveIdleStats::headers().matches(',').count() + 1;
        for _ in 0..num_active_idle_stats_fields { row.push(AnyValue::Null); }

        let num_icmp_stats_fields = super::features::icmp_stats::IcmpStats::headers().matches(',').count() + 1;
        for _ in 0..num_icmp_stats_fields { row.push(AnyValue::Null); }

        let num_retransmission_stats_fields = super::features::retransmission_stats::RetransmissionStats::headers().matches(',').count() + 1;
        for _ in 0..num_retransmission_stats_fields { row.push(AnyValue::Null); }

        let num_window_size_stats_fields = super::features::window_size_stats::WindowSizeStats::headers().matches(',').count() + 1;
        for _ in 0..num_window_size_stats_fields { row.push(AnyValue::Null); }

        let num_tcp_flag_stats_fields = super::features::tcp_flag_stats::TcpFlagStats::headers().matches(',').count() + 1;
        for _ in 0..num_tcp_flag_stats_fields { row.push(AnyValue::Null); }

        // Final rate stats and ratio
        let duration_us = self.basic_flow.get_flow_duration_usec();
        row.push(AnyValue::Float64(safe_per_second_rate(self.payload_len_stats.payload_len.get_total(), duration_us as f64)));
        row.push(AnyValue::Float64(safe_per_second_rate(self.payload_len_stats.payload_len.get_count() as f64, duration_us as f64)));
        row.push(AnyValue::Float64(safe_per_second_rate(self.payload_len_stats.fwd_payload_len.get_total(), duration_us as f64)));
        row.push(AnyValue::Float64(safe_per_second_rate(self.payload_len_stats.fwd_payload_len.get_count() as f64, duration_us as f64)));
        row.push(AnyValue::Float64(safe_per_second_rate(self.payload_len_stats.bwd_payload_len.get_total(), duration_us as f64)));
        row.push(AnyValue::Float64(safe_per_second_rate(self.payload_len_stats.bwd_payload_len.get_count() as f64, duration_us as f64)));
        row.push(AnyValue::Float64(safe_div_int(self.payload_len_stats.fwd_payload_len.get_count(), self.subflow_stats.subflow_count)));
        row.push(AnyValue::Float64(safe_div(self.payload_len_stats.fwd_payload_len.get_total(), self.subflow_stats.subflow_count as f64)));
        row.push(AnyValue::Float64(safe_div_int(self.payload_len_stats.bwd_payload_len.get_count(), self.subflow_stats.subflow_count)));
        row.push(AnyValue::Float64(safe_div(self.payload_len_stats.bwd_payload_len.get_total(), self.subflow_stats.subflow_count as f64)));
        row.push(AnyValue::Float64(safe_div_int(self.payload_len_stats.bwd_payload_len.get_count(), self.payload_len_stats.fwd_payload_len.get_count())));

        row
    }
}
