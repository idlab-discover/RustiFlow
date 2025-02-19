use std::net::IpAddr;

use crate::flows::util::iana_port_mapping;
use crate::packet_features::PacketFeatures;

use super::features::util::FlowFeature;
use super::util::FlowExpireCause;
use super::{basic_flow::BasicFlow, flow::Flow};

use super::features::packet_stats::PacketLengthStats;
use super::features::tcp_flag_stats::TcpFlagStats;

/// Represents a CIDDS Flow as exported by the like-named academic network traffic dataset.
#[derive(Clone)]
pub struct CiddsFlow {
    pub basic_flow: BasicFlow,
    pub tcp_flag_stats: TcpFlagStats,
    pub packet_stats: PacketLengthStats,
}

impl Flow for CiddsFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self {
        CiddsFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp_us,
            ),
            tcp_flag_stats: TcpFlagStats::new(),
            packet_stats: PacketLengthStats::new(),
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, is_fwd: bool) -> bool {
        let last_timestamp_us = self.basic_flow.last_timestamp_us;
        let is_terminated: bool = self.basic_flow.update_flow(packet, is_fwd);

        self.tcp_flag_stats
            .update(packet, is_fwd, last_timestamp_us);
        self.packet_stats.update(packet, is_fwd, last_timestamp_us);

        is_terminated
    }

    fn close_flow(&mut self, timestamp_us: i64, cause: FlowExpireCause) {
        self.basic_flow.close_flow(timestamp_us, cause);

        self.tcp_flag_stats.close(timestamp_us, cause);
        self.packet_stats.close(timestamp_us, cause);
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            if self.basic_flow.protocol == 6 {
                "TCP"
            } else if self.basic_flow.protocol == 17 {
                "UDP"
            } else if self.basic_flow.protocol == 1 {
                "ICMP"
            } else {
                "OTHER"
            },
            self.basic_flow.get_first_timestamp(),
            self.basic_flow.get_flow_duration_msec(),
            self.packet_stats.flow_total(),
            self.packet_stats.flow_count(),
            self.tcp_flag_stats.get_flags(),
        )
    }

    fn get_features() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            "Src IP",
            "Src Port",
            "Dst IP",
            "Dst Port",
            "Proto",
            "Date first seen",
            "Duration",
            "Bytes",
            "Packets",
            "Flags"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            if self.basic_flow.protocol == 6 {
                "TCP"
            } else if self.basic_flow.protocol == 17 {
                "UDP"
            } else if self.basic_flow.protocol == 1 {
                "ICMP"
            } else {
                "OTHER"
            },
            iana_port_mapping(self.basic_flow.port_source),
            iana_port_mapping(self.basic_flow.port_destination),
            self.basic_flow.get_flow_duration_msec(),
            self.packet_stats.flow_total(),
            self.packet_stats.flow_count(),
            self.tcp_flag_stats.get_flags(),
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "{},{},{},{},{},{},{}",
            "Src Port (IANA)", "Dst Port (IANA)", "Proto", "Duration", "Bytes", "Packets", "Flags"
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
