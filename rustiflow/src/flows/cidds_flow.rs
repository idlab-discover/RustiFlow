use chrono::{DateTime, Utc};
use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{basic_flow::BasicFlow, flow::Flow};

/// Represents a CIDDS Flow, encapsulating various metrics and states of a network flow.
///
/// This struct includes detailed information about a flow.
#[derive(Clone)]
pub struct CiddsFlow {
    /// The basic flow information.
    pub basic_flow: BasicFlow,
    /// The number of bytes in the flow.
    pub(crate) bytes: u32,
}

impl CiddsFlow {
    /// Retrieves the flags feature string of the flow.
    ///
    /// Returns the flags feature string of the flow. If no flags were used
    /// the function will return ......
    ///
    /// ### Returns
    ///
    /// Returns a `String` containing the flags feature string of the flow.
    pub(crate) fn get_flags_string(&self) -> String {
        let mut flags = String::new();

        if self.basic_flow.fwd_urg_flag_count + self.basic_flow.bwd_urg_flag_count != 0 {
            flags.push('U');
        } else {
            flags.push('.');
        }
        if self.basic_flow.fwd_ack_flag_count + self.basic_flow.bwd_ack_flag_count != 0 {
            flags.push('A');
        } else {
            flags.push('.');
        }
        if self.basic_flow.fwd_psh_flag_count + self.basic_flow.bwd_psh_flag_count != 0 {
            flags.push('P');
        } else {
            flags.push('.');
        }
        if self.basic_flow.fwd_rst_flag_count + self.basic_flow.bwd_rst_flag_count != 0 {
            flags.push('R');
        } else {
            flags.push('.');
        }
        if self.basic_flow.fwd_syn_flag_count + self.basic_flow.bwd_syn_flag_count != 0 {
            flags.push('S');
        } else {
            flags.push('.');
        }
        if self.basic_flow.fwd_fin_flag_count + self.basic_flow.bwd_fin_flag_count != 0 {
            flags.push('F');
        } else {
            flags.push('.');
        }

        flags
    }
}

impl Flow for CiddsFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        ts_date: DateTime<Utc>,
    ) -> Self {
        CiddsFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                ts_date,
            ),
            bytes: 0,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        self.bytes += packet.length as u32;
        self.basic_flow.update_flow(packet, fwd)
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            self.basic_flow.first_timestamp,
            self.basic_flow
                .last_timestamp
                .signed_duration_since(self.basic_flow.first_timestamp)
                .num_milliseconds(),
            if self.basic_flow.protocol == 6 {
                "TCP"
            } else if self.basic_flow.protocol == 17 {
                "UDP"
            } else if self.basic_flow.protocol == 1 {
                "ICMP"
            } else {
                "OTHER"
            },
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count,
            self.bytes,
            self.get_flags_string(),
        )
    }

    fn get_features() -> String {
        format!(
            "FIRST_TIMESTAMP,LAST_TIMESTAMP,PROTOCOL,SOURCE_IP,SOURCE_PORT,DESTINATION_IP,\
            DESTINATION_PORT,PACKET_COUNT,BYTES,FLAGS"
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.basic_flow
                .last_timestamp
                .signed_duration_since(self.basic_flow.first_timestamp)
                .num_milliseconds(),
            if self.basic_flow.protocol == 6 {
                "TCP"
            } else if self.basic_flow.protocol == 17 {
                "UDP"
            } else if self.basic_flow.protocol == 1 {
                "ICMP"
            } else {
                "OTHER"
            },
            self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count,
            self.bytes,
            self.get_flags_string(),
        )
    }

    fn get_features_without_contamination() -> String {
        format!("DURATION,PROTOCOL,PACKET_COUNT,BYTES,FLAGS")
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
