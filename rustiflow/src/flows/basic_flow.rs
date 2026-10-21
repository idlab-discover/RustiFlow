use std::net::IpAddr;
use std::{fmt::Display, fmt::Write as _};

use chrono::{DateTime, Utc};
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::{
    flows::util::{
        classify_ip_scope, classify_path_locality, iana_port_mapping, IpScope, PathLocality,
    },
    packet_features::PacketFeatures,
};

use super::{flow::Flow, util::FlowExpireCause};

#[derive(Clone, PartialEq, Debug)]
pub(crate) enum FlowState {
    Established,
    FinSent,
    FinAcked,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TcpCloseStyle {
    NotApplicable,
    None,
    HalfClose,
    BidirectionalFin,
    FourWayFin,
    SimultaneousFin,
    Reset,
}

impl TcpCloseStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::None => "none",
            Self::HalfClose => "half_close",
            Self::BidirectionalFin => "bidirectional_fin",
            Self::FourWayFin => "four_way_fin",
            Self::SimultaneousFin => "simultaneous_fin",
            Self::Reset => "reset",
        }
    }
}

/// A basic flow that stores the basic features of a flow.
#[derive(Clone)]
pub struct BasicFlow {
    /// The unique identifier of the flow.
    pub flow_key: String,
    /// The destination IP address of the flow.
    pub ip_destination: IpAddr,
    /// The source IP address of the flow.
    pub ip_source: IpAddr,
    /// The destination port of the flow.
    pub port_destination: u16,
    /// The source port of the flow.
    pub port_source: u16,
    /// The protocol of the flow.
    pub protocol: u8,
    /// The first timestamp of the flow.
    pub first_timestamp_us: i64, // Microseconds since epoch
    /// The last timestamp of the flow.
    pub last_timestamp_us: i64,
    /// The reason this flow expired
    pub flow_expire_cause: FlowExpireCause,

    // Tracking TCP Flow Termination
    pub(crate) state_fwd: FlowState,
    pub(crate) state_bwd: FlowState,
    expected_ack_seq_fwd: Option<u32>,
    expected_ack_seq_bwd: Option<u32>,
    saw_syn_fwd: bool,
    saw_syn_ack_bwd: bool,
    expected_handshake_ack_seq_fwd: Option<u32>,
    pub tcp_handshake_completed: bool,
    pub tcp_reset_before_handshake: bool,
    pub tcp_reset_after_handshake: bool,
    pub tcp_close_style: TcpCloseStyle,
    saw_fin_fwd: bool,
    saw_fin_bwd: bool,
    highest_ack_fwd: Option<u32>,
    highest_ack_bwd: Option<u32>,
    fin_ack_fwd: Option<u32>,
    fin_ack_bwd: Option<u32>,
    handshake_ack_fwd: Option<u32>,
}

impl BasicFlow {
    fn is_tcp(&self) -> bool {
        self.protocol == IpNextHeaderProtocols::Tcp.0
    }

    fn observe_tcp_handshake(&mut self, packet: &PacketFeatures, forward: bool) {
        if !self.is_tcp() || self.tcp_handshake_completed {
            return;
        }

        if forward && packet.syn_flag > 0 && packet.ack_flag == 0 {
            self.saw_syn_fwd = true;
        }
        if !forward && packet.syn_flag > 0 && packet.ack_flag > 0 {
            self.saw_syn_ack_bwd = true;
            self.expected_handshake_ack_seq_fwd = Some(packet.sequence_number.wrapping_add(1));
        }
        if forward && packet.ack_flag > 0 && packet.syn_flag == 0 {
            self.handshake_ack_fwd = Some(packet.sequence_number_ack);
        }
        self.tcp_handshake_completed = self.saw_syn_fwd
            && self.saw_syn_ack_bwd
            && acknowledges(self.handshake_ack_fwd, self.expected_handshake_ack_seq_fwd);
    }

    fn update_tcp_close_style(&mut self, cause: FlowExpireCause) {
        self.tcp_close_style = if !self.is_tcp() {
            TcpCloseStyle::NotApplicable
        } else if cause == FlowExpireCause::TcpReset {
            TcpCloseStyle::Reset
        } else if self.saw_fin_fwd && self.saw_fin_bwd {
            if self.state_fwd == FlowState::FinAcked && self.state_bwd == FlowState::FinAcked {
                if self.fin_ack_fwd.is_some()
                    && self.fin_ack_bwd.is_some()
                    && !acknowledges(self.fin_ack_fwd, self.expected_ack_seq_fwd)
                    && !acknowledges(self.fin_ack_bwd, self.expected_ack_seq_bwd)
                {
                    TcpCloseStyle::SimultaneousFin
                } else {
                    TcpCloseStyle::FourWayFin
                }
            } else {
                TcpCloseStyle::BidirectionalFin
            }
        } else if self.saw_fin_fwd || self.saw_fin_bwd {
            TcpCloseStyle::HalfClose
        } else {
            TcpCloseStyle::None
        };
    }

    /// Checks if the flow is finished.
    ///
    /// A flow is considered finished when both FIN flags are set and the last ACK is received,
    /// and the sequence numbers have been acknowledged by both parties.
    ///
    /// ### Arguments
    ///
    /// * `packet` - The packet to be checked.
    ///
    /// ### Returns
    ///
    /// A boolean indicating if the flow is finished.
    pub fn is_tcp_finished(&mut self, packet: &PacketFeatures, forward: bool) -> bool {
        if !self.is_tcp() {
            return false;
        }
        if packet.ack_flag > 0 {
            let highest = if forward {
                &mut self.highest_ack_fwd
            } else {
                &mut self.highest_ack_bwd
            };
            if highest.is_none() || acknowledges(Some(packet.sequence_number_ack), *highest) {
                *highest = Some(packet.sequence_number_ack);
            }
        }
        if packet.fin_flag > 0 {
            let expected = packet
                .sequence_number
                .wrapping_add(u32::from(packet.data_length))
                .wrapping_add(1);
            if forward {
                self.saw_fin_fwd = true;
                self.expected_ack_seq_bwd.get_or_insert(expected);
                if packet.ack_flag > 0 {
                    self.fin_ack_fwd.get_or_insert(packet.sequence_number_ack);
                }
            } else {
                self.saw_fin_bwd = true;
                self.expected_ack_seq_fwd.get_or_insert(expected);
                if packet.ack_flag > 0 {
                    self.fin_ack_bwd.get_or_insert(packet.sequence_number_ack);
                }
            }
        }
        // Re-evaluate both directions: the ACK may have arrived before its FIN.
        if self.saw_fin_fwd {
            self.state_fwd = if acknowledges(self.highest_ack_bwd, self.expected_ack_seq_bwd) {
                FlowState::FinAcked
            } else {
                FlowState::FinSent
            };
        }
        if self.saw_fin_bwd {
            self.state_bwd = if acknowledges(self.highest_ack_fwd, self.expected_ack_seq_fwd) {
                FlowState::FinAcked
            } else {
                FlowState::FinSent
            };
        }
        self.state_fwd == FlowState::FinAcked && self.state_bwd == FlowState::FinAcked
    }

    /// Calculates the flow duration in microseconds.
    ///
    /// Returns the difference between the last and first packet timestamps in microseconds.
    ///
    /// ### Returns
    ///
    /// The duration of the flow in microseconds.
    pub fn get_flow_duration_usec(&self) -> i64 {
        self.last_timestamp_us - self.first_timestamp_us
    }

    /// Calculates the flow duration in milliseconds.
    ///
    /// Returns the difference between the last and first packet timestamps in milliseconds.
    ///
    /// ### Returns
    ///
    /// The duration of the flow in milliseconds.
    pub fn get_flow_duration_msec(&self) -> i64 {
        (self.last_timestamp_us - self.first_timestamp_us) / 1_000
    }

    pub fn get_last_timestamp(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_micros(self.last_timestamp_us).unwrap()
    }

    pub fn get_first_timestamp(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_micros(self.first_timestamp_us).unwrap()
    }

    pub fn get_ip_version(&self) -> u8 {
        match self.ip_source {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }

    pub fn get_source_ip_scope(&self) -> IpScope {
        classify_ip_scope(self.ip_source)
    }

    pub fn get_destination_ip_scope(&self) -> IpScope {
        classify_ip_scope(self.ip_destination)
    }

    pub fn get_path_locality(&self) -> PathLocality {
        classify_path_locality(self.ip_source, self.ip_destination)
    }
}

// TCP serial comparisons are defined within half the 32-bit sequence space.
fn acknowledges(ack: Option<u32>, expected: Option<u32>) -> bool {
    ack.zip(expected)
        .is_some_and(|(ack, expected)| (ack.wrapping_sub(expected) as i32) >= 0)
}

fn push_csv_display(output: &mut String, value: impl Display) {
    if !output.is_empty() {
        output.push(',');
    }
    let _ = write!(output, "{value}");
}

impl Flow for BasicFlow {
    fn new(
        flow_id: String,
        ip_source: IpAddr,
        port_source: u16,
        ip_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        first_timestamp_us: i64,
    ) -> Self {
        BasicFlow {
            flow_key: flow_id,
            ip_destination,
            ip_source,
            port_destination,
            port_source,
            protocol,
            first_timestamp_us,
            last_timestamp_us: first_timestamp_us,
            flow_expire_cause: FlowExpireCause::None,
            state_fwd: FlowState::Established,
            state_bwd: FlowState::Established,
            expected_ack_seq_fwd: None,
            expected_ack_seq_bwd: None,
            saw_syn_fwd: false,
            saw_syn_ack_bwd: false,
            expected_handshake_ack_seq_fwd: None,
            tcp_handshake_completed: false,
            tcp_reset_before_handshake: false,
            tcp_reset_after_handshake: false,
            tcp_close_style: TcpCloseStyle::None,
            saw_fin_fwd: false,
            saw_fin_bwd: false,
            highest_ack_fwd: None,
            highest_ack_bwd: None,
            fin_ack_fwd: None,
            fin_ack_bwd: None,
            handshake_ack_fwd: None,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        self.first_timestamp_us = self.first_timestamp_us.min(packet.timestamp_us);
        self.last_timestamp_us = self.last_timestamp_us.max(packet.timestamp_us);
        self.observe_tcp_handshake(packet, fwd);

        if self.is_tcp_finished(packet, fwd) {
            self.flow_expire_cause = FlowExpireCause::TcpTermination;
            self.update_tcp_close_style(self.flow_expire_cause);
            return true;
        }

        if self.is_tcp() && packet.rst_flag > 0 {
            if self.tcp_handshake_completed {
                self.tcp_reset_after_handshake = true;
            } else {
                self.tcp_reset_before_handshake = true;
            }
            self.flow_expire_cause = FlowExpireCause::TcpReset;
            self.update_tcp_close_style(self.flow_expire_cause);
            return true;
        }

        false
    }

    fn close_flow(&mut self, _timestamp_us: i64, cause: FlowExpireCause) {
        self.flow_expire_cause = cause;
        self.update_tcp_close_style(cause);
    }

    fn append_to_csv_row(&self, output: &mut String) {
        push_csv_display(output, &self.flow_key);
        push_csv_display(output, self.ip_source);
        push_csv_display(output, self.port_source);
        push_csv_display(output, self.ip_destination);
        push_csv_display(output, self.port_destination);
        push_csv_display(output, self.protocol);
        push_csv_display(output, self.get_first_timestamp());
        push_csv_display(output, self.get_last_timestamp());
        push_csv_display(output, self.get_flow_duration_usec());
        push_csv_display(output, self.flow_expire_cause.as_str());
    }

    fn get_features() -> String {
        "flow_id,source_ip,source_port,destination_ip,destination_port,protocol,\
            first_timestamp,last_timestamp,duration,flow_expire_cause"
            .to_string()
    }

    fn append_to_csv_row_without_contamination(&self, output: &mut String) {
        push_csv_display(output, iana_port_mapping(self.port_source));
        push_csv_display(output, iana_port_mapping(self.port_destination));
        push_csv_display(output, self.protocol);
        push_csv_display(output, self.get_flow_duration_usec());
        push_csv_display(output, self.flow_expire_cause.as_str());
    }

    fn get_features_without_contamination() -> String {
        "src_port_iana,dst_port_iana,protocol,duration,flow_expire_cause".to_string()
    }

    fn get_first_timestamp_us(&self) -> i64 {
        self.first_timestamp_us
    }

    fn is_expired(
        &self,
        timestamp_us: i64,
        active_timeout: u64,
        idle_timeout: u64,
    ) -> (bool, FlowExpireCause) {
        if self.flow_expire_cause != FlowExpireCause::None {
            return (true, self.flow_expire_cause);
        }

        if (timestamp_us.saturating_sub(self.first_timestamp_us).max(0) / 1_000_000) as u64
            > active_timeout
        {
            return (true, FlowExpireCause::ActiveTimeout);
        }

        if (timestamp_us.saturating_sub(self.last_timestamp_us).max(0) / 1_000_000) as u64
            > idle_timeout
        {
            return (true, FlowExpireCause::IdleTimeout);
        }

        (false, FlowExpireCause::None)
    }
}
