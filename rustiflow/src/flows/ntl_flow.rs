use chrono::{DateTime, Utc};
use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{
    cic_flow::CicFlow,
    flow::Flow,
    util::{calculate_mean, calculate_std},
};

/// Represents a NTL Flow, encapsulating various metrics and states of a network flow.
///
/// This flow represents the same flow as the NTLFlowLyzer does.
#[derive(Clone)]
pub struct NTLFlow {
    /// The cic flow information.
    pub cic_flow: CicFlow,
    /// The minimum header length of the forward flow.
    pub(crate) fwd_header_len_min: u32,
    /// The maximum header length of the forward flow.
    pub(crate) fwd_header_len_max: u32,
    /// The mean packet length of the forward flow.
    pub(crate) fwd_header_len_mean: f32,
    /// The std header length of the forward flow.
    pub(crate) fwd_header_len_std: f32,
    /// The minimum header length of the backward flow.
    pub(crate) bwd_header_len_min: u32,
    /// The maximum header length of the backward flow.
    pub(crate) bwd_header_len_max: u32,
    /// The mean packet length of the backward flow.
    pub(crate) bwd_header_len_mean: f32,
    /// The std header length of the backward flow.
    pub(crate) bwd_header_len_std: f32,
}

impl NTLFlow {
    /// Updates statistics for the header length of forward packets.
    ///
    /// This method updates the maximum, minimum, total, mean, and standard deviation
    /// for the header lengths of forward packets. It's used for analyzing header size
    /// distributions in the forward direction of the flow.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length of the new packet header to be incorporated into the statistics.
    pub(crate) fn update_fwd_header_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.fwd_header_len_max {
            self.fwd_header_len_max = len;
        }
        if len < self.fwd_header_len_min {
            self.fwd_header_len_min = len;
        }

        // update total
        self.cic_flow.fwd_header_length += len;

        // update mean and std
        let new_fwd_header_len_mean = calculate_mean(
            self.cic_flow.basic_flow.fwd_packet_count as u64,
            self.fwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.fwd_header_len_std = calculate_std(
            self.cic_flow.basic_flow.fwd_packet_count as u64,
            self.fwd_header_len_std as f64,
            self.fwd_header_len_mean as f64,
            new_fwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.fwd_header_len_mean = new_fwd_header_len_mean;
    }

    /// Updates statistics for the length of forward packets.
    ///
    /// This method updates the maximum, minimum, total, mean, and standard deviation
    /// for the lengths of forward packets. It's used for analyzing packet size
    /// distributions in the forward direction of the flow.
    ///
    /// ### Arguments
    ///
    /// * `len` - The length of the new packet to be incorporated into the statistics.
    pub(crate) fn update_bwd_header_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.bwd_header_len_max {
            self.bwd_header_len_max = len;
        }
        if len < self.bwd_header_len_min {
            self.bwd_header_len_min = len;
        }

        // update total
        self.cic_flow.bwd_header_length += len;

        // update mean and std
        let new_bwd_header_len_mean = calculate_mean(
            self.cic_flow.basic_flow.bwd_packet_count as u64,
            self.bwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.bwd_header_len_std = calculate_std(
            self.cic_flow.basic_flow.bwd_packet_count as u64,
            self.bwd_header_len_std as f64,
            self.bwd_header_len_mean as f64,
            new_bwd_header_len_mean as f64,
            len as f64,
        ) as f32;
        self.bwd_header_len_mean = new_bwd_header_len_mean;
    }

    /// Retrieves the minimum packet header length for forward packets.
    ///
    /// Returns the minimum packet header length observed in the forward direction.
    /// Returns 0 if the minimum header length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum forward packet header length, or 0 if not set.
    pub fn get_fwd_header_length_min(&self) -> u32 {
        if self.fwd_header_len_min == u32::MAX {
            return 0;
        }
        self.fwd_header_len_min
    }

    /// Retrieves the minimum packet header length for backward packets.
    ///
    /// Returns the minimum packet header length observed in the backward direction.
    /// Returns 0 if the minimum header length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum backward packet header length, or 0 if not set.
    pub fn get_bwd_header_length_min(&self) -> u32 {
        if self.bwd_header_len_min == u32::MAX {
            return 0;
        }
        self.bwd_header_len_min
    }

    /// Retrieves the maximum packet header length in the flow, considering both forward and backward directions.
    ///
    /// Compares the maximum packet header lengths of forward and backward flows and returns the larger value.
    ///
    /// ### Returns
    ///
    /// Maximum packet header length in the flow.
    pub fn get_flow_header_length_max(&self) -> u32 {
        if self.fwd_header_len_max > self.bwd_header_len_max {
            return self.fwd_header_len_max;
        }
        self.bwd_header_len_max
    }

    /// Retrieves the minimum packet header length in the flow, considering both forward and backward directions.
    ///
    /// Compares the minimum packet header lengths of forward and backward flows and returns the smaller value.
    /// Returns 0 if the minimum length is not set (indicated by `u32::MAX`).
    ///
    /// ### Returns
    ///
    /// Minimum packet header length in the flow, or 0 if not set.
    pub fn get_flow_header_length_min(&self) -> u32 {
        if self.fwd_header_len_min < self.bwd_header_len_min {
            if self.fwd_header_len_min == u32::MAX {
                return 0;
            }
            self.fwd_header_len_min
        } else {
            if self.bwd_header_len_min == u32::MAX {
                return 0;
            }
            self.bwd_header_len_min
        }
    }

    /// Calculates the mean packet header length of the flow, averaging both forward and backward packet header lengths.
    ///
    /// The mean is computed by considering the header lengths and counts of packets in both directions.
    ///
    /// ### Returns
    ///
    /// Mean packet header length of the flow.
    pub fn get_flow_header_length_mean(&self) -> f32 {
        (self.fwd_header_len_mean * self.cic_flow.basic_flow.fwd_packet_count as f32
            + self.bwd_header_len_mean * self.cic_flow.basic_flow.bwd_packet_count as f32)
            as f32
            / (self.cic_flow.basic_flow.fwd_packet_count
                + self.cic_flow.basic_flow.bwd_packet_count) as f32
    }

    /// Calculates the variance of the packet lengths in the flow.
    ///
    /// Computes the variance by considering the standard deviations of packet lengths
    /// in both forward and backward directions.
    ///
    /// ### Returns
    ///
    /// Variance of the flow's packet lengths, or 0 if not enough data.
    pub fn get_flow_header_length_variance(&self) -> f64 {
        if self.cic_flow.basic_flow.fwd_packet_count < 1
            || self.cic_flow.basic_flow.bwd_packet_count < 1
            || self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count
                < 3
        {
            return 0.0;
        }

        let fwd_pkt_std_squared = self.fwd_header_len_std.powf(2.0);
        let bwd_pkt_std_squared = self.bwd_header_len_std.powf(2.0);

        ((self.cic_flow.basic_flow.fwd_packet_count - 1) as f64 * fwd_pkt_std_squared as f64
            + (self.cic_flow.basic_flow.bwd_packet_count - 1) as f64 * bwd_pkt_std_squared as f64)
            / (self.cic_flow.basic_flow.fwd_packet_count
                + self.cic_flow.basic_flow.bwd_packet_count
                - 2) as f64
    }

    /// Retrieves the standard deviation of packet lengths in the flow.
    ///
    /// Utilizes the calculated variance of packet lengths to compute the standard deviation.
    ///
    /// ### Returns
    ///
    /// Standard deviation of the flow's packet lengths.
    pub fn get_flow_header_length_std(&self) -> f64 {
        self.get_flow_header_length_variance().sqrt()
    }
}

impl Flow for NTLFlow {
    fn new(
        flow_id: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp: DateTime<Utc>,
    ) -> Self {
        NTLFlow {
            cic_flow: CicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp,
            ),
            fwd_header_len_min: u32::MAX,
            fwd_header_len_max: 0,
            fwd_header_len_mean: 0.0,
            fwd_header_len_std: 0.0,
            bwd_header_len_min: u32::MAX,
            bwd_header_len_max: 0,
            bwd_header_len_mean: 0.0,
            bwd_header_len_std: 0.0,
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        let is_terminated = self.cic_flow.update_flow(packet, fwd);
        if fwd {
            self.update_fwd_header_len_stats(packet.header_length as u32);
        } else {
            self.update_bwd_header_len_stats(packet.header_length as u32);
        }
        is_terminated
    }

    fn dump(&self) -> String {
        let flow_duration =
            self.cic_flow.basic_flow.last_timestamp - self.cic_flow.basic_flow.first_timestamp;
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.cic_flow.basic_flow.flow_key,
            self.cic_flow.basic_flow.ip_source,
            self.cic_flow.basic_flow.port_source,
            self.cic_flow.basic_flow.ip_destination,
            self.cic_flow.basic_flow.port_destination,
            self.cic_flow.basic_flow.protocol,
            flow_duration.num_microseconds().unwrap(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.fwd_pkt_len_tot,
            self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.get_flow_packet_length_max(),
            self.cic_flow.get_flow_packet_length_min(),
            self.cic_flow.get_flow_packet_length_mean(),
            self.cic_flow.get_flow_packet_length_std(),
            self.cic_flow.get_flow_packet_length_variance(),
            self.cic_flow.fwd_pkt_len_max,
            self.cic_flow.get_fwd_packet_length_min(),
            self.cic_flow.fwd_pkt_len_mean,
            self.cic_flow.fwd_pkt_len_std,
            self.cic_flow.fwd_pkt_len_std.powf(2.0),
            self.cic_flow.bwd_pkt_len_max,
            self.cic_flow.get_bwd_packet_length_min(),
            self.cic_flow.bwd_pkt_len_mean,
            self.cic_flow.bwd_pkt_len_std,
            self.cic_flow.bwd_pkt_len_std.powf(2.0),
            self.cic_flow.fwd_header_length + self.cic_flow.bwd_header_length,
            self.get_flow_header_length_max(),
            self.get_flow_header_length_min(),
            self.get_flow_header_length_mean(),
            self.get_flow_header_length_std(),
            self.cic_flow.fwd_header_length,
            self.fwd_header_len_max,
            self.get_fwd_header_length_min(),
            self.fwd_header_len_mean,
            self.fwd_header_len_std,
            self.cic_flow.bwd_header_length,
            self.bwd_header_len_max,
            self.get_bwd_header_length_min(),
            self.bwd_header_len_mean,
            self.bwd_header_len_std,
            self.cic_flow.get_fwd_segment_length_mean(),
            self.cic_flow.get_bwd_segment_length_mean(),
            self.cic_flow.get_flow_segment_length_mean(),
            self.cic_flow.fwd_init_win_bytes,
            self.cic_flow.bwd_init_win_bytes,
            self.cic_flow.get_active_min(),
            self.cic_flow.active_max,
            self.cic_flow.active_mean,
            self.cic_flow.active_std,
            self.cic_flow.get_idle_min(),
            self.cic_flow.idle_max,
            self.cic_flow.idle_mean,
            self.cic_flow.idle_std,
            (self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot) as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.fwd_pkt_len_tot as f64 / flow_duration.num_milliseconds() as f64 / 1000.0,
            self.cic_flow.bwd_pkt_len_tot as f64 / flow_duration.num_milliseconds() as f64 / 1000.0,
            (self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count)
                as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.basic_flow.bwd_packet_count as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.basic_flow.fwd_packet_count as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.get_down_up_ratio(),
            self.cic_flow.get_fwd_bytes_bulk(),
            self.cic_flow.get_fwd_packets_bulk(),
            self.cic_flow.get_fwd_bulk_rate(),
            self.cic_flow.get_bwd_bytes_bulk(),
            self.cic_flow.get_bwd_packets_bulk(),
            self.cic_flow.get_bwd_bulk_rate(),
            self.cic_flow.fwd_bulk_state_count,
            self.cic_flow.fwd_bulk_size_total,
            self.cic_flow.fwd_bulk_packet_count,
            self.cic_flow.fwd_bulk_duration,
            self.cic_flow.bwd_bulk_state_count,
            self.cic_flow.bwd_bulk_size_total,
            self.cic_flow.bwd_bulk_packet_count,
            self.cic_flow.bwd_bulk_duration,
            self.cic_flow.basic_flow.fwd_fin_flag_count
                + self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count
                + self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count
                + self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count
                + self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count
                + self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count
                + self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count
                + self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count
                + self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count,
            self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.get_flow_iat_mean(),
            self.cic_flow.get_flow_iat_std(),
            self.cic_flow.get_flow_iat_max(),
            self.cic_flow.get_flow_iat_min(),
            self.cic_flow.fwd_iat_total + self.cic_flow.bwd_iat_total,
            self.cic_flow.fwd_iat_mean,
            self.cic_flow.fwd_iat_std,
            self.cic_flow.fwd_iat_max,
            self.cic_flow.get_fwd_iat_min(),
            self.cic_flow.fwd_iat_total,
            self.cic_flow.fwd_iat_total,
            self.cic_flow.bwd_iat_mean,
            self.cic_flow.bwd_iat_std,
            self.cic_flow.bwd_iat_max,
            self.cic_flow.get_bwd_iat_min(),
            self.cic_flow.bwd_iat_total,
            self.cic_flow.get_sf_fwd_packets(),
            self.cic_flow.get_sf_bwd_packets(),
            self.cic_flow.get_sf_fwd_bytes(),
            self.cic_flow.get_sf_bwd_bytes(),
        )
    }

    fn get_features() -> String {
        format!(
            "FLOW_ID,IP_SOURCE,PORT_SOURCE,IP_DESTINATION,PORT_DESTINATION,PROTOCOL,\
            DURATION,TOTAL_PACKETS,FWD_PACKETS,BWD_PACKETS,TOTAL_BYTES,FWD_BYTES,BWD_BYTES,\
            PACKET_LENGTH_MAX,PACKET_LENGTH_MIN,PACKET_LENGTH_MEAN,PACKET_LENGTH_STD,\
            PACKET_LENGTH_VARIANCE,FWD_PACKET_LENGTH_MAX,FWD_PACKET_LENGTH_MIN,\
            FWD_PACKET_LENGTH_MEAN,FWD_PACKET_LENGTH_STD,FWD_PACKET_LENGTH_VARIANCE,\
            BWD_PACKET_LENGTH_MAX,BWD_PACKET_LENGTH_MIN,BWD_PACKET_LENGTH_MEAN,\
            BWD_PACKET_LENGTH_STD,BWD_PACKET_LENGTH_VARIANCE,HEADER_LENGTH_TOTAL,\
            HEADER_LENGTH_MAX,HEADER_LENGTH_MIN,HEADER_LENGTH_MEAN,HEADER_LENGTH_STD,\
            FWD_HEADER_LENGTH_TOTAL,FWD_HEADER_LENGTH_MAX,FWD_HEADER_LENGTH_MIN,\
            FWD_HEADER_LENGTH_MEAN,FWD_HEADER_LENGTH_STD,BWD_HEADER_LENGTH_TOTAL,\
            BWD_HEADER_LENGTH_MAX,BWD_HEADER_LENGTH_MIN,BWD_HEADER_LENGTH_MEAN,\
            BWD_HEADER_LENGTH_STD,FWD_SEGMENT_LENGTH_MEAN,BWD_SEGMENT_LENGTH_MEAN,\
            FLOW_SEGMENT_LENGTH_MEAN,FWD_INIT_WIN_BYTES,BWD_INIT_WIN_BYTES,ACTIVE_MIN,\
            ACTIVE_MAX,ACTIVE_MEAN,ACTIVE_STD,IDLE_MIN,IDLE_MAX,IDLE_MEAN,IDLE_STD,\
            BYTES_RATE,FWD_BYTES_RATE,BWD_BYTES_RATE,\
            PACKETS_RATE,FWD_PACKETS_RATE,BWD_PACKETS_RATE,\
            DOWN_UP_RATIO,FWD_BYTES_BULK,FWD_PACKETS_BULK,FWD_BULK_RATE,\
            BWD_BYTES_BULK,BWD_PACKETS_BULK,BWD_BULK_RATE,FWD_BULK_STATE_COUNT,\
            FWD_BULK_SIZE_TOTAL,FWD_BULK_PACKET_COUNT,FWD_BULK_DURATION,BWD_BULK_STATE_COUNT,\
            BWD_BULK_SIZE_TOTAL,BWD_BULK_PACKET_COUNT,BWD_BULK_DURATION,FLOW_FIN_COUNT,\
            FLOW_PSH_COUNT,FLOW_URG_COUNT,FLOW_ECE_COUNT,FLOW_SYN_COUNT,FLOW_ACK_COUNT,\
            FLOW_CWE_COUNT,FLOW_RST_COUNT,FWD_FIN_COUNT,FWD_PSH_COUNT,FWD_URG_COUNT,\
            FWD_ECE_COUNT,FWD_SYN_COUNT,FWD_ACK_COUNT,FWD_CWE_COUNT,FWD_RST_COUNT,\
            BWD_FIN_COUNT,BWD_PSH_COUNT,BWD_URG_COUNT,BWD_ECE_COUNT,BWD_SYN_COUNT,\
            BWD_ACK_COUNT,BWD_CWE_COUNT,BWD_RST_COUNT,FLOW_IAT_MEAN,FLOW_IAT_STD,\
            FLOW_IAT_MAX,FLOW_IAT_MIN,FLOW_IAT_SUM,FWD_IAT_MEAN,\
            FWD_IAT_STD,FWD_IAT_MAX,FWD_IAT_MIN,FWD_IAT_SUM,BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,\
            BWD_IAT_MIN,BWD_IAT_SUM,SF_FWD_PACKETS,SF_BWD_PACKETS,SF_FWD_BYTES,SF_BWD_BYTES"
        )
    }

    fn dump_without_contamination(&self) -> String {
        let flow_duration =
            self.cic_flow.basic_flow.last_timestamp - self.cic_flow.basic_flow.first_timestamp;
        // Can be further updated after more research
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{}",
            flow_duration.num_microseconds().unwrap(),
            self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.basic_flow.fwd_packet_count,
            self.cic_flow.basic_flow.bwd_packet_count,
            self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.fwd_pkt_len_tot,
            self.cic_flow.bwd_pkt_len_tot,
            self.cic_flow.get_flow_packet_length_max(),
            self.cic_flow.get_flow_packet_length_min(),
            self.cic_flow.get_flow_packet_length_mean(),
            self.cic_flow.get_flow_packet_length_std(),
            self.cic_flow.get_flow_packet_length_variance(),
            self.cic_flow.fwd_pkt_len_max,
            self.cic_flow.get_fwd_packet_length_min(),
            self.cic_flow.fwd_pkt_len_mean,
            self.cic_flow.fwd_pkt_len_std,
            self.cic_flow.fwd_pkt_len_std.powf(2.0),
            self.cic_flow.bwd_pkt_len_max,
            self.cic_flow.get_bwd_packet_length_min(),
            self.cic_flow.bwd_pkt_len_mean,
            self.cic_flow.bwd_pkt_len_std,
            self.cic_flow.bwd_pkt_len_std.powf(2.0),
            self.cic_flow.fwd_header_length + self.cic_flow.bwd_header_length,
            self.get_flow_header_length_max(),
            self.get_flow_header_length_min(),
            self.get_flow_header_length_mean(),
            self.get_flow_header_length_std(),
            self.cic_flow.fwd_header_length,
            self.fwd_header_len_max,
            self.get_fwd_header_length_min(),
            self.fwd_header_len_mean,
            self.fwd_header_len_std,
            self.cic_flow.bwd_header_length,
            self.bwd_header_len_max,
            self.get_bwd_header_length_min(),
            self.bwd_header_len_mean,
            self.bwd_header_len_std,
            self.cic_flow.get_fwd_segment_length_mean(),
            self.cic_flow.get_bwd_segment_length_mean(),
            self.cic_flow.get_flow_segment_length_mean(),
            self.cic_flow.fwd_init_win_bytes,
            self.cic_flow.bwd_init_win_bytes,
            self.cic_flow.get_active_min(),
            self.cic_flow.active_max,
            self.cic_flow.active_mean,
            self.cic_flow.active_std,
            self.cic_flow.get_idle_min(),
            self.cic_flow.idle_max,
            self.cic_flow.idle_mean,
            self.cic_flow.idle_std,
            (self.cic_flow.fwd_pkt_len_tot + self.cic_flow.bwd_pkt_len_tot) as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.fwd_pkt_len_tot as f64 / flow_duration.num_milliseconds() as f64 / 1000.0,
            self.cic_flow.bwd_pkt_len_tot as f64 / flow_duration.num_milliseconds() as f64 / 1000.0,
            (self.cic_flow.basic_flow.fwd_packet_count + self.cic_flow.basic_flow.bwd_packet_count)
                as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.basic_flow.bwd_packet_count as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.basic_flow.fwd_packet_count as f64
                / flow_duration.num_milliseconds() as f64
                / 1000.0,
            self.cic_flow.get_down_up_ratio(),
            self.cic_flow.get_fwd_bytes_bulk(),
            self.cic_flow.get_fwd_packets_bulk(),
            self.cic_flow.get_fwd_bulk_rate(),
            self.cic_flow.get_bwd_bytes_bulk(),
            self.cic_flow.get_bwd_packets_bulk(),
            self.cic_flow.get_bwd_bulk_rate(),
            self.cic_flow.fwd_bulk_state_count,
            self.cic_flow.fwd_bulk_size_total,
            self.cic_flow.fwd_bulk_packet_count,
            self.cic_flow.fwd_bulk_duration,
            self.cic_flow.bwd_bulk_state_count,
            self.cic_flow.bwd_bulk_size_total,
            self.cic_flow.bwd_bulk_packet_count,
            self.cic_flow.bwd_bulk_duration,
            self.cic_flow.basic_flow.fwd_fin_flag_count
                + self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count
                + self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count
                + self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count
                + self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count
                + self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count
                + self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count
                + self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count
                + self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.basic_flow.fwd_fin_flag_count,
            self.cic_flow.basic_flow.fwd_psh_flag_count,
            self.cic_flow.basic_flow.fwd_urg_flag_count,
            self.cic_flow.basic_flow.fwd_ece_flag_count,
            self.cic_flow.basic_flow.fwd_syn_flag_count,
            self.cic_flow.basic_flow.fwd_ack_flag_count,
            self.cic_flow.basic_flow.fwd_cwe_flag_count,
            self.cic_flow.basic_flow.fwd_rst_flag_count,
            self.cic_flow.basic_flow.bwd_fin_flag_count,
            self.cic_flow.basic_flow.bwd_psh_flag_count,
            self.cic_flow.basic_flow.bwd_urg_flag_count,
            self.cic_flow.basic_flow.bwd_ece_flag_count,
            self.cic_flow.basic_flow.bwd_syn_flag_count,
            self.cic_flow.basic_flow.bwd_ack_flag_count,
            self.cic_flow.basic_flow.bwd_cwe_flag_count,
            self.cic_flow.basic_flow.bwd_rst_flag_count,
            self.cic_flow.get_flow_iat_mean(),
            self.cic_flow.get_flow_iat_std(),
            self.cic_flow.get_flow_iat_max(),
            self.cic_flow.get_flow_iat_min(),
            self.cic_flow.fwd_iat_total + self.cic_flow.bwd_iat_total,
            self.cic_flow.fwd_iat_mean,
            self.cic_flow.fwd_iat_std,
            self.cic_flow.fwd_iat_max,
            self.cic_flow.get_fwd_iat_min(),
            self.cic_flow.fwd_iat_total,
            self.cic_flow.bwd_iat_mean,
            self.cic_flow.bwd_iat_std,
            self.cic_flow.bwd_iat_max,
            self.cic_flow.get_bwd_iat_min(),
            self.cic_flow.bwd_iat_total,
            self.cic_flow.get_sf_fwd_packets(),
            self.cic_flow.get_sf_bwd_packets(),
            self.cic_flow.get_sf_fwd_bytes(),
            self.cic_flow.get_sf_bwd_bytes(),
        )
    }

    fn get_features_without_contamination() -> String {
        format!(
            "DURATION,TOTAL_PACKETS,FWD_PACKETS,BWD_PACKETS,TOTAL_BYTES,FWD_BYTES,BWD_BYTES,\
            PACKET_LENGTH_MAX,PACKET_LENGTH_MIN,PACKET_LENGTH_MEAN,PACKET_LENGTH_STD,\
            PACKET_LENGTH_VARIANCE,FWD_PACKET_LENGTH_MAX,FWD_PACKET_LENGTH_MIN,\
            FWD_PACKET_LENGTH_MEAN,FWD_PACKET_LENGTH_STD,FWD_PACKET_LENGTH_VARIANCE,\
            BWD_PACKET_LENGTH_MAX,BWD_PACKET_LENGTH_MIN,BWD_PACKET_LENGTH_MEAN,\
            BWD_PACKET_LENGTH_STD,BWD_PACKET_LENGTH_VARIANCE,HEADER_LENGTH_TOTAL,\
            HEADER_LENGTH_MAX,HEADER_LENGTH_MIN,HEADER_LENGTH_MEAN,HEADER_LENGTH_STD,\
            FWD_HEADER_LENGTH_TOTAL,FWD_HEADER_LENGTH_MAX,FWD_HEADER_LENGTH_MIN,\
            FWD_HEADER_LENGTH_MEAN,FWD_HEADER_LENGTH_STD,BWD_HEADER_LENGTH_TOTAL,\
            BWD_HEADER_LENGTH_MAX,BWD_HEADER_LENGTH_MIN,BWD_HEADER_LENGTH_MEAN,\
            BWD_HEADER_LENGTH_STD,FWD_SEGMENT_LENGTH_MEAN,BWD_SEGMENT_LENGTH_MEAN,\
            FLOW_SEGMENT_LENGTH_MEAN,FWD_INIT_WIN_BYTES,BWD_INIT_WIN_BYTES,ACTIVE_MIN,\
            ACTIVE_MAX,ACTIVE_MEAN,ACTIVE_STD,IDLE_MIN,IDLE_MAX,IDLE_MEAN,IDLE_STD,\
            BYTES_RATE,FWD_BYTES_RATE,BWD_BYTES_RATE,PACKETS_RATE,FWD_PACKETS_RATE,\
            BWD_PACKETS_RATE,DOWN_UP_RATIO,FWD_BYTES_BULK,FWD_PACKETS_BULK,FWD_BULK_RATE,\
            BWD_BYTES_BULK,BWD_PACKETS_BULK,BWD_BULK_RATE,FWD_BULK_STATE_COUNT,\
            FWD_BULK_SIZE_TOTAL,FWD_BULK_PACKET_COUNT,FWD_BULK_DURATION,BWD_BULK_STATE_COUNT,\
            BWD_BULK_SIZE_TOTAL,BWD_BULK_PACKET_COUNT,BWD_BULK_DURATION,FLOW_FIN_COUNT,\
            FLOW_PSH_COUNT,FLOW_URG_COUNT,FLOW_ECE_COUNT,FLOW_SYN_COUNT,FLOW_ACK_COUNT,\
            FLOW_CWE_COUNT,FLOW_RST_COUNT,FWD_FIN_COUNT,FWD_PSH_COUNT,FWD_URG_COUNT,\
            FWD_ECE_COUNT,FWD_SYN_COUNT,FWD_ACK_COUNT,FWD_CWE_COUNT,FWD_RST_COUNT,\
            BWD_FIN_COUNT,BWD_PSH_COUNT,BWD_URG_COUNT,BWD_ECE_COUNT,BWD_SYN_COUNT,\
            BWD_ACK_COUNT,BWD_CWE_COUNT,BWD_RST_COUNT,FLOW_IAT_MEAN,FLOW_IAT_STD,\
            FLOW_IAT_MAX,FLOW_IAT_MIN,FLOW_IAT_SUM,FWD_IAT_MEAN,\
            FWD_IAT_STD,FWD_IAT_MAX,FWD_IAT_MIN,FWD_IAT_SUM,BWD_IAT_MEAN,BWD_IAT_STD,BWD_IAT_MAX,\
            BWD_IAT_MIN,BWD_IAT_SUM,SF_FWD_PACKETS,SF_BWD_PACKETS,SF_FWD_BYTES,SF_BWD_BYTES"
        )
    }

    fn get_first_timestamp(&self) -> DateTime<Utc> {
        self.cic_flow.get_first_timestamp()
    }

    fn is_expired(&self, timestamp: DateTime<Utc>, active_timeout: u64, idle_timeout: u64) -> bool {
        self.cic_flow
            .is_expired(timestamp, active_timeout, idle_timeout)
    }

    fn flow_key(&self) -> &String {
        &self.cic_flow.basic_flow.flow_key
    }
}
