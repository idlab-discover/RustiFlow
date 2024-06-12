use std::net::IpAddr;

use chrono::{DateTime, Utc};

/// Creates a unique identifier for a network flow.
///
/// This function generates a string identifier for a network flow based on source and destination
/// IP addresses, port numbers, and the protocol used. The identifier follows the format
/// "source_ip:source_port-destination_ip:destination_port-protocol".
///
/// ### Arguments
///
/// * `ipv4_source` - The source IP address, represented as IpAddr.
/// * `port_source` - The source port number.
/// * `ipv4_destination` - The destination IP address, represented as IpAddr.
/// * `port_destination` - The destination port number.
/// * `protocol` - The protocol used, represented as a u8.
///
/// ### Returns
///
/// A string representing the unique identifier of the network flow.
pub fn create_flow_id(
    ip_source: &IpAddr,
    port_source: u16,
    ip_destination: &IpAddr,
    port_destination: u16,
    protocol: u8,
) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        ip_source, port_source, ip_destination, port_destination, protocol
    )
}

/// Calculates the duration between two timestamps in microseconds.
///
/// ### Arguments
///
/// * `start` - The starting timestamp.
/// * `end` - The ending timestamp.
///
/// ### Returns
///
/// Duration between `start` and `end` in microseconds.
pub fn get_duration(start: DateTime<Utc>, end: DateTime<Utc>) -> f64 {
    let duration = end.signed_duration_since(start);
    duration.num_microseconds().unwrap() as f64
}

/// Calculates the new mean using the old_mean, the number of packets, and the new value.
///
/// ### Arguments
///
/// * `packet_count` - The number of packets in the flow.
/// * `old_mean` - The previous mean value.
/// * `new_value` - The new value to be added to the mean.
///
/// ### Returns
///
/// The new mean value.
pub fn calculate_mean(packet_count: u64, old_mean: f64, new_value: f64) -> f64 {
    (((packet_count - 1) as f64 * old_mean) + new_value) / packet_count as f64
}

/// Calculates the new standard deviation using the old standard deviation, the old mean, the new mean, and the new value.
///
/// ### Arguments
///
/// * `packet_count` - The number of packets in the flow.
/// * `old_std` - The previous standard deviation value.
/// * `old_mean` - The previous mean value.
/// * `new_mean` - The new mean value.
/// * `new_value` - The new value to be added to the standard deviation.
///
/// ### Returns
///
/// The new standard deviation value.
pub fn calculate_std(
    packet_count: u64,
    old_std: f64,
    old_mean: f64,
    new_mean: f64,
    new_value: f64,
) -> f64 {
    ((((packet_count - 1) as f64 * old_std.powf(2.0))
        + ((new_value - old_mean) * (new_value - new_mean)))
        / packet_count as f64)
        .sqrt()
}

pub struct BasicFeatures {
    pub fin_flag: u8,
    pub syn_flag: u8,
    pub rst_flag: u8,
    pub psh_flag: u8,
    pub ack_flag: u8,
    pub urg_flag: u8,
    pub cwe_flag: u8,
    pub ece_flag: u8,
    pub data_length: u16,
    pub header_length: u8,
    pub length: u16,
    pub window_size: u16,
}
