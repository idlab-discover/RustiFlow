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