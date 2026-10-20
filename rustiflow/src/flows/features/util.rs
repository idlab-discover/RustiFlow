use std::{fmt::Display, fmt::Write as _};

use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

/// Trait for network flow features that can be updated, closed, and dumped to CSV format
pub trait FlowFeature: Send + Sync + Clone {
    /// Updates the feature with a new packet
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, last_timestamp: i64);

    /// Finalizes any active state when the flow is terminated
    fn close(&mut self, last_timestamp: i64, cause: FlowExpireCause);

    /// Appends the current state as CSV fields to an existing row buffer.
    fn append_to_csv(&self, output: &mut String);

    /// Dumps the current state as a standalone CSV string.
    #[cfg(test)]
    fn dump(&self) -> String {
        let mut output = String::new();
        self.append_to_csv(&mut output);
        output
    }

    /// Returns the CSV headers for this feature
    fn headers() -> String
    where
        Self: Sized;
}

#[derive(Clone)]
pub struct FeatureStats {
    total: f64,
    min: f64,
    max: f64,
    mean: f64,
    m2: f64,
    count: u32,
}

impl FeatureStats {
    pub fn new() -> Self {
        Self {
            total: 0.0,
            min: f64::MAX,
            max: f64::MIN,
            mean: 0.0,
            m2: 0.0,
            count: 0,
        }
    }

    pub fn get_total(&self) -> f64 {
        self.total
    }

    pub fn get_min(&self) -> f64 {
        if self.count > 0 {
            self.min
        } else {
            0.0
        }
    }

    pub fn get_max(&self) -> f64 {
        if self.count > 0 {
            self.max
        } else {
            0.0
        }
    }

    pub fn get_mean(&self) -> f64 {
        self.mean
    }

    pub fn get_std(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            (self.m2 / self.count as f64).sqrt()
        }
    }

    pub fn get_count(&self) -> u32 {
        self.count
    }

    fn update_min(&mut self, value: f64) {
        if value < self.min {
            self.min = value;
        }
    }

    fn update_max(&mut self, value: f64) {
        if value > self.max {
            self.max = value;
        }
    }

    pub fn add_value(&mut self, value: f64) {
        self.total += value;
        self.update_min(value);
        self.update_max(value);
        self.count += 1;

        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn dump_headers(prefix: &str) -> String {
        format!("{prefix}_total,{prefix}_mean,{prefix}_std,{prefix}_max,{prefix}_min")
    }

    pub fn append_csv_values(&self, output: &mut String) {
        push_csv_f64(output, self.get_total());
        push_csv_f64(output, self.get_mean());
        push_csv_f64(output, self.get_std());
        push_csv_f64(output, self.get_max());
        push_csv_f64(output, self.get_min());
    }
}

pub fn push_csv_display(output: &mut String, value: impl Display) {
    if !output.is_empty() {
        output.push(',');
    }
    let _ = write!(output, "{value}");
}

/// Largest magnitude below which every integral `f64` converts to `i64` exactly.
const EXACT_INTEGER_F64_LIMIT: f64 = 9_007_199_254_740_992.0; // 2^53

/// Appends `value` as a CSV field, byte-identical to its `Display` output.
///
/// `Display` renders integral floats without a fractional part (`3`, `-0`), so
/// integral values take the much cheaper integer formatter. Most exported
/// statistics (lengths, counts, totals, empty stats) are integral. Negative zero
/// keeps the float path because `-0` has no `i64` representation.
pub fn push_csv_f64(output: &mut String, value: f64) {
    if !output.is_empty() {
        output.push(',');
    }
    // The round trip through i64 tests integrality without a libm `trunc` call;
    // NaN fails the range check.
    let integer = value as i64;
    if value.abs() < EXACT_INTEGER_F64_LIMIT
        && integer as f64 == value
        && !(value == 0.0 && value.is_sign_negative())
    {
        push_i64_digits(output, integer);
    } else {
        let _ = write!(output, "{value}");
    }
}

/// Appends an integer CSV field, byte-identical to its `Display` output.
pub fn push_csv_int(output: &mut String, value: impl Into<i64>) {
    if !output.is_empty() {
        output.push(',');
    }
    push_i64_digits(output, value.into());
}

/// Appends the decimal form of `value`, matching its `Display` output without
/// going through the `fmt` machinery.
fn push_i64_digits(output: &mut String, value: i64) {
    if value < 0 {
        output.push('-');
    }
    let mut remaining = value.unsigned_abs();
    let mut digits = [0u8; 20]; // u64::MAX has 20 decimal digits
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    output.extend(digits[start..].iter().map(|&digit| char::from(digit)));
}

/// Safely performs floating point division, returning 0.0 if denominator is 0
pub fn safe_div(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Safely performs integer division, returning 0.0 if denominator is 0
pub fn safe_div_int(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Safely calculates per-second rate, handling zero duration
pub fn safe_per_second_rate(value: f64, duration_usec: f64) -> f64 {
    safe_div(value, duration_usec / 1_000_000.0)
}
