use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

/// Trait for network flow features that can be updated, closed, and dumped to CSV format
pub trait FlowFeature: Send + Sync + Clone {
    /// Updates the feature with a new packet
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, last_timestamp: i64);

    /// Finalizes any active state when the flow is terminated
    fn close(&mut self, last_timestamp: i64, cause: FlowExpireCause);

    /// Dumps the current state as a CSV string
    fn dump(&self) -> String;

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
    std: f64,
    count: u32,
}

impl FeatureStats {
    pub fn new() -> Self {
        Self {
            total: 0.0,
            min: f64::MAX,
            max: f64::MIN,
            mean: 0.0,
            std: 0.0,
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
        self.std
    }

    pub fn get_count(&self) -> u32 {
        self.count
    }

    fn update_mean(&mut self, value: f64) {
        self.mean = (((self.count - 1) as f64 * self.mean) + value) / self.count as f64;
    }

    fn update_std(&mut self, value: f64, old_mean: f64) {
        self.std = ((((self.count - 1) as f64 * self.std.powf(2.0))
            + ((value - old_mean) * (value - self.mean)))
            / self.count as f64)
            .sqrt();
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
        self.count += 1;
        self.total += value;
        self.update_min(value);
        self.update_max(value);
        let old_mean: f64 = self.mean;
        self.update_mean(value);
        self.update_std(value, old_mean);
    }

    pub fn dump_headers(prefix: &str) -> String {
        format!("{prefix}_total,{prefix}_mean,{prefix}_std,{prefix}_max,{prefix}_min")
    }

    pub fn dump_values(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.get_total(),
            self.get_mean(),
            self.get_std(),
            self.get_max(),
            self.get_min(),
        )
    }
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
