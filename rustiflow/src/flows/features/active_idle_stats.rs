use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

const ACTIVE_IDLE_TIMEOUT: i64 = 5_000; // 5s

#[derive(Clone)]
pub struct ActiveIdleStats {
    active_start: i64, // Microseconds since epoch
    active_end: i64,
    pub active_stats: FeatureStats,
    pub idle_stats: FeatureStats,
}

impl ActiveIdleStats {
    pub fn new(timestamp_us: i64) -> Self {
        ActiveIdleStats {
            active_start: timestamp_us,
            active_end: timestamp_us,
            active_stats: FeatureStats::new(),
            idle_stats: FeatureStats::new(),
        }
    }
}

impl FlowFeature for ActiveIdleStats {
    fn update(&mut self, packet: &PacketFeatures, _is_forward: bool, _last_timestamp_us: i64) {
        let current_ts = packet.timestamp_us;
        let duration_ms = (current_ts - self.active_end) / 1_000; // Convert to milliseconds

        if duration_ms > ACTIVE_IDLE_TIMEOUT {
            let active_duration = (self.active_end - self.active_start) / 1_000;
            if active_duration > 0 {
                self.active_stats.add_value(active_duration as f64);
            }
            self.idle_stats.add_value(duration_ms as f64);
            self.active_start = current_ts;
        }
        self.active_end = current_ts;
    }

    fn close(&mut self, last_timestamp_us: i64, cause: FlowExpireCause) {
        // If the active period is not empty, we add it to the active stats
        let duration = self.active_end - self.active_start;
        if duration > 0 {
            self.active_stats.add_value(duration as f64 / 1_000.0);
        }

        // If flow expired because of inactivity, we add the idle period to the idle stats
        if cause == FlowExpireCause::IdleTimeout {
            self.idle_stats
                .add_value((last_timestamp_us - self.active_end) as f64 / 1_000.0);
        }
    }

    fn dump(&self) -> String {
        format!(
            "{},{}",
            self.active_stats.dump_values(),
            self.idle_stats.dump_values(),
        )
    }

    fn headers() -> String {
        format!(
            "{},{}",
            FeatureStats::dump_headers("active"),
            FeatureStats::dump_headers("idle"),
        )
    }
}
