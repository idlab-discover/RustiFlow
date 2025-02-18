use chrono::{DateTime, Utc};

use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

const ACTIVE_IDLE_TIMEOUT: i64 = 5_000; // 5s

#[derive(Clone)]
pub struct ActiveIdleStats {
    active_start: DateTime<Utc>,
    active_end: DateTime<Utc>,
    pub active_stats: FeatureStats,
    pub idle_stats: FeatureStats,
}

impl ActiveIdleStats {
    pub fn new(timestamp: &DateTime<Utc>) -> Self {
        ActiveIdleStats {
            active_start: *timestamp,
            active_end: *timestamp,
            active_stats: FeatureStats::new(),
            idle_stats: FeatureStats::new(),
        }
    }
}

impl FlowFeature for ActiveIdleStats {
    fn update(
        &mut self,
        packet: &PacketFeatures,
        _is_forward: bool,
        _last_timestamp: &DateTime<Utc>,
    ) {
        // If the packet is older than the active timeout, we consider it as a new active period
        let duration_ms = packet
            .timestamp
            .signed_duration_since(self.active_end)
            .num_milliseconds();
        if duration_ms > ACTIVE_IDLE_TIMEOUT {
            // If the active period is not empty, we add it to the active stats
            let active_duration = self.active_end.signed_duration_since(self.active_start);
            if active_duration.num_milliseconds() > 0 {
                self.active_stats
                    .add_value(active_duration.num_milliseconds() as f64);
            }
            // We add the idle period to the idle stats
            self.idle_stats.add_value(duration_ms as f64);
            self.active_start = packet.timestamp;
        }
        self.active_end = packet.timestamp;
    }

    fn close(&mut self, last_timestamp: &DateTime<Utc>, cause: FlowExpireCause) {
        // If the active period is not empty, we add it to the active stats
        let duration = self.active_end.signed_duration_since(self.active_start);
        if duration.num_milliseconds() > 0 {
            self.active_stats
                .add_value(duration.num_milliseconds() as f64);
        }

        // If flow expired because of inactivity, we add the idle period to the idle stats
        if cause == FlowExpireCause::IdleTimeout {
            self.idle_stats.add_value(
                last_timestamp
                    .signed_duration_since(self.active_end)
                    .num_milliseconds() as f64,
            );
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
