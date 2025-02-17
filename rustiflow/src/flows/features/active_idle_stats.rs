use chrono::{DateTime, Utc};

use crate::packet_features::PacketFeatures;

use super::util::FeatureStats;

const ACTIVE_IDLE_TIMEOUT: i64 = 5_000;

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

    pub fn update(&mut self, packet: &PacketFeatures) {
        // If the packet is older than the active timeout, we consider it as a new active period
        if packet
            .timestamp
            .signed_duration_since(self.active_end)
            .num_milliseconds()
            > ACTIVE_IDLE_TIMEOUT
        {
            // If the active period is not empty, we add it to the active stats
            let duration = self.active_end.signed_duration_since(self.active_start);
            if duration.num_milliseconds() > 0 {
                self.active_stats
                    .add_value(duration.num_milliseconds() as f64);
            }
            // We add the idle period to the idle stats
            self.idle_stats.add_value(
                packet
                    .timestamp
                    .signed_duration_since(self.active_end)
                    .num_milliseconds() as f64,
            );
            self.active_start = packet.timestamp;
        }
        self.active_end = packet.timestamp;
    }

    pub fn end_flow(&mut self) {
        // If the active period is not empty, we add it to the active stats
        let duration = self.active_end.signed_duration_since(self.active_start);
        if duration.num_milliseconds() > 0 {
            self.active_stats
                .add_value(duration.num_milliseconds() as f64);
        }

        // If flow expired because of inactivity, we add the idle period to the idle stats
        // ...
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{}",
            self.active_stats.dump_values(),
            self.idle_stats.dump_values(),
        )
    }

    pub fn header() -> String {
        format!(
            "{},{}",
            FeatureStats::dump_headers("active"),
            FeatureStats::dump_headers("idle"),
        )
    }
}
