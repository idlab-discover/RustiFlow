use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

#[derive(Clone)]
pub struct IATStats {
    pub fwd_iat: FeatureStats,
    pub bwd_iat: FeatureStats,
    pub iat: FeatureStats,
    last_timestamp_fwd: Option<i64>, // Microseconds since epoch
    last_timestamp_bwd: Option<i64>,
    last_timestamp: Option<i64>,
}

impl IATStats {
    pub fn new() -> Self {
        IATStats {
            fwd_iat: FeatureStats::new(),
            bwd_iat: FeatureStats::new(),
            iat: FeatureStats::new(),
            last_timestamp_fwd: None,
            last_timestamp_bwd: None,
            last_timestamp: None,
        }
    }
}

impl FlowFeature for IATStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        let current_ts = packet.timestamp_us / 1000;

        let duration = |last_timestamp: Option<i64>| {
            last_timestamp.map(|ts| {
                (current_ts - ts) as f64 // Convert to milliseconds
            })
        };

        if let Some(dur) = duration(self.last_timestamp) {
            self.iat.add_value(dur);
        }
        self.last_timestamp = Some(current_ts);

        if is_forward {
            if let Some(dur) = duration(self.last_timestamp_fwd) {
                self.fwd_iat.add_value(dur);
            }
            self.last_timestamp_fwd = Some(current_ts);
        } else {
            if let Some(dur) = duration(self.last_timestamp_bwd) {
                self.bwd_iat.add_value(dur);
            }
            self.last_timestamp_bwd = Some(current_ts);
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{}",
            self.iat.dump_values(),
            self.fwd_iat.dump_values(),
            self.bwd_iat.dump_values(),
        )
    }

    fn headers() -> String {
        format!(
            "{},{},{}",
            FeatureStats::dump_headers("iat"),
            FeatureStats::dump_headers("fwd_iat"),
            FeatureStats::dump_headers("bwd_iat")
        )
    }
}
