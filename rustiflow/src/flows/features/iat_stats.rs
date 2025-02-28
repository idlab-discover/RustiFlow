use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

#[derive(Clone)]
pub struct IATStats {
    pub fwd_iat: FeatureStats,
    pub bwd_iat: FeatureStats,
    pub iat: FeatureStats,
    last_timestamp_fwd_ms: Option<i64>,
    last_timestamp_bwd_ms: Option<i64>,
    last_timestamp_ms: Option<i64>,
}

impl IATStats {
    pub fn new() -> Self {
        IATStats {
            fwd_iat: FeatureStats::new(),
            bwd_iat: FeatureStats::new(),
            iat: FeatureStats::new(),
            last_timestamp_fwd_ms: None,
            last_timestamp_bwd_ms: None,
            last_timestamp_ms: None,
        }
    }
}

impl FlowFeature for IATStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        let current_ts_ms = packet.timestamp_us / 1000;

        let duration_ms = |last_timestamp_ms: Option<i64>| {
            last_timestamp_ms.map(|ts_ms| (current_ts_ms - ts_ms) as f64)
        };

        if let Some(dur) = duration_ms(self.last_timestamp_ms) {
            self.iat.add_value(dur);
        }
        self.last_timestamp_ms = Some(current_ts_ms);

        if is_forward {
            if let Some(dur) = duration_ms(self.last_timestamp_fwd_ms) {
                self.fwd_iat.add_value(dur);
            }
            self.last_timestamp_fwd_ms = Some(current_ts_ms);
        } else {
            if let Some(dur) = duration_ms(self.last_timestamp_bwd_ms) {
                self.bwd_iat.add_value(dur);
            }
            self.last_timestamp_bwd_ms = Some(current_ts_ms);
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
