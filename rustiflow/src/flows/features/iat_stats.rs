use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

#[derive(Clone)]
pub struct IATStats {
    pub fwd_iat: FeatureStats,
    pub bwd_iat: FeatureStats,
    pub iat: FeatureStats,
    last_timestamp_fwd_us: Option<i64>,
    last_timestamp_bwd_us: Option<i64>,
    last_timestamp_us: Option<i64>,
}

impl IATStats {
    pub fn new() -> Self {
        IATStats {
            fwd_iat: FeatureStats::new(),
            bwd_iat: FeatureStats::new(),
            iat: FeatureStats::new(),
            last_timestamp_fwd_us: None,
            last_timestamp_bwd_us: None,
            last_timestamp_us: None,
        }
    }
}

impl FlowFeature for IATStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        let current_ts_us = packet.timestamp_us;

        let duration_ms = |last_timestamp_us: Option<i64>| {
            last_timestamp_us.map(|ts_us| (current_ts_us - ts_us) as f64 / 1_000.0)
        };

        if let Some(dur) = duration_ms(self.last_timestamp_us) {
            self.iat.add_value(dur);
        }
        self.last_timestamp_us = Some(current_ts_us);

        if is_forward {
            if let Some(dur) = duration_ms(self.last_timestamp_fwd_us) {
                self.fwd_iat.add_value(dur);
            }
            self.last_timestamp_fwd_us = Some(current_ts_us);
        } else {
            if let Some(dur) = duration_ms(self.last_timestamp_bwd_us) {
                self.bwd_iat.add_value(dur);
            }
            self.last_timestamp_bwd_us = Some(current_ts_us);
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

    fn append_to_csv(&self, output: &mut String) {
        self.iat.append_csv_values(output);
        self.fwd_iat.append_csv_values(output);
        self.bwd_iat.append_csv_values(output);
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
