use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

#[derive(Clone)]
pub struct HeaderLengthStats {
    pub header_len: FeatureStats,
    pub fwd_header_len: FeatureStats,
    pub bwd_header_len: FeatureStats,
}

impl HeaderLengthStats {
    pub fn new() -> Self {
        HeaderLengthStats {
            header_len: FeatureStats::new(),
            fwd_header_len: FeatureStats::new(),
            bwd_header_len: FeatureStats::new(),
        }
    }
}

impl FlowFeature for HeaderLengthStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        self.header_len.add_value(packet.header_length as f64);
        if is_forward {
            self.fwd_header_len.add_value(packet.header_length as f64);
        } else {
            self.bwd_header_len.add_value(packet.header_length as f64);
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{}",
            self.header_len.dump_values(),
            self.fwd_header_len.dump_values(),
            self.bwd_header_len.dump_values(),
        )
    }

    fn headers() -> String {
        format!(
            "{},{},{}",
            FeatureStats::dump_headers("header_len"),
            FeatureStats::dump_headers("fwd_header_len"),
            FeatureStats::dump_headers("bwd_header_len"),
        )
    }
}
