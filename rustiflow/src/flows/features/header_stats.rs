use crate::packet_features::PacketFeatures;

use super::util::FeatureStats;

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

    pub fn update(&mut self, packet: &PacketFeatures, is_fwd: bool) {
        self.header_len.add_value(packet.header_length as f64);
        if is_fwd {
            self.fwd_header_len.add_value(packet.header_length as f64);
        } else {
            self.bwd_header_len.add_value(packet.header_length as f64);
        }
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{},{}",
            self.header_len.dump_values(),
            self.fwd_header_len.dump_values(),
            self.bwd_header_len.dump_values(),
        )
    }

    pub fn header() -> String {
        format!(
            "{},{},{}",
            FeatureStats::dump_headers("header_len"),
            FeatureStats::dump_headers("fwd_header_len"),
            FeatureStats::dump_headers("bwd_header_len"),
        )
    }
}
