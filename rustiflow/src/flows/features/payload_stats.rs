use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::{FeatureStats, FlowFeature};

#[derive(Clone)]
pub struct PayloadLengthStats {
    pub payload_len: FeatureStats,
    pub fwd_payload_len: FeatureStats,
    pub bwd_payload_len: FeatureStats,
    pub fwd_non_zero_payload_packets: u32,
    pub bwd_non_zero_payload_packets: u32,
}

impl PayloadLengthStats {
    pub fn new() -> Self {
        PayloadLengthStats {
            payload_len: FeatureStats::new(),
            fwd_payload_len: FeatureStats::new(),
            bwd_payload_len: FeatureStats::new(),
            fwd_non_zero_payload_packets: 0,
            bwd_non_zero_payload_packets: 0,
        }
    }
}

impl FlowFeature for PayloadLengthStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        self.payload_len.add_value(packet.data_length as f64);
        if is_forward {
            self.fwd_payload_len.add_value(packet.data_length as f64);
            if packet.data_length > 0 {
                self.fwd_non_zero_payload_packets += 1;
            }
        } else {
            self.bwd_payload_len.add_value(packet.data_length as f64);
            if packet.data_length > 0 {
                self.bwd_non_zero_payload_packets += 1;
            }
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.payload_len.dump_values(),
            self.fwd_payload_len.dump_values(),
            self.bwd_payload_len.dump_values(),
            self.fwd_non_zero_payload_packets,
            self.bwd_non_zero_payload_packets,
        )
    }

    fn headers() -> String {
        format!(
            "{},{},{},{},{}",
            FeatureStats::dump_headers("payload_len"),
            FeatureStats::dump_headers("fwd_payload_len"),
            FeatureStats::dump_headers("bwd_payload_len"),
            "fwd_non_zero_payload_packets",
            "bwd_non_zero_payload_packets",
        )
    }
}
