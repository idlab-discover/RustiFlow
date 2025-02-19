use std::collections::HashSet;

use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct RetransmissionStats {
    pub fwd_retransmission_count: u32,
    pub bwd_retransmission_count: u32,
    // We store seen sequence numbers in each direction
    fwd_seen_seqs: HashSet<u32>,
    bwd_seen_seqs: HashSet<u32>,
}

/// Our implementation only tracks full retransmissions, i.e., packets that are
/// sent more than once. We do not track partial retransmissions or overlapping segments.
impl RetransmissionStats {
    pub fn new() -> Self {
        RetransmissionStats {
            fwd_retransmission_count: 0,
            bwd_retransmission_count: 0,
            fwd_seen_seqs: HashSet::new(),
            bwd_seen_seqs: HashSet::new(),
        }
    }
}

impl FlowFeature for RetransmissionStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        let seq = packet.sequence_number;

        if is_forward {
            if !self.fwd_seen_seqs.insert(seq) {
                self.fwd_retransmission_count += 1;
            }
        } else {
            if !self.bwd_seen_seqs.insert(seq) {
                self.bwd_retransmission_count += 1;
            }
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{}",
            self.fwd_retransmission_count + self.bwd_retransmission_count,
            self.fwd_retransmission_count,
            self.bwd_retransmission_count
        )
    }

    fn headers() -> String {
        format!(
            "{},{},{}",
            "flow_retransmission_count", "fwd_retransmission_count", "bwd_retransmission_count"
        )
    }
}
