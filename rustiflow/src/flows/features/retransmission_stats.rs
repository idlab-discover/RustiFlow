use std::collections::HashSet;

use crate::packet_features::PacketFeatures;

const RETRA: i64 = 1_000;

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

    pub fn update(&mut self, packet: &PacketFeatures, is_fwd: bool) {
        let seq = packet.sequence_number;

        if is_fwd {
            if !self.fwd_seen_seqs.insert(seq) {
                self.fwd_retransmission_count += 1;
            }
        } else {
            if !self.bwd_seen_seqs.insert(seq) {
                self.bwd_retransmission_count += 1;
            }
        }
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{},{}",
            self.fwd_retransmission_count + self.bwd_retransmission_count,
            self.fwd_retransmission_count,
            self.bwd_retransmission_count
        )
    }

    pub fn header() -> String {
        format!(
            "{},{},{}",
            "flow_retransmission_count", "fwd_retransmission_count", "bwd_retransmission_count"
        )
    }
}
