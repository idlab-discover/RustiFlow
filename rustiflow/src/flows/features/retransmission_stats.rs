use crate::flows::row::Record;
use std::{collections::BTreeMap, ops::Range};

use pnet_packet::ip::IpNextHeaderProtocols;

use crate::{
    flows::util::FlowExpireCause,
    packet_features::{PacketFeatures, ACK_FLAG, FIN_FLAG, SYN_FLAG},
};

use super::util::FlowFeature;

const MAX_SEQUENCE_RANGES: usize = 1024;

#[derive(Clone)]
pub struct RetransmissionStats {
    pub fwd_retransmission_count: u32,
    pub bwd_retransmission_count: u32,
    fwd_history: SequenceHistory,
    bwd_history: SequenceHistory,
}

#[derive(Clone, Default)]
struct SequenceHistory {
    // Disjoint, non-adjacent half-open ranges in unwrapped sequence space.
    // The highest range is inline and serves as the unwrap reference.
    // An empty latest range means this direction has seen no sequence space.
    latest: Range<i64>,
    earlier: BTreeMap<i64, i64>,
}

impl SequenceHistory {
    fn observe(&mut self, sequence: u32, length: u32) -> bool {
        if length == 0 {
            return false;
        }
        let length = i64::from(length);
        if sequence == self.latest.end as u32 {
            self.latest.end += length;
            return false;
        }
        if self.latest.is_empty() {
            let start = i64::from(sequence);
            self.latest = start..start + length;
            return false;
        }
        self.observe_nonadjacent(sequence, length)
    }

    // Keep the range searches and merging out of the in-order path.
    #[inline(never)]
    fn observe_nonadjacent(&mut self, sequence: u32, length: i64) -> bool {
        // Choose the nearest sequence epoch. As with TCP serial comparisons,
        // a jump of half the sequence space or more is ambiguous.
        let reference = self.latest.end;
        let mut start = reference + i64::from(sequence.wrapping_sub(reference as u32) as i32);
        let mut end = start + length;
        if start > self.latest.end {
            let previous = std::mem::replace(&mut self.latest, start..end);
            self.insert_earlier(previous.start, previous.end);
            return false;
        }
        if start >= self.latest.start {
            self.latest.end = self.latest.end.max(end);
            return true;
        }

        let overlaps = end > self.latest.start
            || self
                .earlier
                .range(..end)
                .next_back()
                .is_some_and(|(_, &seen_end)| seen_end > start);
        if let Some((&previous_start, &previous_end)) = self.earlier.range(..=start).next_back() {
            if previous_end >= start {
                self.earlier.remove(&previous_start);
                start = previous_start;
                end = end.max(previous_end);
            }
        }
        while let Some((&next_start, &next_end)) = self.earlier.range(start..=end).next() {
            self.earlier.remove(&next_start);
            end = end.max(next_end);
        }
        if end >= self.latest.start {
            self.latest = start..self.latest.end.max(end);
        } else {
            self.insert_earlier(start, end);
        }
        overlaps
    }

    fn insert_earlier(&mut self, start: i64, end: i64) {
        self.earlier.insert(start, end);
        if self.earlier.len() == MAX_SEQUENCE_RANGES {
            self.earlier.pop_first();
        }
    }
}

/// Counts packets overlapping retained TCP data or SYN/FIN sequence space.
/// Each direction retains at most 1024 merged ranges, evicting the lowest
/// sequence ranges first. Retransmissions into evicted history may be missed.
impl RetransmissionStats {
    pub fn new() -> Self {
        Self {
            fwd_retransmission_count: 0,
            bwd_retransmission_count: 0,
            fwd_history: SequenceHistory::default(),
            bwd_history: SequenceHistory::default(),
        }
    }

    fn update_direction(history: &mut SequenceHistory, count: &mut u32, packet: &PacketFeatures) {
        let length = u32::from(packet.data_length)
            + u32::from(packet.flags & SYN_FLAG != 0)
            + u32::from(packet.flags & FIN_FLAG != 0);
        if history.observe(packet.sequence_number, length) {
            *count += 1;
        }
    }
}

impl FlowFeature for RetransmissionStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        if packet.protocol != IpNextHeaderProtocols::Tcp.0 {
            // Retransmission stats are TCP-only.
            return;
        }

        // Exclude pure ACKs (only ACK flag set, no data length).
        if packet.flags == ACK_FLAG && packet.data_length == 0 {
            return;
        }

        if is_forward {
            Self::update_direction(
                &mut self.fwd_history,
                &mut self.fwd_retransmission_count,
                packet,
            );
        } else {
            Self::update_direction(
                &mut self.bwd_history,
                &mut self.bwd_retransmission_count,
                packet,
            );
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn write_fields(&self, output: &mut impl Record) {
        output.field(self.fwd_retransmission_count + self.bwd_retransmission_count);
        output.field(self.fwd_retransmission_count);
        output.field(self.bwd_retransmission_count);
    }

    fn headers() -> String {
        "flow_retransmission_count,fwd_retransmission_count,bwd_retransmission_count".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{SequenceHistory, MAX_SEQUENCE_RANGES};

    #[test]
    fn range_tracking_matches_byte_coverage_across_wrap() {
        let mut history = SequenceHistory::default();
        let mut seen = [false; 520];
        let mut seed = 17_u32;
        for _ in 0..2000 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let offset = (seed % 500) as usize;
            let length = ((seed >> 16) % 20 + 1) as usize;
            let bytes = &mut seen[offset..offset + length];
            let expected = bytes.iter().any(|seen| *seen);
            let sequence = (u32::MAX - 200).wrapping_add(offset as u32);
            assert_eq!(history.observe(sequence, length as u32), expected);
            bytes.fill(true);
        }
    }

    #[test]
    fn reused_sequence_numbers_in_a_later_epoch_are_new_data() {
        let mut history = SequenceHistory::default();
        for epoch in 0..3 {
            for quarter in 0..4 {
                let sequence = quarter * (1 << 30);
                assert!(!history.observe(sequence, 100), "epoch {epoch}");
                assert!(history.observe(sequence, 100));
            }
        }
    }

    #[test]
    fn out_of_order_segments_fill_and_overlap_ranges_across_wrap() {
        let mut history = SequenceHistory::default();
        for (sequence, length, overlaps) in [
            (u32::MAX - 7, 4, false),
            (0, 4, false),
            (4, 4, false),
            (u32::MAX - 3, 4, false),
            (u32::MAX - 19, 2, false),
            (u32::MAX - 18, 1, true),
            (u32::MAX - 18, 22, true),
            (8, 1, false),
            (2, 12, true),
            (14, 1, false),
        ] {
            assert_eq!(history.observe(sequence, length), overlaps, "{sequence}");
        }
        assert!(history.earlier.is_empty());
    }

    #[test]
    fn sparse_sequence_history_stays_bounded_and_merges_adjacent_ranges() {
        let mut history = SequenceHistory::default();
        for index in 0..40_000 {
            assert!(!history.observe(index * 200, 100));
            assert!(history.earlier.len() < MAX_SEQUENCE_RANGES);
        }
        assert_eq!(history.earlier.len() + 1, MAX_SEQUENCE_RANGES);
        assert!(!history.observe(0, 100));
        assert!(!history.observe(0, 100));
        assert!(!history.observe(39_998 * 200 + 100, 100));
        assert_eq!(history.earlier.len() + 1, MAX_SEQUENCE_RANGES - 1);
        assert!(history.observe(39_998 * 200 + 50, 200));
        assert_eq!(history.earlier.len() + 1, MAX_SEQUENCE_RANGES - 1);
    }
}
