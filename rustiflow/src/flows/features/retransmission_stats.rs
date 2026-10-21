use std::collections::BTreeMap;

use pnet::packet::ip::IpNextHeaderProtocols;

use crate::{
    flows::util::FlowExpireCause,
    packet_features::{PacketFeatures, ACK_FLAG, FIN_FLAG, SYN_FLAG},
};

use super::util::{push_csv_int, FlowFeature};

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
    ranges: BTreeMap<i64, i64>,
    latest_end: Option<i64>,
}

impl SequenceHistory {
    fn observe(&mut self, sequence: u32, length: u32) -> bool {
        if length == 0 {
            return false;
        }
        // Choose the nearest sequence epoch. As with TCP serial comparisons,
        // a jump of half the sequence space or more is ambiguous.
        let mut start = self.latest_end.map_or(i64::from(sequence), |reference| {
            reference + i64::from(sequence.wrapping_sub(reference as u32) as i32)
        });
        let mut end = start + i64::from(length);
        self.latest_end = Some(self.latest_end.map_or(end, |latest| latest.max(end)));
        let overlaps = self
            .ranges
            .range(..end)
            .next_back()
            .is_some_and(|(_, &seen_end)| seen_end > start);

        if let Some((&previous_start, &previous_end)) = self.ranges.range(..=start).next_back() {
            if previous_end >= start {
                self.ranges.remove(&previous_start);
                start = previous_start;
                end = end.max(previous_end);
            }
        }
        while let Some((&next_start, &next_end)) = self.ranges.range(start..=end).next() {
            self.ranges.remove(&next_start);
            end = end.max(next_end);
        }
        self.ranges.insert(start, end);
        if self.ranges.len() > MAX_SEQUENCE_RANGES {
            self.ranges.pop_first();
        }
        overlaps
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

    fn append_to_csv(&self, output: &mut String) {
        push_csv_int(
            output,
            self.fwd_retransmission_count + self.bwd_retransmission_count,
        );
        push_csv_int(output, self.fwd_retransmission_count);
        push_csv_int(output, self.bwd_retransmission_count);
    }

    fn headers() -> String {
        "flow_retransmission_count,fwd_retransmission_count,bwd_retransmission_count".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{SequenceHistory, MAX_SEQUENCE_RANGES};

    #[test]
    fn sparse_sequence_history_stays_bounded_and_merges_adjacent_ranges() {
        let mut history = SequenceHistory::default();
        for index in 0..40_000 {
            assert!(!history.observe(index * 200, 100));
            assert!(history.ranges.len() <= MAX_SEQUENCE_RANGES);
        }
        assert_eq!(history.ranges.len(), MAX_SEQUENCE_RANGES);
        assert!(!history.observe(39_998 * 200 + 100, 100));
        assert_eq!(history.ranges.len(), MAX_SEQUENCE_RANGES - 1);
        assert!(history.observe(39_998 * 200 + 50, 200));
        assert_eq!(history.ranges.len(), MAX_SEQUENCE_RANGES - 1);
    }
}
