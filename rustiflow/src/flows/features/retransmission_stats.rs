use pnet::packet::ip::IpNextHeaderProtocols;

use crate::{
    flows::util::FlowExpireCause,
    packet_features::{PacketFeatures, ACK_FLAG, FIN_FLAG, SYN_FLAG},
};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct RetransmissionStats {
    pub fwd_retransmission_count: u32,
    pub bwd_retransmission_count: u32,
    fwd_seen_ranges: Vec<SequenceRange>,
    bwd_seen_ranges: Vec<SequenceRange>,
}

#[derive(Clone, Copy)]
struct SequenceRange {
    start: u32,
    end: u32,
}

impl SequenceRange {
    fn overlaps(self, other: SequenceRange) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Retransmissions are tracked for TCP sequence-space segments only.
///
/// This counts one retransmission when a TCP packet's sequence-space range
/// overlaps data or SYN/FIN sequence space that was already seen in the same
/// direction. It still does not try to model full TCP stream reassembly or
/// sequence-number wraparound.
impl RetransmissionStats {
    pub fn new() -> Self {
        RetransmissionStats {
            fwd_retransmission_count: 0,
            bwd_retransmission_count: 0,
            fwd_seen_ranges: Vec::new(),
            bwd_seen_ranges: Vec::new(),
        }
    }

    fn update_direction(
        ranges: &mut Vec<SequenceRange>,
        retransmission_count: &mut u32,
        packet: &PacketFeatures,
    ) {
        let Some(packet_range) = sequence_range(packet) else {
            return;
        };

        if ranges
            .iter()
            .any(|seen_range| seen_range.overlaps(packet_range))
        {
            *retransmission_count += 1;
        }

        insert_sequence_range(ranges, packet_range);
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
                &mut self.fwd_seen_ranges,
                &mut self.fwd_retransmission_count,
                packet,
            );
        } else {
            Self::update_direction(
                &mut self.bwd_seen_ranges,
                &mut self.bwd_retransmission_count,
                packet,
            );
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
        "flow_retransmission_count,fwd_retransmission_count,bwd_retransmission_count".to_string()
    }
}

fn sequence_range(packet: &PacketFeatures) -> Option<SequenceRange> {
    let control_length =
        u32::from((packet.flags & SYN_FLAG) != 0) + u32::from((packet.flags & FIN_FLAG) != 0);
    let segment_length = u32::from(packet.data_length) + control_length;

    if segment_length == 0 {
        return None;
    }

    Some(SequenceRange {
        start: packet.sequence_number,
        end: packet.sequence_number.saturating_add(segment_length),
    })
}

fn insert_sequence_range(ranges: &mut Vec<SequenceRange>, mut new_range: SequenceRange) {
    let mut index = 0;

    while index < ranges.len() {
        let current = ranges[index];
        if current.end < new_range.start {
            index += 1;
            continue;
        }

        if new_range.end < current.start {
            break;
        }

        new_range.start = new_range.start.min(current.start);
        new_range.end = new_range.end.max(current.end);
        ranges.remove(index);
    }

    ranges.insert(index, new_range);
}
