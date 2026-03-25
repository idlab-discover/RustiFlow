use pnet::packet::ip::IpNextHeaderProtocols;

use crate::{
    flows::util::FlowExpireCause,
    packet_features::{PacketFeatures, ACK_FLAG},
};

use super::util::FlowFeature;

#[derive(Clone, Copy)]
struct AckObservation {
    ack_number: u32,
    window_size: u16,
}

#[derive(Clone)]
pub struct TcpQualityStats {
    pub fwd_duplicate_ack_count: u32,
    pub bwd_duplicate_ack_count: u32,
    pub fwd_zero_window_count: u32,
    pub bwd_zero_window_count: u32,
    last_fwd_ack: Option<AckObservation>,
    last_bwd_ack: Option<AckObservation>,
}

impl TcpQualityStats {
    pub fn new() -> Self {
        Self {
            fwd_duplicate_ack_count: 0,
            bwd_duplicate_ack_count: 0,
            fwd_zero_window_count: 0,
            bwd_zero_window_count: 0,
            last_fwd_ack: None,
            last_bwd_ack: None,
        }
    }

    fn is_duplicate_ack_candidate(packet: &PacketFeatures) -> bool {
        packet.protocol == IpNextHeaderProtocols::Tcp.0
            && packet.flags == ACK_FLAG
            && packet.data_length == 0
    }

    fn update_duplicate_ack_state(
        last_ack: &mut Option<AckObservation>,
        duplicate_ack_count: &mut u32,
        packet: &PacketFeatures,
    ) {
        if !Self::is_duplicate_ack_candidate(packet) {
            *last_ack = None;
            return;
        }

        let observation = AckObservation {
            ack_number: packet.sequence_number_ack,
            window_size: packet.window_size,
        };

        if last_ack.is_some_and(|last| {
            last.ack_number == observation.ack_number && last.window_size == observation.window_size
        }) {
            *duplicate_ack_count += 1;
        }

        *last_ack = Some(observation);
    }
}

impl FlowFeature for TcpQualityStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        if packet.protocol != IpNextHeaderProtocols::Tcp.0 {
            return;
        }

        if is_forward {
            if packet.window_size == 0 {
                self.fwd_zero_window_count += 1;
            }
            Self::update_duplicate_ack_state(
                &mut self.last_fwd_ack,
                &mut self.fwd_duplicate_ack_count,
                packet,
            );
        } else {
            if packet.window_size == 0 {
                self.bwd_zero_window_count += 1;
            }
            Self::update_duplicate_ack_state(
                &mut self.last_bwd_ack,
                &mut self.bwd_duplicate_ack_count,
                packet,
            );
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close.
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.fwd_duplicate_ack_count + self.bwd_duplicate_ack_count,
            self.fwd_duplicate_ack_count,
            self.bwd_duplicate_ack_count,
            self.fwd_zero_window_count + self.bwd_zero_window_count,
            self.fwd_zero_window_count,
            self.bwd_zero_window_count,
        )
    }

    fn headers() -> String {
        [
            "flow_duplicate_ack_count",
            "fwd_duplicate_ack_count",
            "bwd_duplicate_ack_count",
            "flow_zero_window_count",
            "fwd_zero_window_count",
            "bwd_zero_window_count",
        ]
        .join(",")
    }
}
