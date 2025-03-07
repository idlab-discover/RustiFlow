use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct TimingStats {
    pub first_timestamp_fwd_ms: Option<i64>,
    pub first_timestamp_bwd_ms: Option<i64>,
    pub last_timestamp_fwd_ms: Option<i64>,
    pub last_timestamp_bwd_ms: Option<i64>,
}

impl TimingStats {
    pub fn new() -> Self {
        TimingStats {
            first_timestamp_fwd_ms: None,
            first_timestamp_bwd_ms: None,
            last_timestamp_fwd_ms: None,
            last_timestamp_bwd_ms: None,
        }
    }

    pub fn get_fwd_duration(&self) -> i64 {
        if let (Some(first), Some(last)) = (self.first_timestamp_fwd_ms, self.last_timestamp_fwd_ms)
        {
            last - first
        } else {
            0
        }
    }

    pub fn get_bwd_duration(&self) -> i64 {
        if let (Some(first), Some(last)) = (self.first_timestamp_bwd_ms, self.last_timestamp_bwd_ms)
        {
            last - first
        } else {
            0
        }
    }
}

impl FlowFeature for TimingStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        let current_ts = packet.timestamp_us / 1000;
        if is_forward {
            if self.first_timestamp_fwd_ms.is_none() {
                self.first_timestamp_fwd_ms = Some(current_ts);
            }
            self.last_timestamp_fwd_ms = Some(current_ts);
        } else {
            if self.first_timestamp_bwd_ms.is_none() {
                self.first_timestamp_bwd_ms = Some(current_ts);
            }
            self.last_timestamp_bwd_ms = Some(current_ts);
        }
    }

    fn close(&mut self, _last_timestamp: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.first_timestamp_fwd_ms.unwrap_or(0),
            self.first_timestamp_bwd_ms.unwrap_or(0),
            self.last_timestamp_fwd_ms.unwrap_or(0),
            self.last_timestamp_bwd_ms.unwrap_or(0),
            self.get_fwd_duration(),
            self.get_bwd_duration()
        )
    }

    fn headers() -> String {
        [
            "first_timestamp_fwd",
            "first_timestamp_bwd",
            "last_timestamp_fwd",
            "last_timestamp_bwd",
            "fwd_duration_ms",
            "bwd_duration_ms",
        ]
        .join(",")
    }
}
