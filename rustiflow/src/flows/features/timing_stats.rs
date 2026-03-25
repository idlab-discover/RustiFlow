use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct TimingStats {
    first_timestamp_fwd_us: Option<i64>,
    first_timestamp_bwd_us: Option<i64>,
    last_timestamp_fwd_us: Option<i64>,
    last_timestamp_bwd_us: Option<i64>,
}

impl TimingStats {
    pub fn new() -> Self {
        TimingStats {
            first_timestamp_fwd_us: None,
            first_timestamp_bwd_us: None,
            last_timestamp_fwd_us: None,
            last_timestamp_bwd_us: None,
        }
    }

    pub fn first_timestamp_fwd_ms(&self) -> f64 {
        self.first_timestamp_fwd_us
            .map_or(0.0, |timestamp_us| timestamp_us as f64 / 1_000.0)
    }

    pub fn first_timestamp_bwd_ms(&self) -> f64 {
        self.first_timestamp_bwd_us
            .map_or(0.0, |timestamp_us| timestamp_us as f64 / 1_000.0)
    }

    pub fn last_timestamp_fwd_ms(&self) -> f64 {
        self.last_timestamp_fwd_us
            .map_or(0.0, |timestamp_us| timestamp_us as f64 / 1_000.0)
    }

    pub fn last_timestamp_bwd_ms(&self) -> f64 {
        self.last_timestamp_bwd_us
            .map_or(0.0, |timestamp_us| timestamp_us as f64 / 1_000.0)
    }

    pub fn get_fwd_duration(&self) -> f64 {
        if let (Some(first), Some(last)) = (self.first_timestamp_fwd_us, self.last_timestamp_fwd_us)
        {
            (last - first) as f64 / 1_000.0
        } else {
            0.0
        }
    }

    pub fn get_bwd_duration(&self) -> f64 {
        if let (Some(first), Some(last)) = (self.first_timestamp_bwd_us, self.last_timestamp_bwd_us)
        {
            (last - first) as f64 / 1_000.0
        } else {
            0.0
        }
    }
}

impl FlowFeature for TimingStats {
    fn update(&mut self, packet: &PacketFeatures, is_forward: bool, _last_timestamp_us: i64) {
        let current_ts = packet.timestamp_us;
        if is_forward {
            if self.first_timestamp_fwd_us.is_none() {
                self.first_timestamp_fwd_us = Some(current_ts);
            }
            self.last_timestamp_fwd_us = Some(current_ts);
        } else {
            if self.first_timestamp_bwd_us.is_none() {
                self.first_timestamp_bwd_us = Some(current_ts);
            }
            self.last_timestamp_bwd_us = Some(current_ts);
        }
    }

    fn close(&mut self, _last_timestamp: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.first_timestamp_fwd_ms(),
            self.first_timestamp_bwd_ms(),
            self.last_timestamp_fwd_ms(),
            self.last_timestamp_bwd_ms(),
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
