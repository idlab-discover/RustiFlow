use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};
use chrono::{DateTime, Utc};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct TimingStats {
    pub first_timestamp_fwd: Option<DateTime<Utc>>,
    pub first_timestamp_bwd: Option<DateTime<Utc>>,
    pub last_timestamp_fwd: Option<DateTime<Utc>>,
    pub last_timestamp_bwd: Option<DateTime<Utc>>,
}

impl TimingStats {
    pub fn new() -> Self {
        TimingStats {
            first_timestamp_fwd: None,
            first_timestamp_bwd: None,
            last_timestamp_fwd: None,
            last_timestamp_bwd: None,
        }
    }

    pub fn get_last_timestamp(&self) -> Option<DateTime<Utc>> {
        match (self.last_timestamp_fwd, self.last_timestamp_bwd) {
            (Some(fwd), Some(bwd)) => Some(fwd.max(bwd)),
            (Some(fwd), None) => Some(fwd),
            (None, Some(bwd)) => Some(bwd),
            (None, None) => None,
        }
    }

    pub fn get_fwd_duration(&self) -> i64 {
        if let (Some(first), Some(last)) = (self.first_timestamp_fwd, self.last_timestamp_fwd) {
            last.signed_duration_since(first).num_milliseconds()
        } else {
            0
        }
    }

    pub fn get_bwd_duration(&self) -> i64 {
        if let (Some(first), Some(last)) = (self.first_timestamp_bwd, self.last_timestamp_bwd) {
            last.signed_duration_since(first).num_milliseconds()
        } else {
            0
        }
    }
}

impl FlowFeature for TimingStats {
    fn update(
        &mut self,
        packet: &PacketFeatures,
        is_forward: bool,
        _last_timestamp: &DateTime<Utc>,
    ) {
        if is_forward {
            if self.first_timestamp_fwd.is_none() {
                self.first_timestamp_fwd = Some(packet.timestamp);
            }
            self.last_timestamp_fwd = Some(packet.timestamp);
        } else {
            if self.first_timestamp_bwd.is_none() {
                self.first_timestamp_bwd = Some(packet.timestamp);
            }
            self.last_timestamp_bwd = Some(packet.timestamp);
        }
    }

    fn close(&mut self, _last_timestamp: &DateTime<Utc>, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.first_timestamp_fwd
                .map(|t| t.timestamp_millis())
                .unwrap_or(0),
            self.first_timestamp_bwd
                .map(|t| t.timestamp_millis())
                .unwrap_or(0),
            self.last_timestamp_fwd
                .map(|t| t.timestamp_millis())
                .unwrap_or(0),
            self.last_timestamp_bwd
                .map(|t| t.timestamp_millis())
                .unwrap_or(0),
            self.get_fwd_duration(),
            self.get_bwd_duration()
        )
    }

    fn headers() -> String {
        format!(
            "{},{},{},{},{},{}",
            "first_timestamp_fwd",
            "first_timestamp_bwd",
            "last_timestamp_fwd",
            "last_timestamp_bwd",
            "fwd_duration_ms",
            "bwd_duration_ms"
        )
    }
}
