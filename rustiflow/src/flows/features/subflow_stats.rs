use chrono::{DateTime, Utc};

use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::FlowFeature;

const SUBFLOW_TIMEOUT: i64 = 1_000;

#[derive(Clone)]
pub struct SubflowStats {
    pub subflow_count: u32,
}

impl SubflowStats {
    pub fn new() -> Self {
        SubflowStats { subflow_count: 0 }
    }
}

impl FlowFeature for SubflowStats {
    fn update(
        &mut self,
        packet: &PacketFeatures,
        _is_forward: bool,
        last_timestamp: &DateTime<Utc>,
    ) {
        if packet
            .timestamp
            .signed_duration_since(last_timestamp)
            .num_milliseconds()
            > SUBFLOW_TIMEOUT
        {
            self.subflow_count += 1;
        }
    }

    fn close(&mut self, _last_timestamp: &DateTime<Utc>, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!("{}", self.subflow_count)
    }

    fn headers() -> String {
        format!("{}", "subflow_count")
    }
}
