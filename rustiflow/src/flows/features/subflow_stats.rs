use chrono::{DateTime, Utc};

use crate::packet_features::PacketFeatures;

const SUBFLOW_TIMEOUT: i64 = 1_000;

#[derive(Clone)]
pub struct SubflowStats {
    pub subflow_count: u32,
}

impl SubflowStats {
    pub fn new() -> Self {
        SubflowStats { subflow_count: 0 }
    }

    pub fn update(&mut self, packet: &PacketFeatures, last_timestamp: &DateTime<Utc>) {
        if packet
            .timestamp
            .signed_duration_since(last_timestamp)
            .num_milliseconds()
            > SUBFLOW_TIMEOUT
        {
            self.subflow_count += 1;
        }
    }

    pub fn dump(&self) -> String {
        format!("{}", self.subflow_count)
    }

    pub fn header() -> String {
        format!("{}", "subflow_count")
    }
}
