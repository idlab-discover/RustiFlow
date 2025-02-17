use chrono::{DateTime, Utc};

use crate::packet_features::PacketFeatures;

use super::util::FeatureStats;

const MIN_BULK_PACKETS: u32 = 4;
const BULK_IDLE_MS: i64 = 1000;

#[derive(Clone)]
pub struct BulkState {
    // Tracks "bulk in progress" state
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub packet_count: u32,
    pub size: u32,
}

impl BulkState {
    pub fn new(start_time: DateTime<Utc>, packet_len: u16) -> Self {
        Self {
            start_time,
            last_time: start_time,
            packet_count: 1,
            size: packet_len as u32,
        }
    }

    pub fn update(&mut self, packet_len: u16, timestamp: DateTime<Utc>) {
        self.packet_count += 1;
        self.size += packet_len as u32;
        self.last_time = timestamp;
    }
}

#[derive(Clone)]
pub struct BulkStats {
    pub fwd_bulk_payload_size: FeatureStats,
    pub fwd_bulk_packets: FeatureStats,
    pub fwd_bulk_duration: FeatureStats,
    // Tracks "bulk in progress" state
    fwd_bulk_state: Option<BulkState>,

    pub bwd_bulk_payload_size: FeatureStats,
    pub bwd_bulk_packets: FeatureStats,
    pub bwd_bulk_duration: FeatureStats,
    // Tracks "bulk in progress" state
    bwd_bulk_state: Option<BulkState>,
}

impl BulkStats {
    pub fn new() -> Self {
        BulkStats {
            fwd_bulk_payload_size: FeatureStats::new(),
            fwd_bulk_packets: FeatureStats::new(),
            fwd_bulk_duration: FeatureStats::new(),
            fwd_bulk_state: None,

            bwd_bulk_payload_size: FeatureStats::new(),
            bwd_bulk_packets: FeatureStats::new(),
            bwd_bulk_duration: FeatureStats::new(),
            bwd_bulk_state: None,
        }
    }

    /// Get the rate of bulk bytes in the forward direction per second.
    pub fn fwd_bulk_rate(&self) -> f64 {
        if self.fwd_bulk_duration.get_count() == 0 {
            return 0.0;
        }
        self.fwd_bulk_payload_size.get_total() / (self.fwd_bulk_duration.get_total() / 1_000_000.0)
    }

    /// Get the rate of bulk bytes in the backward direction per second.
    pub fn bwd_bulk_rate(&self) -> f64 {
        if self.bwd_bulk_duration.get_count() == 0 {
            return 0.0;
        }
        self.bwd_bulk_payload_size.get_total() / (self.bwd_bulk_duration.get_total() / 1_000_000.0)
    }

    /// Finalize a BulkState (if it meets the minimum packet threshold),
    /// adding its stats to the appropriate FeatureStats.
    fn finalize_bulk(&mut self, bulk: BulkState, is_fwd: bool) {
        if bulk.packet_count >= MIN_BULK_PACKETS {
            let duration_us = bulk
                .last_time
                .signed_duration_since(bulk.start_time)
                .num_microseconds()
                .unwrap_or(0) as f64;

            if is_fwd {
                self.fwd_bulk_packets.add_value(bulk.packet_count as f64);
                self.fwd_bulk_payload_size.add_value(bulk.size as f64);
                self.fwd_bulk_duration.add_value(duration_us);
            } else {
                self.bwd_bulk_packets.add_value(bulk.packet_count as f64);
                self.bwd_bulk_payload_size.add_value(bulk.size as f64);
                self.bwd_bulk_duration.add_value(duration_us);
            }
        }
    }

    /// Finalize the current bulk (if any) for the given direction.
    pub fn finalize_current_bulk(&mut self, is_fwd: bool) {
        let old_bulk = if is_fwd {
            self.fwd_bulk_state.take()
        } else {
            self.bwd_bulk_state.take()
        };

        if let Some(bulk) = old_bulk {
            self.finalize_bulk(bulk, is_fwd);
        }
    }

    /// Update the bulk logic for a given packet and direction.
    /// Logic adopted from CICFlowMeter's bulk feature, but adjusted for capturing stats on bulk finish.
    pub fn update(&mut self, packet: &PacketFeatures, is_fwd: bool) {
        // 1. Skip zero-length packets
        let packet_len = packet.length;
        if packet_len <= 0 {
            return;
        }

        // Pick which bulk_state Option we modify (fwd or bwd).
        let bulk_opt = if is_fwd {
            &mut self.fwd_bulk_state
        } else {
            &mut self.bwd_bulk_state
        };

        // We'll store any finished bulk here, finalize it once we drop `bulk_opt`
        let mut old_bulk: Option<BulkState> = None;

        match bulk_opt.as_mut() {
            // 2. If there's an existing bulk in progress:
            Some(current_bulk) => {
                let gap_ms = packet
                    .timestamp
                    .signed_duration_since(current_bulk.last_time)
                    .num_milliseconds();

                if gap_ms > BULK_IDLE_MS {
                    // The old bulk has ended -> remove it
                    old_bulk = bulk_opt.take();
                    // Start a fresh bulk with the current packet
                    *bulk_opt = Some(BulkState::new(packet.timestamp, packet.length));
                } else {
                    // Continue the same bulk
                    current_bulk.update(packet.length, packet.timestamp);
                }
            }
            // 3. If there's no bulk in progress, start one
            None => {
                *bulk_opt = Some(BulkState::new(packet.timestamp, packet.length));
                // Finalize bulk in the other direction since we're starting a new bulk in this direction
                self.finalize_current_bulk(!is_fwd);
            }
        }

        // 4. Now that we're done borrowing `bulk_opt`,
        //    we can safely finalize the old bulk.
        if let Some(bulk) = old_bulk {
            self.finalize_bulk(bulk, is_fwd);
        }
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            self.fwd_bulk_rate(),
            self.bwd_bulk_rate(),
            self.fwd_bulk_packets.get_count(),
            self.bwd_bulk_packets.get_count(),
            self.fwd_bulk_packets.dump_values(),
            self.bwd_bulk_packets.dump_values(),
            self.fwd_bulk_payload_size.dump_values(),
            self.bwd_bulk_payload_size.dump_values(),
            self.fwd_bulk_duration.dump_values(),
            self.bwd_bulk_duration.dump_values(),
        )
    }

    pub fn header() -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            "fwd_bulk_rate_s",
            "bwd_bulk_rate_s",
            "fwd_bulk_count",
            "bwd_bulk_count",
            FeatureStats::dump_headers("fwd_bulk_packets"),
            FeatureStats::dump_headers("bwd_bulk_packets"),
            FeatureStats::dump_headers("fwd_bulk_bytes"),
            FeatureStats::dump_headers("bwd_bulk_bytes"),
            FeatureStats::dump_headers("fwd_bulk_duration"),
            FeatureStats::dump_headers("bwd_bulk_duration"),
        )
    }
}
