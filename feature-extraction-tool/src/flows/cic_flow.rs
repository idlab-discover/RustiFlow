use chrono::{DateTime, Utc};
use common::BasicFeatures;
use std::{net::Ipv4Addr, time::Instant};

use super::{basic_flow::BasicFlow, flow::Flow};

pub struct CicFlow {
    // BasicFlow
    pub basic_flow: BasicFlow,
    // Subflows
    sf_last_packet_timestamp: Option<Instant>,
    sf_count: u32,
    start_active: Instant,
    end_active: Instant,
    active_count: u32,
    active_mean: f64,
    active_std: f64,
    active_max: f64,
    active_min: f64,
    idle_count: u32,
    idle_mean: f64,
    idle_std: f64,
    idle_max: f64,
    idle_min: f64,
    // Forward
    fwd_init_win_bytes: u16,
    fwd_act_data_pkt: u32,
    fwd_header_len_min: u32,
    fwd_last_timestamp: Option<Instant>,
    fwd_pkt_len_tot: u32,
    fwd_pkt_len_max: u32,
    fwd_pkt_len_min: u32,
    fwd_pkt_len_mean: f32,
    fwd_pkt_len_std: f32,
    fwd_iat_total: f64,
    fwd_iat_mean: f64,
    fwd_iat_std: f64,
    fwd_iat_max: f64,
    fwd_iat_min: f64,
    fwd_header_length: u32,
    fwd_bulk_duration: f64,
    fwd_bulk_packet_count: u64,
    fwd_bulk_size_total: u32,
    fwd_bulk_state_count: u64,
    fwd_bulk_packet_count_help: u64,
    fwd_bulk_start_help: Option<Instant>,
    fwd_bulk_size_help: u32,
    fwd_last_bulk_timestamp: Option<Instant>,
    // Backward
    bwd_init_win_bytes: u16,
    bwd_last_timestamp: Option<Instant>,
    bwd_pkt_len_tot: u32,
    bwd_pkt_len_max: u32,
    bwd_pkt_len_min: u32,
    bwd_pkt_len_mean: f32,
    bwd_pkt_len_std: f32,
    bwd_iat_total: f64,
    bwd_iat_mean: f64,
    bwd_iat_std: f64,
    bwd_iat_max: f64,
    bwd_iat_min: f64,
    bwd_header_length: u32,
    bwd_bulk_duration: f64,
    bwd_bulk_packet_count: u64,
    bwd_bulk_size_total: u32,
    bwd_bulk_state_count: u64,
    bwd_bulk_packet_count_help: u64,
    bwd_bulk_start_help: Option<Instant>,
    bwd_bulk_size_help: u32,
    bwd_last_bulk_timestamp: Option<Instant>,
}

impl CicFlow {
    pub fn new(
        flow_id: String,
        ipv4_source: u32,
        port_source: u16,
        ipv4_destination: u32,
        port_destination: u16,
        protocol: u8,
    ) -> Self {
        CicFlow {
            basic_flow: BasicFlow::new(
                flow_id,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
            ),
            sf_last_packet_timestamp: None,
            sf_count: 0,
            start_active: Instant::now(),
            end_active: Instant::now(),
            active_count: 0,
            active_mean: 0.0,
            active_std: 0.0,
            active_max: 0.0,
            active_min: f64::MAX,
            idle_count: 0,
            idle_mean: 0.0,
            idle_std: 0.0,
            idle_max: 0.0,
            idle_min: f64::MAX,
            fwd_act_data_pkt: 0,
            fwd_init_win_bytes: 0,
            fwd_header_len_min: u32::MAX,
            fwd_last_timestamp: None,
            fwd_pkt_len_tot: 0,
            fwd_pkt_len_max: 0,
            fwd_pkt_len_min: u32::MAX,
            fwd_pkt_len_mean: 0.0,
            fwd_pkt_len_std: 0.0,
            fwd_iat_total: 0.0,
            fwd_iat_mean: 0.0,
            fwd_iat_std: 0.0,
            fwd_iat_max: 0.0,
            fwd_iat_min: f64::MAX,
            fwd_header_length: 0,
            fwd_bulk_duration: 0.0,
            fwd_bulk_packet_count: 0,
            fwd_bulk_size_total: 0,
            fwd_bulk_state_count: 0,
            fwd_bulk_packet_count_help: 0,
            fwd_bulk_start_help: None,
            fwd_bulk_size_help: 0,
            fwd_last_bulk_timestamp: None,
            bwd_init_win_bytes: 0,
            bwd_last_timestamp: None,
            bwd_pkt_len_tot: 0,
            bwd_pkt_len_max: 0,
            bwd_pkt_len_min: u32::MAX,
            bwd_pkt_len_mean: 0.0,
            bwd_pkt_len_std: 0.0,
            bwd_iat_total: 0.0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            bwd_iat_max: 0.0,
            bwd_iat_min: f64::MAX,
            bwd_header_length: 0,
            bwd_bulk_duration: 0.0,
            bwd_bulk_packet_count: 0,
            bwd_bulk_size_total: 0,
            bwd_bulk_state_count: 0,
            bwd_bulk_packet_count_help: 0,
            bwd_bulk_start_help: None,
            bwd_bulk_size_help: 0,
            bwd_last_bulk_timestamp: None,
        }
    }

    // setters
    fn increase_fwd_header_length(&mut self, len: u32) {
        self.fwd_header_length += len;
    }

    fn increase_bwd_header_length(&mut self, len: u32) {
        self.bwd_header_length += len;
    }

    fn update_fwd_header_len_min(&mut self, len: u32) {
        if len < self.fwd_header_len_min {
            self.fwd_header_len_min = len;
        }
    }

    fn update_fwd_pkt_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.fwd_pkt_len_max {
            self.fwd_pkt_len_max = len;
        }
        if len < self.fwd_pkt_len_min {
            self.fwd_pkt_len_min = len;
        }

        // update total
        self.fwd_pkt_len_tot += len;

        // update mean and std
        let new_fwd_pkt_len_mean = (((self.basic_flow.fwd_packet_count - 1) as f32 * self.fwd_pkt_len_mean) + len as f32) / self.basic_flow.fwd_packet_count as f32;
        self.fwd_pkt_len_std = (((((self.basic_flow.fwd_packet_count - 1) as f32 * self.fwd_pkt_len_std.powf(2.0)) + ((len as f32 - self.fwd_pkt_len_mean) * (len as f32 - new_fwd_pkt_len_mean))) / self.basic_flow.fwd_packet_count as f32)).sqrt();
        self.fwd_pkt_len_mean = new_fwd_pkt_len_mean;
    }

    fn update_bwd_pkt_len_stats(&mut self, len: u32) {
        // update max and min
        if len > self.bwd_pkt_len_max {
            self.bwd_pkt_len_max = len;
        }
        if len < self.bwd_pkt_len_min {
            self.bwd_pkt_len_min = len;
        }

        // update total
        self.bwd_pkt_len_tot += len;

        // update mean and std
        let new_bwd_pkt_len_mean = (((self.basic_flow.bwd_packet_count - 1) as f32 * self.bwd_pkt_len_mean) + len as f32) / self.basic_flow.bwd_packet_count as f32;
        self.bwd_pkt_len_std = (((((self.basic_flow.bwd_packet_count - 1) as f32 * self.bwd_pkt_len_std.powf(2.0)) + ((len as f32 - self.bwd_pkt_len_mean) * (len as f32 - new_bwd_pkt_len_mean))) / self.basic_flow.bwd_packet_count as f32)).sqrt();
        self.bwd_pkt_len_mean = new_bwd_pkt_len_mean;
    }

    fn update_fwd_iat_stats(&mut self, iat: f64) {
        // update max and min
        if iat > self.fwd_iat_max {
            self.fwd_iat_max = iat;
        }
        if iat < self.fwd_iat_min {
            self.fwd_iat_min = iat;
        }
        // update total
        self.fwd_iat_total += iat;

        // update mean and std
        let new_fwd_iat_mean = ((self.basic_flow.fwd_packet_count - 2) as f64 * self.fwd_iat_mean + iat) / (self.basic_flow.fwd_packet_count - 1) as f64;
        self.fwd_iat_std = (((((self.basic_flow.fwd_packet_count - 2) as f64 * self.fwd_iat_std.powf(2.0)) + ((iat - self.fwd_iat_mean) * (iat - new_fwd_iat_mean))) / (self.basic_flow.fwd_packet_count - 1) as f64)).sqrt();
        self.fwd_iat_mean = new_fwd_iat_mean;
    }

    fn update_bwd_iat_stats(&mut self, iat: f64) {
        // update max and min
        if iat > self.bwd_iat_max {
            self.bwd_iat_max = iat;
        }
        if iat < self.bwd_iat_min {
            self.bwd_iat_min = iat;
        }
        // update total
        self.bwd_iat_total += iat;

        // update mean and std
        let new_bwd_iat_mean = ((self.basic_flow.bwd_packet_count - 2) as f64 * self.bwd_iat_mean + iat) / (self.basic_flow.bwd_packet_count - 1) as f64;
        self.bwd_iat_std = (((((self.basic_flow.bwd_packet_count - 2) as f64 * self.bwd_iat_std.powf(2.0)) + ((iat - self.bwd_iat_mean) * (iat - new_bwd_iat_mean))) / (self.basic_flow.bwd_packet_count - 1) as f64)).sqrt();
        self.bwd_iat_mean = new_bwd_iat_mean;
    }

    fn update_active_flow(&mut self, duration: f64) {
        self.active_count += 1;

        // update max and min
        if duration > self.active_max {
            self.active_max = duration;
        }
        if duration < self.active_min {
            self.active_min = duration;
        }

        // update mean and std
        let new_active_mean = (((self.active_count - 1) as f64 * self.active_mean) + duration) / self.active_count as f64;
        self.active_std = (((((self.active_count - 1) as f64 * self.active_std.powf(2.0)) + ((duration - self.active_mean) * (duration - new_active_mean))) / self.active_count as f64)).sqrt();
        self.active_mean = new_active_mean;
    }

    fn update_idle_flow(&mut self, duration: f64) {
        self.idle_count += 1;

        // update max and min
        if duration > self.idle_max {
            self.idle_max = duration;
        }
        if duration < self.idle_min {
            self.idle_min = duration;
        }

        // update mean and std
        let new_idle_mean = (((self.idle_count - 1) as f64 * self.idle_mean) + duration) / self.idle_count as f64;
        self.idle_std = (((((self.idle_count - 1) as f64 * self.idle_std.powf(2.0)) + ((duration - self.idle_mean) * (duration - new_idle_mean))) / self.idle_count as f64)).sqrt();
        self.idle_mean = new_idle_mean;
    }

    fn update_fwd_bulk_stats(&mut self, timestamp: &Instant, len: u32) {
        if self.bwd_last_bulk_timestamp > self.fwd_bulk_start_help {
            self.fwd_bulk_start_help = None;
        }
        if len <= 0 {
            return;
        }

        if self.fwd_bulk_start_help == None {
            self.fwd_bulk_start_help = Some(*timestamp);
            self.fwd_bulk_packet_count_help = 1;
            self.fwd_bulk_size_help = len;
            self.fwd_last_bulk_timestamp = Some(*timestamp);
        } else {
            // too much idle time -> new bulk
            if timestamp
                .duration_since(self.fwd_last_bulk_timestamp.unwrap())
                .as_secs_f64()
                > 1.0
            {
                self.fwd_bulk_start_help = Some(*timestamp);
                self.fwd_last_bulk_timestamp = Some(*timestamp);
                self.fwd_bulk_packet_count_help = 1;
                self.fwd_bulk_size_help = len;
            } else {
                self.fwd_bulk_packet_count_help += 1;
                self.fwd_bulk_size_help += len;
                // new bulk
                if self.fwd_bulk_packet_count_help == 4 {
                    self.fwd_bulk_state_count += 1;
                    self.fwd_bulk_packet_count += self.fwd_bulk_packet_count_help;
                    self.fwd_bulk_size_total += self.fwd_bulk_size_help;
                    self.fwd_bulk_duration += timestamp
                        .duration_since(self.fwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
                // continu bulk
                else if self.fwd_bulk_packet_count_help > 4 {
                    self.fwd_bulk_packet_count += 1;
                    self.fwd_bulk_size_total += len;
                    self.fwd_bulk_duration += timestamp
                        .duration_since(self.fwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
            }
            self.fwd_last_bulk_timestamp = Some(*timestamp);
        }
    }

    fn update_bwd_bulk_stats(&mut self, timestamp: &Instant, len: u32) {
        if self.fwd_last_bulk_timestamp > self.bwd_bulk_start_help {
            self.bwd_bulk_start_help = None;
        }
        if len <= 0 {
            return;
        }

        if self.bwd_bulk_start_help == None {
            self.bwd_bulk_start_help = Some(*timestamp);
            self.bwd_bulk_packet_count_help = 1;
            self.bwd_bulk_size_help = len;
            self.bwd_last_bulk_timestamp = Some(*timestamp);
        } else {
            // to much idle time -> new bulk
            if timestamp
                .duration_since(self.bwd_last_bulk_timestamp.unwrap())
                .as_secs_f64()
                > 1.0
            {
                self.bwd_bulk_start_help = Some(*timestamp);
                self.bwd_last_bulk_timestamp = Some(*timestamp);
                self.bwd_bulk_packet_count_help = 1;
                self.bwd_bulk_size_help = len;
            } else {
                self.bwd_bulk_packet_count_help += 1;
                self.bwd_bulk_size_help += len;
                // new bulk
                if self.bwd_bulk_packet_count_help == 4 {
                    self.bwd_bulk_state_count += 1;
                    self.bwd_bulk_packet_count += self.bwd_bulk_packet_count_help;
                    self.bwd_bulk_size_total += self.bwd_bulk_size_help;
                    self.bwd_bulk_duration += timestamp
                        .duration_since(self.bwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
                // continu bulk
                else if self.bwd_bulk_packet_count_help > 4 {
                    self.bwd_bulk_packet_count += 1;
                    self.bwd_bulk_size_total += len;
                    self.bwd_bulk_duration += timestamp
                        .duration_since(self.bwd_bulk_start_help.unwrap())
                        .as_micros() as f64;
                }
            }
            self.bwd_last_bulk_timestamp = Some(*timestamp);
        }
    }

    fn update_subflows(&mut self, timestamp: &Instant) {
        if self.sf_last_packet_timestamp == None {
            self.sf_last_packet_timestamp = Some(*timestamp);
        }

        if timestamp.duration_since(self.sf_last_packet_timestamp.unwrap()).as_secs_f64() > 1.0 {
            self.sf_count += 1;
            self.update_active_idle_time(timestamp, 5_000_000.0);
        }

        self.sf_last_packet_timestamp = Some(*timestamp);
    }

    fn update_active_idle_time(&mut self, timestamp: &Instant, threshold: f64) {
        if timestamp.duration_since(self.end_active).as_micros() as f64 > threshold {
            let duration = self.end_active.duration_since(self.start_active);
            if duration.as_secs_f64() > 0.0 {
                self.update_active_flow(
                    duration.as_micros() as f64,
                );
            }
            self.update_idle_flow(timestamp.duration_since(self.end_active).as_micros() as f64);
            self.start_active = *timestamp;
            self.end_active = *timestamp;
        } else {
            self.end_active = *timestamp;
        }
    }

    // getters
    fn get_fwd_header_len_min(&self) -> u32 {
        if self.fwd_header_len_min == u32::MAX {
            0
        } else {
            self.fwd_header_len_min
        }
    }

    fn get_flow_iat_std(&self) -> f64 {
        if self.basic_flow.bwd_packet_count < 2 {
            return 0.0;
        }

        let fwd_iat_std_squared = self.fwd_iat_std.powi(2);
        let bwd_iat_std_squared = self.bwd_iat_std.powi(2);

        let pooled_variance = ((self.basic_flow.fwd_packet_count - 1) as f64 * fwd_iat_std_squared
            + (self.basic_flow.bwd_packet_count - 1) as f64 * bwd_iat_std_squared)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count - 2) as f64;

        pooled_variance.sqrt()
    }

    fn get_flow_iat_mean(&self) -> f64 {
        (self.fwd_iat_mean * self.basic_flow.fwd_packet_count as f64
            + self.bwd_iat_mean * self.basic_flow.bwd_packet_count as f64)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f64
    }

    fn get_flow_iat_max(&self) -> f64 {
        if self.fwd_iat_max > self.bwd_iat_max {
            self.fwd_iat_max
        } else {
            self.bwd_iat_max
        }
    }

    fn get_flow_iat_min(&self) -> f64 {
        if self.fwd_iat_min < self.bwd_iat_min {
            if self.fwd_iat_min == f64::MAX {
                0.0
            } else {
                self.fwd_iat_min
            }
        } else {
            if self.bwd_iat_min == f64::MAX {
                0.0
            } else {
                self.bwd_iat_min
            }
        }
    }

    fn get_fwd_iat_min(&self) -> f64 {
        if self.fwd_iat_min == f64::MAX {
            0.0
        } else {
            self.fwd_iat_min
        }
    }

    fn get_bwd_iat_min(&self) -> f64 {
        if self.bwd_iat_min == f64::MAX {
            0.0
        } else {
            self.bwd_iat_min
        }
    }

    fn get_flow_packet_length_min(&self) -> u32 {
        if self.fwd_pkt_len_min < self.bwd_pkt_len_min {
            if self.fwd_pkt_len_min == u32::MAX {
                0
            } else {
                self.fwd_pkt_len_min
            }
        } else {
            if self.bwd_pkt_len_min == u32::MAX {
                0
            } else {
                self.bwd_pkt_len_min
            }
        }
    }

    fn get_flow_packet_length_max(&self) -> u32 {
        if self.fwd_pkt_len_max > self.bwd_pkt_len_max {
            self.fwd_pkt_len_max
        } else {
            self.bwd_pkt_len_max
        }
    }

    fn get_fwd_packet_length_min(&self) -> u32 {
        if self.fwd_pkt_len_min == u32::MAX {
            0
        } else {
            self.fwd_pkt_len_min
        }
    }

    fn get_bwd_packet_length_min(&self) -> u32 {
        if self.bwd_pkt_len_min == u32::MAX {
            0
        } else {
            self.bwd_pkt_len_min
        }
    }

    fn get_flow_packet_length_mean(&self) -> f32 {
        (self.fwd_pkt_len_mean * self.basic_flow.fwd_packet_count as f32
            + self.bwd_pkt_len_mean * self.basic_flow.bwd_packet_count as f32) as f32
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f32
    }

    fn get_flow_packet_length_variance(&self) -> f64 {
        if self.basic_flow.fwd_packet_count < 1 || self.basic_flow.bwd_packet_count < 1 || self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count < 3{
            return 0.0;
        }

        let fwd_pkt_std_squared = self.fwd_pkt_len_std.powf(2.0);
        let bwd_pkt_std_squared = self.bwd_pkt_len_std.powf(2.0);

        ((self.basic_flow.fwd_packet_count - 1) as f64 * fwd_pkt_std_squared as f64
            + (self.basic_flow.bwd_packet_count - 1) as f64 * bwd_pkt_std_squared as f64)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count - 2) as f64
    }

    fn get_flow_packet_length_std(&self) -> f64 {
        self.get_flow_packet_length_variance().sqrt()
    }

    fn get_down_up_ratio(&self) -> f64 {
        if self.basic_flow.bwd_packet_count > 0 {
            return self.basic_flow.fwd_packet_count as f64
                / self.basic_flow.bwd_packet_count as f64;
        }

        0.0
    }

    fn get_fwd_packet_length_mean(&self) -> u32 {
        if self.basic_flow.fwd_packet_count == 0 {
            return 0;
        }
        self.fwd_pkt_len_tot / self.basic_flow.fwd_packet_count
    }

    fn get_bwd_packet_length_mean(&self) -> u32 {
        if self.basic_flow.bwd_packet_count == 0 {
            return 0;
        }
        self.bwd_pkt_len_tot / self.basic_flow.bwd_packet_count
    }

    /// Calculates the duration between two timestamps in microseconds.
    pub fn get_duration(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> f64 {
        let duration = end.signed_duration_since(start);
        duration.num_microseconds().unwrap() as f64
    }

    fn get_flow_bytes_s(&self) -> f64 {
        (self.fwd_pkt_len_tot + self.bwd_pkt_len_tot) as f64
            / (self.get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    fn get_flow_packets_s(&self) -> f64 {
        (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f64
            / (self.get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    fn get_fwd_packets_s(&self) -> f64 {
        self.basic_flow.fwd_packet_count as f64
            / (self.get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    fn get_bwd_packets_s(&self) -> f64 {
        self.basic_flow.bwd_packet_count as f64
            / (self.get_duration(
                self.basic_flow.first_timestamp,
                self.basic_flow.last_timestamp,
            ) / 1_000_000.0)
    }

    fn get_fwd_bytes_bulk(&self) -> f64 {
        if self.fwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.fwd_bulk_size_total as f64 / self.fwd_bulk_state_count as f64
    }

    fn get_fwd_packets_bulk(&self) -> f64 {
        if self.fwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.fwd_bulk_packet_count as f64 / self.fwd_bulk_state_count as f64
    }

    fn get_fwd_bulk_rate(&self) -> f64 {
        if self.fwd_bulk_duration == 0.0 {
            return 0.0;
        }

        self.fwd_bulk_size_total as f64 / (self.fwd_bulk_duration / 1_000_000.0)
    }

    fn get_bwd_bytes_bulk(&self) -> f64 {
        if self.bwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.bwd_bulk_size_total as f64 / self.bwd_bulk_state_count as f64
    }

    fn get_bwd_packets_bulk(&self) -> f64 {
        if self.bwd_bulk_state_count == 0 {
            return 0.0;
        }

        self.bwd_bulk_packet_count as f64 / self.bwd_bulk_state_count as f64
    }

    fn get_bwd_bulk_rate(&self) -> f64 {
        if self.bwd_bulk_duration == 0.0 {
            return 0.0;
        }

        self.bwd_bulk_size_total as f64 / (self.bwd_bulk_duration / 1_000_000.0)
    }

    fn get_sf_fwd_packets(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.basic_flow.fwd_packet_count as f64 / self.sf_count as f64
    }

    fn get_sf_fwd_bytes(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.fwd_pkt_len_tot as f64 / self.sf_count as f64
    }

    fn get_sf_bwd_packets(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.basic_flow.bwd_packet_count as f64 / self.sf_count as f64
    }

    fn get_sf_bwd_bytes(&self) -> f64 {
        if self.sf_count == 0 {
            return 0.0;
        }
        self.bwd_pkt_len_tot as f64 / self.sf_count as f64
    }

    fn get_active_min(&self) -> f64 {
        if self.active_min == f64::MAX {
            0.0
        } else {
            self.active_min
        }
    }

    fn get_idle_min(&self) -> f64 {
        if self.idle_min == f64::MAX {
            0.0
        } else {
            self.idle_min
        }
    }
}

impl Flow for CicFlow {
    fn update_flow(
        &mut self,
        packet: BasicFeatures,
        timestamp: &Instant,
        fwd: bool,
    ) -> Option<String> {
        self.basic_flow.update_flow(packet, fwd);
        self.update_subflows(timestamp);

        if fwd {
            self.update_fwd_pkt_len_stats(packet.data_length);
            self.update_fwd_header_len_min(packet.header_length);

            if self.basic_flow.fwd_packet_count > 1 {
                self.update_fwd_iat_stats(
                    timestamp
                        .duration_since(self.fwd_last_timestamp.unwrap())
                        .as_micros() as f64,
                );
            }

            if self.basic_flow.fwd_packet_count == 1 {
                self.fwd_init_win_bytes = packet.window_size;
            }

            if packet.data_length > 0 {
                self.fwd_act_data_pkt += 1;
            }

            self.update_fwd_bulk_stats(timestamp, packet.data_length);
            self.increase_fwd_header_length(packet.header_length);
            self.fwd_last_timestamp = Some(*timestamp);

        } else {
            self.update_bwd_pkt_len_stats(packet.data_length);

            if self.basic_flow.bwd_packet_count > 1 {
                self.update_bwd_iat_stats(
                    timestamp
                        .duration_since(self.bwd_last_timestamp.unwrap())
                        .as_micros() as f64,
                );
            }

            if self.basic_flow.bwd_packet_count == 1 {
                self.bwd_init_win_bytes = packet.window_size;
            }

            self.update_bwd_bulk_stats(timestamp, packet.data_length);
            self.increase_bwd_header_length(packet.header_length);
            self.bwd_last_timestamp = Some(*timestamp);
        }

        if self.basic_flow.flow_end_of_flow_ack > 0
            || self.basic_flow.fwd_rst_flag_count > 0
            || self.basic_flow.bwd_rst_flag_count > 0
        {
            return Some(self.dump());
        }

        None
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
            {},{},{},{}",
            self.basic_flow.flow_id,
            Ipv4Addr::from(self.basic_flow.ipv4_source),
            self.basic_flow.port_source,
            Ipv4Addr::from(self.basic_flow.ipv4_destination),
            self.basic_flow.port_destination,
            self.basic_flow.protocol,
            self.basic_flow.first_timestamp,
            self.get_duration(self.basic_flow.first_timestamp, self.basic_flow.last_timestamp),
            self.basic_flow.fwd_packet_count,
            self.basic_flow.bwd_packet_count,
            self.fwd_pkt_len_tot,
            self.bwd_pkt_len_tot,
            self.fwd_pkt_len_max,
            self.get_fwd_packet_length_min(),
            self.fwd_pkt_len_mean,
            self.fwd_pkt_len_std,
            self.bwd_pkt_len_max,
            self.get_bwd_packet_length_min(),
            self.bwd_pkt_len_mean,
            self.bwd_pkt_len_std,
            self.get_flow_bytes_s(),
            self.get_flow_packets_s(),
            self.get_flow_iat_mean(),
            self.get_flow_iat_std(),
            self.get_flow_iat_max(),
            self.get_flow_iat_min(),
            self.fwd_iat_total,
            self.fwd_iat_mean,
            self.fwd_iat_std,
            self.fwd_iat_max,
            self.get_fwd_iat_min(),
            self.bwd_iat_total,
            self.bwd_iat_mean,
            self.bwd_iat_std,
            self.bwd_iat_max,
            self.get_bwd_iat_min(),
            self.basic_flow.fwd_psh_flag_count,
            self.basic_flow.bwd_psh_flag_count,
            self.basic_flow.fwd_urg_flag_count,
            self.basic_flow.bwd_urg_flag_count,
            self.fwd_header_length,
            self.bwd_header_length,
            self.get_fwd_packets_s(),
            self.get_bwd_packets_s(),
            self.get_flow_packet_length_min(),
            self.get_flow_packet_length_max(),
            self.get_flow_packet_length_mean(),
            self.get_flow_packet_length_std(),
            self.get_flow_packet_length_variance(),
            self.basic_flow.fwd_fin_flag_count + self.basic_flow.bwd_fin_flag_count,
            self.basic_flow.fwd_syn_flag_count + self.basic_flow.bwd_syn_flag_count,
            self.basic_flow.fwd_rst_flag_count + self.basic_flow.bwd_rst_flag_count,
            self.basic_flow.fwd_psh_flag_count + self.basic_flow.bwd_psh_flag_count,
            self.basic_flow.fwd_ack_flag_count + self.basic_flow.bwd_ack_flag_count,
            self.basic_flow.fwd_urg_flag_count + self.basic_flow.bwd_urg_flag_count,
            self.basic_flow.fwd_cwe_flag_count + self.basic_flow.bwd_cwe_flag_count,
            self.basic_flow.fwd_ece_flag_count + self.basic_flow.bwd_ece_flag_count,
            self.get_down_up_ratio(),
            self.get_flow_packet_length_mean(), // this is a duplicate feature
            self.get_fwd_packet_length_mean(),
            self.get_bwd_packet_length_mean(),
            self.fwd_header_length, // this is a duplicate feature
            self.get_fwd_bytes_bulk(),
            self.get_fwd_packets_bulk(),
            self.get_fwd_bulk_rate(),
            self.get_bwd_bytes_bulk(),
            self.get_bwd_packets_bulk(),
            self.get_bwd_bulk_rate(),
            self.get_sf_fwd_packets(),
            self.get_sf_fwd_bytes(),
            self.get_sf_bwd_packets(),
            self.get_sf_bwd_bytes(),
            self.fwd_init_win_bytes,
            self.bwd_init_win_bytes,
            self.fwd_act_data_pkt,
            self.get_fwd_header_len_min(), // known as min_seg_size_forward but this is actually the min header length in the forward direction
            self.active_mean,
            self.active_std,
            self.active_max,
            self.get_active_min(),
            self.idle_mean,
            self.idle_std,
            self.idle_max,
            self.get_idle_min(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::flows::{cic_flow::CicFlow, flow::Flow};
    use common::BasicFeatures;
    use std::time::{Duration, Instant};

    fn setup_cic_flow() -> CicFlow {
        CicFlow::new("".to_string(), 1, 80, 2, 8080, 6)
    }

    #[test]
    fn test_increase_fwd_header_length() {
        let mut cic_flow = setup_cic_flow();

        let initial_length = cic_flow.fwd_header_length;

        cic_flow.increase_fwd_header_length(20);
        assert_eq!(cic_flow.fwd_header_length, initial_length + 20);

        cic_flow.increase_fwd_header_length(0);
        assert_eq!(cic_flow.fwd_header_length, initial_length + 20);
    }

    #[test]
    fn test_increase_bwd_header_length() {
        let mut cic_flow = setup_cic_flow();

        let initial_length = cic_flow.bwd_header_length;

        cic_flow.increase_bwd_header_length(30);
        assert_eq!(cic_flow.bwd_header_length, initial_length + 30);

        cic_flow.increase_bwd_header_length(0);
        assert_eq!(cic_flow.bwd_header_length, initial_length + 30);
    }

    #[test]
    fn test_update_fwd_pkt_len_stats() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.fwd_packet_count = 1;

        cic_flow.update_fwd_pkt_len_stats(100);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 100);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 100.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 100);

        cic_flow.basic_flow.fwd_packet_count = 2;

        cic_flow.update_fwd_pkt_len_stats(50);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 50);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 75.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 25.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 150);

        cic_flow.basic_flow.fwd_packet_count = 3;

        cic_flow.update_fwd_pkt_len_stats(0);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 0);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 50.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 40.824829046386306);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 150);
    }

    #[test]
    fn test_update_bwd_pkt_len_stats() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.bwd_packet_count = 1;

        cic_flow.update_bwd_pkt_len_stats(100);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 100);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 100.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 100);

        cic_flow.basic_flow.bwd_packet_count = 2;

        cic_flow.update_bwd_pkt_len_stats(50);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 50);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 75.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 25.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 150);

        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.update_bwd_pkt_len_stats(0);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 0);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 50.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 40.824829046386306);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 150);
    }

    #[test]
    fn test_update_fwd_iat_stats() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-9; // floating-point arithmetic is not exact

        cic_flow.basic_flow.fwd_packet_count = 2;

        cic_flow.update_fwd_iat_stats(0.05);

        assert_eq!(cic_flow.fwd_iat_max, 0.05);
        assert_eq!(cic_flow.fwd_iat_min, 0.05);
        assert_eq!(cic_flow.fwd_iat_mean, 0.05);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.05);

        cic_flow.basic_flow.fwd_packet_count = 3;

        cic_flow.update_fwd_iat_stats(0.01);

        assert_eq!(cic_flow.fwd_iat_max, 0.05);
        assert_eq!(cic_flow.fwd_iat_min, 0.01);
        assert!(
            (cic_flow.fwd_iat_mean - 0.03).abs() < epsilon,
            "fwd_iat_mean is not within the expected range"
        );
        assert_eq!(cic_flow.fwd_iat_std, 0.02);
        assert!(
            (cic_flow.fwd_iat_total - 0.06).abs() < epsilon,
            "fwd_iat_total is not within the expected range"
        );

        cic_flow.basic_flow.fwd_packet_count = 4;

        cic_flow.update_fwd_iat_stats(0.698456231458);

        assert_eq!(cic_flow.fwd_iat_max, 0.698456231458);
        assert_eq!(cic_flow.fwd_iat_min, 0.01);
        assert_eq!(cic_flow.fwd_iat_mean, 0.25281874381933334);
        assert_eq!(cic_flow.fwd_iat_std, 0.31553613400230096);
        assert_eq!(cic_flow.fwd_iat_total, 0.758456231458);
    }

    #[test]
    fn test_update_bwd_iat_stats() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-9; // floating-point arithmetic is not exact

        cic_flow.basic_flow.bwd_packet_count = 2;

        cic_flow.update_bwd_iat_stats(0.05);

        assert_eq!(cic_flow.bwd_iat_max, 0.05);
        assert_eq!(cic_flow.bwd_iat_min, 0.05);
        assert_eq!(cic_flow.bwd_iat_mean, 0.05);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.05);

        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.update_bwd_iat_stats(0.01);

        assert_eq!(cic_flow.bwd_iat_max, 0.05);
        assert_eq!(cic_flow.bwd_iat_min, 0.01);
        assert!(
            (cic_flow.bwd_iat_mean - 0.03).abs() < epsilon,
            "fwd_iat_mean is not within the expected range"
        );
        assert_eq!(cic_flow.bwd_iat_std, 0.02);
        assert!(
            (cic_flow.bwd_iat_total - 0.06).abs() < epsilon,
            "fwd_iat_total is not within the expected range"
        );

        cic_flow.basic_flow.bwd_packet_count = 4;

        cic_flow.update_bwd_iat_stats(0.698456231458);

        assert_eq!(cic_flow.bwd_iat_max, 0.698456231458);
        assert_eq!(cic_flow.bwd_iat_min, 0.01);
        assert_eq!(cic_flow.bwd_iat_mean, 0.25281874381933334);
        assert_eq!(cic_flow.bwd_iat_std, 0.31553613400230096);
        assert_eq!(cic_flow.bwd_iat_total, 0.758456231458);
    }

    #[test]
    fn test_update_fwd_bulk_stats() {
        let mut cic_flow = setup_cic_flow();
        let timestamp = Instant::now();
        let timestamp_2 = Instant::now();
        let timestamp_3 = Instant::now();
        let timestamp_4 = Instant::now();

        cic_flow.update_fwd_bulk_stats(&timestamp, 100);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 100);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_fwd_bulk_stats(&timestamp_2, 200);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 300);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_fwd_bulk_stats(&timestamp_3, 150);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 450);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_fwd_bulk_stats(&timestamp_4, 50);

        assert_eq!(cic_flow.fwd_bulk_state_count, 1);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.fwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.fwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 4);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 500);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_4));

        std::thread::sleep(std::time::Duration::from_secs(1));

        let new_timestamp = Instant::now();

        cic_flow.update_fwd_bulk_stats(&new_timestamp, 50);

        assert_eq!(cic_flow.fwd_bulk_state_count, 1);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.fwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.fwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(new_timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 50);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(new_timestamp));
    }

    #[test]
    fn test_update_bwd_bulk_stats() {
        let mut cic_flow = setup_cic_flow();
        let timestamp = Instant::now();
        let timestamp_2 = Instant::now();
        let timestamp_3 = Instant::now();
        let timestamp_4 = Instant::now();

        cic_flow.update_bwd_bulk_stats(&timestamp, 100);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 100);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_bwd_bulk_stats(&timestamp_2, 200);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 300);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_bwd_bulk_stats(&timestamp_3, 150);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 450);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_bwd_bulk_stats(&timestamp_4, 50);

        assert_eq!(cic_flow.bwd_bulk_state_count, 1);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.bwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.bwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 4);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 500);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_4));

        std::thread::sleep(std::time::Duration::from_secs(1));

        let new_timestamp = Instant::now();

        cic_flow.update_bwd_bulk_stats(&new_timestamp, 50);

        assert_eq!(cic_flow.bwd_bulk_state_count, 1);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.bwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.bwd_bulk_duration,
            timestamp_4.duration_since(timestamp).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(new_timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 50);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(new_timestamp));
    }

    #[test]
    fn test_update_active_flow() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.update_active_flow(100.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 100.0);
        assert_eq!(cic_flow.active_mean, 100.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.active_count, 1);

        cic_flow.update_active_flow(50.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 50.0);
        assert_eq!(cic_flow.active_mean, 75.0);
        assert_eq!(cic_flow.active_std, 25.0);
        assert_eq!(cic_flow.active_count, 2);

        cic_flow.update_active_flow(0.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 0.0);
        assert_eq!(cic_flow.active_mean, 50.0);
        assert_eq!(cic_flow.active_std, 40.824829046386306);
        assert_eq!(cic_flow.active_count, 3);
    }

    #[test]
    fn test_update_idle_flow() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.update_idle_flow(100.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 100.0);
        assert_eq!(cic_flow.idle_mean, 100.0);
        assert_eq!(cic_flow.idle_std, 0.0);
        assert_eq!(cic_flow.idle_count, 1);

        cic_flow.update_idle_flow(50.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 50.0);
        assert_eq!(cic_flow.idle_mean, 75.0);
        assert_eq!(cic_flow.idle_std, 25.0);
        assert_eq!(cic_flow.idle_count, 2);

        cic_flow.update_idle_flow(0.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 0.0);
        assert_eq!(cic_flow.idle_mean, 50.0);
        assert_eq!(cic_flow.idle_std, 40.824829046386306);
        assert_eq!(cic_flow.idle_count, 3);
    }

    #[test]
    fn test_update_active_idle_time() {
        let mut cic_flow = setup_cic_flow();
    
        let threshold = 60_000_000.0;
    
        let timestamp = Instant::now();
        let timestamp_2 = timestamp + Duration::new(30, 0); // 30 seconds later
        let timestamp_3 = timestamp + Duration::new(91, 0); // 90 seconds later
    
        cic_flow.update_active_idle_time(&timestamp, threshold);

        assert_eq!(cic_flow.end_active, timestamp);
        assert_ne!(cic_flow.start_active, timestamp);
        assert_eq!(cic_flow.active_count, 0);
        assert_eq!(cic_flow.active_max, 0.0);
        assert_eq!(cic_flow.active_min, f64::MAX);
        assert_eq!(cic_flow.active_mean, 0.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.idle_count, 0);
        assert_eq!(cic_flow.idle_max, 0.0);
        assert_eq!(cic_flow.idle_min, f64::MAX);
        assert_eq!(cic_flow.idle_mean, 0.0);
        assert_eq!(cic_flow.idle_std, 0.0);
    
        cic_flow.update_active_idle_time(&timestamp_2, threshold);
        
        assert_eq!(cic_flow.end_active, timestamp_2);
        assert_ne!(cic_flow.start_active, timestamp_2);
        assert_eq!(cic_flow.active_count, 0);
        assert_eq!(cic_flow.active_max, 0.0);
        assert_eq!(cic_flow.active_min, f64::MAX);
        assert_eq!(cic_flow.active_mean, 0.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.idle_count, 0);
        assert_eq!(cic_flow.idle_max, 0.0);
        assert_eq!(cic_flow.idle_min, f64::MAX);
        assert_eq!(cic_flow.idle_mean, 0.0);
        assert_eq!(cic_flow.idle_std, 0.0);
    
        cic_flow.update_active_idle_time(&timestamp_3, threshold);
        assert_eq!(cic_flow.end_active, timestamp_3);
        assert_eq!(cic_flow.start_active, timestamp_3);
        assert_eq!(cic_flow.active_count, 1);
        assert_ne!(cic_flow.active_max, 0.0);
        assert_ne!(cic_flow.active_min, f64::MAX);
        assert_ne!(cic_flow.active_mean, 0.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.idle_count, 1);
        assert_ne!(cic_flow.idle_max, 0.0);
        assert_ne!(cic_flow.idle_min, f64::MAX);
        assert_ne!(cic_flow.idle_mean, 0.0);
        assert_eq!(cic_flow.idle_std, 0.0);
    
    }

    #[test]
    fn test_get_flow_iat_mean() {
        let mut cic_flow = setup_cic_flow();

        //let forward_iat = [1.0, 2.0, 3.0, 4.0, 5.0];
        //let backward_iat = [1.5, 2.5, 3.5];

        cic_flow.fwd_iat_mean = 3.0;
        cic_flow.bwd_iat_mean = 2.5;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_iat_mean(), 2.8125);
    }

    #[test]
    fn test_get_flow_iat_std() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-2; // floating-point arithmetic is not exact, here we have a lot of casting and the formula is also an approximation

        //let forward_iat = [1.0, 2.0, 3.0, 4.0, 5.0];
        //let backward_iat = [1.5, 2.5, 3.5];

        cic_flow.fwd_iat_mean = 3.0;
        cic_flow.bwd_iat_mean = 2.5;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.fwd_iat_std = 1.4142135623731;
        cic_flow.bwd_iat_std = 0.81649658092773;

        assert!(
            (cic_flow.get_flow_iat_std() - 1.2484365222149).abs() < epsilon,
            "get_flow_iat_std is not within the expected range"
        );
    }

    #[test]
    fn test_get_flow_iat_max() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_iat_max = 5.0;
        cic_flow.bwd_iat_max = 3.0;

        assert_eq!(cic_flow.get_flow_iat_max(), 5.0);
    }

    #[test]
    fn test_get_flow_iat_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_flow_iat_min(), 0.0);

        cic_flow.fwd_iat_min = 1.0;
        cic_flow.bwd_iat_min = 2.0;

        assert_eq!(cic_flow.get_flow_iat_min(), 1.0);
    }

    #[test]
    fn test_get_fwd_iat_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_iat_min(), 0.0);

        cic_flow.fwd_iat_min = 1.0;

        assert_eq!(cic_flow.get_fwd_iat_min(), 1.0);
    }

    #[test]
    fn test_get_bwd_iat_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_iat_min(), 0.0);

        cic_flow.bwd_iat_min = 2.0;

        assert_eq!(cic_flow.get_bwd_iat_min(), 2.0);
    }

    #[test]
    fn test_get_flow_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_flow_packet_length_min(), 0);

        cic_flow.fwd_pkt_len_min = 50;
        cic_flow.bwd_pkt_len_min = 100;

        assert_eq!(cic_flow.get_flow_packet_length_min(), 50);
    }

    #[test]
    fn test_get_fwd_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_packet_length_min(), 0);

        cic_flow.fwd_pkt_len_min = 50;

        assert_eq!(cic_flow.get_fwd_packet_length_min(), 50);
    }

    #[test]
    fn test_get_bwd_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_packet_length_min(), 0);

        cic_flow.bwd_pkt_len_min = 100;

        assert_eq!(cic_flow.get_bwd_packet_length_min(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_max() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_pkt_len_max = 100;
        cic_flow.bwd_pkt_len_max = 50;

        assert_eq!(cic_flow.get_flow_packet_length_max(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_mean() {
        let mut cic_flow = setup_cic_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_pkt_len_mean = 30.0;
        cic_flow.bwd_pkt_len_mean = 25.0;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_packet_length_mean(), 28.125);
    }

    #[test]
    fn test_get_flow_packet_length_variance() {
        let mut cic_flow = setup_cic_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_pkt_len_std = 14.142135623731;
        cic_flow.bwd_pkt_len_std = 8.1649658092773;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_packet_length_variance() as u32, 155); // removing everything behind the comma because of arithmetic errors
    }

    #[test]
    fn test_get_flow_packet_length_std() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-1; // floating-point arithmetic is not exact, here we have a lot of casting and the formula is also an approximation

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_pkt_len_std = 14.142135623731;
        cic_flow.bwd_pkt_len_std = 8.1649658092773;

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert!(
            (cic_flow.get_flow_packet_length_std() - 12.484365222149).abs() < epsilon,
            "get_flow_packet_length_std is not within the expected range"
        );
    }

    #[test]
    fn test_get_up_down_ratio() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_down_up_ratio(), 5 as f64 / 3 as f64);
    }

    #[test]
    fn test_get_fwd_packet_length_mean() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_pkt_len_tot = 100;
        cic_flow.basic_flow.fwd_packet_count = 5;

        assert_eq!(cic_flow.get_fwd_packet_length_mean(), 20);
    }

    #[test]
    fn test_get_bwd_packet_length_mean() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.bwd_pkt_len_tot = 100;
        cic_flow.basic_flow.bwd_packet_count = 5;

        assert_eq!(cic_flow.get_bwd_packet_length_mean(), 20);
    }

    #[test]
    fn test_get_duration() {
        let cic_flow = setup_cic_flow();

        let start = chrono::Utc::now();
        let end = chrono::Utc::now() + chrono::Duration::seconds(5);

        assert_eq!(cic_flow.get_duration(start, end), 5_000_000.0);
    }

    #[test]
    fn test_get_flow_bytes_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp = chrono::Utc::now() + chrono::Duration::seconds(5);

        cic_flow.fwd_pkt_len_tot = 100;
        cic_flow.bwd_pkt_len_tot = 100;

        assert_eq!(cic_flow.get_flow_bytes_s(), 40.0);
    }

    #[test]
    fn test_get_flow_packets_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp = chrono::Utc::now() + chrono::Duration::seconds(5);

        cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.basic_flow.bwd_packet_count = 5;

        assert_eq!(cic_flow.get_flow_packets_s(), 2.0);
    }

    #[test]
    fn test_get_fwd_packets_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp = chrono::Utc::now() + chrono::Duration::seconds(5);

        cic_flow.basic_flow.fwd_packet_count = 5;

        assert_eq!(cic_flow.get_fwd_packets_s(), 1.0);
    }

    #[test]
    fn test_get_bwd_packets_s() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.first_timestamp = chrono::Utc::now();
        cic_flow.basic_flow.last_timestamp = chrono::Utc::now() + chrono::Duration::seconds(5);

        cic_flow.basic_flow.bwd_packet_count = 5;

        assert_eq!(cic_flow.get_bwd_packets_s(), 1.0);
    }

    #[test]
    fn test_get_fwd_bytes_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_bytes_bulk(), 0.0);

        cic_flow.fwd_bulk_size_total = 100;
        cic_flow.fwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_fwd_bytes_bulk(), 20.0);
    }

    #[test]
    fn test_get_fwd_packets_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_packets_bulk(), 0.0);

        cic_flow.fwd_bulk_packet_count = 100;
        cic_flow.fwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_fwd_packets_bulk(), 20.0);
    }

    #[test]
    fn test_get_fwd_bulk_rate() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_fwd_bulk_rate(), 0.0);

        cic_flow.fwd_bulk_size_total = 100;
        cic_flow.fwd_bulk_duration = 5_000_000.0;

        assert_eq!(cic_flow.get_fwd_bulk_rate(), 20.0);
    }

    #[test]
    fn test_get_bwd_bytes_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_bytes_bulk(), 0.0);

        cic_flow.bwd_bulk_size_total = 100;
        cic_flow.bwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_bwd_bytes_bulk(), 20.0);
    }

    #[test]
    fn test_get_bwd_packets_bulk() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_packets_bulk(), 0.0);

        cic_flow.bwd_bulk_packet_count = 100;
        cic_flow.bwd_bulk_state_count = 5;

        assert_eq!(cic_flow.get_bwd_packets_bulk(), 20.0);
    }

    #[test]
    fn test_get_bwd_bulk_rate() {
        let mut cic_flow = setup_cic_flow();

        assert_eq!(cic_flow.get_bwd_bulk_rate(), 0.0);

        cic_flow.bwd_bulk_size_total = 100;
        cic_flow.bwd_bulk_duration = 5_000_000.0;

        assert_eq!(cic_flow.get_bwd_bulk_rate(), 20.0);
    }

    #[test]
    fn test_update_flow_first_with_fwd_packet() {
        let mut cic_flow = CicFlow::new("".to_string(), 1, 80, 2, 8080, 6);
        let packet = BasicFeatures {
            ipv4_destination: 2,
            ipv4_source: 1,
            port_destination: 8080,
            port_source: 80,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp = Instant::now();

        cic_flow.update_flow(packet, &timestamp, true);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 1);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 0);
        assert_eq!(cic_flow.fwd_pkt_len_max, 25);
        assert_eq!(cic_flow.fwd_pkt_len_min, 25);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 25.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 25);
        assert_eq!(cic_flow.fwd_iat_max, 0.0);
        assert_eq!(cic_flow.fwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.fwd_iat_mean, 0.0);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.0);
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 25);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp));
        assert_eq!(cic_flow.fwd_header_length, 40);
        assert_eq!(cic_flow.fwd_last_timestamp, Some(timestamp));
        assert_eq!(cic_flow.fwd_init_win_bytes, 500);
        assert_eq!(cic_flow.bwd_header_length, 0);
        assert_eq!(cic_flow.bwd_last_timestamp, None);
        assert_eq!(cic_flow.bwd_pkt_len_max, 0);
        assert_eq!(cic_flow.bwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.bwd_iat_max, 0.0);
        assert_eq!(cic_flow.bwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.bwd_iat_mean, 0.0);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.0);
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.bwd_bulk_start_help, None);
        assert_eq!(cic_flow.bwd_bulk_size_help, 0);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.bwd_init_win_bytes, 0);
    }

    #[test]
    fn test_update_flow_first_with_bwd_packet() {
        let mut cic_flow = CicFlow::new("".to_string(), 1, 80, 2, 8080, 6);
        let packet = BasicFeatures {
            ipv4_destination: 2,
            ipv4_source: 1,
            port_destination: 8080,
            port_source: 80,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp = Instant::now();

        cic_flow.update_flow(packet, &timestamp, false);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 0);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 1);
        assert_eq!(cic_flow.fwd_pkt_len_max, 0);
        assert_eq!(cic_flow.fwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.fwd_iat_max, 0.0);
        assert_eq!(cic_flow.fwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.fwd_iat_mean, 0.0);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.0);
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.fwd_bulk_start_help, None);
        assert_eq!(cic_flow.fwd_bulk_size_help, 0);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.fwd_header_length, 0);
        assert_eq!(cic_flow.fwd_last_timestamp, None);
        assert_eq!(cic_flow.fwd_init_win_bytes, 0);
        assert_eq!(cic_flow.bwd_header_length, 40);
        assert_eq!(cic_flow.bwd_last_timestamp, Some(timestamp));
        assert_eq!(cic_flow.bwd_pkt_len_max, 25);
        assert_eq!(cic_flow.bwd_pkt_len_min, 25);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 25.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 25);
        assert_eq!(cic_flow.bwd_iat_max, 0.0);
        assert_eq!(cic_flow.bwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.bwd_iat_mean, 0.0);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.0);
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 25);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp));
        assert_eq!(cic_flow.bwd_init_win_bytes, 500);
    }

    #[test]
    fn test_update_flow_with_fwd_packet() {
        let mut cic_flow = CicFlow::new("".to_string(), 1, 80, 2, 8080, 6);
        let packet_1 = BasicFeatures {
            ipv4_destination: 2,
            ipv4_source: 1,
            port_destination: 8080,
            port_source: 80,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp_1 = Instant::now();

        cic_flow.update_flow(packet_1, &timestamp_1, true);

        std::thread::sleep(std::time::Duration::from_secs(1));

        let packet_2 = BasicFeatures {
            ipv4_destination: 2,
            ipv4_source: 1,
            port_destination: 8080,
            port_source: 80,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 50,
            header_length: 40,
            length: 100,
            window_size: 100,
        };
        let timestamp_2 = Instant::now();

        cic_flow.update_flow(packet_2, &timestamp_2, true);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 2);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 0);
        assert_eq!(cic_flow.fwd_pkt_len_max, 50);
        assert_eq!(cic_flow.fwd_pkt_len_min, 25);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 37.5);
        assert_eq!(cic_flow.fwd_pkt_len_std, 12.5);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 75);
        assert_eq!(
            cic_flow.fwd_iat_max,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.fwd_iat_min,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.fwd_iat_mean,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(
            cic_flow.fwd_iat_total,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp_2));
        assert_eq!(cic_flow.fwd_bulk_size_help, 50);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.fwd_header_length, 80);
        assert_eq!(cic_flow.fwd_last_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.fwd_init_win_bytes, 500);
        assert_eq!(cic_flow.bwd_header_length, 0);
        assert_eq!(cic_flow.bwd_last_timestamp, None);
        assert_eq!(cic_flow.bwd_pkt_len_max, 0);
        assert_eq!(cic_flow.bwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.bwd_iat_max, 0.0);
        assert_eq!(cic_flow.bwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.bwd_iat_mean, 0.0);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.0);
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.bwd_bulk_start_help, None);
        assert_eq!(cic_flow.bwd_bulk_size_help, 0);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.bwd_init_win_bytes, 0);
    }

    #[test]
    fn test_update_flow_with_bwd_packet() {
        let mut cic_flow = CicFlow::new("".to_string(), 1, 80, 2, 8080, 6);
        let packet_1 = BasicFeatures {
            ipv4_destination: 2,
            ipv4_source: 1,
            port_destination: 8080,
            port_source: 80,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 25,
            header_length: 40,
            length: 80,
            window_size: 500,
        };
        let timestamp_1 = Instant::now();

        cic_flow.update_flow(packet_1, &timestamp_1, false);

        std::thread::sleep(std::time::Duration::from_secs(1));

        let packet_2 = BasicFeatures {
            ipv4_destination: 2,
            ipv4_source: 1,
            port_destination: 8080,
            port_source: 80,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 1,
            data_length: 50,
            header_length: 40,
            length: 100,
            window_size: 100,
        };
        let timestamp_2 = Instant::now();

        cic_flow.update_flow(packet_2, &timestamp_2, false);

        assert_eq!(cic_flow.basic_flow.fwd_packet_count, 0);
        assert_eq!(cic_flow.basic_flow.bwd_packet_count, 2);
        assert_eq!(cic_flow.fwd_pkt_len_max, 0);
        assert_eq!(cic_flow.fwd_pkt_len_min, u32::MAX);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 0);
        assert_eq!(cic_flow.fwd_iat_max, 0.0);
        assert_eq!(cic_flow.fwd_iat_min, f64::MAX);
        assert_eq!(cic_flow.fwd_iat_mean, 0.0);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.0);
        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 0);
        assert_eq!(cic_flow.fwd_bulk_start_help, None);
        assert_eq!(cic_flow.fwd_bulk_size_help, 0);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, None);
        assert_eq!(cic_flow.fwd_header_length, 0);
        assert_eq!(cic_flow.fwd_last_timestamp, None);
        assert_eq!(cic_flow.fwd_init_win_bytes, 0);
        assert_eq!(cic_flow.bwd_header_length, 80);
        assert_eq!(cic_flow.bwd_last_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.bwd_pkt_len_max, 50);
        assert_eq!(cic_flow.bwd_pkt_len_min, 25);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 37.5);
        assert_eq!(cic_flow.bwd_pkt_len_std, 12.5);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 75);
        assert_eq!(
            cic_flow.bwd_iat_max,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.bwd_iat_min,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(
            cic_flow.bwd_iat_mean,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(
            cic_flow.bwd_iat_total,
            timestamp_2.duration_since(timestamp_1).as_micros() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp_2));
        assert_eq!(cic_flow.bwd_bulk_size_help, 50);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_2));
        assert_eq!(cic_flow.bwd_init_win_bytes, 500);
    }
}
