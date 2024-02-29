use std::time::Instant;

use chrono::{DateTime, Utc};
use common::BasicFeatures;

use super::{basic_flow::BasicFlow, flow::Flow};
pub struct CicFlow {
    // BasicFlow
    pub basic_flow: BasicFlow,
    // General
    pub iat_mean: f64,
    pub iat_std: f64,
    pub iat_max: f64,
    pub iat_min: f64,
    // Forward
    pub fwd_last_timestamp: Option<Instant>,
    pub fwd_pkt_len_tot: u32,
    pub fwd_pkt_len_max: u32,
    pub fwd_pkt_len_min: u32,
    pub fwd_pkt_len_mean: f32,
    pub fwd_pkt_len_std: f64,
    pub fwd_iat_total: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_std: f64,
    pub fwd_iat_max: f64,
    pub fwd_iat_min: f64,
    pub fwd_header_length: u32,
    pub fwd_bulk_duration: f64,
    pub fwd_bulk_packet_count: u64,
    pub fwd_bulk_size_total: u32,
    pub fwd_bulk_state_count: u64,
    pub fwd_bulk_packet_count_help: u64,
    pub fwd_bulk_start_help: Option<Instant>,
    pub fwd_bulk_size_help: u32,
    pub fwd_last_bulk_timestamp: Option<Instant>,
    // Backward
    pub bwd_last_timestamp: Option<Instant>,
    pub bwd_pkt_len_tot: u32,
    pub bwd_pkt_len_max: u32,
    pub bwd_pkt_len_min: u32,
    pub bwd_pkt_len_mean: f32,
    pub bwd_pkt_len_std: f64,
    pub bwd_iat_total: f64,
    pub bwd_iat_mean: f64,
    pub bwd_iat_std: f64,
    pub bwd_iat_max: f64,
    pub bwd_iat_min: f64,
    pub bwd_header_length: u32,
    pub bwd_bulk_duration: f64,
    pub bwd_bulk_packet_count: u64,
    pub bwd_bulk_size_total: u32,
    pub bwd_bulk_state_count: u64,
    pub bwd_bulk_packet_count_help: u64,
    pub bwd_bulk_start_help: Option<Instant>,
    pub bwd_bulk_size_help: u32,
    pub bwd_last_bulk_timestamp: Option<Instant>,
}

impl CicFlow {
    pub fn new(
        ipv4_source: u32,
        port_source: u16,
        ipv4_destination: u32,
        port_destination: u16,
        protocol: u8,
    ) -> Self {
        CicFlow {
            basic_flow: BasicFlow::new(
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
            ),
            iat_mean: 0.0,
            iat_std: 0.0,
            iat_max: 0.0,
            iat_min: f64::MAX,
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

    /// setters
    fn increase_fwd_header_length(&mut self, len: u32) {
        self.fwd_header_length += len;
    }

    fn increase_bwd_header_length(&mut self, len: u32) {
        self.bwd_header_length += len;
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

        // handle the first packet
        if self.basic_flow.fwd_packet_count == 1 {
            self.fwd_pkt_len_mean = len as f32;
            self.fwd_pkt_len_std = 0.0;
            return;
        }

        // handle the second packet
        if self.basic_flow.fwd_packet_count == 2 {
            let new_fwd_pkt_len_mean = (self.fwd_pkt_len_mean as f64 + len as f64) / 2.0;
            self.fwd_pkt_len_std = ((self.fwd_pkt_len_mean as f64 - new_fwd_pkt_len_mean).powi(2)
                + (len as f64 - new_fwd_pkt_len_mean).powi(2))
                / 2.0;
            self.fwd_pkt_len_std = self.fwd_pkt_len_std.sqrt();
            self.fwd_pkt_len_mean = new_fwd_pkt_len_mean as f32;
            return;
        }

        // update mean and std
        let new_fwd_pkt_len_mean =
            (((self.basic_flow.fwd_packet_count - 1) as f32 * self.fwd_pkt_len_mean) + len as f32)
                / self.basic_flow.fwd_packet_count as f32;
        self.fwd_pkt_len_std = ((((self.basic_flow.fwd_packet_count - 1) as f64
            * self.fwd_pkt_len_std.powf(2.0))
            + ((len as f64 - self.fwd_pkt_len_mean as f64)
                * (len as f64 - new_fwd_pkt_len_mean as f64)))
            / self.basic_flow.fwd_packet_count as f64)
            .sqrt();
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

        // handle the first packet
        if self.basic_flow.bwd_packet_count == 1 {
            self.bwd_pkt_len_mean = len as f32;
            self.bwd_pkt_len_std = 0.0;
            return;
        }

        // handle the second packet
        if self.basic_flow.bwd_packet_count == 2 {
            let new_bwd_pkt_len_mean = (self.bwd_pkt_len_mean as f64 + len as f64) / 2.0;
            self.bwd_pkt_len_std = ((self.bwd_pkt_len_mean as f64 - new_bwd_pkt_len_mean).powi(2)
                + (len as f64 - new_bwd_pkt_len_mean).powi(2))
                / 2.0;
            self.bwd_pkt_len_std = self.bwd_pkt_len_std.sqrt();
            self.bwd_pkt_len_mean = new_bwd_pkt_len_mean as f32;
            return;
        }

        // update mean and std
        let new_bwd_pkt_len_mean =
            (((self.basic_flow.bwd_packet_count - 1) as f32 * self.bwd_pkt_len_mean) + len as f32)
                / self.basic_flow.bwd_packet_count as f32;
        self.bwd_pkt_len_std = ((((self.basic_flow.bwd_packet_count - 1) as f64
            * self.bwd_pkt_len_std.powf(2.0))
            + ((len as f64 - self.bwd_pkt_len_mean as f64)
                * (len as f64 - new_bwd_pkt_len_mean as f64)))
            / self.basic_flow.bwd_packet_count as f64)
            .sqrt();
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

        // handle the second packet (the update is done in the second packet because the first packet is not a flow IAT)
        if self.basic_flow.fwd_packet_count == 2 {
            self.fwd_iat_mean = iat;
            self.fwd_iat_std = 0.0;
            return;
        }

        // handle the third packet
        if self.basic_flow.fwd_packet_count == 3 {
            let new_fwd_iat_mean = (self.fwd_iat_mean + iat) / 2.0;
            self.fwd_iat_std = ((self.fwd_iat_mean - new_fwd_iat_mean).powi(2)
                + (iat - new_fwd_iat_mean).powi(2))
                / 2.0;
            self.fwd_iat_std = self.fwd_iat_std.sqrt();
            self.fwd_iat_mean = new_fwd_iat_mean;
            return;
        }

        // update mean and std
        let new_fwd_iat_mean = ((self.basic_flow.fwd_packet_count - 2) as f64 * self.fwd_iat_mean
            + iat)
            / (self.basic_flow.fwd_packet_count - 1) as f64;
        self.fwd_iat_std = ((((self.basic_flow.fwd_packet_count - 2) as f64
            * self.fwd_iat_std.powf(2.0))
            + ((iat - self.fwd_iat_mean) * (iat - new_fwd_iat_mean)))
            / (self.basic_flow.fwd_packet_count - 1) as f64)
            .sqrt();
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

        // handle the second packet (the update is done in the second packet because the first packet is not a flow IAT)
        if self.basic_flow.bwd_packet_count == 2 {
            self.bwd_iat_mean = iat;
            self.bwd_iat_std = 0.0;
            return;
        }

        // handle the third packet
        if self.basic_flow.bwd_packet_count == 3 {
            let new_bwd_iat_mean = (self.bwd_iat_mean + iat) / 2.0;
            self.bwd_iat_std = ((self.bwd_iat_mean - new_bwd_iat_mean).powi(2)
                + (iat - new_bwd_iat_mean).powi(2))
                / 2.0;
            self.bwd_iat_std = self.bwd_iat_std.sqrt();
            self.bwd_iat_mean = new_bwd_iat_mean;
            return;
        }

        // update mean and std
        let new_bwd_iat_mean = ((self.basic_flow.bwd_packet_count - 2) as f64 * self.bwd_iat_mean
            + iat)
            / (self.basic_flow.bwd_packet_count - 1) as f64;
        self.bwd_iat_std = ((((self.basic_flow.bwd_packet_count - 2) as f64
            * self.bwd_iat_std.powf(2.0))
            + ((iat - self.bwd_iat_mean) * (iat - new_bwd_iat_mean)))
            / (self.basic_flow.bwd_packet_count - 1) as f64)
            .sqrt();
        self.bwd_iat_mean = new_bwd_iat_mean;
    }

    fn update_fwd_bulk_stats(&mut self, timestamp: Instant, len: u32) {
        if self.bwd_last_bulk_timestamp > self.fwd_bulk_start_help {
            self.fwd_bulk_start_help = None;
        }
        if len <= 0 {
            return;
        }

        if self.fwd_bulk_start_help == None {
            self.fwd_bulk_start_help = Some(timestamp);
            self.fwd_bulk_packet_count_help = 1;
            self.fwd_bulk_size_help = len;
            self.fwd_last_bulk_timestamp = Some(timestamp);
        } else {
            // too much idle time -> new bulk
            if timestamp
                .duration_since(self.fwd_last_bulk_timestamp.unwrap())
                .as_secs_f64()
                > 1.0
            {
                self.fwd_bulk_start_help = Some(timestamp);
                self.fwd_last_bulk_timestamp = Some(timestamp);
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
            self.fwd_last_bulk_timestamp = Some(timestamp);
        }
    }

    fn update_bwd_bulk_stats(&mut self, timestamp: Instant, len: u32) {
        if self.fwd_last_bulk_timestamp > self.bwd_bulk_start_help {
            self.bwd_bulk_start_help = None;
        }
        if len <= 0 {
            return;
        }

        if self.bwd_bulk_start_help == None {
            self.bwd_bulk_start_help = Some(timestamp);
            self.bwd_bulk_packet_count_help = 1;
            self.bwd_bulk_size_help = len;
            self.bwd_last_bulk_timestamp = Some(timestamp);
        } else {
            // to much idle time -> new bulk
            if timestamp
                .duration_since(self.bwd_last_bulk_timestamp.unwrap())
                .as_secs_f64()
                > 1.0
            {
                self.bwd_bulk_start_help = Some(timestamp);
                self.bwd_last_bulk_timestamp = Some(timestamp);
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
            self.bwd_last_bulk_timestamp = Some(timestamp);
        }
    }

    /// getters
    fn get_flow_iat_std(&self) -> f64 {
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
            self.fwd_iat_min
        } else {
            self.bwd_iat_min
        }
    }

    fn get_flow_packet_length_min(&self) -> u32 {
        if self.fwd_pkt_len_min < self.bwd_pkt_len_min {
            self.fwd_pkt_len_min
        } else {
            self.bwd_pkt_len_min
        }
    }

    fn get_flow_packet_length_max(&self) -> u32 {
        if self.fwd_pkt_len_max > self.bwd_pkt_len_max {
            self.fwd_pkt_len_max
        } else {
            self.bwd_pkt_len_max
        }
    }

    fn get_flow_packet_length_mean(&self) -> f32 {
        (self.fwd_pkt_len_mean * self.basic_flow.fwd_packet_count as f32
            + self.bwd_pkt_len_mean * self.basic_flow.bwd_packet_count as f32) as f32
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count) as f32
    }

    fn get_flow_packet_length_variance(&self) -> f64 {
        let fwd_pkt_std_squared = self.fwd_pkt_len_std.powf(2.0);
        let bwd_pkt_std_squared = self.bwd_pkt_len_std.powf(2.0);

        ((self.basic_flow.fwd_packet_count - 1) as f64 * fwd_pkt_std_squared as f64
            + (self.basic_flow.bwd_packet_count - 1) as f64 * bwd_pkt_std_squared as f64)
            / (self.basic_flow.fwd_packet_count + self.basic_flow.bwd_packet_count - 2) as f64
    }

    fn get_flow_packet_length_std(&self) -> f64 {
        self.get_flow_packet_length_variance().sqrt()
    }

    fn get_up_down_ratio(&self) -> f64 {
        if self.basic_flow.fwd_packet_count > 0 {
            return self.basic_flow.bwd_packet_count as f64
                / self.basic_flow.fwd_packet_count as f64;
        }

        0.0
    }

    fn get_fwd_packet_length_mean(&self) -> u32 {
        self.fwd_pkt_len_tot / self.basic_flow.fwd_packet_count
    }

    fn get_bwd_packet_length_mean(&self) -> u32 {
        self.bwd_pkt_len_tot / self.basic_flow.bwd_packet_count
    }

    fn get_duration(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> f64 {
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
}

impl Flow for CicFlow {
    fn update_flow(&mut self, packet: BasicFeatures, timestamp: Instant, fwd: bool) {
        self.basic_flow.update_flow(packet, fwd);
        if fwd {
            self.update_fwd_pkt_len_stats(packet.data_length);
            self.update_fwd_iat_stats(
                timestamp
                    .duration_since(self.fwd_last_timestamp.unwrap())
                    .as_micros() as f64,
            );
            self.update_fwd_bulk_stats(timestamp, packet.data_length);
            self.increase_fwd_header_length(packet.header_length);
            self.fwd_last_timestamp = Some(timestamp);
        } else {
            self.update_bwd_pkt_len_stats(packet.data_length);
            self.update_bwd_iat_stats(
                timestamp
                    .duration_since(self.bwd_last_timestamp.unwrap())
                    .as_micros() as f64,
            );
            self.update_bwd_bulk_stats(timestamp, packet.data_length);
            self.increase_bwd_header_length(packet.header_length);
            self.bwd_last_timestamp = Some(timestamp);
        }
    }

    fn update_flow_first(&mut self, packet: BasicFeatures, timestamp: Instant, fwd: bool) {
        self.basic_flow.update_flow(packet, fwd);
        if fwd {
            self.update_fwd_pkt_len_stats(packet.data_length);
            self.update_fwd_bulk_stats(timestamp, packet.data_length);
            self.increase_fwd_header_length(packet.header_length);
            self.fwd_last_timestamp = Some(timestamp);
        } else {
            self.update_bwd_pkt_len_stats(packet.data_length);
            self.update_bwd_bulk_stats(timestamp, packet.data_length);
            self.increase_bwd_header_length(packet.header_length);
            self.bwd_last_timestamp = Some(timestamp);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::flows::{cic_flow::CicFlow, flow::Flow};
    use common::BasicFeatures;
    use std::time::Instant;

    fn setup_cic_flow() -> CicFlow {
        CicFlow::new(1, 80, 2, 8080, 6)
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

        cic_flow.update_fwd_bulk_stats(timestamp, 100);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 100);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_fwd_bulk_stats(timestamp_2, 200);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 300);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_fwd_bulk_stats(timestamp_3, 150);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 450);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_fwd_bulk_stats(timestamp_4, 50);

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

        cic_flow.update_fwd_bulk_stats(new_timestamp, 50);

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

        cic_flow.update_bwd_bulk_stats(timestamp, 100);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 100);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_bwd_bulk_stats(timestamp_2, 200);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 300);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_bwd_bulk_stats(timestamp_3, 150);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 450);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_bwd_bulk_stats(timestamp_4, 50);

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

        cic_flow.update_bwd_bulk_stats(new_timestamp, 50);

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

        cic_flow.fwd_iat_min = 1.0;
        cic_flow.bwd_iat_min = 2.0;

        assert_eq!(cic_flow.get_flow_iat_min(), 1.0);
    }

    #[test]
    fn test_get_flow_packet_length_min() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.fwd_pkt_len_min = 50;
        cic_flow.bwd_pkt_len_min = 100;

        assert_eq!(cic_flow.get_flow_packet_length_min(), 50);
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

        assert_eq!(cic_flow.get_up_down_ratio(), 0.6);
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
    fn test_update_flow_first_with_fwd_packet() {
        let mut cic_flow = CicFlow::new(1, 80, 2, 8080, 6);
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
        };
        let timestamp = Instant::now();

        cic_flow.update_flow_first(packet, timestamp, true);

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
    }

    #[test]
    fn test_update_flow_first_with_bwd_packet() {
        let mut cic_flow = CicFlow::new(1, 80, 2, 8080, 6);
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
        };
        let timestamp = Instant::now();

        cic_flow.update_flow_first(packet, timestamp, false);

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
    }

    #[test]
    fn test_update_flow_with_fwd_packet() {
        let mut cic_flow = CicFlow::new(1, 80, 2, 8080, 6);
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
        };
        let timestamp_1 = Instant::now();

        cic_flow.update_flow_first(packet_1, timestamp_1, true);

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
        };
        let timestamp_2 = Instant::now();

        cic_flow.update_flow(packet_2, timestamp_2, true);

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
    }

    #[test]
    fn test_update_flow_with_bwd_packet() {
        let mut cic_flow = CicFlow::new(1, 80, 2, 8080, 6);
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
        };
        let timestamp_1 = Instant::now();

        cic_flow.update_flow_first(packet_1, timestamp_1, false);

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
        };
        let timestamp_2 = Instant::now();

        cic_flow.update_flow(packet_2, timestamp_2, false);

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
    }
}
