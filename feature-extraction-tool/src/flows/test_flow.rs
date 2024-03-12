use std::time::{Duration, Instant};

use common::PacketLog;

/// A test flow that stores the basic features of a flow.
pub struct TestFlow {
    pub flow_id: String,
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub protocol: u8,
    pub flow_end_of_flow_ack: u8,
    pub fwd_fin_flag_count: u32,
    pub fwd_rst_flag_count: u32,
    pub fwd_ack_flag_count: u32,
    pub fwd_packet_count: u32,
    pub bwd_fin_flag_count: u32,
    pub bwd_rst_flag_count: u32,
    pub bwd_ack_flag_count: u32,
    pub bwd_packet_count: u32,

    pub fwd_length_mean: f64,
    pub bwd_length_mean: f64,
    pub fwd_length_mean_packets: f64,
    pub bwd_length_mean_packets: f64,
    pub fwd_lengths: Vec<u32>,
    pub bwd_lengths: Vec<u32>,
    pub processing_times_streams: Vec<Duration>,
    pub processing_times_packets: Vec<Duration>,
}

impl TestFlow {
    pub fn new(
        flow_id: String,
        ipv4_source: u32,
        port_source: u16,
        ipv4_destination: u32,
        port_destination: u16,
        protocol: u8,
    ) -> Self {
        TestFlow {
            flow_id,
            ipv4_destination,
            ipv4_source,
            port_destination,
            port_source,
            protocol,
            flow_end_of_flow_ack: 0,
            fwd_fin_flag_count: 0,
            fwd_rst_flag_count: 0,
            fwd_ack_flag_count: 0,
            fwd_packet_count: 0,
            bwd_fin_flag_count: 0,
            bwd_rst_flag_count: 0,
            bwd_ack_flag_count: 0,
            bwd_packet_count: 0,
            fwd_length_mean: 0.0,
            bwd_length_mean: 0.0,
            fwd_length_mean_packets: 0.0,
            bwd_length_mean_packets: 0.0,
            fwd_lengths: Vec::new(),
            bwd_lengths: Vec::new(),
            processing_times_streams: Vec::new(),
            processing_times_packets: Vec::new(),
        }
    }
}

impl TestFlow {
    pub fn update_flow(&mut self, packet: &PacketLog, fwd: bool) -> Option<String> {
        // when both FIN flags are set, the flow can be finished when the last ACK is received
        if self.fwd_fin_flag_count > 0 && self.bwd_fin_flag_count > 0 {
            self.flow_end_of_flow_ack = packet.ack_flag;
        }

        if fwd {
            self.fwd_packet_count += 1;
            self.fwd_fin_flag_count += u32::from(packet.fin_flag);
            self.fwd_rst_flag_count += u32::from(packet.rst_flag);
            self.fwd_ack_flag_count += u32::from(packet.ack_flag);

            // update the mean of the length of the packets
            let start = Instant::now();
            self.update_fwd_mean(packet.length);
            let duration = start.elapsed();
            self.processing_times_streams.push(duration);

            let start2 = Instant::now();
            self.fwd_lengths.push(packet.length);
            let duration2 = start2.elapsed();
            self.processing_times_packets.push(duration2);
        } else {
            self.bwd_packet_count += 1;
            self.bwd_fin_flag_count += u32::from(packet.fin_flag);
            self.bwd_rst_flag_count += u32::from(packet.rst_flag);
            self.bwd_ack_flag_count += u32::from(packet.ack_flag);

            // update the mean of the length of the packets
            let start = Instant::now();
            self.update_bwd_mean(packet.length);
            let duration = start.elapsed();
            self.processing_times_streams.push(duration);

            let start2 = Instant::now();
            self.bwd_lengths.push(packet.length);
            let duration2 = start2.elapsed();
            self.processing_times_packets.push(duration2);
        }

        if self.flow_end_of_flow_ack > 0
            || self.fwd_rst_flag_count > 0
            || self.bwd_rst_flag_count > 0
        {
            let start = Instant::now();
            self.fwd_length_mean_packets = self.get_fwd_length_mean();
            self.bwd_length_mean_packets = self.get_bwd_length_mean();
            let duration = start.elapsed();

            self.processing_times_packets.push(duration);
            return Some(self.dump());
        }

        None
    }

    fn get_fwd_length_mean(&self) -> f64 {
        if self.fwd_lengths.is_empty() {
            return 0.0;
        }

        let sum: u32 = self.fwd_lengths.iter().sum();

        sum as f64 / self.fwd_packet_count as f64
    }

    fn get_bwd_length_mean(&self) -> f64 {
        if self.bwd_lengths.is_empty() {
            return 0.0;
        }

        let sum: u32 = self.bwd_lengths.iter().sum();

        sum as f64 / self.bwd_packet_count as f64
    }

    fn update_fwd_mean(&mut self, len: u32) {
        self.fwd_length_mean = (((self.fwd_packet_count - 1) as f64 * self.fwd_length_mean)
            + len as f64)
            / self.fwd_packet_count as f64;
    }

    fn update_bwd_mean(&mut self, len: u32) {
        self.bwd_length_mean = (((self.bwd_packet_count - 1) as f64 * self.bwd_length_mean)
            + len as f64)
            / self.bwd_packet_count as f64;
    }

    fn sum_processing_times_streams(&self) -> Duration {
        self.processing_times_streams.iter().sum()
    }

    fn sum_processing_times_packets(&self) -> Duration {
        self.processing_times_packets.iter().sum()
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{},{}",
            self.flow_id,
            self.sum_processing_times_streams().as_nanos(),
            self.sum_processing_times_packets().as_nanos(),
        )
    }
}
