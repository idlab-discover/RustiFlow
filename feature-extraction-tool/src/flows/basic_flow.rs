use chrono::{DateTime, Utc};
use common::BasicFeatures;

pub struct BasicFlow {
    pub flow_id: String,
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub protocol: u8,
    pub first_timestamp: DateTime<Utc>,
    pub last_timestamp: DateTime<Utc>,
    // Forward
    pub fwd_fin_flag_count: u32,
    pub fwd_syn_flag_count: u32,
    pub fwd_rst_flag_count: u32,
    pub fwd_psh_flag_count: u32,
    pub fwd_ack_flag_count: u32,
    pub fwd_urg_flag_count: u32,
    pub fwd_cwe_flag_count: u32,
    pub fwd_ece_flag_count: u32,
    pub fwd_packet_count: u32,
    // Backward
    pub bwd_fin_flag_count: u32,
    pub bwd_syn_flag_count: u32,
    pub bwd_rst_flag_count: u32,
    pub bwd_psh_flag_count: u32,
    pub bwd_ack_flag_count: u32,
    pub bwd_urg_flag_count: u32,
    pub bwd_cwe_flag_count: u32,
    pub bwd_ece_flag_count: u32,
    pub bwd_packet_count: u32,
}

fn create_flow_id(
    ipv4_source: u32,
    port_source: u16,
    ipv4_destination: u32,
    port_destination: u16,
    protocol: u8,
) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        ipv4_source, port_source, ipv4_destination, port_destination, protocol
    )
}

impl BasicFlow {
    pub fn new(
        ipv4_source: u32,
        port_source: u16,
        ipv4_destination: u32,
        port_destination: u16,
        protocol: u8,
    ) -> Self {
        BasicFlow {
            flow_id: create_flow_id(
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
            ),
            ipv4_destination,
            ipv4_source,
            port_destination,
            port_source,
            protocol,
            first_timestamp: Utc::now(),
            last_timestamp: Utc::now(),
            fwd_fin_flag_count: 0,
            fwd_syn_flag_count: 0,
            fwd_rst_flag_count: 0,
            fwd_psh_flag_count: 0,
            fwd_ack_flag_count: 0,
            fwd_urg_flag_count: 0,
            fwd_cwe_flag_count: 0,
            fwd_ece_flag_count: 0,
            fwd_packet_count: 0,
            bwd_fin_flag_count: 0,
            bwd_syn_flag_count: 0,
            bwd_rst_flag_count: 0,
            bwd_psh_flag_count: 0,
            bwd_ack_flag_count: 0,
            bwd_urg_flag_count: 0,
            bwd_cwe_flag_count: 0,
            bwd_ece_flag_count: 0,
            bwd_packet_count: 0,
        }
    }
}

impl BasicFlow {
    pub fn update_flow(&mut self, packet: BasicFeatures, fwd: bool) {
        self.last_timestamp = Utc::now();
        if fwd {
            self.fwd_packet_count += 1;
            self.fwd_fin_flag_count += u32::from(packet.fin_flag);
            self.fwd_syn_flag_count += u32::from(packet.syn_flag);
            self.fwd_rst_flag_count += u32::from(packet.rst_flag);
            self.fwd_psh_flag_count += u32::from(packet.psh_flag);
            self.fwd_ack_flag_count += u32::from(packet.ack_flag);
            self.fwd_urg_flag_count += u32::from(packet.urg_flag);
            self.fwd_cwe_flag_count += u32::from(packet.cwe_flag);
            self.fwd_ece_flag_count += u32::from(packet.ece_flag);
        } else {
            self.bwd_packet_count += 1;
            self.bwd_fin_flag_count += u32::from(packet.fin_flag);
            self.bwd_syn_flag_count += u32::from(packet.syn_flag);
            self.bwd_rst_flag_count += u32::from(packet.rst_flag);
            self.bwd_psh_flag_count += u32::from(packet.psh_flag);
            self.bwd_ack_flag_count += u32::from(packet.ack_flag);
            self.bwd_urg_flag_count += u32::from(packet.urg_flag);
            self.bwd_cwe_flag_count += u32::from(packet.cwe_flag);
            self.bwd_ece_flag_count += u32::from(packet.ece_flag);
        }
    }
}
