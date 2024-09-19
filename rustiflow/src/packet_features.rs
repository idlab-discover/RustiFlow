use std::net::IpAddr;

use chrono::{DateTime, Utc};

pub struct PacketFeatures {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub timestamp: DateTime<Utc>,
    pub fin_flag: u8,
    pub syn_flag: u8,
    pub rst_flag: u8,
    pub psh_flag: u8,
    pub ack_flag: u8,
    pub urg_flag: u8,
    pub cwe_flag: u8,
    pub ece_flag: u8,
    pub data_length: u16,
    pub header_length: u8,
    pub length: u16,
    pub window_size: u16,
}

impl PacketFeatures {
    /// Creates a new instance of PacketFeatures.
    pub fn new(
        source_ip: IpAddr,
        destination_ip: IpAddr,
        source_port: u16,
        destination_port: u16,
        protocol: u8,
        timestamp: DateTime<Utc>,
        fin_flag: u8,
        syn_flag: u8,
        rst_flag: u8,
        psh_flag: u8,
        ack_flag: u8,
        urg_flag: u8,
        cwe_flag: u8,
        ece_flag: u8,
        data_length: u16,
        header_length: u8,
        length: u16,
        window_size: u16,
    ) -> Self {
        PacketFeatures {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            timestamp,
            fin_flag,
            syn_flag,
            rst_flag,
            psh_flag,
            ack_flag,
            urg_flag,
            cwe_flag,
            ece_flag,
            data_length,
            header_length,
            length,
            window_size,
        }
    }

    /// Generates a flow key based on IPs, ports, and protocol
    pub fn flow_key(&self) -> String {
        format!(
            "{}:{}-{}:{}-{}",
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol
        )
    }

    /// Generates a flow key based on IPs, ports, and protocol in the reverse direction
    pub fn flow_key_bwd(&self) -> String {
        format!(
            "{}:{}-{}:{}-{}",
            self.destination_ip,
            self.destination_port,
            self.source_ip,
            self.source_port,
            self.protocol
        )
    }

    /// Generates a biflow key
    pub fn biflow_key(&self) -> String {
        // Create tuples of (IP, port) for comparison
        let src = (&self.source_ip, self.source_port);
        let dst = (&self.destination_ip, self.destination_port);
    
        // Determine the correct order (src < dst)
        if src < dst {
            format!(
                "{}:{}-{}:{}-{}",
                self.source_ip,
                self.source_port,
                self.destination_ip,
                self.destination_port,
                self.protocol
            )
        } else {
            // If destination IP/port is "smaller", swap the order
            format!(
                "{}:{}-{}:{}-{}",
                self.destination_ip,
                self.destination_port,
                self.source_ip,
                self.source_port,
                self.protocol
            )
        }
    }
}