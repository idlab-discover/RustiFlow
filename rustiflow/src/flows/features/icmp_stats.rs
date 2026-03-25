use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};
use pnet::packet::ip::IpNextHeaderProtocols;

use super::util::FlowFeature;

#[derive(Clone)]
pub struct IcmpStats {
    pub first_packet: bool,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub echo_request_count: u32,
    pub echo_reply_count: u32,
    pub error_count: u32,
    pub destination_unreachable_count: u32,
}

impl IcmpStats {
    pub fn new() -> Self {
        IcmpStats {
            first_packet: true,
            icmp_type: None,
            icmp_code: None,
            echo_request_count: 0,
            echo_reply_count: 0,
            error_count: 0,
            destination_unreachable_count: 0,
        }
    }

    pub fn get_type(&self) -> i16 {
        self.icmp_type.map(|v| v as i16).unwrap_or(-1)
    }

    pub fn get_code(&self) -> i16 {
        self.icmp_code.map(|v| v as i16).unwrap_or(-1)
    }

    fn record_behavior(&mut self, packet: &PacketFeatures) {
        match packet.protocol {
            protocol if protocol == IpNextHeaderProtocols::Icmp.0 => match packet.icmp_type {
                Some(8) => self.echo_request_count += 1,
                Some(0) => self.echo_reply_count += 1,
                Some(3) => {
                    self.error_count += 1;
                    self.destination_unreachable_count += 1;
                }
                Some(4 | 5 | 11 | 12) => self.error_count += 1,
                _ => {}
            },
            protocol if protocol == IpNextHeaderProtocols::Icmpv6.0 => match packet.icmp_type {
                Some(128) => self.echo_request_count += 1,
                Some(129) => self.echo_reply_count += 1,
                Some(1) => {
                    self.error_count += 1;
                    self.destination_unreachable_count += 1;
                }
                Some(2 | 3 | 4) => self.error_count += 1,
                _ => {}
            },
            _ => {}
        }
    }
}

impl FlowFeature for IcmpStats {
    fn update(&mut self, packet: &PacketFeatures, _is_forward: bool, _last_timestamp_us: i64) {
        if packet.protocol != IpNextHeaderProtocols::Icmp.0
            && packet.protocol != IpNextHeaderProtocols::Icmpv6.0
        {
            return;
        }

        // Set ICMP type and code for the first ICMP packet.
        if self.first_packet {
            self.icmp_type = packet.icmp_type;
            self.icmp_code = packet.icmp_code;
            self.first_packet = false;
        }

        self.record_behavior(packet);
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.get_type(),
            self.get_code(),
            self.echo_request_count,
            self.echo_reply_count,
            self.error_count,
            self.destination_unreachable_count
        )
    }

    fn headers() -> String {
        "icmp_type,icmp_code,icmp_echo_request_count,icmp_echo_reply_count,icmp_error_count,icmp_destination_unreachable_count".to_string()
    }
}
