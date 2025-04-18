use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct IcmpStats {
    pub first_packet: bool,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
}

impl IcmpStats {
    pub fn new() -> Self {
        IcmpStats {
            first_packet: true,
            icmp_type: None,
            icmp_code: None,
        }
    }

    pub fn get_type(&self) -> i16 {
        self.icmp_type.map(|v| v as i16).unwrap_or(-1)
    }

    pub fn get_code(&self) -> i16 {
        self.icmp_code.map(|v| v as i16).unwrap_or(-1)
    }
}

impl FlowFeature for IcmpStats {
    fn update(&mut self, packet: &PacketFeatures, _is_forward: bool, _last_timestamp_us: i64) {
        // Set ICMP type and code for the first packet
        if self.first_packet {
            self.icmp_type = packet.icmp_type;
            self.icmp_code = packet.icmp_code;
            self.first_packet = false;
        }
    }

    fn close(&mut self, _last_timestamp_us: i64, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!("{},{}", self.get_type(), self.get_code())
    }

    fn headers() -> String {
        "icmp_type,icmp_code".to_string()
    }
}
