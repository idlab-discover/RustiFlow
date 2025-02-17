use crate::packet_features::PacketFeatures;

const SUBFLOW_TIMEOUT: i64 = 1_000;

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

    pub fn update(&mut self, packet: &PacketFeatures) {
        // Set ICMP type and code for the first packet
        if self.first_packet {
            self.icmp_type = packet.icmp_type;
            self.icmp_code = packet.icmp_code;
            self.first_packet = false;
        }
    }

    pub fn get_type(&self) -> u8 {
        self.icmp_type.unwrap_or(0)
    }

    pub fn get_code(&self) -> u8 {
        self.icmp_code.unwrap_or(0)
    }

    pub fn dump(&self) -> String {
        format!("{},{}", self.get_type(), self.get_code())
    }

    pub fn header() -> String {
        format!("{},{}", "icmp_type", "icmp_code")
    }
}
