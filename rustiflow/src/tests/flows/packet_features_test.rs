#[cfg(test)]
mod tests {
    use pnet::packet::{ip::IpNextHeaderProtocols, ipv6::Ipv6Packet};
    use std::net::{IpAddr, Ipv4Addr};

    use crate::packet_features::PacketFeatures;

    fn build_packet(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> PacketFeatures {
        PacketFeatures {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol: 6,
            timestamp_us: 1_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn biflow_key_is_direction_invariant() {
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10));
        let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20));

        let forward = build_packet(client_ip, 55000, server_ip, 443);
        let backward = build_packet(server_ip, 443, client_ip, 55000);

        assert_eq!(forward.biflow_key(), backward.biflow_key());
    }

    fn build_ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn ipv6_hop_by_hop_extension_is_skipped_before_tcp_parse() {
        let mut payload = vec![0_u8; 8 + 20];
        payload[0] = IpNextHeaderProtocols::Tcp.0;
        payload[1] = 0;
        payload[8..10].copy_from_slice(&12345_u16.to_be_bytes());
        payload[10..12].copy_from_slice(&443_u16.to_be_bytes());
        payload[20] = 0x50;
        payload[21] = 0x02;

        let bytes = build_ipv6_packet(IpNextHeaderProtocols::Hopopt.0, &payload);
        let packet = Ipv6Packet::new(&bytes).unwrap();
        let features = PacketFeatures::from_ipv6_packet(&packet, 42).unwrap();

        assert_eq!(features.protocol, IpNextHeaderProtocols::Tcp.0);
        assert_eq!(features.source_port, 12345);
        assert_eq!(features.destination_port, 443);
    }

    #[test]
    fn ipv6_fragment_extension_is_skipped_before_udp_parse() {
        let mut payload = vec![0_u8; 8 + 8];
        payload[0] = IpNextHeaderProtocols::Udp.0;
        payload[8..10].copy_from_slice(&5353_u16.to_be_bytes());
        payload[10..12].copy_from_slice(&53_u16.to_be_bytes());
        payload[12..14].copy_from_slice(&8_u16.to_be_bytes());

        let bytes = build_ipv6_packet(IpNextHeaderProtocols::Ipv6Frag.0, &payload);
        let packet = Ipv6Packet::new(&bytes).unwrap();
        let features = PacketFeatures::from_ipv6_packet(&packet, 99).unwrap();

        assert_eq!(features.protocol, IpNextHeaderProtocols::Udp.0);
        assert_eq!(features.source_port, 5353);
        assert_eq!(features.destination_port, 53);
    }

    #[test]
    fn ipv6_non_first_fragment_is_rejected() {
        let mut payload = vec![0_u8; 8 + 8];
        payload[0] = IpNextHeaderProtocols::Udp.0;
        payload[2..4].copy_from_slice(&0x0008_u16.to_be_bytes());
        payload[8..10].copy_from_slice(&5353_u16.to_be_bytes());
        payload[10..12].copy_from_slice(&53_u16.to_be_bytes());
        payload[12..14].copy_from_slice(&8_u16.to_be_bytes());

        let bytes = build_ipv6_packet(IpNextHeaderProtocols::Ipv6Frag.0, &payload);
        let packet = Ipv6Packet::new(&bytes).unwrap();

        assert!(PacketFeatures::from_ipv6_packet(&packet, 100).is_none());
    }

    #[test]
    fn truncated_ipv6_extension_header_is_rejected() {
        let bytes = build_ipv6_packet(
            IpNextHeaderProtocols::Hopopt.0,
            &[IpNextHeaderProtocols::Tcp.0],
        );
        let packet = Ipv6Packet::new(&bytes).unwrap();

        assert!(PacketFeatures::from_ipv6_packet(&packet, 7).is_none());
    }

    #[test]
    fn ipv6_auth_extension_is_skipped_before_tcp_parse() {
        let mut payload = vec![0_u8; 12 + 20];
        payload[0] = IpNextHeaderProtocols::Tcp.0;
        payload[1] = 1;
        payload[12..14].copy_from_slice(&42424_u16.to_be_bytes());
        payload[14..16].copy_from_slice(&443_u16.to_be_bytes());
        payload[24] = 0x50;
        payload[25] = 0x10;

        let bytes = build_ipv6_packet(IpNextHeaderProtocols::Ah.0, &payload);
        let packet = Ipv6Packet::new(&bytes).unwrap();
        let features = PacketFeatures::from_ipv6_packet(&packet, 123).unwrap();

        assert_eq!(features.protocol, IpNextHeaderProtocols::Tcp.0);
        assert_eq!(features.source_port, 42424);
        assert_eq!(features.destination_port, 443);
    }

    #[test]
    fn ipv6_esp_extension_is_rejected() {
        let bytes = build_ipv6_packet(IpNextHeaderProtocols::Esp.0, &[0_u8; 16]);
        let packet = Ipv6Packet::new(&bytes).unwrap();

        assert!(PacketFeatures::from_ipv6_packet(&packet, 55).is_none());
    }
}
