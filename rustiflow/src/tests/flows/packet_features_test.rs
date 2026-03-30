#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use common::{EbpfEventIpv4, EbpfEventIpv6};
    use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, ipv6::Ipv6Packet};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

        assert_eq!(forward.biflow_key_value(), backward.biflow_key_value());
        assert_eq!(
            forward.biflow_key_value().to_string(),
            backward.biflow_key_value().to_string()
        );
        assert_eq!(
            backward.flow_key_value().to_string(),
            "192.168.0.20:443-192.168.0.10:55000-6"
        );
        assert_eq!(
            forward.flow_key_value().to_string(),
            "192.168.0.10:55000-192.168.0.20:443-6"
        );
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

    fn build_ipv4_packet(protocol: u8, fragment_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + payload.len()];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&(fragment_offset & 0x1fff).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
        packet[20..].copy_from_slice(payload);
        packet
    }

    #[cfg(target_os = "linux")]
    fn assert_packet_features_match(
        parsed_packet: &PacketFeatures,
        realtime_packet: &PacketFeatures,
        expected_timestamp_us: i64,
    ) {
        assert_eq!(realtime_packet.source_ip, parsed_packet.source_ip);
        assert_eq!(realtime_packet.destination_ip, parsed_packet.destination_ip);
        assert_eq!(realtime_packet.source_port, parsed_packet.source_port);
        assert_eq!(
            realtime_packet.destination_port,
            parsed_packet.destination_port
        );
        assert_eq!(realtime_packet.protocol, parsed_packet.protocol);
        assert_eq!(realtime_packet.timestamp_us, expected_timestamp_us);
        assert_eq!(realtime_packet.fin_flag, parsed_packet.fin_flag);
        assert_eq!(realtime_packet.syn_flag, parsed_packet.syn_flag);
        assert_eq!(realtime_packet.rst_flag, parsed_packet.rst_flag);
        assert_eq!(realtime_packet.psh_flag, parsed_packet.psh_flag);
        assert_eq!(realtime_packet.ack_flag, parsed_packet.ack_flag);
        assert_eq!(realtime_packet.urg_flag, parsed_packet.urg_flag);
        assert_eq!(realtime_packet.cwr_flag, parsed_packet.cwr_flag);
        assert_eq!(realtime_packet.ece_flag, parsed_packet.ece_flag);
        assert_eq!(realtime_packet.data_length, parsed_packet.data_length);
        assert_eq!(realtime_packet.header_length, parsed_packet.header_length);
        assert_eq!(realtime_packet.length, parsed_packet.length);
        assert_eq!(realtime_packet.window_size, parsed_packet.window_size);
        assert_eq!(
            realtime_packet.sequence_number,
            parsed_packet.sequence_number
        );
        assert_eq!(
            realtime_packet.sequence_number_ack,
            parsed_packet.sequence_number_ack
        );
        assert_eq!(realtime_packet.icmp_type, parsed_packet.icmp_type);
        assert_eq!(realtime_packet.icmp_code, parsed_packet.icmp_code);
        assert_eq!(realtime_packet.flags, parsed_packet.flags);
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

    #[test]
    fn ipv4_non_first_fragment_is_rejected() {
        let bytes = build_ipv4_packet(IpNextHeaderProtocols::Udp.0, 1, &[0_u8; 8]);
        let packet = Ipv4Packet::new(&bytes).unwrap();

        assert!(PacketFeatures::from_ipv4_packet(&packet, 88).is_none());
    }

    #[test]
    fn ipv4_first_fragment_still_parses_transport_header() {
        let mut payload = vec![0_u8; 8];
        payload[0..2].copy_from_slice(&5353_u16.to_be_bytes());
        payload[2..4].copy_from_slice(&53_u16.to_be_bytes());
        payload[4..6].copy_from_slice(&8_u16.to_be_bytes());

        let bytes = build_ipv4_packet(IpNextHeaderProtocols::Udp.0, 0, &payload);
        let packet = Ipv4Packet::new(&bytes).unwrap();
        let features = PacketFeatures::from_ipv4_packet(&packet, 89).unwrap();

        assert_eq!(features.protocol, IpNextHeaderProtocols::Udp.0);
        assert_eq!(features.source_port, 5353);
        assert_eq!(features.destination_port, 53);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv4_tcp_packet_and_ebpf_event_produce_matching_features() {
        let payload = b"rust";
        let mut tcp = vec![0_u8; 20 + payload.len()];
        tcp[0..2].copy_from_slice(&12345_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0x0506_0708_u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x1a;
        tcp[14..16].copy_from_slice(&4096_u16.to_be_bytes());
        tcp[20..].copy_from_slice(payload);

        let bytes = build_ipv4_packet(IpNextHeaderProtocols::Tcp.0, 0, &tcp);
        let packet = Ipv4Packet::new(&bytes).unwrap();
        let parsed_packet = PacketFeatures::from_ipv4_packet(&packet, 1_234_567).unwrap();

        let realtime_offset_us = 1_000_000;
        let event = EbpfEventIpv4::new(
            (1_234_567 - realtime_offset_us) as u64 * 1_000,
            u32::from(Ipv4Addr::new(192, 0, 2, 2)).to_be(),
            u32::from(Ipv4Addr::new(192, 0, 2, 1)).to_be(),
            443,
            12345,
            payload.len() as u16,
            44,
            4096,
            0x1a,
            IpNextHeaderProtocols::Tcp.0,
            20,
            0x0102_0304,
            0x0506_0708,
            0,
            0,
        );
        let realtime_packet = PacketFeatures::from_ebpf_event_ipv4(&event, realtime_offset_us);

        assert_packet_features_match(&parsed_packet, &realtime_packet, 1_234_567);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_udp_packet_and_ebpf_event_produce_matching_features() {
        let payload = b"flow";
        let mut udp = vec![0_u8; 8 + payload.len()];
        udp[0..2].copy_from_slice(&5353_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);

        let bytes = build_ipv6_packet(IpNextHeaderProtocols::Udp.0, &udp);
        let packet = Ipv6Packet::new(&bytes).unwrap();
        let parsed_packet = PacketFeatures::from_ipv6_packet(&packet, 2_345_678).unwrap();

        let realtime_offset_us = 2_000_000;
        let event = EbpfEventIpv6::new(
            (2_345_678 - realtime_offset_us) as u64 * 1_000,
            u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)).to_be(),
            u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)).to_be(),
            53,
            5353,
            payload.len() as u16,
            52,
            0,
            0,
            IpNextHeaderProtocols::Udp.0,
            8,
            0,
            0,
            0,
            0,
        );
        let realtime_packet = PacketFeatures::from_ebpf_event_ipv6(&event, realtime_offset_us);

        assert_packet_features_match(&parsed_packet, &realtime_packet, 2_345_678);
    }
}
