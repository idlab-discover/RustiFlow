#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        flows::{basic_flow::BasicFlow, flow::Flow, util::FlowExpireCause},
        packet_features::PacketFeatures,
    };

    fn build_packet(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        timestamp_us: i64,
    ) -> PacketFeatures {
        PacketFeatures {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol: 6,
            timestamp_us,
            ..Default::default()
        }
    }

    #[test]
    fn close_flow_records_expiration_cause() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let mut flow = BasicFlow::new(
            "flow-1".to_string(),
            ip_source,
            4242,
            ip_destination,
            443,
            6,
            1_000_000,
        );

        flow.close_flow(2_000_000, FlowExpireCause::IdleTimeout);

        assert_eq!(flow.flow_expire_cause, FlowExpireCause::IdleTimeout);
    }

    #[test]
    fn tcp_fin_handshake_terminates_flow() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut flow = BasicFlow::new(
            "flow-2".to_string(),
            ip_source,
            50000,
            ip_destination,
            80,
            6,
            1_000_000,
        );

        let mut fin_fwd = build_packet(ip_source, 50000, ip_destination, 80, 1_000_100);
        fin_fwd.fin_flag = 1;
        fin_fwd.sequence_number = 100;
        assert!(!flow.update_flow(&fin_fwd, true));

        let mut ack_bwd = build_packet(ip_destination, 80, ip_source, 50000, 1_000_200);
        ack_bwd.ack_flag = 1;
        ack_bwd.sequence_number_ack = 101;
        assert!(!flow.update_flow(&ack_bwd, false));

        let mut fin_bwd = build_packet(ip_destination, 80, ip_source, 50000, 1_000_300);
        fin_bwd.fin_flag = 1;
        fin_bwd.sequence_number = 200;
        assert!(!flow.update_flow(&fin_bwd, false));

        let mut ack_fwd = build_packet(ip_source, 50000, ip_destination, 80, 1_000_400);
        ack_fwd.ack_flag = 1;
        ack_fwd.sequence_number_ack = 201;
        assert!(flow.update_flow(&ack_fwd, true));
        assert_eq!(flow.flow_expire_cause, FlowExpireCause::TcpTermination);
    }

    #[test]
    fn tcp_handshake_completion_is_tracked() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut flow = BasicFlow::new(
            "flow-3".to_string(),
            ip_source,
            50001,
            ip_destination,
            443,
            6,
            1_000_000,
        );

        let mut syn = build_packet(ip_source, 50001, ip_destination, 443, 1_000_100);
        syn.syn_flag = 1;
        assert!(!flow.update_flow(&syn, true));
        assert!(!flow.tcp_handshake_completed);

        let mut syn_ack = build_packet(ip_destination, 443, ip_source, 50001, 1_000_200);
        syn_ack.syn_flag = 1;
        syn_ack.ack_flag = 1;
        syn_ack.sequence_number = 700;
        assert!(!flow.update_flow(&syn_ack, false));
        assert!(!flow.tcp_handshake_completed);

        let mut ack = build_packet(ip_source, 50001, ip_destination, 443, 1_000_300);
        ack.ack_flag = 1;
        ack.sequence_number_ack = 701;
        assert!(!flow.update_flow(&ack, true));

        assert!(flow.tcp_handshake_completed);
        assert!(!flow.tcp_reset_before_handshake);
        assert!(!flow.tcp_reset_after_handshake);
    }

    #[test]
    fn tcp_reset_before_handshake_is_classified() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut flow = BasicFlow::new(
            "flow-4".to_string(),
            ip_source,
            50002,
            ip_destination,
            22,
            6,
            1_000_000,
        );

        let mut syn = build_packet(ip_source, 50002, ip_destination, 22, 1_000_100);
        syn.syn_flag = 1;
        assert!(!flow.update_flow(&syn, true));

        let mut rst = build_packet(ip_destination, 22, ip_source, 50002, 1_000_200);
        rst.rst_flag = 1;
        assert!(flow.update_flow(&rst, false));

        assert_eq!(flow.flow_expire_cause, FlowExpireCause::TcpReset);
        assert!(!flow.tcp_handshake_completed);
        assert!(flow.tcp_reset_before_handshake);
        assert!(!flow.tcp_reset_after_handshake);
    }

    #[test]
    fn tcp_reset_after_handshake_is_classified() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut flow = BasicFlow::new(
            "flow-5".to_string(),
            ip_source,
            50003,
            ip_destination,
            22,
            6,
            1_000_000,
        );

        let mut syn = build_packet(ip_source, 50003, ip_destination, 22, 1_000_100);
        syn.syn_flag = 1;
        assert!(!flow.update_flow(&syn, true));

        let mut syn_ack = build_packet(ip_destination, 22, ip_source, 50003, 1_000_200);
        syn_ack.syn_flag = 1;
        syn_ack.ack_flag = 1;
        syn_ack.sequence_number = 900;
        assert!(!flow.update_flow(&syn_ack, false));

        let mut ack = build_packet(ip_source, 50003, ip_destination, 22, 1_000_300);
        ack.ack_flag = 1;
        ack.sequence_number_ack = 901;
        assert!(!flow.update_flow(&ack, true));

        let mut rst = build_packet(ip_destination, 22, ip_source, 50003, 1_000_400);
        rst.rst_flag = 1;
        assert!(flow.update_flow(&rst, false));

        assert_eq!(flow.flow_expire_cause, FlowExpireCause::TcpReset);
        assert!(flow.tcp_handshake_completed);
        assert!(!flow.tcp_reset_before_handshake);
        assert!(flow.tcp_reset_after_handshake);
    }

    #[test]
    fn ack_only_packet_does_not_complete_tcp_handshake() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
        let mut flow = BasicFlow::new(
            "flow-6".to_string(),
            ip_source,
            50010,
            ip_destination,
            443,
            6,
            1_000_000,
        );

        let mut ack = build_packet(ip_source, 50010, ip_destination, 443, 1_000_100);
        ack.ack_flag = 1;
        ack.sequence_number_ack = 42;
        assert!(!flow.update_flow(&ack, true));

        assert!(!flow.tcp_handshake_completed);
        assert_eq!(flow.flow_expire_cause, FlowExpireCause::None);
    }

    #[test]
    fn syn_ack_without_initial_syn_does_not_complete_handshake() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
        let mut flow = BasicFlow::new(
            "flow-7".to_string(),
            ip_source,
            50011,
            ip_destination,
            443,
            6,
            1_000_000,
        );

        let mut syn_ack = build_packet(ip_destination, 443, ip_source, 50011, 1_000_100);
        syn_ack.syn_flag = 1;
        syn_ack.ack_flag = 1;
        syn_ack.sequence_number = 1000;
        assert!(!flow.update_flow(&syn_ack, false));

        let mut ack = build_packet(ip_source, 50011, ip_destination, 443, 1_000_200);
        ack.ack_flag = 1;
        ack.sequence_number_ack = 1001;
        assert!(!flow.update_flow(&ack, true));

        assert!(!flow.tcp_handshake_completed);
        assert_eq!(flow.flow_expire_cause, FlowExpireCause::None);
    }

    #[test]
    fn fin_with_payload_uses_payload_sequence_space_for_termination() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 2));
        let mut flow = BasicFlow::new(
            "flow-8".to_string(),
            ip_source,
            50012,
            ip_destination,
            80,
            6,
            1_000_000,
        );

        let mut fin_fwd = build_packet(ip_source, 50012, ip_destination, 80, 1_000_100);
        fin_fwd.fin_flag = 1;
        fin_fwd.sequence_number = 100;
        fin_fwd.data_length = 20;
        assert!(!flow.update_flow(&fin_fwd, true));

        let mut ack_bwd = build_packet(ip_destination, 80, ip_source, 50012, 1_000_200);
        ack_bwd.ack_flag = 1;
        ack_bwd.sequence_number_ack = 121;
        assert!(!flow.update_flow(&ack_bwd, false));

        let mut fin_bwd = build_packet(ip_destination, 80, ip_source, 50012, 1_000_300);
        fin_bwd.fin_flag = 1;
        fin_bwd.sequence_number = 200;
        assert!(!flow.update_flow(&fin_bwd, false));

        let mut ack_fwd = build_packet(ip_source, 50012, ip_destination, 80, 1_000_400);
        ack_fwd.ack_flag = 1;
        ack_fwd.sequence_number_ack = 201;
        assert!(flow.update_flow(&ack_fwd, true));

        assert_eq!(flow.flow_expire_cause, FlowExpireCause::TcpTermination);
    }

    #[test]
    fn non_tcp_flows_ignore_rst_classification() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 2));
        let mut flow = BasicFlow::new(
            "flow-9".to_string(),
            ip_source,
            53000,
            ip_destination,
            53,
            17,
            1_000_000,
        );

        let mut packet = build_packet(ip_source, 53000, ip_destination, 53, 1_000_100);
        packet.protocol = 17;
        packet.rst_flag = 1;
        assert!(!flow.update_flow(&packet, true));

        assert_eq!(flow.flow_expire_cause, FlowExpireCause::None);
        assert!(!flow.tcp_handshake_completed);
        assert!(!flow.tcp_reset_before_handshake);
        assert!(!flow.tcp_reset_after_handshake);
    }

    #[test]
    fn simultaneous_tcp_close_terminates_after_final_ack() {
        let ip_source = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
        let ip_destination = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 2));
        let mut flow = BasicFlow::new(
            "flow-10".to_string(),
            ip_source,
            50013,
            ip_destination,
            443,
            6,
            1_000_000,
        );

        let mut syn = build_packet(ip_source, 50013, ip_destination, 443, 1_000_100);
        syn.syn_flag = 1;
        assert!(!flow.update_flow(&syn, true));

        let mut syn_ack = build_packet(ip_destination, 443, ip_source, 50013, 1_000_200);
        syn_ack.syn_flag = 1;
        syn_ack.ack_flag = 1;
        syn_ack.sequence_number = 700;
        assert!(!flow.update_flow(&syn_ack, false));

        let mut ack = build_packet(ip_source, 50013, ip_destination, 443, 1_000_300);
        ack.ack_flag = 1;
        ack.sequence_number_ack = 701;
        assert!(!flow.update_flow(&ack, true));
        assert!(flow.tcp_handshake_completed);

        let mut fin_fwd = build_packet(ip_source, 50013, ip_destination, 443, 1_000_400);
        fin_fwd.fin_flag = 1;
        fin_fwd.sequence_number = 100;
        assert!(!flow.update_flow(&fin_fwd, true));

        let mut fin_ack_bwd = build_packet(ip_destination, 443, ip_source, 50013, 1_000_500);
        fin_ack_bwd.fin_flag = 1;
        fin_ack_bwd.ack_flag = 1;
        fin_ack_bwd.sequence_number = 200;
        fin_ack_bwd.sequence_number_ack = 101;
        assert!(!flow.update_flow(&fin_ack_bwd, false));

        let mut final_ack = build_packet(ip_source, 50013, ip_destination, 443, 1_000_600);
        final_ack.ack_flag = 1;
        final_ack.sequence_number_ack = 201;
        assert!(flow.update_flow(&final_ack, true));

        assert_eq!(flow.flow_expire_cause, FlowExpireCause::TcpTermination);
        assert!(flow.tcp_handshake_completed);
    }
}
