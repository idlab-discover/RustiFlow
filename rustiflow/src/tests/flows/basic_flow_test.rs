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
}
