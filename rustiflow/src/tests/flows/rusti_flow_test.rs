#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        flows::{basic_flow::TcpCloseStyle, flow::Flow, rusti_flow::RustiFlow},
        packet_features::{PacketFeatures, ACK_FLAG, SYN_FLAG},
    };

    fn setup_rusti_flow() -> RustiFlow {
        RustiFlow::new(
            "rusti-flow".to_string(),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            44444,
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
            443,
            6,
            1_000_000,
        )
    }

    fn count_csv_fields(row: &str) -> usize {
        row.split(',').count()
    }

    fn packet(
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
            window_size: 4096,
            ..Default::default()
        }
    }

    #[test]
    fn dump_matches_feature_headers() {
        let flow = setup_rusti_flow();

        assert_eq!(
            count_csv_fields(&flow.dump()),
            count_csv_fields(&RustiFlow::get_features())
        );
        assert_eq!(
            count_csv_fields(&flow.dump_without_contamination()),
            count_csv_fields(&RustiFlow::get_features_without_contamination())
        );
    }

    #[test]
    fn rusti_flow_updates_lifecycle_timing_and_retransmission_features_together() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let destination_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2));
        let mut flow = setup_rusti_flow();

        let mut syn = packet(source_ip, 44444, destination_ip, 443, 1_000_100);
        syn.syn_flag = 1;
        syn.flags = SYN_FLAG;
        assert!(!flow.update_flow(&syn, true));

        let mut syn_ack = packet(destination_ip, 443, source_ip, 44444, 1_000_200);
        syn_ack.syn_flag = 1;
        syn_ack.ack_flag = 1;
        syn_ack.flags = SYN_FLAG | ACK_FLAG;
        syn_ack.sequence_number = 700;
        assert!(!flow.update_flow(&syn_ack, false));

        let mut ack = packet(source_ip, 44444, destination_ip, 443, 1_000_300);
        ack.ack_flag = 1;
        ack.flags = ACK_FLAG;
        ack.sequence_number_ack = 701;
        assert!(!flow.update_flow(&ack, true));

        let mut data = packet(source_ip, 44444, destination_ip, 443, 1_001_000);
        data.ack_flag = 1;
        data.flags = ACK_FLAG;
        data.sequence_number = 100;
        data.sequence_number_ack = 701;
        data.data_length = 100;
        assert!(!flow.update_flow(&data, true));

        let mut ack_bwd = packet(destination_ip, 443, source_ip, 44444, 1_001_500);
        ack_bwd.ack_flag = 1;
        ack_bwd.flags = ACK_FLAG;
        ack_bwd.sequence_number = 701;
        ack_bwd.sequence_number_ack = 200;
        assert!(!flow.update_flow(&ack_bwd, false));

        let mut duplicate_ack_bwd = packet(destination_ip, 443, source_ip, 44444, 1_001_650);
        duplicate_ack_bwd.ack_flag = 1;
        duplicate_ack_bwd.flags = ACK_FLAG;
        duplicate_ack_bwd.sequence_number = 702;
        duplicate_ack_bwd.sequence_number_ack = 200;
        assert!(!flow.update_flow(&duplicate_ack_bwd, false));

        let mut zero_window_bwd = packet(destination_ip, 443, source_ip, 44444, 1_001_700);
        zero_window_bwd.ack_flag = 1;
        zero_window_bwd.flags = ACK_FLAG;
        zero_window_bwd.sequence_number = 703;
        zero_window_bwd.sequence_number_ack = 200;
        zero_window_bwd.window_size = 0;
        assert!(!flow.update_flow(&zero_window_bwd, false));

        let mut overlap = packet(source_ip, 44444, destination_ip, 443, 1_001_800);
        overlap.ack_flag = 1;
        overlap.flags = ACK_FLAG;
        overlap.sequence_number = 150;
        overlap.sequence_number_ack = 701;
        overlap.data_length = 100;
        assert!(!flow.update_flow(&overlap, true));

        assert!(flow.basic_flow.tcp_handshake_completed);
        assert_eq!(flow.basic_flow.tcp_close_style, TcpCloseStyle::None);
        assert_eq!(flow.retransmission_stats.fwd_retransmission_count, 1);
        assert_eq!(flow.retransmission_stats.bwd_retransmission_count, 0);
        assert_eq!(flow.tcp_quality_stats.fwd_duplicate_ack_count, 0);
        assert_eq!(flow.tcp_quality_stats.bwd_duplicate_ack_count, 1);
        assert_eq!(flow.tcp_quality_stats.fwd_zero_window_count, 0);
        assert_eq!(flow.tcp_quality_stats.bwd_zero_window_count, 1);
        assert_eq!(flow.iat_stats.iat.get_count(), 7);
        assert_eq!(flow.iat_stats.fwd_iat.get_count(), 3);
        assert_eq!(flow.iat_stats.bwd_iat.get_count(), 3);
        assert_eq!(flow.subflow_stats.subflow_count, 1);
        assert!((flow.timing_stats.get_fwd_duration() - 1.7).abs() < f64::EPSILON);
        assert!((flow.timing_stats.get_bwd_duration() - 1.5).abs() < f64::EPSILON);
        assert_eq!(flow.payload_len_stats.fwd_non_zero_payload_packets, 2);
        assert_eq!(flow.payload_len_stats.bwd_non_zero_payload_packets, 0);
    }
}
