#[cfg(test)]
mod tests {
    use pnet::packet::ip::IpNextHeaderProtocols;

    use crate::{
        flows::{
            features::{
                active_idle_stats::ActiveIdleStats, iat_stats::IATStats, icmp_stats::IcmpStats,
                payload_stats::PayloadLengthStats, retransmission_stats::RetransmissionStats,
                subflow_stats::SubflowStats, timing_stats::TimingStats, util::FlowFeature,
                window_size_stats::WindowSizeStats,
            },
            util::FlowExpireCause,
        },
        packet_features::{PacketFeatures, ACK_FLAG, FIN_FLAG, SYN_FLAG},
    };

    fn packet(timestamp_us: i64) -> PacketFeatures {
        PacketFeatures {
            timestamp_us,
            ..Default::default()
        }
    }

    #[test]
    fn icmp_stats_keep_first_type_code_and_track_behavior_counts() {
        let mut stats = IcmpStats::new();

        let mut first = packet(1_000_000);
        first.protocol = IpNextHeaderProtocols::Icmp.0;
        first.icmp_type = Some(8);
        first.icmp_code = Some(0);
        stats.update(&first, true, first.timestamp_us);

        let mut second = packet(2_000_000);
        second.protocol = IpNextHeaderProtocols::Icmp.0;
        second.icmp_type = Some(3);
        second.icmp_code = Some(1);
        stats.update(&second, false, first.timestamp_us);

        let mut third = packet(3_000_000);
        third.protocol = IpNextHeaderProtocols::Icmpv6.0;
        third.icmp_type = Some(129);
        third.icmp_code = Some(0);
        stats.update(&third, true, second.timestamp_us);

        let mut fourth = packet(4_000_000);
        fourth.protocol = IpNextHeaderProtocols::Icmpv6.0;
        fourth.icmp_type = Some(1);
        fourth.icmp_code = Some(4);
        stats.update(&fourth, false, third.timestamp_us);

        assert_eq!(stats.get_type(), 8);
        assert_eq!(stats.get_code(), 0);
        assert_eq!(stats.echo_request_count, 1);
        assert_eq!(stats.echo_reply_count, 1);
        assert_eq!(stats.error_count, 2);
        assert_eq!(stats.destination_unreachable_count, 2);
        assert_eq!(stats.dump(), "8,0,1,1,2,2");
    }

    #[test]
    fn retransmission_stats_only_track_tcp_overlap_by_direction() {
        let mut stats = RetransmissionStats::new();

        let mut pure_ack = packet(1_000_000);
        pure_ack.protocol = IpNextHeaderProtocols::Tcp.0;
        pure_ack.flags = ACK_FLAG;
        pure_ack.ack_flag = 1;
        pure_ack.sequence_number = 11;
        stats.update(&pure_ack, true, pure_ack.timestamp_us);
        stats.update(&pure_ack, true, pure_ack.timestamp_us);

        let mut udp = packet(1_250_000);
        udp.protocol = IpNextHeaderProtocols::Udp.0;
        udp.sequence_number = 0;
        stats.update(&udp, true, pure_ack.timestamp_us);
        stats.update(&udp, true, pure_ack.timestamp_us);

        let mut icmp = packet(1_500_000);
        icmp.protocol = IpNextHeaderProtocols::Icmp.0;
        icmp.sequence_number = 22;
        stats.update(&icmp, true, pure_ack.timestamp_us);
        stats.update(&icmp, true, pure_ack.timestamp_us);

        let mut fwd = packet(2_000_000);
        fwd.protocol = IpNextHeaderProtocols::Tcp.0;
        fwd.sequence_number = 100;
        fwd.data_length = 100;
        stats.update(&fwd, true, pure_ack.timestamp_us);

        let mut partial_fwd = packet(2_100_000);
        partial_fwd.protocol = IpNextHeaderProtocols::Tcp.0;
        partial_fwd.sequence_number = 150;
        partial_fwd.data_length = 100;
        stats.update(&partial_fwd, true, fwd.timestamp_us);

        let mut bwd = packet(2_500_000);
        bwd.protocol = IpNextHeaderProtocols::Tcp.0;
        bwd.flags = SYN_FLAG;
        bwd.syn_flag = 1;
        bwd.sequence_number = 200;
        stats.update(&bwd, false, fwd.timestamp_us);

        let mut duplicate_syn = packet(2_600_000);
        duplicate_syn.protocol = IpNextHeaderProtocols::Tcp.0;
        duplicate_syn.flags = SYN_FLAG;
        duplicate_syn.syn_flag = 1;
        duplicate_syn.sequence_number = 200;
        stats.update(&duplicate_syn, false, bwd.timestamp_us);

        assert_eq!(stats.fwd_retransmission_count, 1);
        assert_eq!(stats.bwd_retransmission_count, 1);
        assert_eq!(stats.dump(), "2,1,1");
    }

    #[test]
    fn retransmission_stats_treat_fin_sequence_space_as_retransmittable() {
        let mut stats = RetransmissionStats::new();

        let mut fin = packet(1_000_000);
        fin.protocol = IpNextHeaderProtocols::Tcp.0;
        fin.flags = FIN_FLAG | ACK_FLAG;
        fin.fin_flag = 1;
        fin.ack_flag = 1;
        fin.sequence_number = 500;
        stats.update(&fin, true, fin.timestamp_us);

        let mut duplicate_fin = packet(1_100_000);
        duplicate_fin.protocol = IpNextHeaderProtocols::Tcp.0;
        duplicate_fin.flags = FIN_FLAG | ACK_FLAG;
        duplicate_fin.fin_flag = 1;
        duplicate_fin.ack_flag = 1;
        duplicate_fin.sequence_number = 500;
        stats.update(&duplicate_fin, true, fin.timestamp_us);

        assert_eq!(stats.fwd_retransmission_count, 1);
        assert_eq!(stats.bwd_retransmission_count, 0);
    }

    #[test]
    fn retransmission_stats_ignore_adjacent_tcp_segments_but_count_later_overlap() {
        let mut stats = RetransmissionStats::new();

        let mut first = packet(1_000_000);
        first.protocol = IpNextHeaderProtocols::Tcp.0;
        first.sequence_number = 100;
        first.data_length = 100;
        stats.update(&first, true, first.timestamp_us);

        let mut adjacent = packet(1_050_000);
        adjacent.protocol = IpNextHeaderProtocols::Tcp.0;
        adjacent.sequence_number = 200;
        adjacent.data_length = 100;
        stats.update(&adjacent, true, first.timestamp_us);

        let mut overlap = packet(1_100_000);
        overlap.protocol = IpNextHeaderProtocols::Tcp.0;
        overlap.sequence_number = 150;
        overlap.data_length = 100;
        stats.update(&overlap, true, adjacent.timestamp_us);

        assert_eq!(stats.fwd_retransmission_count, 1);
        assert_eq!(stats.bwd_retransmission_count, 0);
        assert_eq!(stats.dump(), "1,1,0");
    }

    #[test]
    fn window_size_stats_capture_initial_sizes_for_each_direction() {
        let mut stats = WindowSizeStats::new();

        let mut fwd_first = packet(1_000_000);
        fwd_first.window_size = 1_024;
        stats.update(&fwd_first, true, fwd_first.timestamp_us);

        let mut bwd_first = packet(1_100_000);
        bwd_first.window_size = 2_048;
        stats.update(&bwd_first, false, fwd_first.timestamp_us);

        let mut fwd_second = packet(1_200_000);
        fwd_second.window_size = 4_096;
        stats.update(&fwd_second, true, bwd_first.timestamp_us);

        let mut bwd_second = packet(1_300_000);
        bwd_second.window_size = 8_192;
        stats.update(&bwd_second, false, fwd_second.timestamp_us);

        assert_eq!(stats.fwd_init_window_size, 1_024);
        assert_eq!(stats.bwd_init_window_size, 2_048);
        assert_eq!(stats.fwd_window_size.get_count(), 2);
        assert_eq!(stats.bwd_window_size.get_count(), 2);
    }

    #[test]
    fn payload_stats_count_non_zero_payload_packets_per_direction() {
        let mut stats = PayloadLengthStats::new();

        let mut fwd_zero = packet(1_000_000);
        fwd_zero.data_length = 0;
        stats.update(&fwd_zero, true, fwd_zero.timestamp_us);

        let mut fwd_payload = packet(1_100_000);
        fwd_payload.data_length = 37;
        stats.update(&fwd_payload, true, fwd_zero.timestamp_us);

        let mut bwd_zero = packet(1_200_000);
        bwd_zero.data_length = 0;
        stats.update(&bwd_zero, false, fwd_payload.timestamp_us);

        let mut bwd_payload = packet(1_300_000);
        bwd_payload.data_length = 19;
        stats.update(&bwd_payload, false, bwd_zero.timestamp_us);

        assert_eq!(stats.fwd_non_zero_payload_packets, 1);
        assert_eq!(stats.bwd_non_zero_payload_packets, 1);
        assert_eq!(stats.payload_len.get_count(), 4);
    }

    #[test]
    fn subflow_stats_count_initial_subflow_and_increment_only_on_gaps_greater_than_one_second() {
        let mut stats = SubflowStats::new();

        let first_ts = 1_000_000;
        let second_ts = 2_000_000;
        let third_ts = 3_000_001;

        let first = packet(first_ts);
        stats.update(&first, true, first_ts);

        let second = packet(second_ts);
        stats.update(&second, false, first_ts);

        let third = packet(third_ts);
        stats.update(&third, true, second_ts);

        assert_eq!(stats.subflow_count, 2);
    }

    #[test]
    fn active_idle_stats_record_active_and_idle_periods_on_gap_and_close() {
        let mut stats = ActiveIdleStats::new(0);

        let first = packet(1_000_000);
        stats.update(&first, true, 0);

        let second = packet(7_000_000);
        stats.update(&second, false, first.timestamp_us);

        stats.close(10_000_000, FlowExpireCause::IdleTimeout);

        assert_eq!(stats.active_stats.get_total(), 1_000.0);
        assert_eq!(stats.active_stats.get_count(), 1);
        assert_eq!(stats.idle_stats.get_total(), 9_000.0);
        assert_eq!(stats.idle_stats.get_count(), 2);
    }

    #[test]
    fn active_idle_stats_preserve_gap_precision_and_exact_threshold_behavior() {
        let first = packet(1_000_000);
        let mut stats = ActiveIdleStats::new(first.timestamp_us);
        stats.update(&first, true, 0);

        let exact_threshold = packet(6_000_000);
        stats.update(&exact_threshold, false, first.timestamp_us);

        let over_threshold = packet(11_000_500);
        stats.update(&over_threshold, true, exact_threshold.timestamp_us);

        assert_eq!(stats.active_stats.get_count(), 1);
        assert!((stats.active_stats.get_total() - 5_000.0).abs() < f64::EPSILON);
        assert_eq!(stats.idle_stats.get_count(), 1);
        assert!((stats.idle_stats.get_total() - 5_000.5).abs() < f64::EPSILON);
    }

    #[test]
    fn iat_stats_preserve_sub_millisecond_precision() {
        let mut stats = IATStats::new();

        let first = packet(1_000_000);
        stats.update(&first, true, first.timestamp_us);

        let second = packet(1_000_500);
        stats.update(&second, true, first.timestamp_us);

        let third = packet(1_001_250);
        stats.update(&third, false, second.timestamp_us);

        assert_eq!(stats.fwd_iat.get_count(), 1);
        assert!((stats.fwd_iat.get_mean() - 0.5).abs() < f64::EPSILON);
        assert_eq!(stats.iat.get_count(), 2);
        assert!((stats.iat.get_total() - 1.25).abs() < f64::EPSILON);
    }

    #[test]
    fn timing_stats_preserve_sub_millisecond_precision() {
        let mut stats = TimingStats::new();

        let first = packet(1_000_000);
        stats.update(&first, true, first.timestamp_us);

        let second = packet(1_000_750);
        stats.update(&second, true, first.timestamp_us);

        let third = packet(1_001_250);
        stats.update(&third, false, second.timestamp_us);

        let fourth = packet(1_002_125);
        stats.update(&fourth, false, third.timestamp_us);

        assert!((stats.first_timestamp_fwd_ms() - 1_000.0).abs() < f64::EPSILON);
        assert!((stats.last_timestamp_fwd_ms() - 1_000.75).abs() < f64::EPSILON);
        assert!((stats.get_fwd_duration() - 0.75).abs() < f64::EPSILON);
        assert!((stats.get_bwd_duration() - 0.875).abs() < f64::EPSILON);
    }
}
