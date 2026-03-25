#[cfg(test)]
mod tests {
    use pnet::packet::ip::IpNextHeaderProtocols;

    use crate::{
        flows::{
            features::{
                active_idle_stats::ActiveIdleStats, icmp_stats::IcmpStats,
                payload_stats::PayloadLengthStats, retransmission_stats::RetransmissionStats,
                subflow_stats::SubflowStats, util::FlowFeature, window_size_stats::WindowSizeStats,
            },
            util::FlowExpireCause,
        },
        packet_features::{PacketFeatures, ACK_FLAG},
    };

    fn packet(timestamp_us: i64) -> PacketFeatures {
        PacketFeatures {
            timestamp_us,
            ..Default::default()
        }
    }

    #[test]
    fn icmp_stats_only_keep_first_packet_type_and_code() {
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

        assert_eq!(stats.get_type(), 8);
        assert_eq!(stats.get_code(), 0);
    }

    #[test]
    fn retransmission_stats_skip_pure_acks_and_icmp_and_track_duplicates_by_direction() {
        let mut stats = RetransmissionStats::new();

        let mut pure_ack = packet(1_000_000);
        pure_ack.protocol = IpNextHeaderProtocols::Tcp.0;
        pure_ack.flags = ACK_FLAG;
        pure_ack.ack_flag = 1;
        pure_ack.sequence_number = 11;
        stats.update(&pure_ack, true, pure_ack.timestamp_us);
        stats.update(&pure_ack, true, pure_ack.timestamp_us);

        let mut icmp = packet(1_500_000);
        icmp.protocol = IpNextHeaderProtocols::Icmp.0;
        icmp.sequence_number = 22;
        stats.update(&icmp, true, pure_ack.timestamp_us);
        stats.update(&icmp, true, pure_ack.timestamp_us);

        let mut fwd = packet(2_000_000);
        fwd.protocol = IpNextHeaderProtocols::Tcp.0;
        fwd.sequence_number = 100;
        stats.update(&fwd, true, pure_ack.timestamp_us);
        stats.update(&fwd, true, pure_ack.timestamp_us);

        let mut bwd = packet(2_500_000);
        bwd.protocol = IpNextHeaderProtocols::Tcp.0;
        bwd.sequence_number = 200;
        stats.update(&bwd, false, fwd.timestamp_us);
        stats.update(&bwd, false, fwd.timestamp_us);

        assert_eq!(stats.fwd_retransmission_count, 1);
        assert_eq!(stats.bwd_retransmission_count, 1);
        assert_eq!(stats.dump(), "2,1,1");
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
    fn subflow_stats_increment_only_on_gaps_greater_than_one_second() {
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

        assert_eq!(stats.subflow_count, 1);
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
}
