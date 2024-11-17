#[cfg(test)]
mod tests {
    use crate::flows::{cic_flow::CicFlow, flow::Flow};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn setup_cic_flow() -> CicFlow {
        CicFlow::new(
            "".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        )
    }

    #[test]
    fn test_increase_fwd_header_length() {
        let mut cic_flow = setup_cic_flow();

        let initial_length = cic_flow.fwd_header_length;

        cic_flow.increase_fwd_header_length(20);
        assert_eq!(cic_flow.fwd_header_length, initial_length + 20);

        cic_flow.increase_fwd_header_length(0);
        assert_eq!(cic_flow.fwd_header_length, initial_length + 20);
    }

    #[test]
    fn test_increase_bwd_header_length() {
        let mut cic_flow = setup_cic_flow();

        let initial_length = cic_flow.bwd_header_length;

        cic_flow.increase_bwd_header_length(30);
        assert_eq!(cic_flow.bwd_header_length, initial_length + 30);

        cic_flow.increase_bwd_header_length(0);
        assert_eq!(cic_flow.bwd_header_length, initial_length + 30);
    }

    #[test]
    fn test_update_fwd_pkt_len_stats() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.fwd_packet_count = 1;

        cic_flow.update_fwd_pkt_len_stats(100);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 100);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 100.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 100);

        cic_flow.basic_flow.fwd_packet_count = 2;

        cic_flow.update_fwd_pkt_len_stats(50);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 50);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 75.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 25.0);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 150);

        cic_flow.basic_flow.fwd_packet_count = 3;

        cic_flow.update_fwd_pkt_len_stats(0);

        assert_eq!(cic_flow.fwd_pkt_len_max, 100);
        assert_eq!(cic_flow.fwd_pkt_len_min, 0);
        assert_eq!(cic_flow.fwd_pkt_len_mean, 50.0);
        assert_eq!(cic_flow.fwd_pkt_len_std, 40.824829046386306);
        assert_eq!(cic_flow.fwd_pkt_len_tot, 150);
    }

    #[test]
    fn test_update_bwd_pkt_len_stats() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.basic_flow.bwd_packet_count = 1;

        cic_flow.update_bwd_pkt_len_stats(100);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 100);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 100.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 0.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 100);

        cic_flow.basic_flow.bwd_packet_count = 2;

        cic_flow.update_bwd_pkt_len_stats(50);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 50);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 75.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 25.0);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 150);

        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.update_bwd_pkt_len_stats(0);

        assert_eq!(cic_flow.bwd_pkt_len_max, 100);
        assert_eq!(cic_flow.bwd_pkt_len_min, 0);
        assert_eq!(cic_flow.bwd_pkt_len_mean, 50.0);
        assert_eq!(cic_flow.bwd_pkt_len_std, 40.824829046386306);
        assert_eq!(cic_flow.bwd_pkt_len_tot, 150);
    }

    #[test]
    fn test_update_fwd_iat_stats() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-9; // floating-point arithmetic is not exact

        cic_flow.basic_flow.fwd_packet_count = 2;

        cic_flow.update_fwd_iat_stats(0.05);

        assert_eq!(cic_flow.fwd_iat_max, 0.05);
        assert_eq!(cic_flow.fwd_iat_min, 0.05);
        assert_eq!(cic_flow.fwd_iat_mean, 0.05);
        assert_eq!(cic_flow.fwd_iat_std, 0.0);
        assert_eq!(cic_flow.fwd_iat_total, 0.05);

        cic_flow.basic_flow.fwd_packet_count = 3;

        cic_flow.update_fwd_iat_stats(0.01);

        assert_eq!(cic_flow.fwd_iat_max, 0.05);
        assert_eq!(cic_flow.fwd_iat_min, 0.01);
        assert!(
            (cic_flow.fwd_iat_mean - 0.03).abs() < epsilon,
            "fwd_iat_mean is not within the expected range"
        );
        assert_eq!(cic_flow.fwd_iat_std, 0.02);
        assert!(
            (cic_flow.fwd_iat_total - 0.06).abs() < epsilon,
            "fwd_iat_total is not within the expected range"
        );

        cic_flow.basic_flow.fwd_packet_count = 4;

        cic_flow.update_fwd_iat_stats(0.698456231458);

        assert_eq!(cic_flow.fwd_iat_max, 0.698456231458);
        assert_eq!(cic_flow.fwd_iat_min, 0.01);
        assert_eq!(cic_flow.fwd_iat_mean, 0.25281874381933334);
        assert_eq!(cic_flow.fwd_iat_std, 0.31553613400230096);
        assert_eq!(cic_flow.fwd_iat_total, 0.758456231458);
    }

    #[test]
    fn test_update_bwd_iat_stats() {
        let mut cic_flow = setup_cic_flow();
        let epsilon = 1e-9; // floating-point arithmetic is not exact

        cic_flow.basic_flow.bwd_packet_count = 2;

        cic_flow.update_bwd_iat_stats(0.05);

        assert_eq!(cic_flow.bwd_iat_max, 0.05);
        assert_eq!(cic_flow.bwd_iat_min, 0.05);
        assert_eq!(cic_flow.bwd_iat_mean, 0.05);
        assert_eq!(cic_flow.bwd_iat_std, 0.0);
        assert_eq!(cic_flow.bwd_iat_total, 0.05);

        cic_flow.basic_flow.bwd_packet_count = 3;

        cic_flow.update_bwd_iat_stats(0.01);

        assert_eq!(cic_flow.bwd_iat_max, 0.05);
        assert_eq!(cic_flow.bwd_iat_min, 0.01);
        assert!(
            (cic_flow.bwd_iat_mean - 0.03).abs() < epsilon,
            "fwd_iat_mean is not within the expected range"
        );
        assert_eq!(cic_flow.bwd_iat_std, 0.02);
        assert!(
            (cic_flow.bwd_iat_total - 0.06).abs() < epsilon,
            "fwd_iat_total is not within the expected range"
        );

        cic_flow.basic_flow.bwd_packet_count = 4;

        cic_flow.update_bwd_iat_stats(0.698456231458);

        assert_eq!(cic_flow.bwd_iat_max, 0.698456231458);
        assert_eq!(cic_flow.bwd_iat_min, 0.01);
        assert_eq!(cic_flow.bwd_iat_mean, 0.25281874381933334);
        assert_eq!(cic_flow.bwd_iat_std, 0.31553613400230096);
        assert_eq!(cic_flow.bwd_iat_total, 0.758456231458);
    }

    #[test]
    fn test_update_fwd_bulk_stats() {
        let mut cic_flow = setup_cic_flow();
        let timestamp = Utc::now();
        let timestamp_2 = Utc::now();
        let timestamp_3 = Utc::now();
        let timestamp_4 = Utc::now();

        cic_flow.update_fwd_bulk_stats(&timestamp, 100);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 100);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_fwd_bulk_stats(&timestamp_2, 200);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 300);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_fwd_bulk_stats(&timestamp_3, 150);

        assert_eq!(cic_flow.fwd_bulk_state_count, 0);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.fwd_bulk_size_total, 0);
        assert_eq!(cic_flow.fwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 450);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_fwd_bulk_stats(&timestamp_4, 50);

        assert_eq!(cic_flow.fwd_bulk_state_count, 1);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.fwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.fwd_bulk_duration,
            timestamp_4
                .signed_duration_since(timestamp)
                .num_microseconds()
                .unwrap() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 4);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 500);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(timestamp_4));

        std::thread::sleep(std::time::Duration::from_secs(1));

        let new_timestamp = Utc::now();

        cic_flow.update_fwd_bulk_stats(&new_timestamp, 50);

        assert_eq!(cic_flow.fwd_bulk_state_count, 1);
        assert_eq!(cic_flow.fwd_bulk_packet_count, 5);
        assert_eq!(cic_flow.fwd_bulk_size_total, 550);
        assert_eq!(
            cic_flow.fwd_bulk_duration,
            new_timestamp
                .signed_duration_since(timestamp)
                .num_microseconds()
                .unwrap() as f64
        );
        assert_eq!(cic_flow.fwd_bulk_packet_count_help, 5);
        assert_eq!(cic_flow.fwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.fwd_bulk_size_help, 550);
        assert_eq!(cic_flow.fwd_last_bulk_timestamp, Some(new_timestamp));
    }

    #[test]
    fn test_update_bwd_bulk_stats() {
        let mut cic_flow = setup_cic_flow();
        let timestamp = Utc::now();
        let timestamp_2 = Utc::now();
        let timestamp_3 = Utc::now();
        let timestamp_4 = Utc::now();

        cic_flow.update_bwd_bulk_stats(&timestamp, 100);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 1);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 100);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp));

        cic_flow.update_bwd_bulk_stats(&timestamp_2, 200);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 2);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 300);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_2));

        cic_flow.update_bwd_bulk_stats(&timestamp_3, 150);

        assert_eq!(cic_flow.bwd_bulk_state_count, 0);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 0);
        assert_eq!(cic_flow.bwd_bulk_size_total, 0);
        assert_eq!(cic_flow.bwd_bulk_duration, 0.0);
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 3);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 450);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_3));

        cic_flow.update_bwd_bulk_stats(&timestamp_4, 50);

        assert_eq!(cic_flow.bwd_bulk_state_count, 1);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 4);
        assert_eq!(cic_flow.bwd_bulk_size_total, 500);
        assert_eq!(
            cic_flow.bwd_bulk_duration,
            timestamp_4
                .signed_duration_since(timestamp)
                .num_microseconds()
                .unwrap() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 4);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 500);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(timestamp_4));

        std::thread::sleep(std::time::Duration::from_secs(1));

        let new_timestamp = Utc::now();

        cic_flow.update_bwd_bulk_stats(&new_timestamp, 50);

        assert_eq!(cic_flow.bwd_bulk_state_count, 1);
        assert_eq!(cic_flow.bwd_bulk_packet_count, 5);
        assert_eq!(cic_flow.bwd_bulk_size_total, 550);
        assert_eq!(
            cic_flow.bwd_bulk_duration,
            new_timestamp
                .signed_duration_since(timestamp)
                .num_microseconds()
                .unwrap() as f64
        );
        assert_eq!(cic_flow.bwd_bulk_packet_count_help, 5);
        assert_eq!(cic_flow.bwd_bulk_start_help, Some(timestamp));
        assert_eq!(cic_flow.bwd_bulk_size_help, 550);
        assert_eq!(cic_flow.bwd_last_bulk_timestamp, Some(new_timestamp));
    }

    #[test]
    fn test_update_active_flow() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.update_active_flow(100.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 100.0);
        assert_eq!(cic_flow.active_mean, 100.0);
        assert_eq!(cic_flow.active_std, 0.0);
        assert_eq!(cic_flow.active_count, 1);

        cic_flow.update_active_flow(50.0);

        assert_eq!(cic_flow.active_max, 100.0);
        assert_eq!(cic_flow.active_min, 50.0);
        assert_eq!(cic_flow.active_mean, 75.0);
        assert_eq!(cic_flow.active_std, 25.0);
        assert_eq!(cic_flow.active_count, 2);
    }

    #[test]
    fn test_update_idle_flow() {
        let mut cic_flow = setup_cic_flow();

        cic_flow.update_idle_flow(100.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 100.0);
        assert_eq!(cic_flow.idle_mean, 100.0);
        assert_eq!(cic_flow.idle_std, 0.0);
        assert_eq!(cic_flow.idle_count, 1);

        cic_flow.update_idle_flow(50.0);

        assert_eq!(cic_flow.idle_max, 100.0);
        assert_eq!(cic_flow.idle_min, 50.0);
        assert_eq!(cic_flow.idle_mean, 75.0);
        assert_eq!(cic_flow.idle_std, 25.0);
        assert_eq!(cic_flow.idle_count, 2);
    }
}
