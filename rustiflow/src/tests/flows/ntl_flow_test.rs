#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::flows::{flow::Flow, ntl_flow::NTLFlow};

    fn setup_ntl_flow() -> NTLFlow {
        NTLFlow::new(
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
    fn test_update_fwd_pkt_len_stats() {
        let mut ntl_flow = setup_ntl_flow();

        ntl_flow.cic_flow.basic_flow.fwd_packet_count = 1;

        ntl_flow.update_fwd_header_len_stats(100);

        assert_eq!(ntl_flow.fwd_header_len_max, 100);
        assert_eq!(ntl_flow.fwd_header_len_min, 100);
        assert_eq!(ntl_flow.fwd_header_len_mean, 100.0);
        assert_eq!(ntl_flow.fwd_header_len_std, 0.0);
        assert_eq!(ntl_flow.cic_flow.fwd_header_length, 100);

        ntl_flow.cic_flow.basic_flow.fwd_packet_count = 2;

        ntl_flow.update_fwd_header_len_stats(50);

        assert_eq!(ntl_flow.fwd_header_len_max, 100);
        assert_eq!(ntl_flow.fwd_header_len_min, 50);
        assert_eq!(ntl_flow.fwd_header_len_mean, 75.0);
        assert_eq!(ntl_flow.fwd_header_len_std, 25.0);
        assert_eq!(ntl_flow.cic_flow.fwd_header_length, 150);

        ntl_flow.cic_flow.basic_flow.fwd_packet_count = 3;

        ntl_flow.update_fwd_header_len_stats(0);

        assert_eq!(ntl_flow.fwd_header_len_max, 100);
        assert_eq!(ntl_flow.fwd_header_len_min, 0);
        assert_eq!(ntl_flow.fwd_header_len_mean, 50.0);
        assert_eq!(ntl_flow.fwd_header_len_std, 40.824829046386306);
        assert_eq!(ntl_flow.cic_flow.fwd_header_length, 150);
    }

    #[test]
    fn test_update_bwd_pkt_len_stats() {
        let mut ntl_flow = setup_ntl_flow();

        ntl_flow.cic_flow.basic_flow.bwd_packet_count = 1;

        ntl_flow.update_bwd_header_len_stats(100);

        assert_eq!(ntl_flow.bwd_header_len_max, 100);
        assert_eq!(ntl_flow.bwd_header_len_min, 100);
        assert_eq!(ntl_flow.bwd_header_len_mean, 100.0);
        assert_eq!(ntl_flow.bwd_header_len_std, 0.0);
        assert_eq!(ntl_flow.cic_flow.bwd_header_length, 100);

        ntl_flow.cic_flow.basic_flow.bwd_packet_count = 2;

        ntl_flow.update_bwd_header_len_stats(50);

        assert_eq!(ntl_flow.bwd_header_len_max, 100);
        assert_eq!(ntl_flow.bwd_header_len_min, 50);
        assert_eq!(ntl_flow.bwd_header_len_mean, 75.0);
        assert_eq!(ntl_flow.bwd_header_len_std, 25.0);
        assert_eq!(ntl_flow.cic_flow.bwd_header_length, 150);

        ntl_flow.cic_flow.basic_flow.bwd_packet_count = 3;

        ntl_flow.update_bwd_header_len_stats(0);

        assert_eq!(ntl_flow.bwd_header_len_max, 100);
        assert_eq!(ntl_flow.bwd_header_len_min, 0);
        assert_eq!(ntl_flow.bwd_header_len_mean, 50.0);
        assert_eq!(ntl_flow.bwd_header_len_std, 40.824829046386306);
        assert_eq!(ntl_flow.cic_flow.bwd_header_length, 150);
    }

    #[test]
    fn test_get_fwd_header_length_min() {
        let mut cic_flow = setup_ntl_flow();

        assert_eq!(cic_flow.get_fwd_header_length_min(), 0);

        cic_flow.fwd_header_len_min = 50;

        assert_eq!(cic_flow.get_fwd_header_length_min(), 50);
    }

    #[test]
    fn test_get_bwd_header_length_min() {
        let mut cic_flow = setup_ntl_flow();

        assert_eq!(cic_flow.get_bwd_header_length_min(), 0);

        cic_flow.bwd_header_len_min = 100;

        assert_eq!(cic_flow.get_bwd_header_length_min(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_min() {
        let mut cic_flow = setup_ntl_flow();

        cic_flow.fwd_header_len_min = 100;
        cic_flow.bwd_header_len_min = 50;

        assert_eq!(cic_flow.get_flow_header_length_min(), 50);
    }

    #[test]
    fn test_get_flow_packet_length_max() {
        let mut cic_flow = setup_ntl_flow();

        cic_flow.fwd_header_len_max = 100;
        cic_flow.bwd_header_len_max = 50;

        assert_eq!(cic_flow.get_flow_header_length_max(), 100);
    }

    #[test]
    fn test_get_flow_packet_length_mean() {
        let mut cic_flow = setup_ntl_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_header_len_mean = 30.0;
        cic_flow.bwd_header_len_mean = 25.0;

        cic_flow.cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_header_length_mean(), 28.125);
    }

    #[test]
    fn test_get_flow_packet_length_variance() {
        let mut cic_flow = setup_ntl_flow();

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_header_len_std = 14.142135623731;
        cic_flow.bwd_header_len_std = 8.1649658092773;

        cic_flow.cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.cic_flow.basic_flow.bwd_packet_count = 3;

        assert_eq!(cic_flow.get_flow_header_length_variance() as u32, 155); // removing everything behind the comma because of arithmetic errors
    }

    #[test]
    fn test_get_flow_packet_length_std() {
        let mut cic_flow = setup_ntl_flow();
        let epsilon = 1e-1; // floating-point arithmetic is not exact, here we have a lot of casting and the formula is also an approximation

        //let forward_iat = [10, 20, 30, 40, 50];
        //let backward_iat = [15, 25, 35];

        cic_flow.fwd_header_len_std = 14.142135623731;
        cic_flow.bwd_header_len_std = 8.1649658092773;

        cic_flow.cic_flow.basic_flow.fwd_packet_count = 5;
        cic_flow.cic_flow.basic_flow.bwd_packet_count = 3;

        assert!(
            (cic_flow.get_flow_header_length_std() - 12.484365222149).abs() < epsilon,
            "get_flow_packet_length_std is not within the expected range"
        );
    }
}
