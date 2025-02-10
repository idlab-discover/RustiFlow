#[cfg(test)]
mod tests {
    use crate::flows::{cidds_flow::CiddsFlow, flow::Flow};
    use crate::packet_features::PacketFeatures;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn setup_ciddsflow() -> CiddsFlow {
        CiddsFlow::new(
            "test_flow_id".to_string(),
            IpAddr::V4(Ipv4Addr::from(1)),
            80,
            IpAddr::V4(Ipv4Addr::from(2)),
            8080,
            6,
            chrono::Utc::now(),
        )
    }

    #[test]
    fn test_get_flags_string() {
        let mut flow = setup_ciddsflow();
        assert_eq!(flow.get_flags_string(), "......");

        flow.basic_flow.fwd_urg_flag_count = 1;
        assert_eq!(flow.get_flags_string(), "U.....");

        flow.basic_flow.fwd_fin_flag_count = 1;
        assert_eq!(flow.get_flags_string(), "U....F");

        flow.basic_flow.fwd_ack_flag_count = 1;
        assert_eq!(flow.get_flags_string(), "UA...F");

        flow.basic_flow.fwd_psh_flag_count = 1;
        assert_eq!(flow.get_flags_string(), "UAP..F");

        flow.basic_flow.fwd_rst_flag_count = 1;
        assert_eq!(flow.get_flags_string(), "UAPR.F");

        flow.basic_flow.fwd_syn_flag_count = 1;
        assert_eq!(flow.get_flags_string(), "UAPRSF");
    }

    #[test]
    fn test_new_flow() {
        let flow = setup_ciddsflow();
        assert_eq!(flow.basic_flow.ip_source, IpAddr::V4(Ipv4Addr::from(1)));
        assert_eq!(flow.basic_flow.port_source, 80);
        assert_eq!(
            flow.basic_flow.ip_destination,
            IpAddr::V4(Ipv4Addr::from(2))
        );
        assert_eq!(flow.basic_flow.port_destination, 8080);
        assert_eq!(flow.basic_flow.protocol, 6);
        assert_eq!(flow.bytes, 0);
    }

    #[test]
    fn test_update_flow() {
        let mut flow = setup_ciddsflow();
        let packet = PacketFeatures {
            length: 100,
            ..Default::default()
        };
        let end = flow.update_flow(&packet, true);
        assert!(!end);
        assert_eq!(flow.bytes, 100);
        assert_eq!(flow.basic_flow.fwd_packet_count, 1);
    }

    #[test]
    fn test_dump() {
        let flow = setup_ciddsflow();
        let dumped = flow.dump();
        assert!(dumped.contains(&flow.basic_flow.ip_source.to_string()));
        assert!(dumped.contains(&flow.basic_flow.ip_destination.to_string()));
        assert!(dumped.contains("TCP"));
    }

    #[test]
    fn test_get_features() {
        let features = CiddsFlow::get_features();
        assert_eq!(features, "FIRST_TIMESTAMP,LAST_TIMESTAMP,PROTOCOL,SOURCE_IP,SOURCE_PORT,DESTINATION_IP,DESTINATION_PORT,PACKET_COUNT,BYTES,FLAGS");
    }

    #[test]
    fn test_dump_without_contamination() {
        let flow = setup_ciddsflow();
        let dumped = flow.dump_without_contamination();
        assert!(dumped.contains("TCP"));
        assert!(dumped.contains("0")); // packet count and bytes are 0 initially
    }

    #[test]
    fn test_get_features_without_contamination() {
        let features = CiddsFlow::get_features_without_contamination();
        assert_eq!(features, "DURATION,PROTOCOL,PACKET_COUNT,BYTES,FLAGS");
    }

    #[test]
    fn test_get_first_timestamp() {
        let flow = setup_ciddsflow();
        let first_timestamp = flow.get_first_timestamp();
        assert_eq!(first_timestamp, flow.basic_flow.first_timestamp);
    }

    #[test]
    fn test_is_expired() {
        let flow = setup_ciddsflow();
        let now = Utc::now();
        let expired = flow.is_expired(now, 10000, 5000);
        assert!(!expired);
    }

    #[test]
    fn test_flow_key() {
        let flow = setup_ciddsflow();
        assert_eq!(flow.flow_key(), &flow.basic_flow.flow_key);
    }
}
