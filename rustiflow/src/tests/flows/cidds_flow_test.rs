#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        flows::{cidds_flow::CiddsFlow, flow::Flow},
        packet_features::{PacketFeatures, SYN_FLAG},
    };

    fn setup_cidds_flow() -> CiddsFlow {
        CiddsFlow::new(
            "cidds-flow".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            443,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            51515,
            6,
            1_000_000,
        )
    }

    fn count_csv_fields(row: &str) -> usize {
        row.split(',').count()
    }

    #[test]
    fn dump_matches_feature_headers() {
        let flow = setup_cidds_flow();

        assert_eq!(
            count_csv_fields(&flow.dump()),
            count_csv_fields(&CiddsFlow::get_features())
        );
        assert_eq!(
            count_csv_fields(&flow.dump_without_contamination()),
            count_csv_fields(&CiddsFlow::get_features_without_contamination())
        );
    }

    #[test]
    fn update_flow_tracks_bytes_packets_and_flags() {
        let mut flow = setup_cidds_flow();
        let packet = PacketFeatures {
            source_ip: flow.basic_flow.ip_source,
            destination_ip: flow.basic_flow.ip_destination,
            source_port: flow.basic_flow.port_source,
            destination_port: flow.basic_flow.port_destination,
            protocol: flow.basic_flow.protocol,
            timestamp_us: 1_000_500,
            length: 128,
            syn_flag: 1,
            flags: SYN_FLAG,
            ..Default::default()
        };

        assert!(!flow.update_flow(&packet, true));

        assert_eq!(flow.packet_stats.flow_total(), 128.0);
        assert_eq!(flow.packet_stats.flow_count(), 1);
        assert_eq!(flow.tcp_flag_stats.get_flags(), "....S.");
    }
}
