#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf,
    };

    use tokio::sync::mpsc;

    use crate::{
        flows::{flow::Flow, nf_flow::NfFlow, util::FlowExpireCause},
        pcap::read_pcap_file,
    };

    fn setup_nf_flow() -> NfFlow {
        NfFlow::new(
            "nf-flow".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            80,
            6,
            1_000_000,
        )
    }

    fn count_csv_fields(row: &str) -> usize {
        row.split(',').count()
    }

    fn csv_fields(row: &str) -> Vec<&str> {
        row.split(',').collect()
    }

    fn fixture_path(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn dump_matches_feature_headers() {
        let flow = setup_nf_flow();

        assert_eq!(
            count_csv_fields(&flow.dump()),
            count_csv_fields(&NfFlow::get_features())
        );
        assert_eq!(
            count_csv_fields(&flow.dump_without_contamination()),
            count_csv_fields(&NfFlow::get_features_without_contamination())
        );
    }

    #[test]
    fn expiration_id_maps_from_close_cause() {
        let mut flow = setup_nf_flow();

        flow.close_flow(2_000_000, FlowExpireCause::ActiveTimeout);
        assert_eq!(flow.get_expiration_id(), 1);

        flow.close_flow(3_000_000, FlowExpireCause::IdleTimeout);
        assert_eq!(flow.get_expiration_id(), 0);

        flow.close_flow(4_000_000, FlowExpireCause::TcpReset);
        assert_eq!(flow.get_expiration_id(), -1);
    }

    #[test]
    fn ip_version_is_exported_for_ipv4_and_ipv6_flows() {
        let ipv4_flow = setup_nf_flow();
        assert_eq!(ipv4_flow.get_ip_version(), 4);
        assert_eq!(csv_fields(&ipv4_flow.dump())[7], "4");
        assert_eq!(csv_fields(&ipv4_flow.dump_without_contamination())[3], "4");

        let ipv6_flow = NfFlow::new(
            "nf-flow-v6".to_string(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            12345,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            80,
            6,
            1_000_000,
        );
        assert_eq!(ipv6_flow.get_ip_version(), 6);
        assert_eq!(csv_fields(&ipv6_flow.dump())[7], "6");
        assert_eq!(csv_fields(&ipv6_flow.dump_without_contamination())[3], "6");
    }

    #[tokio::test]
    async fn offline_fixture_exports_ipv4_version_for_all_flows() {
        let (tx, mut rx) = mpsc::channel::<NfFlow>(64);

        read_pcap_file::<NfFlow>(
            &fixture_path("nmap_tcp_syn_version.pcap"),
            tx,
            1,
            3600,
            120,
            None,
            60,
        )
        .await
        .expect("fixture pcap should parse successfully");

        let mut flow_count = 0;
        while let Some(flow) = rx.recv().await {
            flow_count += 1;
            assert_eq!(flow.get_ip_version(), 4);
            assert_eq!(csv_fields(&flow.dump())[7], "4");
        }

        assert_eq!(flow_count, 17);
    }
}
