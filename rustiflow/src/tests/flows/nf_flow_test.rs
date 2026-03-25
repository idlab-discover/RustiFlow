#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::flows::{flow::Flow, nf_flow::NfFlow, util::FlowExpireCause};

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
}
