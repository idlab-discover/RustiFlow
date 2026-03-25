#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::flows::{flow::Flow, rusti_flow::RustiFlow};

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
}
