#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::sync::mpsc;

    use crate::{
        flows::{flow::Flow, rusti_flow::RustiFlow, util::FlowExpireCause},
        pcap::read_pcap_file,
    };

    fn fixture_path(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    fn count_csv_fields(row: &str) -> usize {
        row.split(',').count()
    }

    async fn extract_fixture(name: &str) -> Vec<RustiFlow> {
        let (tx, mut rx) = mpsc::channel::<RustiFlow>(64);

        read_pcap_file::<RustiFlow>(&fixture_path(name), tx, 1, 3600, 120, None, 60)
            .await
            .expect("fixture pcap should parse successfully");

        let mut flows = Vec::new();
        while let Some(flow) = rx.recv().await {
            flows.push(flow);
        }

        flows
    }

    #[tokio::test]
    async fn tiny_concap_tcp_syn_fixture_extracts_expected_flows() {
        let flows = extract_fixture("nmap_tcp_syn_version.pcap").await;

        assert_eq!(flows.len(), 17);

        for flow in &flows {
            assert_eq!(
                count_csv_fields(&flow.dump()),
                count_csv_fields(&RustiFlow::get_features())
            );
        }

        let established_http_flow = flows
            .iter()
            .find(|flow| flow.basic_flow.flow_key == "192.168.126.228:54122-192.168.126.224:80-6")
            .expect("expected established HTTP flow in fixture");
        assert_eq!(established_http_flow.packet_len_stats.flow_count(), 10);
        assert_eq!(
            established_http_flow
                .packet_len_stats
                .fwd_packet_len
                .get_count(),
            5
        );
        assert_eq!(
            established_http_flow
                .packet_len_stats
                .bwd_packet_len
                .get_count(),
            5
        );
        assert_eq!(
            established_http_flow.basic_flow.flow_expire_cause,
            FlowExpireCause::TcpTermination
        );
        assert_eq!(established_http_flow.tcp_flags_stats.get_flags(), ".AP.SF");

        let icmp_flow = flows
            .iter()
            .find(|flow| flow.basic_flow.flow_key == "192.168.126.228:0-192.168.126.224:0-1")
            .expect("expected ICMP flow in fixture");
        assert_eq!(icmp_flow.packet_len_stats.flow_count(), 4);
        assert_eq!(icmp_flow.icmp_stats.get_type(), 8);
        assert_eq!(icmp_flow.icmp_stats.get_code(), 0);
        assert_eq!(
            icmp_flow.basic_flow.flow_expire_cause,
            FlowExpireCause::ExporterShutdown
        );
    }

    #[tokio::test]
    async fn tiny_concap_udp_fixture_extracts_expected_protocol_mix() {
        let flows = extract_fixture("nmap_udp_version.pcap").await;

        assert_eq!(flows.len(), 56);

        for flow in &flows {
            assert_eq!(
                count_csv_fields(&flow.dump()),
                count_csv_fields(&RustiFlow::get_features())
            );
        }

        assert_eq!(
            flows
                .iter()
                .filter(|flow| flow.basic_flow.protocol == 17)
                .count(),
            53
        );
        assert_eq!(
            flows
                .iter()
                .filter(|flow| flow.basic_flow.protocol == 6)
                .count(),
            2
        );
        assert_eq!(
            flows
                .iter()
                .filter(|flow| flow.basic_flow.protocol == 1)
                .count(),
            1
        );

        let tcp_port_80_flow = flows
            .iter()
            .find(|flow| flow.basic_flow.flow_key == "192.168.177.151:48385-192.168.126.204:80-6")
            .expect("expected TCP port 80 response flow in fixture");
        assert_eq!(tcp_port_80_flow.packet_len_stats.flow_count(), 2);
        assert_eq!(
            tcp_port_80_flow.basic_flow.flow_expire_cause,
            FlowExpireCause::TcpTermination
        );
        assert_eq!(tcp_port_80_flow.tcp_flags_stats.get_flags(), ".A.R..");

        let icmp_flow = flows
            .iter()
            .find(|flow| flow.basic_flow.flow_key == "192.168.177.151:0-192.168.126.204:0-1")
            .expect("expected ICMP response flow in fixture");
        assert_eq!(icmp_flow.packet_len_stats.flow_count(), 22);
        assert_eq!(icmp_flow.packet_len_stats.fwd_packet_len.get_count(), 2);
        assert_eq!(icmp_flow.packet_len_stats.bwd_packet_len.get_count(), 20);
        assert_eq!(icmp_flow.icmp_stats.get_type(), 8);
        assert_eq!(icmp_flow.icmp_stats.get_code(), 0);
        assert_eq!(
            icmp_flow.basic_flow.flow_expire_cause,
            FlowExpireCause::ExporterShutdown
        );
    }
}
