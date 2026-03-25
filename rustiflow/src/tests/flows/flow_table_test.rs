#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;

    use crate::{
        flow_table::FlowTable,
        flows::{basic_flow::BasicFlow, util::FlowExpireCause},
        packet_features::PacketFeatures,
    };

    fn build_packet(timestamp_us: i64) -> PacketFeatures {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 12345,
            destination_port: 443,
            protocol: 6,
            timestamp_us,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn exports_idle_timed_out_flow_with_idle_timeout_cause() {
        let (tx, mut rx) = mpsc::channel::<BasicFlow>(4);
        let mut flow_table = FlowTable::new(3600, 1, None, tx, 60);

        flow_table.process_packet(&build_packet(1_000_000)).await;
        flow_table.export_expired_flows(3_000_000).await;

        let exported_flow = rx.recv().await.expect("expected an exported flow");

        assert_eq!(
            exported_flow.flow_expire_cause,
            FlowExpireCause::IdleTimeout
        );
        assert_eq!(
            exported_flow.flow_key,
            "192.168.1.1:12345-192.168.1.2:443-6".to_string()
        );
    }

    #[tokio::test]
    async fn preserves_tcp_reset_cause_when_packet_terminates_flow() {
        let (tx, mut rx) = mpsc::channel::<BasicFlow>(4);
        let mut flow_table = FlowTable::new(3600, 120, None, tx, 60);

        let mut syn = build_packet(1_000_000);
        syn.syn_flag = 1;
        flow_table.process_packet(&syn).await;

        let mut rst = build_packet(1_100_000);
        rst.rst_flag = 1;
        flow_table.process_packet(&rst).await;

        let exported_flow = rx.recv().await.expect("expected exported reset flow");
        assert_eq!(exported_flow.flow_expire_cause, FlowExpireCause::TcpReset);
        assert!(!exported_flow.tcp_handshake_completed);
        assert!(exported_flow.tcp_reset_before_handshake);
    }

    #[tokio::test]
    async fn does_not_reexport_first_packet_terminated_flow() {
        let (tx, mut rx) = mpsc::channel::<BasicFlow>(4);
        let mut flow_table = FlowTable::new(3600, 120, None, tx, 60);

        let mut rst = build_packet(1_000_000);
        rst.rst_flag = 1;
        flow_table.process_packet(&rst).await;

        let exported_flow = rx.recv().await.expect("expected first export");
        assert_eq!(exported_flow.flow_expire_cause, FlowExpireCause::TcpReset);

        flow_table.export_all_flows(2_000_000).await;

        assert!(rx.try_recv().is_err());
    }
}
