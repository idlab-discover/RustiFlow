#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;

    use crate::{
        flow_table::FlowTable,
        flows::{basic_flow::BasicFlow, cidds_flow::CiddsFlow, util::FlowExpireCause},
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

    #[tokio::test]
    async fn reverse_direction_packets_stay_in_one_bidirectional_flow() {
        let (tx, mut rx) = mpsc::channel::<CiddsFlow>(4);
        let mut flow_table = FlowTable::new(3600, 120, None, tx, 60);

        let mut forward = build_packet(1_000_000);
        forward.length = 120;
        flow_table.process_packet(&forward).await;

        let reverse = PacketFeatures {
            source_ip: forward.destination_ip,
            destination_ip: forward.source_ip,
            source_port: forward.destination_port,
            destination_port: forward.source_port,
            protocol: forward.protocol,
            timestamp_us: 1_000_500,
            length: 80,
            ..Default::default()
        };
        flow_table.process_packet(&reverse).await;

        flow_table.export_all_flows(2_000_000).await;

        let exported_flow = rx.recv().await.expect("expected exported flow");
        assert_eq!(
            exported_flow.basic_flow.flow_key,
            forward.flow_key_value().to_string()
        );
        assert_eq!(exported_flow.packet_stats.flow_count(), 2);
        assert_eq!(exported_flow.packet_stats.fwd_packet_len.get_count(), 1);
        assert_eq!(exported_flow.packet_stats.bwd_packet_len.get_count(), 1);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn expired_flow_is_replaced_by_new_flow_for_the_same_key() {
        let (tx, mut rx) = mpsc::channel::<BasicFlow>(4);
        let mut flow_table = FlowTable::new(3600, 1, None, tx, 60);

        let first_packet = build_packet(1_000_000);
        let replacement_packet = build_packet(3_000_000);

        flow_table.process_packet(&first_packet).await;
        flow_table.process_packet(&replacement_packet).await;
        flow_table.export_all_flows(4_000_000).await;

        let first_export = rx.recv().await.expect("expected expired flow export");
        let second_export = rx.recv().await.expect("expected replacement flow export");

        assert_eq!(first_export.flow_expire_cause, FlowExpireCause::IdleTimeout);
        assert_eq!(first_export.first_timestamp_us, 1_000_000);
        assert_eq!(first_export.last_timestamp_us, 1_000_000);

        assert_eq!(
            second_export.flow_expire_cause,
            FlowExpireCause::ExporterShutdown
        );
        assert_eq!(second_export.first_timestamp_us, 3_000_000);
        assert_eq!(second_export.last_timestamp_us, 3_000_000);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn early_export_keeps_flow_active_for_later_final_export() {
        let (tx, mut rx) = mpsc::channel::<BasicFlow>(4);
        let mut flow_table = FlowTable::new(3600, 120, Some(1), tx, 60);

        flow_table.process_packet(&build_packet(1_000_000)).await;
        flow_table.process_packet(&build_packet(3_000_001)).await;

        let early_export = rx.recv().await.expect("expected early export");
        assert_eq!(early_export.flow_expire_cause, FlowExpireCause::None);
        assert_eq!(early_export.first_timestamp_us, 1_000_000);
        assert_eq!(early_export.last_timestamp_us, 3_000_001);

        flow_table.export_all_flows(4_000_000).await;

        let final_export = rx.recv().await.expect("expected final export");
        assert_eq!(
            final_export.flow_expire_cause,
            FlowExpireCause::ExporterShutdown
        );
        assert_eq!(final_export.first_timestamp_us, 1_000_000);
        assert_eq!(final_export.last_timestamp_us, 3_000_001);
        assert!(rx.try_recv().is_err());
    }
}
