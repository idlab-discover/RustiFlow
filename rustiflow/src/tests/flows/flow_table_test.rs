#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(target_os = "linux")]
    use common::EbpfEventIpv4;
    use tokio::sync::mpsc;

    use crate::{
        flow_table::FlowTable,
        flows::{
            basic_flow::BasicFlow, cidds_flow::CiddsFlow, flow::Flow, rusti_flow::RustiFlow,
            util::FlowExpireCause,
        },
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

    #[cfg(target_os = "linux")]
    fn build_realtime_packet(
        source_ip: Ipv4Addr,
        source_port: u16,
        destination_ip: Ipv4Addr,
        destination_port: u16,
        timestamp_us: i64,
        flags: u8,
        sequence_number: u32,
        sequence_number_ack: u32,
        data_length: u16,
    ) -> PacketFeatures {
        let realtime_offset_us = 1_000_000;
        let event = EbpfEventIpv4::new(
            (timestamp_us - realtime_offset_us) as u64 * 1_000,
            u32::from(destination_ip).to_be(),
            u32::from(source_ip).to_be(),
            destination_port,
            source_port,
            data_length,
            40 + data_length,
            4096,
            flags,
            6,
            20,
            sequence_number,
            sequence_number_ack,
            0,
            0,
        );
        PacketFeatures::from_ebpf_event_ipv4(&event, realtime_offset_us)
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn offline_and_realtime_bidirectional_exports_match() {
        let (offline_tx, mut offline_rx) = mpsc::channel::<RustiFlow>(4);
        let (realtime_tx, mut realtime_rx) = mpsc::channel::<RustiFlow>(4);
        let mut offline_table = FlowTable::new(3600, 120, None, offline_tx, 60);
        let mut realtime_table = FlowTable::new(3600, 120, None, realtime_tx, 60);

        let client_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_ip = Ipv4Addr::new(192, 168, 1, 2);

        let mut offline_syn = build_packet(1_000_000);
        offline_syn.syn_flag = 1;
        offline_syn.flags = 0x02;
        offline_syn.length = 40;
        offline_syn.header_length = 20;
        offline_syn.window_size = 4096;
        offline_syn.sequence_number = 100;

        let offline_syn_ack = PacketFeatures {
            source_ip: IpAddr::V4(server_ip),
            destination_ip: IpAddr::V4(client_ip),
            source_port: 443,
            destination_port: 12345,
            protocol: 6,
            timestamp_us: 1_000_100,
            syn_flag: 1,
            ack_flag: 1,
            flags: 0x12,
            header_length: 20,
            length: 40,
            window_size: 4096,
            sequence_number: 200,
            sequence_number_ack: 101,
            ..Default::default()
        };

        let mut offline_ack = build_packet(1_000_200);
        offline_ack.ack_flag = 1;
        offline_ack.flags = 0x10;
        offline_ack.length = 40;
        offline_ack.header_length = 20;
        offline_ack.window_size = 4096;
        offline_ack.sequence_number = 101;
        offline_ack.sequence_number_ack = 201;

        let mut offline_payload = build_packet(1_000_300);
        offline_payload.ack_flag = 1;
        offline_payload.psh_flag = 1;
        offline_payload.flags = 0x18;
        offline_payload.header_length = 20;
        offline_payload.data_length = 64;
        offline_payload.length = 104;
        offline_payload.window_size = 4096;
        offline_payload.sequence_number = 101;
        offline_payload.sequence_number_ack = 201;

        let realtime_syn =
            build_realtime_packet(client_ip, 12345, server_ip, 443, 1_000_000, 0x02, 100, 0, 0);
        let realtime_syn_ack = build_realtime_packet(
            server_ip, 443, client_ip, 12345, 1_000_100, 0x12, 200, 101, 0,
        );
        let realtime_ack = build_realtime_packet(
            client_ip, 12345, server_ip, 443, 1_000_200, 0x10, 101, 201, 0,
        );
        let realtime_payload = build_realtime_packet(
            client_ip, 12345, server_ip, 443, 1_000_300, 0x18, 101, 201, 64,
        );

        for packet in [
            &offline_syn,
            &offline_syn_ack,
            &offline_ack,
            &offline_payload,
        ] {
            offline_table.process_packet(packet).await;
        }
        for packet in [
            &realtime_syn,
            &realtime_syn_ack,
            &realtime_ack,
            &realtime_payload,
        ] {
            realtime_table.process_packet(packet).await;
        }

        offline_table.export_all_flows(2_000_000).await;
        realtime_table.export_all_flows(2_000_000).await;

        let offline_export = offline_rx.recv().await.expect("expected offline export");
        let realtime_export = realtime_rx.recv().await.expect("expected realtime export");

        assert_eq!(offline_export.dump(), realtime_export.dump());
        assert_eq!(
            offline_export.dump_without_contamination(),
            realtime_export.dump_without_contamination()
        );
        assert!(offline_rx.try_recv().is_err());
        assert!(realtime_rx.try_recv().is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn offline_and_realtime_idle_expiration_match() {
        let (offline_tx, mut offline_rx) = mpsc::channel::<BasicFlow>(4);
        let (realtime_tx, mut realtime_rx) = mpsc::channel::<BasicFlow>(4);
        let mut offline_table = FlowTable::new(3600, 1, None, offline_tx, 60);
        let mut realtime_table = FlowTable::new(3600, 1, None, realtime_tx, 60);

        let offline_packet = build_packet(1_000_000);
        let realtime_packet = build_realtime_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            12345,
            Ipv4Addr::new(192, 168, 1, 2),
            443,
            1_000_000,
            0,
            0,
            0,
            0,
        );

        offline_table.process_packet(&offline_packet).await;
        realtime_table.process_packet(&realtime_packet).await;

        offline_table.export_expired_flows(3_000_000).await;
        realtime_table.export_expired_flows(3_000_000).await;

        let offline_export = offline_rx.recv().await.expect("expected offline export");
        let realtime_export = realtime_rx.recv().await.expect("expected realtime export");

        assert_eq!(offline_export.dump(), realtime_export.dump());
        assert_eq!(
            offline_export.flow_expire_cause,
            FlowExpireCause::IdleTimeout
        );
        assert_eq!(
            realtime_export.flow_expire_cause,
            FlowExpireCause::IdleTimeout
        );
        assert!(offline_rx.try_recv().is_err());
        assert!(realtime_rx.try_recv().is_err());
    }
}
