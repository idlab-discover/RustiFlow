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
}
