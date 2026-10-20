#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::num::{NonZeroU64, NonZeroUsize};

    use tokio::sync::mpsc;

    use crate::{
        args::{ExportConfig, FlowType, ReplayBenchArgs},
        flows::{rusti_flow::RustiFlow, util::FlowExpireCause},
        realtime::replay_bench,
    };

    /// Replays a small workload and summarizes what reached the exporter.
    async fn replay_and_summarize(ipv6: bool) -> (usize, u32, u32, bool) {
        let replay_args = ReplayBenchArgs {
            packets: NonZeroU64::new(20_000).unwrap(),
            flows: 300,
            sources: NonZeroUsize::new(3).unwrap(),
            // An odd burst size forces many partial-batch flushes.
            drain_burst: NonZeroUsize::new(7).unwrap(),
            payload_bytes: 100,
            virtual_pps: NonZeroU64::new(1_000_000).unwrap(),
            ipv6,
        };
        let config = ExportConfig {
            features: FlowType::Rustiflow,
            active_timeout: 3600,
            idle_timeout: 120,
            early_export: None,
            expiration_check_interval: 60,
            threads: None,
        };
        let (tx, mut rx) = mpsc::channel::<RustiFlow>(1024);

        replay_bench(&replay_args, &config, 4, tx, tokio::spawn(async {}))
            .await
            .expect("replay failed");

        // The shards finish asynchronously; the channel closes once all have
        // exported their flows.
        let mut flows = 0;
        let mut packets = 0;
        let mut retransmissions = 0;
        let mut all_shutdown_exports = true;
        while let Some(flow) = rx.recv().await {
            flows += 1;
            packets += flow.packet_len_stats.flow_count();
            retransmissions += flow.retransmission_stats.fwd_retransmission_count
                + flow.retransmission_stats.bwd_retransmission_count;
            all_shutdown_exports &=
                flow.basic_flow.flow_expire_cause == FlowExpireCause::ExporterShutdown;
        }
        (flows, packets, retransmissions, all_shutdown_exports)
    }

    #[tokio::test]
    async fn replay_delivers_every_event_to_one_flow_per_synthetic_flow() {
        // Every event arrives exactly once, flows stay whole across sources and
        // shards, and the in-order TCP segments look like no retransmissions.
        assert_eq!(replay_and_summarize(false).await, (300, 20_000, 0, true));
        assert_eq!(replay_and_summarize(true).await, (300, 20_000, 0, true));
    }
}
