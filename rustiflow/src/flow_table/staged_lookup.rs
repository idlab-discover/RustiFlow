use std::{
    arch::x86_64::{_mm_prefetch, _MM_HINT_T0},
    mem::size_of,
};

use super::{FlowTable, PacketLookup};
use crate::{packet_features::PacketFeatures, Flow};

const LOOKAHEAD: usize = 8;
const PREFETCH_BYTES: usize = 256;

impl<T: Flow> FlowTable<T> {
    pub(super) async fn process_staged_batch(&mut self, packets: &[PacketFeatures]) {
        let (chunks, remainder) = packets.as_chunks::<LOOKAHEAD>();
        for chunk in chunks {
            let mut lookups: [PacketLookup; LOOKAHEAD] =
                std::array::from_fn(|i| self.packet_lookup(&chunk[i]));
            for lookup in &mut lookups {
                lookup.bucket_hint = self
                    .flow_map
                    .find_bucket_index(lookup.hash, |entry| entry.key == lookup.key);
                if let Some(entry) = lookup.bucket_hint.and_then(|i| self.flow_map.get_bucket(i)) {
                    let address = std::ptr::from_ref(&entry.flow).cast::<i8>();
                    for offset in (0..size_of::<T>().min(PREFETCH_BYTES)).step_by(64) {
                        // SAFETY: x86-64 guarantees SSE. Each address is inside
                        // the live flow, which is only borrowed during staging.
                        unsafe { _mm_prefetch::<_MM_HINT_T0>(address.add(offset)) };
                    }
                }
            }
            for (packet, lookup) in chunk.iter().zip(lookups) {
                self.check_and_export_expired_flows(packet.timestamp_us)
                    .await;
                self.apply_lookup(packet, lookup).await;
            }
        }
        for packet in remainder {
            self.process_packet(packet).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, num::NonZeroU64};

    use tokio::sync::mpsc;

    use super::*;
    use crate::flows::{rusti_flow::RustiFlow, util::FlowExpireCause};

    fn packet(flow: u8, timestamp_us: i64) -> PacketFeatures {
        PacketFeatures {
            source_ip: Ipv4Addr::new(10, 0, 0, flow).into(),
            destination_ip: Ipv4Addr::new(198, 18, 0, 1).into(),
            source_port: 40_000,
            destination_port: 443,
            protocol: 6,
            timestamp_us,
            ..Default::default()
        }
    }

    async fn export_sequence(staged: bool) -> Vec<(String, FlowExpireCause)> {
        let (sender, mut receiver) = mpsc::channel(32);
        let mut table = FlowTable::<RustiFlow>::new(3, 1, NonZeroU64::new(1), sender, 1);
        // Fill the initial three usable buckets so the leading miss must grow
        // the table before any of the remaining hints can be consumed.
        for flow in 1..=3 {
            table.process_packet(&packet(flow, i64::from(flow))).await;
        }
        assert_eq!(table.flow_map.len(), table.flow_map.capacity());
        let mut reset = packet(1, 12);
        reset.rst_flag = 1;
        let mut reverse = packet(1, 13);
        std::mem::swap(&mut reverse.source_ip, &mut reverse.destination_ip);
        std::mem::swap(&mut reverse.source_port, &mut reverse.destination_port);

        let batch = [
            packet(4, 11),
            reset,
            reverse,
            packet(1, 20),
            packet(2, 1_000_003), // early export and scheduled sweep
            packet(3, 2_000_004), // sweep removes the hinted flow before this hit
            packet(3, 2_000_005),
            packet(4, 2_000_020), // idle expiration without a sweep
            packet(1, 2_100_000), // scalar tail
        ];
        if staged {
            table.process_staged_batch(&batch).await;
        } else {
            for packet in &batch {
                table.process_packet(packet).await;
            }
        }
        table.export_all_flows(batch[8].timestamp_us).await;
        drop(table);
        let mut rows = Vec::new();
        while let Some(flow) = receiver.recv().await {
            rows.push((flow.dump(), flow.basic_flow.flow_expire_cause));
        }
        rows
    }

    #[tokio::test]
    async fn staged_lookup_preserves_flow_lifecycle() {
        let scalar = export_sequence(false).await;
        let staged = export_sequence(true).await;
        assert_eq!(staged, scalar);
        assert!(staged
            .iter()
            .any(|(_, cause)| *cause == FlowExpireCause::TcpReset));
        assert!(staged
            .iter()
            .any(|(_, cause)| *cause == FlowExpireCause::IdleTimeout));
        assert!(staged
            .iter()
            .any(|(_, cause)| *cause == FlowExpireCause::None));
    }
}
