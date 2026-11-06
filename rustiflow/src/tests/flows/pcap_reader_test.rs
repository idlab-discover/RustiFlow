#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use tokio::sync::mpsc;

    use crate::{
        flows::{flow::Flow, rusti_flow::RustiFlow, util::FlowExpireCause},
        pcap::read_pcap_file,
    };

    fn temp_pcap_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustiflow-{name}-{unique}.pcap"))
    }

    fn malformed_short_frame_pcap() -> Vec<u8> {
        let mut bytes = Vec::new();

        // pcap global header, little-endian, Ethernet linktype.
        bytes.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());

        let packet_data = [
            0, 1, 2, 3, 4, 5, // dst mac
            6, 7, 8, 9, 10, 11, // src mac
            0x12, 0x34, // unsupported ethertype, forces fallback branch
            0x99, // only one byte after ethertype, so old code could panic at [15]
        ];

        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(packet_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(packet_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&packet_data);

        bytes
    }

    #[tokio::test]
    async fn short_unsupported_frame_does_not_panic_offline_reader() {
        let path = temp_pcap_path("short-unsupported-frame");
        fs::write(&path, malformed_short_frame_pcap()).expect("pcap should be written");

        let (tx, mut rx) = mpsc::channel::<RustiFlow>(8);

        let result =
            read_pcap_file::<RustiFlow>(path.to_str().unwrap(), tx, 1, 3600, 120, None, 60).await;

        fs::remove_file(&path).ok();

        assert!(result.is_ok());
        assert!(rx.try_recv().is_err());
    }

    /// One UDP packet, then a record whose capture length libpcap rejects,
    /// then a second copy of the UDP packet.
    fn corrupt_record_after_one_packet_pcap() -> (Vec<u8>, usize) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());

        let frame = [
            2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00, // Ethernet, IPv4
            0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, // IPv4, 28 bytes, UDP
            10, 99, 0, 1, 10, 99, 0, 2, // 10.99.0.1 -> 10.99.0.2
            0x9c, 0x40, 0, 53, 0, 8, 0, 0, // UDP 40000 -> 53, no payload
        ];
        let record = |caplen: u32| {
            let mut header = Vec::new();
            header.extend_from_slice(&1_u32.to_le_bytes());
            header.extend_from_slice(&0_u32.to_le_bytes());
            header.extend_from_slice(&caplen.to_le_bytes());
            header.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            header
        };

        bytes.extend(record(frame.len() as u32));
        bytes.extend_from_slice(&frame);
        let corrupt_offset = bytes.len();
        bytes.extend(record(0x0010_0000));
        bytes.extend(record(frame.len() as u32));
        bytes.extend_from_slice(&frame);

        (bytes, corrupt_offset)
    }

    #[tokio::test]
    async fn corrupt_record_mid_file_is_an_error_after_exporting_earlier_packets() {
        let path = temp_pcap_path("corrupt-record-mid-file");
        let (bytes, corrupt_offset) = corrupt_record_after_one_packet_pcap();
        fs::write(&path, bytes).expect("pcap should be written");

        let (tx, mut rx) = mpsc::channel::<RustiFlow>(8);

        let result =
            read_pcap_file::<RustiFlow>(path.to_str().unwrap(), tx, 1, 3600, 120, None, 60).await;

        fs::remove_file(&path).ok();

        let error = format!(
            "{:#}",
            result.expect_err("a corrupt record must be reported")
        );
        assert!(
            error.contains(&format!("corrupt record at offset {corrupt_offset}")),
            "{error}"
        );
        let mut flow_keys = Vec::new();
        while let Some(flow) = rx.recv().await {
            flow_keys.push(flow.basic_flow.flow_key);
        }
        assert_eq!(flow_keys, ["10.99.0.1:40000-10.99.0.2:53-17"]);
    }
    #[tokio::test]
    async fn offline_sweeps_and_shutdown_are_independent_of_shards() {
        let (source, offset) = corrupt_record_after_one_packet_pcap();
        let mut bytes = source[..24].to_vec();
        // Many flows at time zero, one packet that advances the capture clock,
        // then a late packet. Every shard must observe the same sweep ordering.
        for (seconds, port) in (0..64_u16)
            .map(|id| (0_u32, 40000 + id))
            .chain([(200, 40064), (1, 40000)])
        {
            let mut record = source[24..offset].to_vec();
            record[..4].copy_from_slice(&seconds.to_le_bytes());
            record[50..52].copy_from_slice(&port.to_be_bytes());
            bytes.extend_from_slice(&record);
        }
        let path = temp_pcap_path("offline-shard-determinism");
        fs::write(&path, bytes).unwrap();
        let mut runs = Vec::new();
        for threads in [1, 1, 8, 8] {
            let (tx, mut rx) = mpsc::channel::<RustiFlow>(128);
            read_pcap_file::<RustiFlow>(path.to_str().unwrap(), tx, threads, 3600, 120, None, 60)
                .await
                .unwrap();
            let mut rows = Vec::new();
            let mut idle_count = 0;
            while let Some(flow) = rx.recv().await {
                idle_count +=
                    usize::from(flow.basic_flow.flow_expire_cause == FlowExpireCause::IdleTimeout);
                rows.push(flow.dump());
            }
            assert_eq!((rows.len(), idle_count), (66, 64));
            rows.sort();
            runs.push(rows);
        }
        fs::remove_file(path).unwrap();
        for run in &runs[1..] {
            assert_eq!(run, &runs[0]);
        }
    }
    #[tokio::test]
    async fn invalid_timestamp_exports_only_earlier_packets() {
        for (magic, fraction) in [
            (0xa1b2c3d4_u32, 1_000_000_u32),
            (0xa1b2c3d4, 3_000_000),
            (0xa1b23c4d, 1_000_000_000),
            (0xa1b23c4d, u32::MAX),
        ] {
            let (mut bytes, offset) = corrupt_record_after_one_packet_pcap();
            // Replace the corrupt length record with two complete UDP records.
            let record = bytes[24..offset].to_vec();
            bytes.truncate(offset);
            bytes.extend_from_slice(&record);
            bytes.extend_from_slice(&record);
            bytes[..4].copy_from_slice(&magic.to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&fraction.to_le_bytes());
            let path = temp_pcap_path("invalid-timestamp");
            fs::write(&path, bytes).unwrap();
            let (tx, mut rx) = mpsc::channel::<RustiFlow>(8);
            let result =
                read_pcap_file::<RustiFlow>(path.to_str().unwrap(), tx, 1, 3600, 120, None, 60)
                    .await;
            fs::remove_file(path).unwrap();
            let error = format!("{:#}", result.unwrap_err());
            assert!(
                error.contains(&format!(
                    "corrupt record at offset {offset}: timestamp fraction out of range"
                )),
                "{error}"
            );
            let flow = rx.recv().await.unwrap();
            assert_eq!(flow.basic_flow.flow_key, "10.99.0.1:40000-10.99.0.2:53-17");
            assert_eq!(flow.packet_len_stats.flow_count(), 1);
            assert!(rx.recv().await.is_none());
        }
    }
    #[tokio::test]
    async fn pcapng_timestamp_range_and_offset_overflow_are_errors() {
        for offset_seconds in [i64::MAX, 10_000_000_000_000] {
            // A section, an interface with if_tsoffset, and a packet at one second.
            let mut bytes = Vec::new();
            for (kind, body) in [
                (0x0a0d0d0a_u32, vec![0x1a2b3c4d, 1, u32::MAX, u32::MAX]),
                (
                    1,
                    vec![
                        1,
                        65535,
                        0x0008000e,
                        offset_seconds as u32,
                        (offset_seconds >> 32) as u32,
                        0,
                    ],
                ),
                (6, vec![0, 0, 1_000_000, 0, 0]),
            ] {
                let len = 12 + body.len() as u32 * 4;
                bytes.extend_from_slice(&kind.to_le_bytes());
                bytes.extend_from_slice(&len.to_le_bytes());
                for word in body {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
                bytes.extend_from_slice(&len.to_le_bytes());
            }
            let path = temp_pcap_path("pcapng-timestamp-range");
            fs::write(&path, bytes).unwrap();
            let (tx, mut rx) = mpsc::channel::<RustiFlow>(8);
            let result =
                read_pcap_file::<RustiFlow>(path.to_str().unwrap(), tx, 1, 3600, 120, None, 60)
                    .await;
            fs::remove_file(path).unwrap();
            let error = format!("{:#}", result.unwrap_err());
            assert!(
                error.contains("offset 64: timestamp out of range"),
                "{error}"
            );
            assert!(rx.recv().await.is_none());
        }
    }
}
