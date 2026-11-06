#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use tokio::sync::mpsc;

    use crate::{flows::rusti_flow::RustiFlow, pcap::read_pcap_file};

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
}
