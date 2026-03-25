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
}
