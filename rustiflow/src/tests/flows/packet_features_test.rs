#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::packet_features::PacketFeatures;

    fn build_packet(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> PacketFeatures {
        PacketFeatures {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol: 6,
            timestamp_us: 1_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn biflow_key_is_direction_invariant() {
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10));
        let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20));

        let forward = build_packet(client_ip, 55000, server_ip, 443);
        let backward = build_packet(server_ip, 443, client_ip, 55000);

        assert_eq!(forward.biflow_key(), backward.biflow_key());
    }
}
