#[cfg(test)]
mod tests {
    use crate::{
        flows::{flow::Flow, nf_flow::NfFlow},
        packet_features::PacketFeatures,
    };

    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn create_packet_features(
        ip_source: IpAddr,
        ip_destination: IpAddr,
        timestamp: DateTime<Utc>,
        fwd: bool,
    ) -> PacketFeatures {
        PacketFeatures {
            source_ip: ip_source,
            destination_ip: ip_destination,
            source_port: if fwd { 12345 } else { 80 },
            destination_port: if fwd { 80 } else { 12345 },
            protocol: 6, // TCP
            timestamp,
            fin_flag: 0,
            syn_flag: 1,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 120,
            window_size: 1000,
            sequence_number: 123456,
            sequence_number_ack: 654321,
        }
    }

    #[test]
    fn test_nf_flow_initialization() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let flow = NfFlow::new(
            flow_id.clone(),
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        assert_eq!(flow.cic_flow.basic_flow.flow_key, flow_id);
        assert_eq!(flow.cic_flow.basic_flow.ip_source, ipv4_source);
        assert_eq!(flow.cic_flow.basic_flow.ip_destination, ipv4_destination);
        assert_eq!(flow.first_timestamp, timestamp);
        assert_eq!(flow.last_timestamp, timestamp);
        assert_eq!(flow.fwd_first_timestamp, timestamp);
        assert_eq!(flow.fwd_last_timestamp, timestamp);
        assert!(flow.bwd_first_timestamp.is_none());
        assert!(flow.bwd_last_timestamp.is_none());
    }

    #[test]
    fn test_nf_flow_update_forward() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let mut flow = NfFlow::new(
            flow_id,
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        let packet = create_packet_features(ipv4_source, ipv4_destination, timestamp, true);
        let is_terminated = flow.update_flow(&packet, true);

        assert_eq!(flow.fwd_last_timestamp, packet.timestamp);
        assert!(!is_terminated);
    }

    #[test]
    fn test_nf_flow_update_backward() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let mut flow = NfFlow::new(
            flow_id,
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        let packet = create_packet_features(ipv4_destination, ipv4_source, timestamp, false);
        let is_terminated = flow.update_flow(&packet, false);

        assert_eq!(flow.bwd_first_timestamp, Some(packet.timestamp));
        assert_eq!(flow.bwd_last_timestamp, Some(packet.timestamp));
        assert!(!is_terminated);
    }

    #[test]
    fn test_get_bwd_duration() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let mut flow = NfFlow::new(
            flow_id,
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        let bwd_first = timestamp + chrono::Duration::milliseconds(100);
        let bwd_last = timestamp + chrono::Duration::milliseconds(200);
        flow.bwd_first_timestamp = Some(bwd_first);
        flow.bwd_last_timestamp = Some(bwd_last);

        assert_eq!(flow.get_bwd_duration(), 100);
    }

    #[test]
    fn test_get_first_bwd_timestamp() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let mut flow = NfFlow::new(
            flow_id,
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        let bwd_first = timestamp + chrono::Duration::milliseconds(100);
        flow.bwd_first_timestamp = Some(bwd_first);

        assert_eq!(flow.get_first_bwd_timestamp(), bwd_first.timestamp_millis());
    }

    #[test]
    fn test_dump() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let flow = NfFlow::new(
            flow_id.clone(),
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        let dump = flow.dump();
        assert!(dump.contains(&flow_id));
        assert!(dump.contains(&ipv4_source.to_string()));
        assert!(dump.contains(&ipv4_destination.to_string()));
    }

    #[test]
    fn test_is_expired() {
        let flow_id = "flow-1".to_string();
        let ipv4_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv4_destination = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let timestamp = Utc::now();

        let mut flow = NfFlow::new(
            flow_id,
            ipv4_source,
            12345,
            ipv4_destination,
            80,
            6,
            timestamp,
        );

        // Active timeout: 60 seconds, Idle timeout: 30 seconds
        let active_timeout = 60;
        let idle_timeout = 30;

        // Case 1: Not expired, within active and idle timeout
        let within_active_and_idle = timestamp + chrono::Duration::seconds(29);
        assert!(!flow.is_expired(within_active_and_idle, active_timeout, idle_timeout));

        // Case 2: Idle timeout exceeded
        let idle_timeout_exceeded = timestamp + chrono::Duration::seconds(31);
        assert!(flow.is_expired(idle_timeout_exceeded, active_timeout, idle_timeout));

        // Case 3: Active timeout exceeded
        let active_timeout_exceeded = timestamp + chrono::Duration::seconds(61);
        assert!(flow.is_expired(active_timeout_exceeded, active_timeout, idle_timeout));

        // Case 4: Update the last timestamp to reset idle timeout
        flow.cic_flow.basic_flow.last_timestamp = timestamp + chrono::Duration::seconds(40);
        flow.cic_flow.basic_flow.first_timestamp = flow.cic_flow.basic_flow.last_timestamp; // Reset first timestamp
        let after_update_within_idle =
            flow.cic_flow.basic_flow.last_timestamp + chrono::Duration::seconds(29);
        let exp = flow.is_expired(after_update_within_idle, active_timeout, idle_timeout);
        assert!(!exp);

        // Case 5: Idle timeout exceeded after update
        let after_update_idle_timeout_exceeded =
            flow.last_timestamp + chrono::Duration::seconds(31);
        assert!(flow.is_expired(
            after_update_idle_timeout_exceeded,
            active_timeout,
            idle_timeout
        ));
    }
}
