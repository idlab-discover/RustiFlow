#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        flows::{
            basic_flow::{BasicFlow, FlowState},
            flow::Flow,
        },
        packet_features::PacketFeatures,
    };

    #[test]
    fn test_basic_flow_creation() {
        let ip_src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let flow = BasicFlow::new(
            "flow1".to_string(),
            ip_src,
            8080,
            ip_dst,
            80,
            6, // TCP protocol
            Utc::now(),
        );

        assert_eq!(flow.flow_key, "flow1");
        assert_eq!(flow.ip_source, ip_src);
        assert_eq!(flow.port_source, 8080);
        assert_eq!(flow.ip_destination, ip_dst);
        assert_eq!(flow.port_destination, 80);
        assert_eq!(flow.protocol, 6);
        assert_eq!(flow.fwd_packet_count, 0);
        assert_eq!(flow.bwd_packet_count, 0);
    }

    #[test]
    fn test_basic_flow_update_forward() {
        let ip_src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let mut flow = BasicFlow::new(
            "flow1".to_string(),
            ip_src,
            8080,
            ip_dst,
            80,
            6, // TCP protocol
            Utc::now(),
        );

        let packet = PacketFeatures {
            source_ip: ip_src,
            destination_ip: ip_dst,
            source_port: 8080,
            destination_port: 80,
            protocol: 6,
            timestamp: Utc::now(),
            fin_flag: 0,
            syn_flag: 1,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 1,
            sequence_number_ack: 0,
        };

        let flow_ended = flow.update_flow(&packet, true);
        assert!(!flow_ended);
        assert_eq!(flow.fwd_packet_count, 1);
        assert_eq!(flow.fwd_syn_flag_count, 1);
    }

    #[test]
    fn test_basic_flow_update_backward() {
        let ip_src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let mut flow = BasicFlow::new(
            "flow1".to_string(),
            ip_src,
            8080,
            ip_dst,
            80,
            6, // TCP protocol
            Utc::now(),
        );

        let packet = PacketFeatures {
            source_ip: ip_dst,
            destination_ip: ip_src,
            source_port: 80,
            destination_port: 8080,
            protocol: 6,
            timestamp: Utc::now(),
            fin_flag: 0,
            syn_flag: 1,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 1,
            sequence_number_ack: 0,
        };

        let flow_ended = flow.update_flow(&packet, false);
        assert!(!flow_ended);
        assert_eq!(flow.bwd_packet_count, 1);
        assert_eq!(flow.bwd_syn_flag_count, 1);
    }

    #[test]
    fn test_tcp_flow_termination() {
        let ip_src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let mut flow = BasicFlow::new(
            "flow1".to_string(),
            ip_src,
            8080,
            ip_dst,
            80,
            6, // TCP protocol
            Utc::now(),
        );

        // Forward FIN
        let packet_fin_fwd = PacketFeatures {
            source_ip: ip_src,
            destination_ip: ip_dst,
            source_port: 8080,
            destination_port: 80,
            protocol: 6,
            timestamp: Utc::now(),
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 100,
            sequence_number_ack: 0,
        };
        flow.update_flow(&packet_fin_fwd, true);

        // Backward ACK for FIN
        let packet_ack_bwd = PacketFeatures {
            source_ip: ip_dst,
            destination_ip: ip_src,
            source_port: 80,
            destination_port: 8080,
            protocol: 6,
            timestamp: Utc::now(),
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 200,
            sequence_number_ack: 101,
        };
        flow.update_flow(&packet_ack_bwd, false);

        // Backward FIN
        let packet_fin_bwd = PacketFeatures {
            source_ip: ip_dst,
            destination_ip: ip_src,
            source_port: 80,
            destination_port: 8080,
            protocol: 6,
            timestamp: Utc::now(),
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 300,
            sequence_number_ack: 0,
        };
        flow.update_flow(&packet_fin_bwd, false);

        // Forward ACK for FIN
        let packet_ack_fwd = PacketFeatures {
            source_ip: ip_src,
            destination_ip: ip_dst,
            source_port: 8080,
            destination_port: 80,
            protocol: 6,
            timestamp: Utc::now(),
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 400,
            sequence_number_ack: 301,
        };
        let flow_ended = flow.update_flow(&packet_ack_fwd, true);

        assert!(flow_ended);
        assert_eq!(flow.state_fwd, FlowState::FinAcked);
        assert_eq!(flow.state_bwd, FlowState::FinAcked);
    }

    #[test]
    fn test_flow_expiry() {
        let ip_src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let first_timestamp = Utc::now();
        let mut flow = BasicFlow::new(
            "flow1".to_string(),
            ip_src,
            8080,
            ip_dst,
            80,
            6, // TCP protocol
            first_timestamp,
        );

        // Active timeout should expire
        let timestamp = first_timestamp + Duration::seconds(61);
        assert!(flow.is_expired(timestamp, 60, 30));

        // Idle timeout should expire
        let packet = PacketFeatures {
            source_ip: ip_src,
            destination_ip: ip_dst,
            source_port: 8080,
            destination_port: 80,
            protocol: 6,
            timestamp: first_timestamp,
            fin_flag: 0,
            syn_flag: 1,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwe_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 20,
            length: 40,
            window_size: 1024,
            sequence_number: 1,
            sequence_number_ack: 0,
        };
        flow.update_flow(&packet, true);

        let timestamp = first_timestamp + Duration::seconds(31);
        assert!(flow.is_expired(timestamp, 60, 30));
    }
}
