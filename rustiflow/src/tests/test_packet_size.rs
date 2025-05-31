use std::net::{IpAddr, Ipv4Addr};

use crate::flows::basic_flow::BasicFlow;
use crate::flows::flow::Flow;
use crate::packet_features::PacketFeatures;

#[test]
fn test_packet_size_signed_length() {
    let mut packet_features = PacketFeatures::default();
    packet_features.length = 100;
    packet_features.signed_length = packet_features.length as i32; // Simulate client-to-server

    assert_eq!(packet_features.signed_length, 100);

    packet_features.signed_length = -(packet_features.length as i32); // Simulate server-to-client
    assert_eq!(packet_features.signed_length, -100);
}

#[test]
fn test_basic_flow_packet_sizes() {
    let mut flow = BasicFlow::new(
        "test_flow".to_string(),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        12345,
        IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        80,
        6, // TCP
        0, // timestamp
    );

    let mut packet1 = PacketFeatures::default();
    packet1.length = 100;
    packet1.signed_length = packet1.length as i32; // client-to-server

    let mut packet2 = PacketFeatures::default();
    packet2.length = 200;
    packet2.signed_length = packet2.length as i32; // server-to-client, sign will be flipped by update_flow

    flow.update_flow(&packet1, true); // fwd = true
    flow.update_flow(&packet2, false); // fwd = false

    assert_eq!(flow.packet_sizes, vec![100, -200]);
}

#[test]
fn test_basic_flow_dump_packet_sizes() {
    let mut flow = BasicFlow::new(
        "test_flow".to_string(),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        12345,
        IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        80,
        6, // TCP
        0, // timestamp
    );

    let mut packet1 = PacketFeatures::default();
    packet1.length = 100;
    packet1.signed_length = packet1.length as i32;


    let mut packet2 = PacketFeatures::default();
    packet2.length = 200;
    packet2.signed_length = packet2.length as i32;

    flow.update_flow(&packet1, true);
    flow.update_flow(&packet2, false);

    let dumped_string = flow.dump();
    assert!(dumped_string.contains(",[100,-200]"));
}

#[test]
fn test_basic_flow_get_features_packet_sizes() {
    let features_string = BasicFlow::get_features();
    assert!(features_string.contains(",packet_sizes"));
}
