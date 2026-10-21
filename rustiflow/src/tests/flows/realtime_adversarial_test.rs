//! Adversarial scenarios built from synthetic eBPF events.
//!
//! Live capture drains ingress and egress from separate rings, so the shard
//! sees the two directions of one biflow interleaved in whatever order the
//! drain tasks happen to deliver. These tests feed decoded events to a flow
//! table in such orders, for IPv4 and IPv6 alike.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Instant,
    };

    use common::{EbpfEventIpv4, EbpfEventIpv6};
    use tokio::sync::mpsc;

    use crate::{
        flow_table::FlowTable,
        flows::{basic_flow::TcpCloseStyle, rusti_flow::RustiFlow, util::FlowExpireCause},
        packet_features::{PacketFeatures, ACK_FLAG, FIN_FLAG, PSH_FLAG, SYN_FLAG},
    };

    const REALTIME_OFFSET_US: i64 = 1_700_000_000_000_000;
    const CLIENT_PORT: u16 = 40_000;
    const SERVER_PORT: u16 = 443;

    #[derive(Clone, Copy, Debug)]
    enum Family {
        Ipv4,
        Ipv6,
    }

    const FAMILIES: [Family; 2] = [Family::Ipv4, Family::Ipv6];

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Direction {
        ClientToServer,
        ServerToClient,
    }
    use Direction::{ClientToServer, ServerToClient};

    #[derive(Clone, Copy)]
    struct Segment {
        timestamp_us: i64,
        direction: Direction,
        flags: u8,
        sequence_number: u32,
        sequence_number_ack: u32,
        data_length: u16,
    }

    fn segment(
        timestamp_us: i64,
        direction: Direction,
        flags: u8,
        sequence_number: u32,
        sequence_number_ack: u32,
        data_length: u16,
    ) -> Segment {
        Segment {
            timestamp_us,
            direction,
            flags,
            sequence_number,
            sequence_number_ack,
            data_length,
        }
    }

    /// Encodes a TCP segment like the eBPF programs and decodes it like the
    /// realtime drain tasks.
    fn decode(family: Family, segment: &Segment) -> PacketFeatures {
        let (source_port, destination_port) = match segment.direction {
            ClientToServer => (CLIENT_PORT, SERVER_PORT),
            ServerToClient => (SERVER_PORT, CLIENT_PORT),
        };
        let timestamp_ns = ((segment.timestamp_us) as u64) * 1_000;
        match family {
            Family::Ipv4 => {
                let client = Ipv4Addr::new(10, 203, 0, 1);
                let server = Ipv4Addr::new(10, 203, 0, 2);
                let (source, destination) = match segment.direction {
                    ClientToServer => (client, server),
                    ServerToClient => (server, client),
                };
                let event = EbpfEventIpv4::new(
                    timestamp_ns,
                    u32::from(destination).to_be(),
                    u32::from(source).to_be(),
                    destination_port,
                    source_port,
                    segment.data_length,
                    40 + segment.data_length,
                    64_000,
                    segment.flags,
                    6,
                    20,
                    segment.sequence_number,
                    segment.sequence_number_ack,
                    0,
                    0,
                );
                PacketFeatures::from_ebpf_event_ipv4(&event, REALTIME_OFFSET_US)
            }
            Family::Ipv6 => {
                let client = Ipv6Addr::new(0xfd42, 0x203, 0, 0, 0, 0, 0, 1);
                let server = Ipv6Addr::new(0xfd42, 0x203, 0, 0, 0, 0, 0, 2);
                let (source, destination) = match segment.direction {
                    ClientToServer => (client, server),
                    ServerToClient => (server, client),
                };
                let event = EbpfEventIpv6::new(
                    timestamp_ns,
                    u128::from(destination).to_be(),
                    u128::from(source).to_be(),
                    destination_port,
                    source_port,
                    segment.data_length,
                    60 + segment.data_length,
                    64_000,
                    segment.flags,
                    6,
                    20,
                    segment.sequence_number,
                    segment.sequence_number_ack,
                    0,
                    0,
                );
                PacketFeatures::from_ebpf_event_ipv6(&event, REALTIME_OFFSET_US)
            }
        }
    }

    fn client_ip(family: Family) -> IpAddr {
        decode(family, &segment(0, ClientToServer, 0, 0, 0, 0)).source_ip
    }

    /// What the scenarios assert about each exported flow.
    #[derive(Debug, PartialEq)]
    struct FlowSummary {
        source_ip: IpAddr,
        source_port: u16,
        packets: u32,
        fwd_packets: u32,
        duration_us: i64,
        handshake_completed: bool,
        expire_cause: FlowExpireCause,
        close_style: TcpCloseStyle,
    }

    fn summarize(flow: &RustiFlow) -> FlowSummary {
        FlowSummary {
            source_ip: flow.basic_flow.ip_source,
            source_port: flow.basic_flow.port_source,
            packets: flow.packet_len_stats.flow_count(),
            fwd_packets: flow.packet_len_stats.fwd_packet_len.get_count(),
            duration_us: flow.basic_flow.get_flow_duration_usec(),
            handshake_completed: flow.basic_flow.tcp_handshake_completed,
            expire_cause: flow.basic_flow.flow_expire_cause,
            close_style: flow.basic_flow.tcp_close_style,
        }
    }

    /// Feeds the segments in the given arrival order, then shuts the table
    /// down at the latest timestamp seen.
    async fn run(family: Family, arrivals: &[Segment]) -> Vec<RustiFlow> {
        let (tx, mut rx) = mpsc::channel::<RustiFlow>(arrivals.len() + 1);
        let mut flow_table = FlowTable::new(3600, 120, None, tx, 60);
        let mut latest_us = i64::MIN;
        for arrival in arrivals {
            let packet = decode(family, arrival);
            latest_us = latest_us.max(packet.timestamp_us);
            flow_table.process_packet(&packet).await;
        }
        flow_table.export_all_flows(latest_us).await;
        drop(flow_table);

        let mut flows = Vec::new();
        while let Some(flow) = rx.recv().await {
            flows.push(flow);
        }
        flows
    }

    /// SYN handshake, one request and one response, then a four-segment close
    /// initiated by the client: FIN, ACK, FIN, ACK.
    fn clean_connection(client_isn: u32, server_isn: u32) -> Vec<Segment> {
        let c = |offset: u32| client_isn.wrapping_add(offset);
        let s = |offset: u32| server_isn.wrapping_add(offset);
        vec![
            segment(0, ClientToServer, SYN_FLAG, c(0), 0, 0),
            segment(100, ServerToClient, SYN_FLAG | ACK_FLAG, s(0), c(1), 0),
            segment(200, ClientToServer, ACK_FLAG, c(1), s(1), 0),
            segment(300, ClientToServer, ACK_FLAG | PSH_FLAG, c(1), s(1), 100),
            segment(400, ServerToClient, ACK_FLAG | PSH_FLAG, s(1), c(101), 200),
            segment(500, ClientToServer, FIN_FLAG | ACK_FLAG, c(101), s(201), 0),
            segment(600, ServerToClient, ACK_FLAG, s(201), c(102), 0),
            segment(700, ServerToClient, FIN_FLAG | ACK_FLAG, s(201), c(102), 0),
            segment(800, ClientToServer, ACK_FLAG, c(102), s(202), 0),
        ]
    }

    fn expected_clean_close(family: Family) -> FlowSummary {
        FlowSummary {
            source_ip: client_ip(family),
            source_port: CLIENT_PORT,
            packets: 9,
            fwd_packets: 5,
            duration_us: 800,
            handshake_completed: true,
            expire_cause: FlowExpireCause::TcpTermination,
            close_style: TcpCloseStyle::FourWayFin,
        }
    }

    fn summaries(flows: &[RustiFlow]) -> Vec<FlowSummary> {
        flows.iter().map(summarize).collect()
    }

    fn direction_interleavings(segments: &[Segment]) -> Vec<Vec<Segment>> {
        fn merge(
            client: &[Segment],
            server: &[Segment],
            prefix: &mut Vec<Segment>,
            output: &mut Vec<Vec<Segment>>,
        ) {
            if client.is_empty() && server.is_empty() {
                output.push(prefix.clone());
                return;
            }
            if let Some((first, rest)) = client.split_first() {
                prefix.push(*first);
                merge(rest, server, prefix, output);
                prefix.pop();
            }
            if let Some((first, rest)) = server.split_first() {
                prefix.push(*first);
                merge(client, rest, prefix, output);
                prefix.pop();
            }
        }
        let (client, server): (Vec<_>, Vec<_>) = segments
            .iter()
            .copied()
            .partition(|segment| segment.direction == ClientToServer);
        let mut output = Vec::new();
        merge(&client, &server, &mut Vec::new(), &mut output);
        output
    }

    #[tokio::test]
    async fn all_direction_preserving_interleavings_close_cleanly() {
        for family in FAMILIES {
            for (client, server) in [(1000, 5000), (u32::MAX - 100, u32::MAX)] {
                for arrivals in direction_interleavings(&clean_connection(client, server)) {
                    let flows = run(family, &arrivals).await;
                    assert_eq!(
                        summaries(&flows),
                        vec![expected_clean_close(family)],
                        "{family:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn simultaneous_fin_exchange_is_classified_independently_of_arrival_order() {
        for family in FAMILIES {
            let mut segments = clean_connection(1000, 5000);
            segments.truncate(5);
            segments.extend([
                segment(500, ClientToServer, FIN_FLAG | ACK_FLAG, 1101, 5201, 0),
                segment(600, ServerToClient, FIN_FLAG | ACK_FLAG, 5201, 1101, 0),
                segment(700, ClientToServer, ACK_FLAG, 1102, 5202, 0),
                segment(800, ServerToClient, ACK_FLAG, 5202, 1102, 0),
            ]);
            let mut expected = expected_clean_close(family);
            expected.close_style = TcpCloseStyle::SimultaneousFin;
            for arrivals in direction_interleavings(&segments) {
                assert_eq!(
                    summaries(&run(family, &arrivals).await),
                    vec![FlowSummary { ..expected }],
                    "{family:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn acknowledgment_numbers_without_ack_flags_do_not_close_a_flow() {
        for family in FAMILIES {
            let mut arrivals = clean_connection(1000, 5000);
            for segment in &mut arrivals[6..] {
                segment.flags &= !ACK_FLAG;
            }
            let mut expected = expected_clean_close(family);
            expected.expire_cause = FlowExpireCause::ExporterShutdown;
            expected.close_style = TcpCloseStyle::BidirectionalFin;
            assert_eq!(summaries(&run(family, &arrivals).await), vec![expected]);
        }
    }

    #[tokio::test]
    async fn baseline_in_order_connection_closes_cleanly() {
        for family in FAMILIES {
            let flows = run(family, &clean_connection(1000, 5000)).await;
            assert_eq!(
                summaries(&flows),
                vec![expected_clean_close(family)],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn syn_ack_drained_before_syn_keeps_client_as_forward() {
        // The ingress ring delivers the SYN-ACK before the egress ring
        // delivers the SYN it answers.
        for family in FAMILIES {
            let mut arrivals = clean_connection(1000, 5000);
            arrivals.swap(0, 1);
            let flows = run(family, &arrivals).await;
            assert_eq!(
                summaries(&flows),
                vec![expected_clean_close(family)],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn peer_fin_drained_before_own_fin_still_terminates() {
        // The server's ACK and FIN reach the shard before the client FIN they
        // answer.
        for family in FAMILIES {
            let mut arrivals = clean_connection(1000, 5000);
            arrivals[5..8].rotate_left(1);
            let flows = run(family, &arrivals).await;
            assert_eq!(
                summaries(&flows),
                vec![expected_clean_close(family)],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn sequence_numbers_crossing_the_wrap_close_cleanly() {
        // Server ISN u32::MAX: the SYN-ACK's expected ACK is 0. Client ISN
        // chosen so its FIN sits right before the wrap.
        for family in FAMILIES {
            let flows = run(family, &clean_connection(u32::MAX - 100, u32::MAX)).await;
            assert_eq!(
                summaries(&flows),
                vec![expected_clean_close(family)],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn one_direction_lagging_by_seconds_stays_one_flow() {
        // The egress ring is drained 1.5 s ahead of the ingress ring: the
        // client's data at t=2 s reaches the shard before the server's reply
        // stamped t=0.5 s.
        for family in FAMILIES {
            let arrivals = [
                segment(0, ClientToServer, ACK_FLAG | PSH_FLAG, 1, 1, 100),
                segment(2_000_000, ClientToServer, ACK_FLAG | PSH_FLAG, 101, 1, 100),
                segment(500_000, ServerToClient, ACK_FLAG | PSH_FLAG, 1, 101, 100),
            ];
            let flows = run(family, &arrivals).await;
            assert_eq!(
                summaries(&flows),
                vec![FlowSummary {
                    source_ip: client_ip(family),
                    source_port: CLIENT_PORT,
                    packets: 3,
                    fwd_packets: 2,
                    duration_us: 2_000_000,
                    handshake_completed: false,
                    expire_cause: FlowExpireCause::ExporterShutdown,
                    close_style: TcpCloseStyle::None,
                }],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn sub_second_lag_never_yields_negative_duration_or_iat() {
        for family in FAMILIES {
            let arrivals = [
                segment(0, ClientToServer, ACK_FLAG | PSH_FLAG, 1, 1, 100),
                segment(900_000, ClientToServer, ACK_FLAG | PSH_FLAG, 101, 1, 100),
                segment(400_000, ServerToClient, ACK_FLAG | PSH_FLAG, 1, 101, 100),
            ];
            let flows = run(family, &arrivals).await;
            assert_eq!(flows.len(), 1, "{family:?}");
            let flow = &flows[0];
            assert_eq!(
                (
                    flow.basic_flow.get_flow_duration_usec(),
                    flow.iat_stats.iat.get_min() >= 0.0,
                ),
                (900_000, true),
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn straggler_fin_after_teardown_is_preserved_in_a_separate_flow() {
        // The server retransmits its FIN because it has not seen the final ACK
        // yet, after the four-way close already exported the flow.
        for family in FAMILIES {
            let mut arrivals = clean_connection(1000, 5000);
            arrivals.push(segment(
                900,
                ServerToClient,
                FIN_FLAG | ACK_FLAG,
                5201,
                1102,
                0,
            ));
            let flows = run(family, &arrivals).await;
            assert_eq!(
                summaries(&flows),
                vec![
                    expected_clean_close(family),
                    FlowSummary {
                        source_ip: decode(family, arrivals.last().unwrap()).source_ip,
                        source_port: SERVER_PORT,
                        packets: 1,
                        fwd_packets: 1,
                        duration_us: 0,
                        handshake_completed: false,
                        expire_cause: FlowExpireCause::ExporterShutdown,
                        close_style: TcpCloseStyle::HalfClose,
                    }
                ],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    async fn fin_ack_answer_to_a_fin_is_not_a_simultaneous_close() {
        // The server acknowledges the client FIN in its own FIN|ACK, the usual
        // three-segment close. Its FIN is sent after it saw the client's.
        for family in FAMILIES {
            let mut arrivals = clean_connection(1000, 5000);
            arrivals.remove(6);
            let flows = run(family, &arrivals).await;
            assert_eq!(
                flows
                    .iter()
                    .map(|flow| flow.basic_flow.tcp_close_style)
                    .collect::<Vec<_>>(),
                vec![TcpCloseStyle::FourWayFin],
                "{family:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "finding 8: manual timing probe; machine-dependent threshold"]
    async fn sparse_sequence_numbers_keep_per_packet_cost_flat() {
        // Segments that never touch leave one tracked range each. Compare the
        // per-packet cost of a short and a long flow made of such segments.
        async fn time_per_packet(packets: u32) -> f64 {
            let arrivals: Vec<_> = (0..packets)
                .map(|index| {
                    segment(
                        i64::from(index),
                        ClientToServer,
                        ACK_FLAG | PSH_FLAG,
                        index * 200,
                        1,
                        100,
                    )
                })
                .collect();
            let start = Instant::now();
            run(Family::Ipv4, &arrivals).await;
            start.elapsed().as_secs_f64() / f64::from(packets)
        }
        let short = time_per_packet(2_000).await;
        let long = time_per_packet(40_000).await;
        eprintln!(
            "sparse segments: {:.0} ns/pkt at 2k, {:.0} ns/pkt at 40k",
            short * 1e9,
            long * 1e9
        );
        assert!(
            long < short * 4.0,
            "per-packet cost grew {:.1}x",
            long / short
        );
    }
}
