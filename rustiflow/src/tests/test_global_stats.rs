use crate::flows::basic_flow::BasicFlow;
use crate::flow_table::FlowTable;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use std::io::Write; // For writeln! in test_output_formatting_logic

#[tokio::test]
async fn test_flow_table_stat_collection_and_sorting() {
    let (tx, _rx) = mpsc::channel::<BasicFlow>(100); // Export channel
    let mut flow_table = FlowTable::<BasicFlow>::new(300, 30, None, tx, 10);

    // Flow 1: starts at 1000, ends at 1500 (duration 500)
    let mut flow1 = BasicFlow::new("flow1".to_string(), IpAddr::V4(Ipv4Addr::new(1,1,1,1)), 1, IpAddr::V4(Ipv4Addr::new(2,2,2,2)), 2, 6, 1000);
    flow1.last_timestamp_us = 1500;

    // Flow 2: starts at 500, ends at 800 (duration 300)
    let mut flow2 = BasicFlow::new("flow2".to_string(), IpAddr::V4(Ipv4Addr::new(1,1,1,3)), 3, IpAddr::V4(Ipv4Addr::new(2,2,2,4)), 4, 6, 500);
    flow2.last_timestamp_us = 800;

    // Flow 3: starts at 1200, ends at 1800 (duration 600)
    let mut flow3 = BasicFlow::new("flow3".to_string(), IpAddr::V4(Ipv4Addr::new(1,1,1,5)), 5, IpAddr::V4(Ipv4Addr::new(2,2,2,6)), 6, 6, 1200);
    flow3.last_timestamp_us = 1800;

    // Manually call export_flow to populate collected_flow_stats directly for this unit test
    flow_table.export_flow(flow1).await;
    flow_table.export_flow(flow2).await;
    flow_table.export_flow(flow3).await;

    // Call export_all_flows to trigger sorting of collected_flow_stats.
    // In a real scenario, export_all_flows would also drain flow_map,
    // but here flow_map is empty as we called export_flow directly.
    let current_simulated_time = 2000;
    flow_table.export_all_flows(current_simulated_time).await;

    let stats = flow_table.get_collected_flow_stats();
    assert_eq!(stats.len(), 3, "Should have collected 3 flow stats");
    // Check sorting by start time (k.0) and correct duration (k.1)
    assert_eq!(stats[0], (500, 300), "Flow2 data incorrect or sort order wrong");
    assert_eq!(stats[1], (1000, 500), "Flow1 data incorrect or sort order wrong");
    assert_eq!(stats[2], (1200, 600), "Flow3 data incorrect or sort order wrong");
}

#[test]
fn test_inter_flow_delta_calculation() {
    // Stats are pre-sorted by start time as they would be from FlowTable
    let flow_stats: Vec<(i64, i64)> = vec![
        (500, 300),  // Flow 2 (start_time, duration)
        (1000, 500), // Flow 1
        (1200, 600), // Flow 3
    ];

    let mut inter_flow_deltas_us: Vec<i64> = Vec::new();
    if flow_stats.len() > 1 {
        for i in 1..flow_stats.len() {
            let delta = flow_stats[i].0 - flow_stats[i-1].0; // delta = current_start_time - prev_start_time
            inter_flow_deltas_us.push(delta);
        }
    }
    assert_eq!(inter_flow_deltas_us, vec![500, 200], "Delta calculation incorrect"); // (1000-500), (1200-1000)

    // Test with less than 2 flows
    let flow_stats_single: Vec<(i64, i64)> = vec![(500, 300)];
    let mut deltas_single: Vec<i64> = Vec::new();
    if flow_stats_single.len() > 1 {
        for i in 1..flow_stats_single.len() {
            deltas_single.push(flow_stats_single[i].0 - flow_stats_single[i-1].0);
        }
    }
    assert!(deltas_single.is_empty(), "Deltas should be empty for single flow");

    let flow_stats_empty: Vec<(i64, i64)> = vec![];
    let mut deltas_empty: Vec<i64> = Vec::new();
    if flow_stats_empty.len() > 1 {
        for i in 1..flow_stats_empty.len() {
            deltas_empty.push(flow_stats_empty[i].0 - flow_stats_empty[i-1].0);
        }
    }
    assert!(deltas_empty.is_empty(), "Deltas should be empty for no flows");
}

#[test]
fn test_all_flow_durations_extraction() {
    let flow_stats: Vec<(i64, i64)> = vec![
        (500, 300),
        (1000, 500),
        (1200, 600),
    ];
    let all_flow_durations_us: Vec<i64> = flow_stats.iter().map(|&(_, duration)| duration).collect();
    assert_eq!(all_flow_durations_us, vec![300, 500, 600], "Durations extraction incorrect");

    let flow_stats_empty: Vec<(i64, i64)> = vec![];
    let durations_empty: Vec<i64> = flow_stats_empty.iter().map(|&(_, duration)| duration).collect();
    assert!(durations_empty.is_empty(), "Durations should be empty for no flows");
}

#[test]
fn test_output_formatting_logic() {
    // Test inter_flow_deltas formatting
    let deltas1: Vec<i64> = vec![100, 200, 300];
    let mut buf1: Vec<u8> = Vec::new();
    if deltas1.is_empty() {
        writeln!(&mut buf1, "INTER_FLOW_DELTAS_US,[]").unwrap();
    } else {
        let deltas_str: Vec<String> = deltas1.iter().map(|d| d.to_string()).collect();
        writeln!(&mut buf1, "INTER_FLOW_DELTAS_US,[{}]", deltas_str.join(",")).unwrap();
    }
    assert_eq!(String::from_utf8(buf1).unwrap().trim(), "INTER_FLOW_DELTAS_US,[100,200,300]");

    let deltas2: Vec<i64> = vec![];
    let mut buf2: Vec<u8> = Vec::new();
    if deltas2.is_empty() {
        writeln!(&mut buf2, "INTER_FLOW_DELTAS_US,[]").unwrap();
    } else {
        let deltas_str: Vec<String> = deltas2.iter().map(|d| d.to_string()).collect();
        writeln!(&mut buf2, "INTER_FLOW_DELTAS_US,[{}]", deltas_str.join(",")).unwrap();
    }
    assert_eq!(String::from_utf8(buf2).unwrap().trim(), "INTER_FLOW_DELTAS_US,[]");

    // Test all_flow_durations formatting
    let durations1: Vec<i64> = vec![50, 150];
    let mut buf3: Vec<u8> = Vec::new();
    if durations1.is_empty() {
        writeln!(&mut buf3, "ALL_FLOW_DURATIONS_US,[]").unwrap();
    } else {
        let durations_str: Vec<String> = durations1.iter().map(|d| d.to_string()).collect();
        writeln!(&mut buf3, "ALL_FLOW_DURATIONS_US,[{}]", durations_str.join(",")).unwrap();
    }
    assert_eq!(String::from_utf8(buf3).unwrap().trim(), "ALL_FLOW_DURATIONS_US,[50,150]");

    let durations2: Vec<i64> = vec![];
    let mut buf4: Vec<u8> = Vec::new();
    if durations2.is_empty() {
        writeln!(&mut buf4, "ALL_FLOW_DURATIONS_US,[]").unwrap();
    } else {
        let durations_str: Vec<String> = durations2.iter().map(|d| d.to_string()).collect();
        writeln!(&mut buf4, "ALL_FLOW_DURATIONS_US,[{}]", durations_str.join(",")).unwrap();
    }
    assert_eq!(String::from_utf8(buf4).unwrap().trim(), "ALL_FLOW_DURATIONS_US,[]");
}
