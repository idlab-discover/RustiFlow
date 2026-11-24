use std::{io, net::Ipv4Addr, time::Instant};

use tokio::sync::mpsc;

use crate::{
    flow_table::FlowTable,
    flows::{basic_flow::BasicFlow, flow::Flow, rusti_flow::RustiFlow},
    packet_features::PacketFeatures,
};

const BATCH_SIZE: usize = 128;

fn packet(flow: u32, timestamp_us: i64) -> PacketFeatures {
    let mut packet = PacketFeatures {
        source_ip: Ipv4Addr::from(0x0a00_0000 | flow).into(),
        destination_ip: Ipv4Addr::new(198, 18, 0, 1).into(),
        source_port: 40_000,
        destination_port: 443,
        protocol: 17,
        timestamp_us,
        header_length: 8,
        data_length: 64,
        length: 92,
        ..Default::default()
    };
    if timestamp_us & 1 != 0 {
        std::mem::swap(&mut packet.source_ip, &mut packet.destination_ip);
        std::mem::swap(&mut packet.source_port, &mut packet.destination_port);
    }
    packet
}

async fn measure<T: Flow>(flows: u32, batches: usize) {
    let (sender, mut receiver) = mpsc::channel(flows as usize);
    let mut table = FlowTable::<T>::new(3_600, 3_600, None, sender, 3_600);
    for flow in 0..flows {
        table.process_packet(&packet(flow, 0)).await;
    }
    let mut rng = 0x5eed_f10e_1234_5678u64;
    let mut batch = std::array::from_fn::<_, BATCH_SIZE, _>(|_| packet(0, 0));
    let mut timestamp_us = 0;

    // An optional stdin gate lets perf enable counters after setup.
    if std::env::var_os("RUSTIFLOW_HIT_BENCH_PAUSE").is_some() {
        println!("HIT_BENCH_READY");
        assert_ne!(io::stdin().read_line(&mut String::new()).unwrap(), 0);
    }
    let start = Instant::now();
    for _ in 0..batches {
        for packet_slot in &mut batch {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            timestamp_us += 1;
            *packet_slot = packet((rng % u64::from(flows)) as u32, timestamp_us);
        }
        table.process_batch(&batch).await;
    }
    println!(
        "HIT_BENCH_DONE flows={flows} packets={timestamp_us} seconds={:.6}",
        start.elapsed().as_secs_f64()
    );
    if std::env::var_os("RUSTIFLOW_HIT_BENCH_PAUSE").is_some() {
        assert_ne!(io::stdin().read_line(&mut String::new()).unwrap(), 0);
    }

    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    table.export_all_flows(timestamp_us).await;
    for _ in 0..flows {
        receiver
            .try_recv()
            .expect("one export for each seeded biflow");
    }
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
#[ignore = "run directly for the flow-table cardinality profile"]
async fn flow_table_hit_bench() {
    let flows = std::env::var("RUSTIFLOW_HIT_BENCH_FLOWS")
        .unwrap_or_else(|_| "16384".into())
        .parse::<u32>()
        .unwrap();
    assert!((1..=(1 << 24)).contains(&flows));
    let batches = std::env::var("RUSTIFLOW_HIT_BENCH_BATCHES")
        .unwrap_or_else(|_| "65536".into())
        .parse::<usize>()
        .unwrap();
    match std::env::var("RUSTIFLOW_HIT_BENCH_FEATURE").as_deref() {
        Ok("basic") => measure::<BasicFlow>(flows, batches).await,
        Ok("rustiflow") | Err(std::env::VarError::NotPresent) => {
            measure::<RustiFlow>(flows, batches).await;
        }
        setting => panic!("unsupported benchmark flow type: {setting:?}"),
    }
}
