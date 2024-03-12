mod args;
mod parsers;
mod records;

use crate::{
    parsers::csv_parser::CsvParser,
    records::{cic_record::CicRecord, print::Print},
};

use anyhow::Context;
use args::{Cli, Commands, Dataset};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use common::PacketLog;
use dashmap::DashMap;
use core::panic;
use log::{info, warn};
use std::{net::Ipv4Addr, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex}, time::{Duration, Instant}};
use tokio::task;
use std::convert::TryInto;

#[derive(Debug, Hash, Eq, PartialEq)]
struct FlowKey {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

struct FlowStats {
    packets: usize,
    bytes: usize,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Realtime { interface } => {
            if let Err(err) = handle_realtime(interface).await {
                eprintln!("Error: {:?}", err);
            }
        }
        Commands::Dataset { dataset, path } => {
            handle_dataset(dataset, &path);
        }
    }
}

async fn handle_realtime(interface: String) -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

    // Loading the eBPF program for egress, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_egress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/feature-extraction-tool-egress"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_egress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/feature-extraction-tool-egress"
    ))?;

    // Loading the eBPF program for ingress, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ingress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/feature-extraction-tool-ingress"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ingress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/feature-extraction-tool-ingress"
    ))?;

    // You can remove this when you don't log anything in your egress eBPF program.
    if let Err(e) = BpfLogger::init(&mut bpf_egress) {
        warn!("failed to initialize the egress eBPF logger: {}", e);
    }

    // You can remove this when you don't log anything in your ingress eBPF program.
    if let Err(e) = BpfLogger::init(&mut bpf_ingress) {
        warn!("failed to initialize the ingress eBPF logger: {}", e);
    }

    // Loading and attaching the eBPF program function for egress
    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_egress: &mut SchedClassifier = bpf_egress
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_egress.load()?;
    program_egress.attach(&interface, TcAttachType::Egress)?;

    // Loading and attaching the eBPF program function for ingress
    let program_ingress: &mut Xdp = bpf_ingress
        .program_mut("xdp_flow_track")
        .unwrap()
        .try_into()?;
    program_ingress.load()?;
    program_ingress.attach(&interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Attach to the event arrays
    let mut flows_egress =
        AsyncPerfEventArray::try_from(bpf_egress.take_map("EVENTS_EGRESS").unwrap())?;

    let mut flows_ingress =
        AsyncPerfEventArray::try_from(bpf_ingress.take_map("EVENTS_INGRESS").unwrap())?;

    let flow_map: Arc<DashMap<FlowKey, FlowStats>> = Arc::new(DashMap::new());

    let processing_times: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));

    let packet_count = Arc::new(AtomicUsize::new(0));

    // Use all online CPUs to process the events in the user space
    for cpu_id in online_cpus()? {
        let mut buf_egress = flows_egress.open(cpu_id, None)?;
        let flow_map_egress = flow_map.clone();
        let processing_times_egress = processing_times.clone();
        let packet_count_egress = packet_count.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };

                    process(&data, &flow_map_egress, &processing_times_egress, &packet_count_egress);
                }
            }
        });

        let mut buf_ingress = flows_ingress.open(cpu_id, None)?;
        let flow_map_ingress = flow_map.clone();
        let processing_times_ingress = processing_times.clone();
        let packet_count_ingress = packet_count.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };

                    process(&data, &flow_map_ingress, &processing_times_ingress, &packet_count_ingress);
                }
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if packet_count.load(Ordering::SeqCst) >= 10_000 {
            info!("Packet count exceeded 10000. writing results to file...");

            let csv_file = "processing_times_rust_ebpf.csv";
            let mut wtr = csv::Writer::from_path(csv_file).unwrap();
            wtr.write_record(&["Packet Number", "Processing Time (seconds)"]).unwrap();

            let processing_times = processing_times.lock().unwrap();

            for (idx, time_val) in processing_times.iter().enumerate() {
                wtr.write_record(&[idx.to_string(), time_val.as_secs_f64().to_string()]).unwrap();
            }
            wtr.flush().unwrap();
            return Ok(());
        }
    }
}

fn process(data: &PacketLog, flow_map: &Arc<DashMap<FlowKey, FlowStats>>, processing_times: &Arc<Mutex<Vec<Duration>>>, packet_count: &Arc<AtomicUsize>) {
    if packet_count.fetch_add(1, Ordering::SeqCst) >= 10_000 {
        return;
    }
    let start_time = Instant::now();

    let flow_key = FlowKey {
        src_ip: Ipv4Addr::from(data.ipv4_source),
        dst_ip: Ipv4Addr::from(data.ipv4_destination),
        src_port: data.port_source,
        dst_port: data.port_destination,
    };

    let mut stats = flow_map.entry(flow_key).or_insert_with(|| FlowStats { packets: 0, bytes: 0 });
    stats.packets += 1;
    stats.bytes += data.data_length as usize;

    let elapsed_time = start_time.elapsed();

    let mut processing_times = processing_times.lock().unwrap();
    processing_times.push(elapsed_time);
}

fn handle_dataset(dataset: Dataset, path: &str) {
    println!(
        "Dataset feature extraction for {:?} from path: {}",
        dataset, path
    );

    match dataset {
        Dataset::CicIds2017 => {
            if path.ends_with(".csv") {
                let parser = CsvParser;

                match parser.parse::<CicRecord>(path) {
                    Ok(records) => {
                        for record in records {
                            match record {
                                Ok(record) => {
                                    record.print();
                                }
                                Err(err) => {
                                    // TODO: Will we output to stderr, drop the record or use default values?
                                    eprintln!("Error: {:?}", err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                    }
                }
            } else if path.ends_with(".pcap") {
                panic!("This file format is not supported yet...");
            } else if path.ends_with(".parquet") {
                panic!("This file format is not supported yet...");
            } else {
                panic!("This file format is not supported...");
            }
        }
        _ => {
            panic!("This is not implemented yet...");
        }
    }
}
