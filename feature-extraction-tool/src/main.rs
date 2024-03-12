mod args;
mod flows;
mod parsers;
mod records;
mod utils;

use crate::{
    flows::test_flow::TestFlow,
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
use core::panic;
use dashmap::DashMap;
use log::{info, warn};
use std::{fs::OpenOptions, sync::{atomic::{AtomicUsize, Ordering}, Arc}, time::Duration};
use std::io::Write;
use tokio::{signal, task};
use utils::utils::create_flow_id;

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

    let flow_map: Arc<DashMap<String, TestFlow>> = Arc::new(DashMap::new());

    let flow_count = Arc::new(AtomicUsize::new(0));

    // Use all online CPUs to process the events in the user space
    for cpu_id in online_cpus()? {
        let mut buf_egress = flows_egress.open(cpu_id, None)?;

        let flow_map_clone_egress = flow_map.clone();
        let flow_count_clone_egress = flow_count.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };

                    let _ = process(&data, flow_map_clone_egress.clone(), false, flow_count_clone_egress.clone());
                }
            }
        });

        let mut buf_ingress = flows_ingress.open(cpu_id, None)?;

        let flow_map_clone_ingress = flow_map.clone();
        let flow_count_clone_ingress = flow_count.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };

                    let _ = process(&data, flow_map_clone_ingress.clone(), true, flow_count_clone_ingress.clone());
                }
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if flow_count.load(Ordering::SeqCst) >= 100 {
            info!("Packet count exceeded 100. Terminating program...");
            return Ok(());
        }
    }
}

fn process(data: &PacketLog, flow_map: Arc<DashMap<String, TestFlow>>, fwd: bool, flow_count: Arc<AtomicUsize>) -> std::io::Result<()> {
    if flow_count.load(Ordering::SeqCst) >= 100 {
        return Ok(());
    }
    
    let flow_id = if fwd {
        create_flow_id(
            data.ipv4_source,
            data.port_source,
            data.ipv4_destination,
            data.port_destination,
            data.protocol,
        )
    } else {
        create_flow_id(
            data.ipv4_destination,
            data.port_destination,
            data.ipv4_source,
            data.port_source,
            data.protocol,
        )
    };

    let flow_id_clone = flow_id.clone();
    let flow_id_remove = flow_id.clone();
    let mut entry = flow_map.entry(flow_id).or_insert_with(|| {
        TestFlow::new(
            flow_id_clone,
            data.ipv4_source,
            data.port_source,
            data.ipv4_destination,
            data.port_destination,
            data.protocol,
        )
    });

    let end = entry.update_flow(&data, fwd);
    if end.is_some() {
        let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("stream_vs_conventional_4.csv")?;

        if let Some(value) = end {
            writeln!(file, "{}", value)?;
        }

        flow_count.fetch_add(1, Ordering::SeqCst);
        drop(entry);
        flow_map.remove(&flow_id_remove);
    }

    Ok(())
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
