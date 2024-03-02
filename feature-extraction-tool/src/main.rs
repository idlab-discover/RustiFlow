mod args;
mod flows;
mod parsers;
mod records;
mod utils;

use crate::{
    flows::cic_flow::CicFlow,
    parsers::csv_parser::CsvParser,
    records::{cic_record::CicRecord, print::Print},
    utils::utils::create_flow_id,
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
use common::BasicFeatures;
use core::panic;
use dashmap::DashMap;
use flows::flow::Flow;
use log::{info, warn};
use std::{net::Ipv4Addr, sync::Arc, time::Instant};
use tokio::{signal, task};

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

    let flow_map: Arc<DashMap<String, CicFlow>> = Arc::new(DashMap::new());

    // Use all online CPUs to process the events in the user space
    for cpu_id in online_cpus()? {
        let mut buf_egress = flows_egress.open(cpu_id, None)?;
        let flow_map_clone_egress = flow_map.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeatures;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet(data, flow_map_clone_egress.clone(), false);
                }
            }
        });

        let mut buf_ingress = flows_ingress.open(cpu_id, None)?;
        let flow_map_clone_ingress = flow_map.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeatures;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet(data, flow_map_clone_ingress.clone(), true);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn process_packet(data: BasicFeatures, flow_map: Arc<DashMap<String, CicFlow>>, fwd: bool) {
    let timestamp = Instant::now();
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

    match flow_map.entry(flow_id.clone()) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            // flow doesn't exist
            let mut new_flow = CicFlow::new(
                flow_id,
                data.ipv4_source,
                data.port_source,
                data.ipv4_destination,
                data.port_destination,
                data.protocol,
            );
            new_flow.update_flow_first(data, timestamp, fwd);
            entry.insert(new_flow);
        }
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            // flow already exists
            let end = entry.get_mut().update_flow(data, timestamp, fwd);
            if end {
                entry.remove();
            }
        }
    }
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
