mod args;
mod flows;
mod parsers;
mod records;
mod utils;

use crate::{
    flows::cic_flow::CicFlow,
    parsers::csv_parser::CsvParser,
    records::{cic_record::CicRecord, print::Print},
    utils::utils::{create_flow_id, get_duration},
};
use anyhow::Context;
use args::{Cli, Commands, Dataset, FlowType};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use chrono::Utc;
use clap::Parser;
use common::BasicFeatures;
use core::panic;
use dashmap::DashMap;
use flows::{basic_flow::BasicFlow, cidds_flow::CiddsFlow, flow::Flow};
use log::info;
use std::{sync::Arc, time::Instant};
use tokio::time::{self, Duration};
use tokio::{signal, task};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Realtime {
            interface,
            flow_type,
            lifespan,
            interval,
        } => {
            if let Some(interval) = interval {
                if interval >= lifespan {
                    panic!("The interval needs to be smaller than the lifespan!");
                }
            }

            match flow_type {
                FlowType::BasicFlow => {
                    if let Err(err) =
                        handle_realtime::<BasicFlow>(interface, interval, lifespan).await
                    {
                        eprintln!("Error: {:?}", err);
                    }
                }
                FlowType::CicFlow => {
                    if let Err(err) =
                        handle_realtime::<CicFlow>(interface, interval, lifespan).await
                    {
                        eprintln!("Error: {:?}", err);
                    }
                }
                FlowType::CiddsFlow => {
                    if let Err(err) =
                        handle_realtime::<CiddsFlow>(interface, interval, lifespan).await
                    {
                        eprintln!("Error: {:?}", err);
                    }
                }
            }
        }
        Commands::Dataset { dataset, path } => {
            handle_dataset(dataset, &path);
        }
    }
}

async fn handle_realtime<T>(
    interface: String,
    interval: Option<u64>,
    lifespan: u64,
) -> Result<(), anyhow::Error>
where
    T: Flow + Send + Sync + 'static,
{
    env_logger::init();

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

    let flow_map: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

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

                    process_packet(&data, &flow_map_clone_egress, false);
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

                    process_packet(&data, &flow_map_clone_ingress, true);
                }
            }
        });
    }

    if let Some(interval) = interval {
        let flow_map_print = flow_map.clone();
        task::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval));
            loop {
                interval.tick().await;
                for entry in flow_map_print.iter() {
                    let flow = entry.value();
                    println!("{}", flow.dump());
                }
            }
        });
    }

    let flow_map_end = flow_map.clone();
    task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let timestamp = Utc::now();

            // Collect keys to remove
            let mut keys_to_remove = Vec::new();
            for entry in flow_map_end.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    println!("{}", flow.dump());
                    keys_to_remove.push(entry.key().clone());
                }
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove {
                flow_map_end.remove(&key);
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn process_packet<T>(data: &BasicFeatures, flow_map: &Arc<DashMap<String, T>>, fwd: bool)
where
    T: Flow,
{
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

    let flow_id_clone = flow_id.clone();
    let flow_id_remove = flow_id.clone();
    let mut entry = flow_map.entry(flow_id).or_insert_with(|| {
        T::new(
            flow_id_clone,
            data.ipv4_source,
            data.port_source,
            data.ipv4_destination,
            data.port_destination,
            data.protocol,
        )
    });

    let end = entry.update_flow(&data, &timestamp, fwd);
    if end.is_some() {
        println!("{}", end.unwrap());
        drop(entry);
        flow_map.remove(&flow_id_remove);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_flow_termination() {
        let flow_map = Arc::new(DashMap::new());

        let data_1 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            fin_flag: 0,
            syn_flag: 1,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet::<CicFlow>(&data_1, &flow_map, true);

        let data_2 = BasicFeatures {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            fin_flag: 0,
            syn_flag: 1,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_2, &flow_map, false);

        assert_eq!(flow_map.len(), 1);
        // 17 is for udp, here we just use it to create a new flow
        let data_3 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 17,
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_3, &flow_map, true);

        assert_eq!(flow_map.len(), 2);

        let data_4 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_4, &flow_map, true);

        assert_eq!(flow_map.len(), 2);

        let data_5 = BasicFeatures {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_5, &flow_map, false);

        assert_eq!(flow_map.len(), 2);

        let data_6 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_6, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_7 = BasicFeatures {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 17,
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 1,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_7, &flow_map, false);

        assert_eq!(flow_map.len(), 0);

        let data_8 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_8, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_9 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_9, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_10 = BasicFeatures {
            ipv4_source: 1,
            port_source: 8080,
            ipv4_destination: 2,
            port_destination: 8000,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };

        process_packet(&data_10, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_11 = BasicFeatures {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            fin_flag: 1,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_11, &flow_map, false);

        assert_eq!(flow_map.len(), 1);

        let data_12 = BasicFeatures {
            ipv4_source: 2,
            port_source: 8000,
            ipv4_destination: 1,
            port_destination: 8080,
            protocol: 6,
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 1,
            urg_flag: 0,
            ece_flag: 0,
            cwe_flag: 0,
            data_length: 100,
            header_length: 20,
            length: 140,
            window_size: 1000,
        };
        process_packet(&data_12, &flow_map, false);

        assert_eq!(flow_map.len(), 0);
    }
}
