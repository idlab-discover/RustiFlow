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
use args::{Cli, Commands, Dataset, FlowType};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use chrono::Utc;
use clap::Parser;
use common::{BasicFeaturesIpv4, BasicFeaturesIpv6};
use core::panic;
use dashmap::DashMap;
use flows::{basic_flow::BasicFlow, cidds_flow::CiddsFlow, flow::Flow, nf_flow::NfFlow};
use log::info;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};
use tokio::time::{self, Duration};
use tokio::{signal, task};
use utils::utils::BasicFeatures;

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
                FlowType::NfFlow => {
                    if let Err(err) = handle_realtime::<NfFlow>(interface, interval, lifespan).await
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
    let mut bpf_egress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/feature-extraction-tool-ipv4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_egress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/feature-extraction-tool-ipv4"
    ))?;

    #[cfg(debug_assertions)]
    let mut bpf_egress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/feature-extraction-tool-ipv6"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_egress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/feature-extraction-tool-ipv6"
    ))?;

    // Loading the eBPF program for ingress, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ingress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/feature-extraction-tool-ipv4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ingress_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/feature-extraction-tool-ipv4"
    ))?;

    #[cfg(debug_assertions)]
    let mut bpf_ingress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/feature-extraction-tool-ipv6"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ingress_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/feature-extraction-tool-ipv6"
    ))?;

    // Loading and attaching the eBPF program function for egress
    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_egress_ipv4: &mut SchedClassifier = bpf_egress_ipv4
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_egress_ipv4.load()?;
    program_egress_ipv4.attach(&interface, TcAttachType::Egress)?;

    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_egress_ipv6: &mut SchedClassifier = bpf_egress_ipv6
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_egress_ipv6.load()?;
    program_egress_ipv6.attach(&interface, TcAttachType::Egress)?;

    // Loading and attaching the eBPF program function for ingress
    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_ingress_ipv4: &mut SchedClassifier = bpf_ingress_ipv4
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_ingress_ipv4.load()?;
    program_ingress_ipv4.attach(&interface, TcAttachType::Ingress)?;

    let _ = tc::qdisc_add_clsact(interface.as_str());
    let program_ingress_ipv6: &mut SchedClassifier = bpf_ingress_ipv6
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_ingress_ipv6.load()?;
    program_ingress_ipv6.attach(&interface, TcAttachType::Ingress)?;

    // Attach to the event arrays
    let mut flows_egress_ipv4 =
        AsyncPerfEventArray::try_from(bpf_egress_ipv4.take_map("EVENTS_IPV4").unwrap())?;

    let mut flows_egress_ipv6 =
        AsyncPerfEventArray::try_from(bpf_egress_ipv6.take_map("EVENTS_IPV6").unwrap())?;

    let mut flows_ingress_ipv4 =
        AsyncPerfEventArray::try_from(bpf_ingress_ipv4.take_map("EVENTS_IPV4").unwrap())?;

    let mut flows_ingress_ipv6 =
        AsyncPerfEventArray::try_from(bpf_ingress_ipv6.take_map("EVENTS_IPV6").unwrap())?;

    let flow_map_ipv4: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    let flow_map_ipv6: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    // Use all online CPUs to process the events in the user space
    for cpu_id in online_cpus()? {
        let mut buf_egress_ipv4 = flows_egress_ipv4.open(cpu_id, None)?;
        let flow_map_clone_egress_ipv4 = flow_map_ipv4.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress_ipv4.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv4;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv4(&data, &flow_map_clone_egress_ipv4, false);
                }
            }
        });

        let mut buf_ingress_ipv4 = flows_ingress_ipv4.open(cpu_id, None)?;
        let flow_map_clone_ingress_ipv4 = flow_map_ipv4.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress_ipv4.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv4;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv4(&data, &flow_map_clone_ingress_ipv4, true);
                }
            }
        });

        let mut buf_egress_ipv6 = flows_egress_ipv6.open(cpu_id, None)?;
        let flow_map_clone_egress_ipv6 = flow_map_ipv6.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_egress_ipv6.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv6;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv6(&data, &flow_map_clone_egress_ipv6, false);
                }
            }
        });

        let mut buf_ingress_ipv6 = flows_ingress_ipv6.open(cpu_id, None)?;
        let flow_map_clone_ingress_ipv6 = flow_map_ipv6.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf_ingress_ipv6.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const BasicFeaturesIpv6;
                    let data = unsafe { ptr.read_unaligned() };

                    process_packet_ipv6(&data, &flow_map_clone_ingress_ipv6, true);
                }
            }
        });
    }

    if let Some(interval) = interval {
        let flow_map_print_ipv4 = flow_map_ipv4.clone();
        let flow_map_print_ipv6 = flow_map_ipv6.clone();
        task::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval));
            loop {
                interval.tick().await;
                for entry in flow_map_print_ipv4.iter() {
                    let flow = entry.value();
                    println!("{}", flow.dump());
                }
                for entry in flow_map_print_ipv6.iter() {
                    let flow = entry.value();
                    println!("{}", flow.dump());
                }
            }
        });
    }

    let flow_map_end_ipv4 = flow_map_ipv4.clone();
    let flow_map_end_ipv6 = flow_map_ipv6.clone();
    task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let timestamp = Utc::now();

            // Collect keys to remove
            let mut keys_to_remove_ipv4 = Vec::new();
            for entry in flow_map_end_ipv4.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    println!("{}", flow.dump());
                    keys_to_remove_ipv4.push(entry.key().clone());
                }
            }

            // Collect keys to remove
            let mut keys_to_remove_ipv6 = Vec::new();
            for entry in flow_map_end_ipv6.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    println!("{}", flow.dump());
                    keys_to_remove_ipv6.push(entry.key().clone());
                }
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove_ipv4 {
                flow_map_end_ipv4.remove(&key);
            }

            // Remove entries outside of the iteration
            for key in keys_to_remove_ipv6 {
                flow_map_end_ipv6.remove(&key);
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn process_packet_ipv4<T>(data: &BasicFeaturesIpv4, flow_map: &Arc<DashMap<String, T>>, fwd: bool)
where
    T: Flow,
{
    let timestamp = Instant::now();
    let destination = std::net::IpAddr::V4(Ipv4Addr::from(data.ipv4_destination));
    let source = std::net::IpAddr::V4(Ipv4Addr::from(data.ipv4_source));
    let features = BasicFeatures {
        fin_flag: data.fin_flag,
        syn_flag: data.syn_flag,
        rst_flag: data.rst_flag,
        psh_flag: data.psh_flag,
        ack_flag: data.ack_flag,
        urg_flag: data.urg_flag,
        ece_flag: data.ece_flag,
        cwe_flag: data.cwe_flag,
        data_length: data.data_length,
        header_length: data.header_length,
        length: data.length,
        window_size: data.window_size,
    };
    let flow_id = if fwd {
        create_flow_id(
            source,
            data.port_source,
            destination,
            data.port_destination,
            data.protocol,
        )
    } else {
        create_flow_id(
            destination,
            data.port_destination,
            source,
            data.port_source,
            data.protocol,
        )
    };

    let flow_id_clone = flow_id.clone();
    let flow_id_remove = flow_id.clone();
    let mut entry = flow_map.entry(flow_id).or_insert_with(|| {
        if fwd {
            T::new(
                flow_id_clone,
                source,
                data.port_source,
                destination,
                data.port_destination,
                data.protocol,
            )
        } else {
            T::new(
                flow_id_clone,
                destination,
                data.port_destination,
                source,
                data.port_source,
                data.protocol,
            )
        }
    });

    let end = entry.update_flow(&features, &timestamp, fwd);
    if end.is_some() {
        println!("{}", end.unwrap());
        drop(entry);
        flow_map.remove(&flow_id_remove);
    }
}

fn process_packet_ipv6<T>(data: &BasicFeaturesIpv6, flow_map: &Arc<DashMap<String, T>>, fwd: bool)
where
    T: Flow,
{
    let timestamp = Instant::now();
    let destination = std::net::IpAddr::V6(Ipv6Addr::from(unsafe {
        data.ipv6_destination.in6_u.u6_addr8
    }));
    let source = std::net::IpAddr::V6(Ipv6Addr::from(unsafe { data.ipv6_source.in6_u.u6_addr8 }));
    let features = BasicFeatures {
        fin_flag: data.fin_flag,
        syn_flag: data.syn_flag,
        rst_flag: data.rst_flag,
        psh_flag: data.psh_flag,
        ack_flag: data.ack_flag,
        urg_flag: data.urg_flag,
        ece_flag: data.ece_flag,
        cwe_flag: data.cwe_flag,
        data_length: data.data_length,
        header_length: data.header_length,
        length: data.length,
        window_size: data.window_size,
    };

    let flow_id = if fwd {
        create_flow_id(
            source,
            data.port_source,
            destination,
            data.port_destination,
            data.protocol,
        )
    } else {
        create_flow_id(
            destination,
            data.port_destination,
            source,
            data.port_source,
            data.protocol,
        )
    };

    let flow_id_clone = flow_id.clone();
    let flow_id_remove = flow_id.clone();
    let mut entry = flow_map.entry(flow_id).or_insert_with(|| {
        if fwd {
            T::new(
                flow_id_clone,
                source,
                data.port_source,
                destination,
                data.port_destination,
                data.protocol,
            )
        } else {
            T::new(
                flow_id_clone,
                destination,
                data.port_destination,
                source,
                data.port_source,
                data.protocol,
            )
        }
    });

    let end = entry.update_flow(&features, &timestamp, fwd);
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

        let data_1 = BasicFeaturesIpv4 {
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
        process_packet_ipv4::<CicFlow>(&data_1, &flow_map, true);

        let data_2 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_2, &flow_map, false);

        assert_eq!(flow_map.len(), 1);
        // 17 is for udp, here we just use it to create a new flow
        let data_3 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_3, &flow_map, true);

        assert_eq!(flow_map.len(), 2);

        let data_4 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_4, &flow_map, true);

        assert_eq!(flow_map.len(), 2);

        let data_5 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_5, &flow_map, false);

        assert_eq!(flow_map.len(), 2);

        let data_6 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_6, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_7 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_7, &flow_map, false);

        assert_eq!(flow_map.len(), 0);

        let data_8 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_8, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_9 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_9, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_10 = BasicFeaturesIpv4 {
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

        process_packet_ipv4(&data_10, &flow_map, true);

        assert_eq!(flow_map.len(), 1);

        let data_11 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_11, &flow_map, false);

        assert_eq!(flow_map.len(), 1);

        let data_12 = BasicFeaturesIpv4 {
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
        process_packet_ipv4(&data_12, &flow_map, false);

        assert_eq!(flow_map.len(), 0);
    }
}
