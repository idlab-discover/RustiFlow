mod args;
mod flows;
mod output;
mod parsers;
mod records;
mod utils;

use crate::{
    flows::cic_flow::CicFlow,
    output::Export,
    parsers::csv_parser::CsvParser,
    records::{cic_record::CicRecord, print::Print},
    utils::utils::{create_flow_id, get_duration},
};
use args::{Cli, Commands, Dataset, ExportMethodType, FlowType, GeneratedMachineType};
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
use lazy_static::lazy_static;
use log::{debug, info};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    Packet,
};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    ops::{Deref, DerefMut},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::time::{self, Duration};
use tokio::{signal, task};
use utils::utils::BasicFeatures;

lazy_static! {
    static ref EXPORT_FUNCTION: Arc<Mutex<Option<Export>>> = Arc::new(Mutex::new(None));
    static ref EXPORT_FILE: Arc<Mutex<Option<BufWriter<File>>>> = Arc::new(Mutex::new(None));
    static ref FLUSH_COUNTER: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(Some(0)));
    static ref NO_CONTAMINANT_FEATURES: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Realtime {
            interface,
            flow_type,
            export_method,
            lifespan,
            no_contaminant_features,
            interval,
        } => {
            if let Some(interval) = interval {
                if interval >= lifespan {
                    panic!("The interval needs to be smaller than the lifespan!");
                }
            }

            let mut ncf = NO_CONTAMINANT_FEATURES.lock().unwrap();
            *ncf = no_contaminant_features;

            // needed to be dropped, because he stayed in scope.
            drop(ncf);

            match export_method.method {
                ExportMethodType::Print => {
                    let func = output::print::print;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);
                }
                ExportMethodType::Csv => {
                    let func = output::csv::export_to_csv;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);

                    if let Some(path) = export_method.export_path {
                        let file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                            .unwrap_or_else(|err| {
                                panic!("Error opening file: {:?}", err);
                            });
                        let mut export_file = EXPORT_FILE.lock().unwrap();
                        *export_file = Some(BufWriter::new(file));
                    }
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
        Commands::Pcap {
            path,
            machine_type,
            flow_type,
            no_contaminant_features,
            export_method,
        } => {

            let mut ncf = NO_CONTAMINANT_FEATURES.lock().unwrap();
            *ncf = no_contaminant_features;

            // needed to be dropped, because he stayed in scope.
            drop(ncf);

            match export_method.method {
                ExportMethodType::Print => {
                    let func = output::print::print;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);
                }
                ExportMethodType::Csv => {
                    let func = output::csv::export_to_csv;
                    let mut export_func = EXPORT_FUNCTION.lock().unwrap();
                    *export_func = Some(func);

                    if let Some(path) = export_method.export_path {
                        let file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                            .unwrap_or_else(|err| {
                                panic!("Error opening file: {:?}", err);
                            });
                        let mut export_file = EXPORT_FILE.lock().unwrap();
                        *export_file = Some(BufWriter::new(file));
                    }
                }
            }

            match (machine_type, flow_type) {
                (GeneratedMachineType::Windows, FlowType::BasicFlow) => {
                    read_pcap_file_ethernet::<BasicFlow>(&path)
                }
                (GeneratedMachineType::Windows, FlowType::CicFlow) => {
                    read_pcap_file_ethernet::<CicFlow>(&path)
                }
                (GeneratedMachineType::Windows, FlowType::CiddsFlow) => {
                    read_pcap_file_ethernet::<CiddsFlow>(&path)
                }
                (GeneratedMachineType::Windows, FlowType::NfFlow) => {
                    read_pcap_file_ethernet::<NfFlow>(&path)
                }
                (GeneratedMachineType::Linux, FlowType::BasicFlow) => {
                    read_pcap_file_linux_cooked::<BasicFlow>(&path)
                }
                (GeneratedMachineType::Linux, FlowType::CicFlow) => {
                    read_pcap_file_linux_cooked::<CicFlow>(&path)
                }
                (GeneratedMachineType::Linux, FlowType::CiddsFlow) => {
                    read_pcap_file_linux_cooked::<CiddsFlow>(&path)
                }
                (GeneratedMachineType::Linux, FlowType::NfFlow) => {
                    read_pcap_file_linux_cooked::<NfFlow>(&path)
                }
            }
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
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    
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
            // 10 buffers with 10240 bytes each, meaning a capacity of 292 packets per buffer (280 bits per packet)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(10_240))
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
                .map(|_| BytesMut::with_capacity(10_240))
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
            // 10 buffers with 10240 bytes each, meaning a capacity of 173 packets per buffer (472 bits per packet)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(10_240))
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
                .map(|_| BytesMut::with_capacity(10_240))
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
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                }
                for entry in flow_map_print_ipv6.iter() {
                    let flow = entry.value();
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
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
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
                    keys_to_remove_ipv4.push(entry.key().clone());
                }
            }

            // Collect keys to remove
            let mut keys_to_remove_ipv6 = Vec::new();
            for entry in flow_map_end_ipv6.iter() {
                let flow = entry.value();
                let end = get_duration(flow.get_first_timestamp(), timestamp) / 1_000_000.0;

                if end >= lifespan as f64 {
                    if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
                        export(&flow.dump_without_contamination());
                    } else {
                        export(&flow.dump());
                    }
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

    for entry in flow_map_ipv4.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    for entry in flow_map_ipv6.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    // Making sure everything is flushed
    if let Some(export_file) = EXPORT_FILE.lock().unwrap().deref_mut() {
        export_file.flush()?;
    }

    info!("Exiting...");

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
                                    eprintln!("Error: {:?}", err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                    }
                }
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

fn read_pcap_file_ethernet<T>(path: &str)
where
    T: Flow,
{
    let start = Instant::now();
    let mut amount_of_packets = 0;

    let flow_map_ipv4: Arc<DashMap<String, T>> = Arc::new(DashMap::new());
    let flow_map_ipv6: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    let mut cap = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Error opening file: {:?}", e);
            return;
        }
    };

    while let Ok(packet) = cap.next_packet() {
        amount_of_packets += 1;
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                        if let Some(features_ipv4) = extract_ipv4_features(&ipv4_packet) {
                            redirect_packet_ipv4(&features_ipv4, &flow_map_ipv4);
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6_packet) = Ipv6Packet::new(ethernet.payload()) {
                        if let Some(features_ipv6) = extract_ipv6_features(&ipv6_packet) {
                            redirect_packet_ipv6(&features_ipv6, &flow_map_ipv6);
                        }
                    }
                }
                _ => {
                    log::debug!("Unknown EtherType, consider using Linux cooked capture by setting the machine type to linux");
                }
            }
        } else {
            log::error!("Error parsing packet...");
        }
    }

    for entry in flow_map_ipv4.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    for entry in flow_map_ipv6.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    let end = Instant::now();
    println!(
        "{} packets were processed in {:?} milliseconds",
        amount_of_packets,
        end.duration_since(start).as_millis()
    );
}

fn read_pcap_file_linux_cooked<T>(path: &str)
where
    T: Flow,
{
    let start = Instant::now();
    let mut amount_of_packets = 0;
    let mut size: usize = 0;

    let flow_map_ipv4: Arc<DashMap<String, T>> = Arc::new(DashMap::new());
    let flow_map_ipv6: Arc<DashMap<String, T>> = Arc::new(DashMap::new());

    let mut cap = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Error opening file: {:?}", e);
            return;
        }
    };

    // Define constants for Linux cooked capture EtherTypes
    const SLL_IPV4: u16 = 0x0800;
    const SLL_IPV6: u16 = 0x86DD;

    while let Ok(packet) = cap.next_packet() {
        if packet.data.len() > 14 {
            amount_of_packets += 1;
            size += packet.data.len();

            let ethertype = u16::from_be_bytes([packet.data[14], packet.data[15]]);
            match ethertype {
                SLL_IPV4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(&packet.data[16..]) {
                        if let Some(features_ipv4) = extract_ipv4_features(&ipv4_packet) {
                            redirect_packet_ipv4(&features_ipv4, &flow_map_ipv4);
                        }
                    }
                }
                SLL_IPV6 => {
                    if let Some(ipv6_packet) = Ipv6Packet::new(&packet.data[16..]) {
                        if let Some(features_ipv6) = extract_ipv6_features(&ipv6_packet) {
                            redirect_packet_ipv6(&features_ipv6, &flow_map_ipv6);
                        }
                    }
                }
                _ => {
                    log::debug!("Unknown SLL EtherType, consider using Ethernet capture by setting the machine type to windows");
                }
            }
        } else {
            log::error!("Packet too short to be SLL");
        }
    }

    for entry in flow_map_ipv4.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    for entry in flow_map_ipv6.iter() {
        let flow = entry.value();
        if *NO_CONTAMINANT_FEATURES.lock().unwrap().deref() {
            export(&flow.dump_without_contamination());
        } else {
            export(&flow.dump());
        }
    }

    let end = Instant::now();
    println!(
        "{} packets with total size of: {} were processed in {:?} milliseconds",
        amount_of_packets,
        size,
        end.duration_since(start).as_millis()
    );
}

/// Export the flow to the set export function.
/// 
/// ### Arguments
/// 
/// * `output` - The output to export.
fn export(output: &String) {
    let export_func = EXPORT_FUNCTION.lock().unwrap();

    if let Some(function) = export_func.deref() {
        let mut export_file_option = EXPORT_FILE.lock().unwrap();
        let mut flush_counter_option = FLUSH_COUNTER.lock().unwrap();

        if let Some(ref mut flush_counter) = 
            flush_counter_option.deref_mut()
        {
            function(&output, export_file_option.deref_mut(), flush_counter);
        } else {
            log::error!("No export file set...")
        }
    } else {
        log::error!("No export function set...")
    }
}

/// Processes an ipv4 packet and updates the flow map.
///
/// ### Arguments
///
/// * `data` - Basic features of the packet.
/// * `flow_map` - Map of flows.
/// * `fwd` - Direction of the packet.
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
        export(&end.unwrap());
        drop(entry);
        flow_map.remove(&flow_id_remove);
    }
}

/// Processes an ipv6 packet and updates the flow map.
///
/// ### Arguments
///
/// * `data` - Basic features of the packet.
/// * `flow_map` - Map of flows.
/// * `fwd` - Direction of the packet.
fn process_packet_ipv6<T>(data: &BasicFeaturesIpv6, flow_map: &Arc<DashMap<String, T>>, fwd: bool)
where
    T: Flow,
{
    let timestamp = Instant::now();
    let destination = std::net::IpAddr::V6(Ipv6Addr::from(data.ipv6_destination));
    let source = std::net::IpAddr::V6(Ipv6Addr::from(data.ipv6_source));
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
        export(&end.unwrap());
        drop(entry);
        flow_map.remove(&flow_id_remove);
    }
}

/// Redirects an ipv4 packet to the correct flow.
///
/// ### Arguments
///
/// * `features_ipv4` - Basic features of the packet.
/// * `flow_map` - Map of flows.
fn redirect_packet_ipv4<T>(features_ipv4: &BasicFeaturesIpv4, flow_map: &Arc<DashMap<String, T>>)
where
    T: Flow,
{
    let fwd_flow_id = create_flow_id(
        std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_source)),
        features_ipv4.port_source,
        std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_destination)),
        features_ipv4.port_destination,
        features_ipv4.protocol,
    );
    let bwd_flow_id = create_flow_id(
        std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_destination)),
        features_ipv4.port_destination,
        std::net::IpAddr::V4(Ipv4Addr::from(features_ipv4.ipv4_source)),
        features_ipv4.port_source,
        features_ipv4.protocol,
    );

    if flow_map.contains_key(&fwd_flow_id) {
        process_packet_ipv4(&features_ipv4, &flow_map, true);
    } else if flow_map.contains_key(&bwd_flow_id) {
        process_packet_ipv4(&features_ipv4, &flow_map, false);
    } else {
        process_packet_ipv4(&features_ipv4, &flow_map, true);
    }
}

/// Redirects an ipv6 packet to the correct flow.
///
/// ### Arguments
///
/// * `features_ipv6` - Basic features of the packet.
/// * `flow_map` - Map of flows.
fn redirect_packet_ipv6<T>(features_ipv6: &BasicFeaturesIpv6, flow_map: &Arc<DashMap<String, T>>)
where
    T: Flow,
{
    let fwd_flow_id = create_flow_id(
        std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_source)),
        features_ipv6.port_source,
        std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_destination)),
        features_ipv6.port_destination,
        features_ipv6.protocol,
    );
    let bwd_flow_id = create_flow_id(
        std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_destination)),
        features_ipv6.port_destination,
        std::net::IpAddr::V6(Ipv6Addr::from(features_ipv6.ipv6_source)),
        features_ipv6.port_source,
        features_ipv6.protocol,
    );

    if flow_map.contains_key(&fwd_flow_id) {
        process_packet_ipv6(&features_ipv6, &flow_map, true);
    } else if flow_map.contains_key(&bwd_flow_id) {
        process_packet_ipv6(&features_ipv6, &flow_map, false);
    } else {
        process_packet_ipv6(&features_ipv6, &flow_map, true);
    }
}

/// Extracts the basic features of an ipv4 packet pnet struct.
///
/// ### Arguments
///
/// * `ipv4_packet` - Ipv4 packet pnet struct.
///
/// ### Returns
///
/// * `Option<BasicFeaturesIpv4>` - Basic features of the packet.
fn extract_ipv4_features(ipv4_packet: &Ipv4Packet) -> Option<BasicFeaturesIpv4> {
    let source_ip = ipv4_packet.get_source();
    let destination_ip = ipv4_packet.get_destination();
    let protocol = ipv4_packet.get_next_level_protocol();

    let source_port: u16;
    let destination_port: u16;

    let mut syn_flag: u8 = 0;
    let mut fin_flag: u8 = 0;
    let mut rst_flag: u8 = 0;
    let mut psh_flag: u8 = 0;
    let mut ack_flag: u8 = 0;
    let mut urg_flag: u8 = 0;
    let mut ece_flag: u8 = 0;
    let mut cwe_flag: u8 = 0;

    let data_length: u32;
    let header_length: u32;
    let length: u32;

    let mut window_size: u16 = 0;

    if protocol.0 == IpNextHeaderProtocols::Tcp.0 {
        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
            source_port = tcp_packet.get_source();
            destination_port = tcp_packet.get_destination();

            syn_flag = (tcp_packet.get_flags() & 0b0000_0010 != 0) as u8;
            fin_flag = (tcp_packet.get_flags() & 0b0000_0001 != 0) as u8;
            rst_flag = (tcp_packet.get_flags() & 0b0000_0100 != 0) as u8;
            psh_flag = (tcp_packet.get_flags() & 0b0000_1000 != 0) as u8;
            ack_flag = (tcp_packet.get_flags() & 0b0001_0000 != 0) as u8;
            urg_flag = (tcp_packet.get_flags() & 0b0010_0000 != 0) as u8;
            ece_flag = (tcp_packet.get_flags() & 0b0100_0000 != 0) as u8;
            cwe_flag = (tcp_packet.get_flags() & 0b1000_0000 != 0) as u8;

            data_length = tcp_packet.payload().len() as u32;
            header_length = (tcp_packet.get_data_offset() * 4) as u32;
            length = tcp_packet.packet().len() as u32;

            window_size = tcp_packet.get_window();
        } else {
            return None;
        }
    } else if protocol.0 == IpNextHeaderProtocols::Udp.0 {
        if let Some(udp_packet) = pnet::packet::udp::UdpPacket::new(ipv4_packet.payload()) {
            source_port = udp_packet.get_source();
            destination_port = udp_packet.get_destination();

            data_length = udp_packet.payload().len() as u32;
            header_length = 8;
            length = udp_packet.packet().len() as u32;
        } else {
            return None;
        }
    } else {
        return None;
    }

    Some(BasicFeaturesIpv4 {
        ipv4_source: source_ip.into(),
        ipv4_destination: destination_ip.into(),
        port_source: source_port,
        port_destination: destination_port,
        protocol: protocol.0,
        fin_flag,
        syn_flag,
        rst_flag,
        psh_flag,
        ack_flag,
        urg_flag,
        ece_flag,
        cwe_flag,
        data_length,
        header_length,
        length,
        window_size,
    })
}

/// Extracts the basic features of an ipv6 packet pnet struct.
///
/// ### Arguments
///
/// * `ipv6_packet` - Ipv6 packet pnet struct.
///
/// ### Returns
///
/// * `Option<BasicFeaturesIpv6>` - Basic features of the packet.
fn extract_ipv6_features(ipv6_packet: &Ipv6Packet) -> Option<BasicFeaturesIpv6> {
    let source_ip = ipv6_packet.get_source();
    let destination_ip = ipv6_packet.get_destination();
    let protocol = ipv6_packet.get_next_header();

    let source_port: u16;
    let destination_port: u16;

    let mut syn_flag: u8 = 0;
    let mut fin_flag: u8 = 0;
    let mut rst_flag: u8 = 0;
    let mut psh_flag: u8 = 0;
    let mut ack_flag: u8 = 0;
    let mut urg_flag: u8 = 0;
    let mut ece_flag: u8 = 0;
    let mut cwe_flag: u8 = 0;

    let data_length: u32;
    let header_length: u32;
    let length: u32;

    let mut window_size: u16 = 0;

    if protocol == IpNextHeaderProtocols::Tcp {
        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
            source_port = tcp_packet.get_source();
            destination_port = tcp_packet.get_destination();

            syn_flag = (tcp_packet.get_flags() & 0b0000_0010 != 0) as u8;
            fin_flag = (tcp_packet.get_flags() & 0b0000_0001 != 0) as u8;
            rst_flag = (tcp_packet.get_flags() & 0b0000_0100 != 0) as u8;
            psh_flag = (tcp_packet.get_flags() & 0b0000_1000 != 0) as u8;
            ack_flag = (tcp_packet.get_flags() & 0b0001_0000 != 0) as u8;
            urg_flag = (tcp_packet.get_flags() & 0b0010_0000 != 0) as u8;
            ece_flag = (tcp_packet.get_flags() & 0b0100_0000 != 0) as u8;
            cwe_flag = (tcp_packet.get_flags() & 0b1000_0000 != 0) as u8;

            data_length = tcp_packet.payload().len() as u32;
            header_length = (tcp_packet.get_data_offset() * 4) as u32;
            length = tcp_packet.packet().len() as u32;

            window_size = tcp_packet.get_window();
        } else {
            return None;
        }
    } else if protocol == IpNextHeaderProtocols::Udp {
        if let Some(udp_packet) = pnet::packet::udp::UdpPacket::new(ipv6_packet.payload()) {
            source_port = udp_packet.get_source();
            destination_port = udp_packet.get_destination();

            data_length = udp_packet.payload().len() as u32;
            header_length = 8;
            length = udp_packet.packet().len() as u32;
        } else {
            return None;
        }
    } else {
        return None;
    }

    Some(BasicFeaturesIpv6 {
        ipv6_source: source_ip.into(),
        ipv6_destination: destination_ip.into(),
        port_source: source_port,
        port_destination: destination_port,
        protocol: protocol.0,
        fin_flag,
        syn_flag,
        rst_flag,
        psh_flag,
        ack_flag,
        urg_flag,
        ece_flag,
        cwe_flag,
        data_length,
        header_length,
        length,
        window_size,
    })
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

        assert_eq!(flow_map.len(), 1);

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
