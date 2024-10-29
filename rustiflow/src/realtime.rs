use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

use crate::debug;
use crate::flow_tui::launch_packet_tui;
use crate::packet_counts::PacketCountPerSecond;
use crate::{flow_table::FlowTable, flows::flow::Flow, packet_features::PacketFeatures};
use aya::maps::PerCpuValues;
use aya::{
    include_bytes_aligned,
    maps::{PerCpuArray, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::{error, info};
use tokio::sync::watch;
use tokio::{
    io::unix::AsyncFd,
    signal,
    sync::mpsc::{self, Sender},
    sync::Mutex,
    task::JoinSet,
};

/// Starts the realtime processing of packets on the given interface.
/// The function will return the number of packets dropped by the eBPF program.
pub async fn handle_realtime<T>(
    interface: &str,
    output_channel: Sender<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
    ingress_only: bool,
    csv_export: bool,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    // Needed for older kernels
    bump_memlock_rlimit();

    // Load the eBPF programs and attach to the event arrays
    let mut bpf_ingress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Ingress)?;
    let mut bpf_ingress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Ingress)?;
    let events_ingress_ipv4 = RingBuf::try_from(bpf_ingress_ipv4.take_map("EVENTS_IPV4").unwrap())?;
    let dropped_packets_ingress_ipv4 =
        PerCpuArray::try_from(bpf_ingress_ipv4.take_map("DROPPED_PACKETS").unwrap())?;
    let events_ingress_ipv6 = RingBuf::try_from(bpf_ingress_ipv6.take_map("EVENTS_IPV6").unwrap())?;
    let dropped_packets_ingress_ipv6 =
        PerCpuArray::try_from(bpf_ingress_ipv6.take_map("DROPPED_PACKETS").unwrap())?;
    let event_sources_v4;
    let event_sources_v6;
    let dropped_packet_counters;

    if !ingress_only {
        let mut bpf_egress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Egress)?;
        let mut bpf_egress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Egress)?;
        let events_egress_ipv4 =
            RingBuf::try_from(bpf_egress_ipv4.take_map("EVENTS_IPV4").unwrap())?;
        let dropped_packets_egress_ipv4 =
            PerCpuArray::try_from(bpf_egress_ipv4.take_map("DROPPED_PACKETS").unwrap())?;
        let events_egress_ipv6 =
            RingBuf::try_from(bpf_egress_ipv6.take_map("EVENTS_IPV6").unwrap())?;
        let dropped_packets_egress_ipv6 =
            PerCpuArray::try_from(bpf_egress_ipv6.take_map("DROPPED_PACKETS").unwrap())?;
        event_sources_v4 = vec![events_egress_ipv4, events_ingress_ipv4];
        event_sources_v6 = vec![events_egress_ipv6, events_ingress_ipv6];
        dropped_packet_counters = vec![
            dropped_packets_egress_ipv4,
            dropped_packets_ingress_ipv4,
            dropped_packets_egress_ipv6,
            dropped_packets_ingress_ipv6,
        ];
    } else {
        event_sources_v4 = vec![events_ingress_ipv4];
        event_sources_v6 = vec![events_ingress_ipv6];
        dropped_packet_counters = vec![dropped_packets_ingress_ipv4, dropped_packets_ingress_ipv6];
    }

    let buffer_num_packets = 10_000;
    let mut shard_senders = Vec::with_capacity(num_threads as usize);

    let (packet_tx, packet_rx) = watch::channel(Vec::new());
    let packet_counter = Arc::new(Mutex::new(PacketCountPerSecond::new()));

    debug!("Creating {} sharded FlowTables...", num_threads);
    for _ in 0..num_threads {
        let (tx, mut rx) = mpsc::channel::<PacketFeatures>(buffer_num_packets);
        let mut flow_table = FlowTable::new(
            active_timeout,
            idle_timeout,
            early_export,
            output_channel.clone(),
            expiration_check_interval,
        );

        // Spawn a task per shard
        tokio::spawn(async move {
            while let Some(packet_features) = rx.recv().await {
                flow_table.process_packet(&packet_features).await;
            }
            debug!("Shard finished processing packets");
            // Handle flow exporting when the receiver is closed
            flow_table.export_all_flows().await;
        });
        shard_senders.push(tx);
    }
    debug!("Sharded FlowTables created");

    // Spawn a task per event source
    let mut handle_set = JoinSet::new();

    for ebpf_event_source in event_sources_v4 {
        let shard_senders_clone = shard_senders.clone();
        let packet_counter_clone = Arc::clone(&packet_counter);
        let packet_tx_clone = packet_tx.clone();

        handle_set.spawn(async move {
            // Wrap the RingBuf in AsyncFd to poll it with tokio
            let mut async_ring_buf = AsyncFd::new(ebpf_event_source).unwrap();

            loop {
                // Wait for data to be available in the ring buffer
                let mut guard = async_ring_buf.readable_mut().await.unwrap();

                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    if csv_export {
                        let mut counter = packet_counter_clone.lock().await;
                        counter.increment();
                        // Send the updated count to the TUI
                        let recent_counts = counter.get_counts_for_last_intervals(100);
                        let _ = packet_tx_clone.send(recent_counts);
                    }
                    let ebpf_event_ipv4: EbpfEventIpv4 =
                        unsafe { std::ptr::read(event.as_ptr() as *const _) };
                    let packet_features = PacketFeatures::from_ebpf_event_ipv4(&ebpf_event_ipv4);
                    let flow_key = packet_features.biflow_key();
                    let shard_index = compute_shard_index(&flow_key, num_threads);

                    if let Err(e) = shard_senders_clone[shard_index].send(packet_features).await {
                        error!(
                            "Failed to send packet_features to shard {}: {}",
                            shard_index, e
                        );
                    }
                }

                // Clear the readiness state for the next iteration
                guard.clear_ready();
            }
        });
    }

    for ebpf_event_source in event_sources_v6 {
        let shard_senders_clone = shard_senders.clone();
        let packet_counter_clone = Arc::clone(&packet_counter);
        let packet_tx_clone = packet_tx.clone();

        handle_set.spawn(async move {
            // Wrap the RingBuf in AsyncFd to poll it with tokio
            let mut async_ring_buf = AsyncFd::new(ebpf_event_source).unwrap();

            loop {
                // Wait for data to be available in the ring buffer
                let mut guard = async_ring_buf.readable_mut().await.unwrap();

                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    if csv_export {
                        let mut counter = packet_counter_clone.lock().await;
                        counter.increment();
                        // Send the updated count to the TUI
                        let recent_counts = counter.get_counts_for_last_intervals(100);
                        let _ = packet_tx_clone.send(recent_counts);
                    }
                    let ebpf_event_ipv6: EbpfEventIpv6 =
                        unsafe { std::ptr::read(event.as_ptr() as *const _) };
                    let packet_features = PacketFeatures::from_ebpf_event_ipv6(&ebpf_event_ipv6);
                    let flow_key = packet_features.biflow_key();
                    let shard_index = compute_shard_index(&flow_key, num_threads);

                    if let Err(e) = shard_senders_clone[shard_index].send(packet_features).await {
                        error!(
                            "Failed to send packet_features to shard {}: {}",
                            shard_index, e
                        );
                    }
                }

                // Clear the readiness state for the next iteration
                guard.clear_ready();
            }
        });
    }

    info!("Waiting for Ctrl-C...");

    if csv_export {
        let _ = launch_packet_tui(packet_rx).await;
    }

    signal::ctrl_c().await?;

    // Fetch the dropped packets counter from the eBPF program before terminating
    let mut total_dropped = 0;
    for dropped_packets_array in dropped_packet_counters {
        let values: PerCpuValues<u64> = dropped_packets_array.get(&0, 0)?;
        for cpu_val in values.iter() {
            total_dropped += *cpu_val;
        }
    }

    // Cancel the tasks reading ebpf events
    handle_set.abort_all();

    // Wait for all tasks to finish
    while let Some(res) = handle_set.join_next().await {
        match res {
            Ok(_) => {
                // Task should never finish by itself
                error!("Event source task finished unexpectedly");
            }
            Err(e) if e.is_cancelled() => {
                // Task was successfully cancelled
                debug!("Task was cancelled as part of graceful shutdown");
            }
            Err(e) => {
                // Log other types of errors
                error!("Task failed: {:?}", e);
            }
        }
    }

    Ok(total_dropped)
}

fn compute_shard_index(flow_key: &str, num_shards: u8) -> usize {
    assert!(num_shards > 0, "num_shards must be greater than 0");
    let mut hasher = DefaultHasher::new();
    flow_key.hash(&mut hasher);
    let hash = hasher.finish();
    (hash % num_shards as u64) as usize
}

fn bump_memlock_rlimit() {
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
}

fn load_ebpf_ipv4(interface: &str, tc_attach_type: TcAttachType) -> Result<Ebpf, anyhow::Error> {
    // Loading the eBPF program, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ipv4 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv4"
    ))?;

    // Attach the eBPF program function
    let _ = EbpfLogger::init(&mut bpf_ipv4);
    let _ = tc::qdisc_add_clsact(interface);

    let program_egress_ipv4: &mut SchedClassifier =
        bpf_ipv4.program_mut("tc_flow_track").unwrap().try_into()?;
    program_egress_ipv4.load().map_err(|e| {
        error!("Failed to load eBPF program: {:?}", e);
        e
    })?;
    program_egress_ipv4
        .attach(&interface, tc_attach_type)
        .map_err(|e| {
            error!("Failed to attach eBPF program: {:?}", e);
            e
        })?;

    Ok(bpf_ipv4)
}

fn load_ebpf_ipv6(interface: &str, tc_attach_type: TcAttachType) -> Result<Ebpf, anyhow::Error> {
    // Loading the eBPF program, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv6"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv6"
    ))?;

    // Attach the eBPF program function
    let _ = EbpfLogger::init(&mut bpf_ipv6);
    let _ = tc::qdisc_add_clsact(interface);

    let program_egress_ipv6: &mut SchedClassifier =
        bpf_ipv6.program_mut("tc_flow_track").unwrap().try_into()?;
    program_egress_ipv6.load()?;
    program_egress_ipv6.attach(&interface, tc_attach_type)?;

    Ok(bpf_ipv6)
}
