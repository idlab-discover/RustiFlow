use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::debug;
use crate::flow_tui::launch_packet_tui;
use crate::packet_counts::PacketCountPerSecond;
use crate::{flow_table::FlowTable, flows::flow::Flow, packet_features::PacketFeatures};
use anyhow::Context;
use aya::{
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
    performance_mode_disabled: bool,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    // Needed for older kernels
    bump_memlock_rlimit();

    let realtime_offset_us = compute_realtime_offset_us()?;

    // Load the eBPF programs and attach to the event arrays
    let mut bpf_ingress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Ingress)?;
    let mut bpf_ingress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Ingress)?;
    let events_ingress_ipv4 = RingBuf::try_from(bpf_ingress_ipv4.take_map("EVENTS_IPV4").unwrap())?;
    let dropped_packets_ingress_ipv4: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv4.take_map("DROPPED_PACKETS").unwrap())?;
    let events_ingress_ipv6 = RingBuf::try_from(bpf_ingress_ipv6.take_map("EVENTS_IPV6").unwrap())?;
    let dropped_packets_ingress_ipv6: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv6.take_map("DROPPED_PACKETS").unwrap())?;
    let event_sources_v4;
    let event_sources_v6;
    let dropped_packet_counters;

    if !ingress_only {
        let mut bpf_egress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Egress)?;
        let mut bpf_egress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Egress)?;
        let events_egress_ipv4 =
            RingBuf::try_from(bpf_egress_ipv4.take_map("EVENTS_IPV4").unwrap())?;
        let dropped_packets_egress_ipv4: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv4.take_map("DROPPED_PACKETS").unwrap())?;
        let events_egress_ipv6 =
            RingBuf::try_from(bpf_egress_ipv6.take_map("EVENTS_IPV6").unwrap())?;
        let dropped_packets_egress_ipv6: PerCpuArray<_, u64> =
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
            let mut last_timestamp = None;
            while let Some(packet_features) = rx.recv().await {
                last_timestamp = Some(packet_features.timestamp_us);
                flow_table.process_packet(&packet_features).await;
            }
            debug!("Shard finished processing packets");
            // Handle flow exporting when the receiver is closed
            if let Some(timestamp) = last_timestamp {
                flow_table.export_all_flows(timestamp).await;
            }
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
        let realtime_offset_us = realtime_offset_us;

        handle_set.spawn(async move {
            // Wrap the RingBuf in AsyncFd to poll it with tokio
            let mut async_ring_buf = AsyncFd::new(ebpf_event_source).unwrap();

            loop {
                // Wait for data to be available in the ring buffer
                let mut guard = async_ring_buf.readable_mut().await.unwrap();

                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    if performance_mode_disabled {
                        let mut counter = packet_counter_clone.lock().await;
                        counter.increment();
                        // Send the updated count to the TUI
                        let recent_counts = counter.get_counts_for_last_intervals(100);
                        let _ = packet_tx_clone.send(recent_counts);
                    }
                    let ebpf_event_ipv4: EbpfEventIpv4 =
                        unsafe { std::ptr::read(event.as_ptr() as *const _) };
                    let packet_features =
                        PacketFeatures::from_ebpf_event_ipv4(&ebpf_event_ipv4, realtime_offset_us);
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
        let realtime_offset_us = realtime_offset_us;

        handle_set.spawn(async move {
            // Wrap the RingBuf in AsyncFd to poll it with tokio
            let mut async_ring_buf = AsyncFd::new(ebpf_event_source).unwrap();

            loop {
                // Wait for data to be available in the ring buffer
                let mut guard = async_ring_buf.readable_mut().await.unwrap();

                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    if performance_mode_disabled {
                        let mut counter = packet_counter_clone.lock().await;
                        counter.increment();
                        // Send the updated count to the TUI
                        let recent_counts = counter.get_counts_for_last_intervals(100);
                        let _ = packet_tx_clone.send(recent_counts);
                    }
                    let ebpf_event_ipv6: EbpfEventIpv6 =
                        unsafe { std::ptr::read(event.as_ptr() as *const _) };
                    let packet_features =
                        PacketFeatures::from_ebpf_event_ipv6(&ebpf_event_ipv6, realtime_offset_us);
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

    if performance_mode_disabled {
        let _ = launch_packet_tui(packet_rx).await;
    }

    signal::ctrl_c().await?;

    // Fetch dropped packets counter from eBPF program before terminating
    info!("Fetching dropped packet counters before exiting...");
    let mut total_dropped = 0;
    for dropped_packets_array in dropped_packet_counters {
        match dropped_packets_array.get(&0, 0) {
            Ok(values) => {
                for cpu_val in values.iter() {
                    total_dropped += *cpu_val;
                }
            }
            Err(e) => {
                error!("Failed to read dropped packets counter: {:?}", e);
            }
        }
    }

    info!("Total dropped packets before exit: {}", total_dropped);

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

fn compute_realtime_offset_us() -> Result<i64, anyhow::Error> {
    let realtime_us = read_clock_us(libc::CLOCK_REALTIME)?;
    let monotonic_us = read_clock_us(libc::CLOCK_MONOTONIC)?;
    Ok(realtime_us - monotonic_us)
}

fn read_clock_us(clock_id: libc::clockid_t) -> Result<i64, anyhow::Error> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(ts.tv_sec * 1_000_000 + ts.tv_nsec / 1_000)
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

fn ebpf_binary_path(program_name: &str) -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target"));
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    target_dir
        .join("bpfel-unknown-none")
        .join(profile)
        .join(program_name)
}

fn load_ebpf_ipv4(interface: &str, tc_attach_type: TcAttachType) -> Result<Ebpf, anyhow::Error> {
    let binary_path = ebpf_binary_path("rustiflow-ebpf-ipv4");
    let mut bpf_ipv4 = Ebpf::load_file(&binary_path).with_context(|| {
        format!(
            "Failed to load eBPF IPv4 binary from {}. Build it first with `cargo xtask ebpf-ipv4`.",
            binary_path.display()
        )
    })?;

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
    let binary_path = ebpf_binary_path("rustiflow-ebpf-ipv6");
    let mut bpf_ipv6 = Ebpf::load_file(&binary_path).with_context(|| {
        format!(
            "Failed to load eBPF IPv6 binary from {}. Build it first with `cargo xtask ebpf-ipv6`.",
            binary_path.display()
        )
    })?;

    // Attach the eBPF program function
    let _ = EbpfLogger::init(&mut bpf_ipv6);
    let _ = tc::qdisc_add_clsact(interface);

    let program_egress_ipv6: &mut SchedClassifier =
        bpf_ipv6.program_mut("tc_flow_track").unwrap().try_into()?;
    program_egress_ipv6.load()?;
    program_egress_ipv6.attach(&interface, tc_attach_type)?;

    Ok(bpf_ipv6)
}
