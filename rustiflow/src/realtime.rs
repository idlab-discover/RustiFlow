use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use crate::debug;
use crate::flow_tui::launch_packet_tui;
use crate::packet_counts::PacketCountPerSecond;
use crate::realtime_mode::PacketGraphMode;
use crate::{flow_table::FlowTable, flows::flow::Flow, packet_features::PacketFeatures};
use anyhow::Context;
use aya::{
    maps::{MapData, PerCpuArray, RingBuf},
    programs::{
        tc,
        tc::{NlOptions, TcAttachOptions},
        SchedClassifier, TcAttachType,
    },
    Ebpf,
};
use aya_log::EbpfLogger;
use common::{EbpfEventIpv4, EbpfEventIpv6, REALTIME_EVENT_QUEUE_COUNT};
use log::{error, info};
use tokio::sync::watch;
use tokio::{
    io::unix::AsyncFd,
    signal,
    sync::mpsc::{self, Receiver, Sender},
    sync::Mutex,
    task::JoinSet,
};

#[derive(Default)]
struct RealtimeSourceStats {
    events: AtomicU64,
    decode_and_shard_ns: AtomicU64,
    dispatch_enqueue_ns: AtomicU64,
    shard_send_wait_ns: AtomicU64,
    packet_graph_ns: AtomicU64,
    total_event_ns: AtomicU64,
    send_errors: AtomicU64,
}

struct RealtimeEbpfCounters {
    label: &'static str,
    dropped_packets: PerCpuArray<MapData, u64>,
    matched_packets: PerCpuArray<MapData, u64>,
    submitted_events: PerCpuArray<MapData, u64>,
}

impl RealtimeSourceStats {
    fn add_decode_and_shard_ns(&self, value: u64) {
        self.decode_and_shard_ns.fetch_add(value, Ordering::Relaxed);
    }

    fn add_dispatch_enqueue_ns(&self, value: u64) {
        self.dispatch_enqueue_ns.fetch_add(value, Ordering::Relaxed);
    }

    fn add_shard_send_wait_ns(&self, value: u64) {
        self.shard_send_wait_ns.fetch_add(value, Ordering::Relaxed);
    }

    fn add_packet_graph_ns(&self, value: u64) {
        self.packet_graph_ns.fetch_add(value, Ordering::Relaxed);
    }

    fn add_total_event_ns(&self, value: u64) {
        self.total_event_ns.fetch_add(value, Ordering::Relaxed);
    }

    fn increment_events(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_send_errors(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }
}

fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn log_source_stats(label: &str, stats: &RealtimeSourceStats) {
    let events = stats.events.load(Ordering::Relaxed);
    let decode_and_shard_ns = stats.decode_and_shard_ns.load(Ordering::Relaxed);
    let dispatch_enqueue_ns = stats.dispatch_enqueue_ns.load(Ordering::Relaxed);
    let shard_send_wait_ns = stats.shard_send_wait_ns.load(Ordering::Relaxed);
    let packet_graph_ns = stats.packet_graph_ns.load(Ordering::Relaxed);
    let total_event_ns = stats.total_event_ns.load(Ordering::Relaxed);
    let send_errors = stats.send_errors.load(Ordering::Relaxed);

    if events == 0 {
        info!("Realtime source {}: no events drained", label);
        return;
    }

    info!(
        "Realtime source {}: events={} total_ms={:.3} decode_ms={:.3} enqueue_wait_ms={:.3} shard_send_wait_ms={:.3} packet_graph_ms={:.3} avg_event_us={:.3} avg_enqueue_wait_us={:.3} avg_shard_send_wait_us={:.3} send_errors={}",
        label,
        events,
        total_event_ns as f64 / 1_000_000.0,
        decode_and_shard_ns as f64 / 1_000_000.0,
        dispatch_enqueue_ns as f64 / 1_000_000.0,
        shard_send_wait_ns as f64 / 1_000_000.0,
        packet_graph_ns as f64 / 1_000_000.0,
        total_event_ns as f64 / events as f64 / 1_000.0,
        dispatch_enqueue_ns as f64 / events as f64 / 1_000.0,
        shard_send_wait_ns as f64 / events as f64 / 1_000.0,
        send_errors,
    );
}

const DEFAULT_SHARD_BATCH_SIZE: usize = 128;
const DEFAULT_SHARD_QUEUE_CAPACITY: usize = 512;
const DEFAULT_SOURCE_DISPATCH_QUEUE_CAPACITY: usize = 1024;

/// Starts the realtime processing of packets on the given interface.
/// The function will return the number of packets dropped by the eBPF program.
#[allow(clippy::too_many_arguments)]
pub async fn handle_realtime<T>(
    interface: &str,
    output_channel: Sender<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
    ingress_only: bool,
    packet_graph_mode: PacketGraphMode,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    let shard_batch_size = read_env_usize(
        "RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE",
        DEFAULT_SHARD_BATCH_SIZE,
    );
    let shard_queue_capacity = read_env_usize(
        "RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY",
        DEFAULT_SHARD_QUEUE_CAPACITY,
    );
    let source_dispatch_queue_capacity = read_env_usize(
        "RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY",
        DEFAULT_SOURCE_DISPATCH_QUEUE_CAPACITY,
    );

    // Needed for older kernels
    bump_memlock_rlimit();

    let realtime_offset_us = compute_realtime_offset_us()?;

    // Load the eBPF programs and attach to the event arrays
    let mut bpf_ingress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Ingress)?;
    let mut bpf_ingress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Ingress)?;
    let events_ingress_ipv4 = take_ring_buf_maps(&mut bpf_ingress_ipv4, "EVENTS_IPV4")?;
    let dropped_packets_ingress_ipv4: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv4.take_map("DROPPED_PACKETS").unwrap())?;
    let matched_packets_ingress_ipv4: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv4.take_map("MATCHED_PACKETS").unwrap())?;
    let submitted_events_ingress_ipv4: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv4.take_map("SUBMITTED_EVENTS").unwrap())?;
    let events_ingress_ipv6 = take_ring_buf_maps(&mut bpf_ingress_ipv6, "EVENTS_IPV6")?;
    let dropped_packets_ingress_ipv6: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv6.take_map("DROPPED_PACKETS").unwrap())?;
    let matched_packets_ingress_ipv6: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv6.take_map("MATCHED_PACKETS").unwrap())?;
    let submitted_events_ingress_ipv6: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf_ingress_ipv6.take_map("SUBMITTED_EVENTS").unwrap())?;
    let event_sources_v4;
    let event_sources_v6;
    let ebpf_counters;

    if !ingress_only {
        let mut bpf_egress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Egress)?;
        let mut bpf_egress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Egress)?;
        let events_egress_ipv4 = take_ring_buf_maps(&mut bpf_egress_ipv4, "EVENTS_IPV4")?;
        let dropped_packets_egress_ipv4: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv4.take_map("DROPPED_PACKETS").unwrap())?;
        let matched_packets_egress_ipv4: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv4.take_map("MATCHED_PACKETS").unwrap())?;
        let submitted_events_egress_ipv4: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv4.take_map("SUBMITTED_EVENTS").unwrap())?;
        let events_egress_ipv6 = take_ring_buf_maps(&mut bpf_egress_ipv6, "EVENTS_IPV6")?;
        let dropped_packets_egress_ipv6: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv6.take_map("DROPPED_PACKETS").unwrap())?;
        let matched_packets_egress_ipv6: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv6.take_map("MATCHED_PACKETS").unwrap())?;
        let submitted_events_egress_ipv6: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf_egress_ipv6.take_map("SUBMITTED_EVENTS").unwrap())?;
        event_sources_v4 = labeled_ringbuf_sources("egress-ipv4", events_egress_ipv4)
            .into_iter()
            .chain(labeled_ringbuf_sources("ingress-ipv4", events_ingress_ipv4))
            .collect();
        event_sources_v6 = labeled_ringbuf_sources("egress-ipv6", events_egress_ipv6)
            .into_iter()
            .chain(labeled_ringbuf_sources("ingress-ipv6", events_ingress_ipv6))
            .collect();
        ebpf_counters = vec![
            RealtimeEbpfCounters {
                label: "egress-ipv4",
                dropped_packets: dropped_packets_egress_ipv4,
                matched_packets: matched_packets_egress_ipv4,
                submitted_events: submitted_events_egress_ipv4,
            },
            RealtimeEbpfCounters {
                label: "ingress-ipv4",
                dropped_packets: dropped_packets_ingress_ipv4,
                matched_packets: matched_packets_ingress_ipv4,
                submitted_events: submitted_events_ingress_ipv4,
            },
            RealtimeEbpfCounters {
                label: "egress-ipv6",
                dropped_packets: dropped_packets_egress_ipv6,
                matched_packets: matched_packets_egress_ipv6,
                submitted_events: submitted_events_egress_ipv6,
            },
            RealtimeEbpfCounters {
                label: "ingress-ipv6",
                dropped_packets: dropped_packets_ingress_ipv6,
                matched_packets: matched_packets_ingress_ipv6,
                submitted_events: submitted_events_ingress_ipv6,
            },
        ];
    } else {
        event_sources_v4 = labeled_ringbuf_sources("ingress-ipv4", events_ingress_ipv4);
        event_sources_v6 = labeled_ringbuf_sources("ingress-ipv6", events_ingress_ipv6);
        ebpf_counters = vec![
            RealtimeEbpfCounters {
                label: "ingress-ipv4",
                dropped_packets: dropped_packets_ingress_ipv4,
                matched_packets: matched_packets_ingress_ipv4,
                submitted_events: submitted_events_ingress_ipv4,
            },
            RealtimeEbpfCounters {
                label: "ingress-ipv6",
                dropped_packets: dropped_packets_ingress_ipv6,
                matched_packets: matched_packets_ingress_ipv6,
                submitted_events: submitted_events_ingress_ipv6,
            },
        ];
    }

    let mut shard_senders = Vec::with_capacity(num_threads as usize);
    let enable_source_stats = std::env::var_os("RUSTIFLOW_REALTIME_STATS").is_some();
    let (packet_graph, packet_rx) = match packet_graph_mode {
        PacketGraphMode::Enabled => {
            let (packet_tx, packet_rx) = watch::channel(Vec::new());
            (
                Some(PacketGraphState {
                    packet_counter: Arc::new(Mutex::new(PacketCountPerSecond::new())),
                    packet_tx,
                }),
                Some(packet_rx),
            )
        }
        PacketGraphMode::Disabled => (None, None),
    };

    debug!("Creating {} sharded FlowTables...", num_threads);
    for _ in 0..num_threads {
        let (tx, mut rx) = mpsc::channel::<Vec<PacketFeatures>>(shard_queue_capacity);
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
            while let Some(packet_batch) = rx.recv().await {
                for packet_features in packet_batch {
                    last_timestamp = Some(packet_features.timestamp_us);
                    flow_table.process_packet(&packet_features).await;
                }
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
    let mut source_stats = Vec::new();

    for (label, ebpf_event_source) in event_sources_v4 {
        let shard_senders_clone = shard_senders.clone();
        let packet_graph = packet_graph.clone();
        let stats = enable_source_stats.then(|| Arc::new(RealtimeSourceStats::default()));
        source_stats.push((label, stats.clone()));
        let dispatch_sender = spawn_source_dispatcher(
            &mut handle_set,
            shard_senders_clone.clone(),
            source_dispatch_queue_capacity,
            stats.clone(),
        );

        handle_set.spawn(async move {
            // Wrap the RingBuf in AsyncFd to poll it with tokio
            let mut async_ring_buf = AsyncFd::new(ebpf_event_source).unwrap();
            let mut pending_batches =
                create_pending_batches(num_threads as usize, shard_batch_size);

            loop {
                // Wait for data to be available in the ring buffer
                let mut guard = async_ring_buf.readable_mut().await.unwrap();

                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    let event_start = enable_source_stats.then(Instant::now);
                    if let Some(packet_graph) = &packet_graph {
                        let packet_graph_start = enable_source_stats.then(Instant::now);
                        packet_graph.record_packet().await;
                        if let (Some(stats), Some(packet_graph_start)) =
                            (&stats, packet_graph_start)
                        {
                            stats.add_packet_graph_ns(elapsed_ns(packet_graph_start));
                        }
                    }
                    let decode_start = enable_source_stats.then(Instant::now);
                    let ebpf_event_ipv4: EbpfEventIpv4 =
                        unsafe { std::ptr::read(event.as_ptr() as *const _) };
                    let packet_features =
                        PacketFeatures::from_ebpf_event_ipv4(&ebpf_event_ipv4, realtime_offset_us);
                    let flow_key = packet_features.biflow_key_value();
                    let shard_index = compute_shard_index(&flow_key, num_threads);
                    if let (Some(stats), Some(decode_start)) = (&stats, decode_start) {
                        stats.add_decode_and_shard_ns(elapsed_ns(decode_start));
                    }
                    pending_batches[shard_index].push(packet_features);

                    if pending_batches[shard_index].len() >= shard_batch_size {
                        enqueue_shard_batch(
                            &dispatch_sender,
                            &mut pending_batches[shard_index],
                            stats.as_ref(),
                            shard_index,
                        )
                        .await;
                    }

                    if let Some(stats) = &stats {
                        stats.increment_events();
                        if let Some(event_start) = event_start {
                            stats.add_total_event_ns(elapsed_ns(event_start));
                        }
                    }
                }

                enqueue_pending_batches(&dispatch_sender, &mut pending_batches, stats.as_ref())
                    .await;

                // Clear the readiness state for the next iteration
                guard.clear_ready();
            }
        });
    }

    for (label, ebpf_event_source) in event_sources_v6 {
        let shard_senders_clone = shard_senders.clone();
        let packet_graph = packet_graph.clone();
        let stats = enable_source_stats.then(|| Arc::new(RealtimeSourceStats::default()));
        source_stats.push((label, stats.clone()));
        let dispatch_sender = spawn_source_dispatcher(
            &mut handle_set,
            shard_senders_clone.clone(),
            source_dispatch_queue_capacity,
            stats.clone(),
        );

        handle_set.spawn(async move {
            // Wrap the RingBuf in AsyncFd to poll it with tokio
            let mut async_ring_buf = AsyncFd::new(ebpf_event_source).unwrap();
            let mut pending_batches =
                create_pending_batches(num_threads as usize, shard_batch_size);

            loop {
                // Wait for data to be available in the ring buffer
                let mut guard = async_ring_buf.readable_mut().await.unwrap();

                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    let event_start = enable_source_stats.then(Instant::now);
                    if let Some(packet_graph) = &packet_graph {
                        let packet_graph_start = enable_source_stats.then(Instant::now);
                        packet_graph.record_packet().await;
                        if let (Some(stats), Some(packet_graph_start)) =
                            (&stats, packet_graph_start)
                        {
                            stats.add_packet_graph_ns(elapsed_ns(packet_graph_start));
                        }
                    }
                    let decode_start = enable_source_stats.then(Instant::now);
                    let ebpf_event_ipv6: EbpfEventIpv6 =
                        unsafe { std::ptr::read(event.as_ptr() as *const _) };
                    let packet_features =
                        PacketFeatures::from_ebpf_event_ipv6(&ebpf_event_ipv6, realtime_offset_us);
                    let flow_key = packet_features.biflow_key_value();
                    let shard_index = compute_shard_index(&flow_key, num_threads);
                    if let (Some(stats), Some(decode_start)) = (&stats, decode_start) {
                        stats.add_decode_and_shard_ns(elapsed_ns(decode_start));
                    }
                    pending_batches[shard_index].push(packet_features);

                    if pending_batches[shard_index].len() >= shard_batch_size {
                        enqueue_shard_batch(
                            &dispatch_sender,
                            &mut pending_batches[shard_index],
                            stats.as_ref(),
                            shard_index,
                        )
                        .await;
                    }

                    if let Some(stats) = &stats {
                        stats.increment_events();
                        if let Some(event_start) = event_start {
                            stats.add_total_event_ns(elapsed_ns(event_start));
                        }
                    }
                }

                enqueue_pending_batches(&dispatch_sender, &mut pending_batches, stats.as_ref())
                    .await;

                // Clear the readiness state for the next iteration
                guard.clear_ready();
            }
        });
    }

    info!("Waiting for Ctrl-C...");

    if let Some(packet_rx) = packet_rx {
        let _ = launch_packet_tui(packet_rx).await;
    }

    signal::ctrl_c().await?;

    // Fetch dropped packets counter from eBPF program before terminating
    info!("Fetching dropped packet counters before exiting...");
    let mut total_dropped = 0;
    for counters in &ebpf_counters {
        let dropped_packets =
            read_per_cpu_counter(&counters.dropped_packets, counters.label, "dropped");
        let matched_packets =
            read_per_cpu_counter(&counters.matched_packets, counters.label, "matched");
        let submitted_events =
            read_per_cpu_counter(&counters.submitted_events, counters.label, "submitted");
        total_dropped += dropped_packets;
        info!(
            "eBPF counters {}: matched_packets={}, submitted_events={}, dropped_packets={}",
            counters.label, matched_packets, submitted_events, dropped_packets
        );
    }

    info!("Total dropped packets before exit: {}", total_dropped);
    for (label, stats) in &source_stats {
        if let Some(stats) = stats.as_ref() {
            log_source_stats(label, stats);
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

fn read_per_cpu_counter(
    counter_array: &PerCpuArray<MapData, u64>,
    label: &str,
    counter_name: &str,
) -> u64 {
    match counter_array.get(&0, 0) {
        Ok(values) => values.iter().sum(),
        Err(e) => {
            error!(
                "Failed to read {} counter for {}: {:?}",
                counter_name, label, e
            );
            0
        }
    }
}

fn create_pending_batches(num_shards: usize, shard_batch_size: usize) -> Vec<Vec<PacketFeatures>> {
    std::iter::repeat_with(|| Vec::with_capacity(shard_batch_size))
        .take(num_shards)
        .collect()
}

async fn enqueue_pending_batches(
    dispatch_sender: &Sender<ShardDispatchBatch>,
    pending_batches: &mut [Vec<PacketFeatures>],
    stats: Option<&Arc<RealtimeSourceStats>>,
) {
    for (shard_index, pending_batch) in pending_batches.iter_mut().enumerate() {
        enqueue_shard_batch(dispatch_sender, pending_batch, stats, shard_index).await;
    }
}

struct ShardDispatchBatch {
    shard_index: usize,
    batch: Vec<PacketFeatures>,
}

fn spawn_source_dispatcher(
    handle_set: &mut JoinSet<()>,
    shard_senders: Vec<Sender<Vec<PacketFeatures>>>,
    source_dispatch_queue_capacity: usize,
    stats: Option<Arc<RealtimeSourceStats>>,
) -> Sender<ShardDispatchBatch> {
    let (dispatch_sender, mut dispatch_receiver) =
        mpsc::channel::<ShardDispatchBatch>(source_dispatch_queue_capacity);

    handle_set.spawn(async move {
        run_source_dispatcher(&shard_senders, &mut dispatch_receiver, stats.as_ref()).await;
    });

    dispatch_sender
}

async fn run_source_dispatcher(
    shard_senders: &[Sender<Vec<PacketFeatures>>],
    dispatch_receiver: &mut Receiver<ShardDispatchBatch>,
    stats: Option<&Arc<RealtimeSourceStats>>,
) {
    while let Some(ShardDispatchBatch { shard_index, batch }) = dispatch_receiver.recv().await {
        let send_start = stats.as_ref().map(|_| Instant::now());
        if let Err(e) = shard_senders[shard_index].send(batch).await {
            if let Some(stats) = stats {
                stats.increment_send_errors();
            }
            error!(
                "Failed to send packet batch to shard {}: {}",
                shard_index, e
            );
        }
        if let (Some(stats), Some(send_start)) = (stats, send_start) {
            stats.add_shard_send_wait_ns(elapsed_ns(send_start));
        }
    }
}

async fn enqueue_shard_batch(
    dispatch_sender: &Sender<ShardDispatchBatch>,
    pending_batch: &mut Vec<PacketFeatures>,
    stats: Option<&Arc<RealtimeSourceStats>>,
    shard_index: usize,
) {
    if pending_batch.is_empty() {
        return;
    }

    let next_capacity = pending_batch.capacity().max(1);
    let batch = std::mem::replace(pending_batch, Vec::with_capacity(next_capacity));
    let send_start = stats.as_ref().map(|_| Instant::now());
    if let Err(e) = dispatch_sender
        .send(ShardDispatchBatch { shard_index, batch })
        .await
    {
        if let Some(stats) = stats {
            stats.increment_send_errors();
        }
        error!(
            "Failed to queue packet batch for shard {}: {}",
            shard_index, e
        );
    }
    if let (Some(stats), Some(send_start)) = (stats, send_start) {
        stats.add_dispatch_enqueue_ns(elapsed_ns(send_start));
    }
}

fn read_env_usize(var_name: &str, default_value: usize) -> usize {
    std::env::var(var_name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_value)
}

#[derive(Clone)]
struct PacketGraphState {
    packet_counter: Arc<Mutex<PacketCountPerSecond>>,
    packet_tx: watch::Sender<Vec<(u64, u64)>>,
}

impl PacketGraphState {
    async fn record_packet(&self) {
        let mut counter = self.packet_counter.lock().await;
        counter.increment();
        let recent_counts = counter.get_counts_for_last_intervals(100);
        let _ = self.packet_tx.send(recent_counts);
    }
}

fn compute_shard_index<H: Hash>(flow_key: &H, num_shards: u8) -> usize {
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

fn labeled_ringbuf_sources(
    label_prefix: &'static str,
    ring_bufs: Vec<RingBuf<MapData>>,
) -> Vec<(String, RingBuf<MapData>)> {
    ring_bufs
        .into_iter()
        .enumerate()
        .map(|(index, ring_buf)| (queue_label(label_prefix, index), ring_buf))
        .collect()
}

fn queue_label(label_prefix: &'static str, index: usize) -> String {
    format!("{label_prefix}-q{index}")
}

fn take_ring_buf_maps(
    bpf: &mut Ebpf,
    base_name: &str,
) -> Result<Vec<RingBuf<MapData>>, anyhow::Error> {
    let mut ring_bufs = Vec::with_capacity(REALTIME_EVENT_QUEUE_COUNT);

    for index in 0..REALTIME_EVENT_QUEUE_COUNT {
        let map_name = format!("{}_{}", base_name, index);
        let ring_buf = RingBuf::try_from(
            bpf.take_map(&map_name)
                .with_context(|| format!("missing ring buffer map {}", map_name))?,
        )?;
        ring_bufs.push(ring_buf);
    }

    Ok(ring_bufs)
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

fn tc_attach_type_label(tc_attach_type: TcAttachType) -> &'static str {
    match tc_attach_type {
        TcAttachType::Ingress => "ingress",
        TcAttachType::Egress => "egress",
        TcAttachType::Custom(_) => "custom",
    }
}

fn load_ebpf_ipv4(interface: &str, tc_attach_type: TcAttachType) -> Result<Ebpf, anyhow::Error> {
    let binary_path = ebpf_binary_path("rustiflow-ebpf-ipv4");
    let attach_label = tc_attach_type_label(tc_attach_type);
    info!(
        "Loading IPv4 eBPF binary {} for {} on {}",
        binary_path.display(),
        attach_label,
        interface
    );
    let mut bpf_ipv4 = Ebpf::load_file(&binary_path).with_context(|| {
        format!(
            "Failed to load eBPF IPv4 binary from {}. Build it first with `cargo xtask ebpf-ipv4`.",
            binary_path.display()
        )
    })?;

    // Attach the eBPF program function
    let _ = EbpfLogger::init(&mut bpf_ipv4);
    match tc::qdisc_add_clsact(interface) {
        Ok(()) => info!("Ensured clsact qdisc on {}", interface),
        Err(e) => debug!("qdisc_add_clsact({}): {:?}", interface, e),
    }

    let program_egress_ipv4: &mut SchedClassifier =
        bpf_ipv4.program_mut("tc_flow_track").unwrap().try_into()?;
    info!(
        "Loading IPv4 tc classifier for {} on {}",
        attach_label, interface
    );
    program_egress_ipv4.load().map_err(|e| {
        error!("Failed to load eBPF program: {:?}", e);
        e
    })?;
    info!(
        "Attaching IPv4 tc classifier to {} on {}",
        attach_label, interface
    );
    program_egress_ipv4
        .attach_with_options(
            interface,
            tc_attach_type,
            TcAttachOptions::Netlink(NlOptions::default()),
        )
        .map_err(|e| {
            error!("Failed to attach eBPF program: {:?}", e);
            e
        })?;
    info!(
        "Attached IPv4 tc classifier to {} on {}",
        attach_label, interface
    );

    Ok(bpf_ipv4)
}

fn load_ebpf_ipv6(interface: &str, tc_attach_type: TcAttachType) -> Result<Ebpf, anyhow::Error> {
    let binary_path = ebpf_binary_path("rustiflow-ebpf-ipv6");
    let attach_label = tc_attach_type_label(tc_attach_type);
    info!(
        "Loading IPv6 eBPF binary {} for {} on {}",
        binary_path.display(),
        attach_label,
        interface
    );
    let mut bpf_ipv6 = Ebpf::load_file(&binary_path).with_context(|| {
        format!(
            "Failed to load eBPF IPv6 binary from {}. Build it first with `cargo xtask ebpf-ipv6`.",
            binary_path.display()
        )
    })?;

    // Attach the eBPF program function
    let _ = EbpfLogger::init(&mut bpf_ipv6);
    match tc::qdisc_add_clsact(interface) {
        Ok(()) => info!("Ensured clsact qdisc on {}", interface),
        Err(e) => debug!("qdisc_add_clsact({}): {:?}", interface, e),
    }

    let program_egress_ipv6: &mut SchedClassifier =
        bpf_ipv6.program_mut("tc_flow_track").unwrap().try_into()?;
    info!(
        "Loading IPv6 tc classifier for {} on {}",
        attach_label, interface
    );
    program_egress_ipv6.load()?;
    info!(
        "Attaching IPv6 tc classifier to {} on {}",
        attach_label, interface
    );
    program_egress_ipv6.attach_with_options(
        interface,
        tc_attach_type,
        TcAttachOptions::Netlink(NlOptions::default()),
    )?;
    info!(
        "Attached IPv6 tc classifier to {} on {}",
        attach_label, interface
    );

    Ok(bpf_ipv6)
}
