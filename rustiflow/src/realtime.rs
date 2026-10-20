mod replay;

pub use replay::replay_bench;

use std::collections::VecDeque;
use std::io;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::debug;
use crate::flow_tui::launch_packet_tui;
use crate::output::FlowSink;
use crate::realtime_mode::PacketGraphMode;
use crate::{
    flow_key::ShardSelector, flow_table::FlowTable, flows::flow::Flow,
    packet_features::PacketFeatures,
};
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
    task::JoinSet,
    time::MissedTickBehavior,
};

#[derive(Default)]
struct RealtimeSourceStats {
    events: AtomicU64,
    decode_and_shard_ns: AtomicU64,
    dispatch_enqueue_ns: AtomicU64,
    shard_send_wait_ns: AtomicU64,
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
    let total_event_ns = stats.total_event_ns.load(Ordering::Relaxed);
    let send_errors = stats.send_errors.load(Ordering::Relaxed);

    if events == 0 {
        info!("Realtime source {}: no events drained", label);
        return;
    }

    info!(
        "Realtime source {}: events={} total_ms={:.3} decode_ms={:.3} enqueue_wait_ms={:.3} shard_send_wait_ms={:.3} avg_event_us={:.3} avg_enqueue_wait_us={:.3} avg_shard_send_wait_us={:.3} send_errors={}",
        label,
        events,
        total_event_ns as f64 / 1_000_000.0,
        decode_and_shard_ns as f64 / 1_000_000.0,
        dispatch_enqueue_ns as f64 / 1_000_000.0,
        shard_send_wait_ns as f64 / 1_000_000.0,
        total_event_ns as f64 / events as f64 / 1_000.0,
        dispatch_enqueue_ns as f64 / events as f64 / 1_000.0,
        shard_send_wait_ns as f64 / events as f64 / 1_000.0,
        send_errors,
    );
}

const DEFAULT_SHARD_BATCH_SIZE: usize = 128;
const DEFAULT_SHARD_QUEUE_CAPACITY: usize = 512;
const DEFAULT_SOURCE_DISPATCH_QUEUE_CAPACITY: usize = 1024;

/// Queue and batch sizes of the userspace stages behind the event rings.
struct PipelineSettings {
    shard_batch_size: usize,
    shard_queue_capacity: usize,
    source_dispatch_queue_capacity: usize,
}

impl PipelineSettings {
    fn from_env() -> Self {
        Self {
            shard_batch_size: read_env_usize(
                "RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE",
                DEFAULT_SHARD_BATCH_SIZE,
            ),
            shard_queue_capacity: read_env_usize(
                "RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY",
                DEFAULT_SHARD_QUEUE_CAPACITY,
            ),
            source_dispatch_queue_capacity: read_env_usize(
                "RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY",
                DEFAULT_SOURCE_DISPATCH_QUEUE_CAPACITY,
            ),
        }
    }
}

struct FlowTableSettings {
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<NonZeroU64>,
    expiration_check_interval: u64,
}

/// Spawns one flow-table worker per shard. Each worker exports its remaining
/// flows once every sender for its shard is dropped.
fn spawn_shard_workers<T: Flow>(
    shard_count: NonZeroUsize,
    shard_queue_capacity: usize,
    flow_table_settings: &FlowTableSettings,
    exporter: &impl FlowSink<T>,
) -> Vec<Sender<Vec<PacketFeatures>>> {
    debug!("Creating {} sharded FlowTables...", shard_count);
    let shard_senders = (0..shard_count.get())
        .map(|_| {
            let (tx, mut rx) = mpsc::channel::<Vec<PacketFeatures>>(shard_queue_capacity);
            let mut flow_table = FlowTable::new(
                flow_table_settings.active_timeout,
                flow_table_settings.idle_timeout,
                flow_table_settings.early_export,
                exporter.shard_sender(),
                flow_table_settings.expiration_check_interval,
            );

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
            tx
        })
        .collect();
    debug!("Sharded FlowTables created");
    shard_senders
}

/// Decodes one raw ring-buffer record into packet features.
type DecodeEvent = fn(&[u8], i64) -> PacketFeatures;

fn decode_ipv4_event(event: &[u8], realtime_offset_us: i64) -> PacketFeatures {
    // SAFETY: the IPv4 programs only submit `EbpfEventIpv4` records to their rings.
    let event: EbpfEventIpv4 = unsafe { std::ptr::read(event.as_ptr() as *const _) };
    PacketFeatures::from_ebpf_event_ipv4(&event, realtime_offset_us)
}

fn decode_ipv6_event(event: &[u8], realtime_offset_us: i64) -> PacketFeatures {
    // SAFETY: the IPv6 programs only submit `EbpfEventIpv6` records to their rings.
    let event: EbpfEventIpv6 = unsafe { std::ptr::read(event.as_ptr() as *const _) };
    PacketFeatures::from_ebpf_event_ipv6(&event, realtime_offset_us)
}

/// One event source's userspace stage: pick a shard per packet, batch per
/// shard, and hand batches to the source's own dispatcher task so draining
/// never waits on a shard queue directly.
struct SourceBatcher {
    shard_selector: ShardSelector,
    shard_batch_size: usize,
    pending_batches: Vec<Vec<PacketFeatures>>,
    dispatch_sender: Sender<ShardDispatchBatch>,
    stats: Option<Arc<RealtimeSourceStats>>,
}

impl SourceBatcher {
    /// Creates the batcher and spawns its dispatcher into `handle_set`.
    fn new(
        handle_set: &mut JoinSet<()>,
        shard_senders: &[Sender<Vec<PacketFeatures>>],
        shard_selector: &ShardSelector,
        settings: &PipelineSettings,
        stats: Option<Arc<RealtimeSourceStats>>,
    ) -> Self {
        let dispatch_sender = spawn_source_dispatcher(
            handle_set,
            shard_senders.to_vec(),
            settings.source_dispatch_queue_capacity,
            stats.clone(),
        );
        Self {
            shard_selector: shard_selector.clone(),
            shard_batch_size: settings.shard_batch_size,
            pending_batches: create_pending_batches(shard_senders.len(), settings.shard_batch_size),
            dispatch_sender,
            stats,
        }
    }

    /// Decodes one event and queues it for its shard, dispatching the shard's
    /// batch once it is full.
    async fn push_event(&mut self, decode: impl FnOnce() -> PacketFeatures) {
        let event_start = self.stats.is_some().then(Instant::now);
        let packet_features = decode();
        let shard_index = self
            .shard_selector
            .shard_index(&packet_features.biflow_key_value());
        if let (Some(stats), Some(event_start)) = (&self.stats, event_start) {
            stats.add_decode_and_shard_ns(elapsed_ns(event_start));
        }

        let pending_batch = &mut self.pending_batches[shard_index];
        pending_batch.push(packet_features);
        if pending_batch.len() >= self.shard_batch_size {
            enqueue_shard_batch(
                &self.dispatch_sender,
                pending_batch,
                self.stats.as_ref(),
                shard_index,
            )
            .await;
        }

        if let (Some(stats), Some(event_start)) = (&self.stats, event_start) {
            stats.increment_events();
            stats.add_total_event_ns(elapsed_ns(event_start));
        }
    }

    /// Dispatches every partial batch, as a source does when its ring runs empty.
    async fn flush(&mut self) {
        enqueue_pending_batches(
            &self.dispatch_sender,
            &mut self.pending_batches,
            self.stats.as_ref(),
        )
        .await;
    }
}

/// Drains one ring buffer for as long as the task runs.
async fn drain_ring_source(
    ring_buf: RingBuf<MapData>,
    mut batcher: SourceBatcher,
    packet_graph: Option<PacketGraphState>,
    decode_event: DecodeEvent,
    realtime_offset_us: i64,
) {
    // Wrap the RingBuf in AsyncFd to poll it with tokio
    let mut async_ring_buf = AsyncFd::new(ring_buf).unwrap();

    loop {
        // Wait for data to be available in the ring buffer
        let mut guard = async_ring_buf.readable_mut().await.unwrap();

        let ring_buf = guard.get_inner_mut();
        let mut drained_events = 0;
        while let Some(event) = ring_buf.next() {
            drained_events += 1;
            if drained_events == PACKET_GRAPH_RECORD_BATCH {
                if let Some(packet_graph) = &packet_graph {
                    packet_graph.record_packets(drained_events);
                }
                drained_events = 0;
            }
            batcher
                .push_event(|| decode_event(&event, realtime_offset_us))
                .await;
        }

        if let Some(packet_graph) = &packet_graph {
            packet_graph.record_packets(drained_events);
        }
        batcher.flush().await;

        // Clear the readiness state for the next iteration
        guard.clear_ready();
    }
}

/// Starts the realtime processing of packets on the given interface.
/// The function will return the number of packets dropped by the eBPF program.
#[allow(clippy::too_many_arguments)]
pub async fn handle_realtime<T>(
    interface: &str,
    exporter: impl FlowSink<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<NonZeroU64>,
    expiration_check_interval: u64,
    ingress_only: bool,
    packet_graph_mode: PacketGraphMode,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    let settings = PipelineSettings::from_env();
    let shard_count =
        NonZeroUsize::new(usize::from(num_threads)).context("thread count must be at least 1")?;
    let shard_selector = ShardSelector::new(shard_count);

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

    let enable_source_stats = std::env::var_os("RUSTIFLOW_REALTIME_STATS").is_some();
    let mut handle_set = JoinSet::new();
    let (packet_graph, packet_rx) = match packet_graph_mode {
        PacketGraphMode::Enabled => {
            let (packet_tx, packet_rx) = watch::channel(Vec::new());
            let packet_graph = PacketGraphState {
                packets_since_tick: Arc::new(AtomicU64::new(0)),
            };
            handle_set.spawn(packet_graph.clone().publish_intervals(packet_tx));
            (Some(packet_graph), Some(packet_rx))
        }
        PacketGraphMode::Disabled => (None, None),
    };

    let shard_senders = spawn_shard_workers(
        shard_count,
        settings.shard_queue_capacity,
        &FlowTableSettings {
            active_timeout,
            idle_timeout,
            early_export,
            expiration_check_interval,
        },
        &exporter,
    );

    // Spawn a drain task and a dispatcher per event source
    let mut source_stats = Vec::new();
    let sources = event_sources_v4
        .into_iter()
        .map(|(label, ring_buf)| (label, ring_buf, decode_ipv4_event as DecodeEvent))
        .chain(
            event_sources_v6
                .into_iter()
                .map(|(label, ring_buf)| (label, ring_buf, decode_ipv6_event as DecodeEvent)),
        );
    for (label, ring_buf, decode_event) in sources {
        let stats = enable_source_stats.then(|| Arc::new(RealtimeSourceStats::default()));
        source_stats.push((label, stats.clone()));
        let batcher = SourceBatcher::new(
            &mut handle_set,
            &shard_senders,
            &shard_selector,
            &settings,
            stats,
        );
        handle_set.spawn(drain_ring_source(
            ring_buf,
            batcher,
            packet_graph.clone(),
            decode_event,
            realtime_offset_us,
        ));
    }
    // Only the dispatchers keep the shards' senders, so aborting them on
    // shutdown lets each shard export its remaining flows.
    drop(shard_senders);

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

const PACKET_GRAPH_INTERVAL: Duration = Duration::from_millis(100);
const PACKET_GRAPH_INTERVALS: usize = 100;
/// Events a source counts locally before adding them to the graph counter, so a
/// ring that never drains empty still reports progress.
const PACKET_GRAPH_RECORD_BATCH: u64 = 1024;

/// Packets counted for the realtime graph since its last tick.
#[derive(Clone)]
struct PacketGraphState {
    packets_since_tick: Arc<AtomicU64>,
}

impl PacketGraphState {
    /// Sources add once per drained batch, keeping the shared counter off the
    /// per-packet path.
    fn record_packets(&self, packets: u64) {
        self.packets_since_tick
            .fetch_add(packets, Ordering::Relaxed);
    }

    /// Publishes per-interval packet counts, newest first, for the last
    /// `PACKET_GRAPH_INTERVALS` ticks. Intervals without packets count as zero.
    async fn publish_intervals(self, packet_tx: watch::Sender<Vec<(u64, u64)>>) {
        let mut intervals = VecDeque::with_capacity(PACKET_GRAPH_INTERVALS + 1);
        let mut ticker = tokio::time::interval(PACKET_GRAPH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let interval_id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since_epoch| {
                    (since_epoch.as_millis() / PACKET_GRAPH_INTERVAL.as_millis()) as u64
                });
            let packets = self.packets_since_tick.swap(0, Ordering::Relaxed);
            intervals.push_front((interval_id, packets));
            intervals.truncate(PACKET_GRAPH_INTERVALS);
            let _ = packet_tx.send(intervals.iter().copied().collect());
        }
    }
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
