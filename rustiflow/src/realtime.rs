mod batch_pool;
mod ebpf_objects;
mod promiscuous;
mod replay;
mod ring_drain;
mod source_reactors;

pub use replay::replay_bench;

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::debug;
use crate::flow_tui::launch_packet_tui;
use crate::output::FlowSink;
use crate::realtime_mode::{PacketGraphMode, PromiscuousMode};
use crate::{
    flow_key::ShardSelector, flow_table::FlowTable, flows::flow::Flow,
    packet_features::PacketFeatures,
};
use anyhow::Context;
use aya::{
    maps::{MapData, PerCpuArray, RingBuf},
    programs::{
        tc,
        tc::{NlOptions, TcAttach},
        SchedClassifier, TcAttachType,
    },
    Ebpf,
};
use aya_log::EbpfLogger;
use batch_pool::BatchPool;
use common::{EbpfEventIpv4, EbpfEventIpv6, REALTIME_EVENT_QUEUE_COUNT};
use ebpf_objects::ebpf_object_path;
use log::{error, info};
use promiscuous::PromiscuousMembership;
use ring_drain::{DrainPolicy, RingStats};
use source_reactors::{ReactorCount, RingSource, RingSourcePipeline};
use tokio::sync::watch;
use tokio::{
    signal,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinSet,
    time::MissedTickBehavior,
};

#[derive(Default)]
struct RealtimeSourceStats {
    ring: Option<RingStats>,
    events: AtomicU64,
    decode_and_shard_ns: AtomicU64,
    dispatch_enqueue_ns: AtomicU64,
    shard_send_wait_ns: AtomicU64,
    total_event_ns: AtomicU64,
    send_errors: AtomicU64,
}

struct RealtimeEbpfCounters {
    labels: &'static [&'static str],
    dropped_packets: PerCpuArray<MapData, u64>,
    matched_packets: PerCpuArray<MapData, u64>,
    submitted_events: PerCpuArray<MapData, u64>,
}

impl RealtimeEbpfCounters {
    fn take(bpf: &mut Ebpf, labels: &'static [&'static str]) -> anyhow::Result<Self> {
        let mut take_counter = |name| {
            PerCpuArray::try_from(
                bpf.take_map(name)
                    .with_context(|| format!("missing eBPF counter map {name}"))?,
            )
            .with_context(|| format!("invalid eBPF counter map {name}"))
        };
        Ok(Self {
            labels,
            dropped_packets: take_counter("DROPPED_PACKETS")?,
            matched_packets: take_counter("MATCHED_PACKETS")?,
            submitted_events: take_counter("SUBMITTED_EVENTS")?,
        })
    }

    fn log_totals(&self) -> u64 {
        let mut total_dropped = 0;
        for (index, &label) in (0..).zip(self.labels) {
            let dropped = read_per_cpu_counter(&self.dropped_packets, index, label, "dropped");
            let matched = read_per_cpu_counter(&self.matched_packets, index, label, "matched");
            let submitted = read_per_cpu_counter(&self.submitted_events, index, label, "submitted");
            total_dropped += dropped;
            info!(
                "eBPF counters {label}: matched_packets={matched}, submitted_events={submitted}, dropped_packets={dropped}"
            );
        }
        total_dropped
    }
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
    if let Some(ring) = &stats.ring {
        ring.log(label);
    }
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
    recycle_shard_batches: bool,
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
            recycle_shard_batches: std::env::var_os("RUSTIFLOW_EXPERIMENT_RECYCLE_SHARD_BATCHES")
                .is_some_and(|value| value == "1"),
        }
    }
}

struct FlowTableSettings {
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<NonZeroU64>,
    expiration_check_interval: u64,
}

struct ShardBatchSender {
    sender: Sender<Vec<PacketFeatures>>,
    batch_pool: Option<Arc<BatchPool>>,
}

/// Spawns one flow-table worker per shard. Each worker exports its remaining
/// flows once every sender for its shard is dropped.
fn spawn_shard_workers<T: Flow>(
    shard_count: NonZeroUsize,
    settings: &PipelineSettings,
    flow_table_settings: &FlowTableSettings,
    exporter: &impl FlowSink<T>,
) -> Vec<ShardBatchSender> {
    debug!("Creating {} sharded FlowTables...", shard_count);
    let shard_senders = (0..shard_count.get())
        .map(|_| {
            let (sender, mut rx) =
                mpsc::channel::<Vec<PacketFeatures>>(settings.shard_queue_capacity);
            let batch_pool = settings
                .recycle_shard_batches
                .then(|| Arc::new(BatchPool::new()));
            let worker_pool = batch_pool.clone();
            let mut flow_table = FlowTable::new(
                flow_table_settings.active_timeout,
                flow_table_settings.idle_timeout,
                flow_table_settings.early_export,
                exporter.shard_output(),
                flow_table_settings.expiration_check_interval,
            );

            tokio::spawn(async move {
                let mut last_timestamp = None;
                while let Some(packet_batch) = rx.recv().await {
                    flow_table.process_batch(&packet_batch).await;
                    if let Some(packet) = packet_batch.last() {
                        last_timestamp = Some(packet.timestamp_us);
                    }
                    if let Some(pool) = &worker_pool {
                        pool.recycle(packet_batch);
                    }
                }
                debug!("Shard finished processing packets");
                // Handle flow exporting when the receiver is closed
                if let Some(timestamp) = last_timestamp {
                    flow_table.export_all_flows(timestamp).await;
                }
            });
            ShardBatchSender { sender, batch_pool }
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
    pending_batches: Vec<PendingShardBatch>,
    dispatch_sender: Sender<ShardDispatchBatch>,
    stats: Option<Arc<RealtimeSourceStats>>,
}

struct PendingShardBatch {
    packets: Vec<PacketFeatures>,
    batch_pool: Option<Arc<BatchPool>>,
}

impl SourceBatcher {
    /// Creates the batcher and spawns its dispatcher into `handle_set`.
    fn new(
        handle_set: &mut JoinSet<()>,
        shard_senders: &[ShardBatchSender],
        shard_selector: &ShardSelector,
        settings: &PipelineSettings,
        stats: Option<Arc<RealtimeSourceStats>>,
    ) -> Self {
        let dispatch_sender = spawn_source_dispatcher(
            handle_set,
            shard_senders
                .iter()
                .map(|shard| shard.sender.clone())
                .collect(),
            settings.source_dispatch_queue_capacity,
            stats.clone(),
        );
        Self {
            shard_selector: shard_selector.clone(),
            shard_batch_size: settings.shard_batch_size,
            pending_batches: shard_senders
                .iter()
                .map(|shard| PendingShardBatch {
                    packets: Vec::with_capacity(settings.shard_batch_size),
                    batch_pool: shard.batch_pool.clone(),
                })
                .collect(),
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
        pending_batch.packets.push(packet_features);
        if pending_batch.packets.len() >= self.shard_batch_size {
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
        for (shard_index, pending_batch) in self.pending_batches.iter_mut().enumerate() {
            enqueue_shard_batch(
                &self.dispatch_sender,
                pending_batch,
                self.stats.as_ref(),
                shard_index,
            )
            .await;
        }
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
    promiscuous_mode: PromiscuousMode,
    packet_graph_mode: PacketGraphMode,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    let reactor_count = ReactorCount::from_env(ingress_only)?;
    let settings = PipelineSettings::from_env();
    let shard_count =
        NonZeroUsize::new(usize::from(num_threads)).context("thread count must be at least 1")?;
    let shard_selector = ShardSelector::new(shard_count);

    // Needed for older kernels
    bump_memlock_rlimit();

    let realtime_offset_us = compute_realtime_offset_us()?;

    // Join before attaching and declare first, so the membership is dropped
    // only after every classifier has been detached.
    let _promiscuous_membership = match promiscuous_mode {
        PromiscuousMode::Enabled => {
            let membership = PromiscuousMembership::join(interface)?;
            info!("Holding {interface} in promiscuous mode until capture stops");
            Some(membership)
        }
        PromiscuousMode::Disabled => None,
    };

    let single_tc = std::env::var_os("RUSTIFLOW_EXPERIMENT_SINGLE_TC").is_some();
    anyhow::ensure!(
        !single_tc || ingress_only,
        "single TC experiment requires --ingress-only"
    );
    let (mut ingress, mut ingress_ipv6) = if single_tc {
        (
            load_classifier("dual-stack", "dual-stack", interface, TcAttachType::Ingress)?,
            None,
        )
    } else {
        let ipv4 = load_classifier("ipv4", "IPv4", interface, TcAttachType::Ingress)?;
        let ipv6 = load_classifier("ipv6", "IPv6", interface, TcAttachType::Ingress)?;
        (ipv4, Some(ipv6))
    };

    let events_ingress_ipv4 = take_ring_buf_maps(&mut ingress, "EVENTS_IPV4")?;
    let (events_ingress_ipv6, mut ebpf_counters) = if let Some(ipv6) = &mut ingress_ipv6 {
        let counters = vec![
            RealtimeEbpfCounters::take(&mut ingress, &["ingress-ipv4"])?,
            RealtimeEbpfCounters::take(ipv6, &["ingress-ipv6"])?,
        ];
        (take_ring_buf_maps(ipv6, "EVENTS_IPV6")?, counters)
    } else {
        let events = take_ring_buf_maps(&mut ingress, "EVENTS_IPV6")?;
        // The experimental object indexes the shared maps by family: v4=0, v6=1.
        let counters = RealtimeEbpfCounters::take(&mut ingress, &["ingress-ipv4", "ingress-ipv6"])?;
        (events, vec![counters])
    };

    let ingress_sources_v4 = labeled_ringbuf_sources("ingress-ipv4", events_ingress_ipv4);
    let ingress_sources_v6 = labeled_ringbuf_sources("ingress-ipv6", events_ingress_ipv6);
    let event_sources_v4;
    let event_sources_v6;
    // Dropping an `Ebpf` detaches its classifiers, so the egress programs must
    // outlive the block that loads them, like the ingress ones above.
    let _egress_programs;
    if ingress_only {
        _egress_programs = None;
        event_sources_v4 = ingress_sources_v4;
        event_sources_v6 = ingress_sources_v6;
    } else {
        let mut ipv4 = load_classifier("ipv4", "IPv4", interface, TcAttachType::Egress)?;
        let mut ipv6 = load_classifier("ipv6", "IPv6", interface, TcAttachType::Egress)?;
        event_sources_v4 =
            labeled_ringbuf_sources("egress-ipv4", take_ring_buf_maps(&mut ipv4, "EVENTS_IPV4")?)
                .into_iter()
                .chain(ingress_sources_v4)
                .collect();
        event_sources_v6 =
            labeled_ringbuf_sources("egress-ipv6", take_ring_buf_maps(&mut ipv6, "EVENTS_IPV6")?)
                .into_iter()
                .chain(ingress_sources_v6)
                .collect();
        ebpf_counters.insert(0, RealtimeEbpfCounters::take(&mut ipv4, &["egress-ipv4"])?);
        ebpf_counters.insert(2, RealtimeEbpfCounters::take(&mut ipv6, &["egress-ipv6"])?);
        _egress_programs = Some([ipv4, ipv6]);
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
        &settings,
        &FlowTableSettings {
            active_timeout,
            idle_timeout,
            early_export,
            expiration_check_interval,
        },
        &exporter,
    );

    // Spawn a drain task and a dispatcher per event source
    let drain_policy = DrainPolicy::from_env();
    let mut source_stats = Vec::new();
    let sources = event_sources_v4
        .into_iter()
        .map(|(label, ring_buf)| (label, ring_buf, decode_ipv4_event as DecodeEvent))
        .chain(
            event_sources_v6
                .into_iter()
                .map(|(label, ring_buf)| (label, ring_buf, decode_ipv6_event as DecodeEvent)),
        );
    let sources = sources
        .map(|(label, ring, decode)| {
            let stats = enable_source_stats.then(|| {
                Arc::new(RealtimeSourceStats {
                    ring: Some(RingStats::new(realtime_offset_us)),
                    ..RealtimeSourceStats::default()
                })
            });

            source_stats.push((label, stats.clone()));
            RingSource {
                ring,
                decode,
                stats,
            }
        })
        .collect();
    let mut reactors = RingSourcePipeline {
        shard_senders,
        shard_selector,
        settings,
        packet_graph,
        drain_policy,
        realtime_offset_us,
    }
    .start(reactor_count, &mut handle_set, sources)
    .await?;

    info!("Waiting for Ctrl-C...");

    if let Some(packet_rx) = packet_rx {
        let _ = launch_packet_tui(packet_rx).await;
    }

    let capture_result = tokio::select! {
        signal = signal::ctrl_c() => signal.context("waiting for Ctrl-C"),
        error = reactors.unexpected_exit() => Err(error),
    };

    // Fetch dropped packets counter from eBPF program before terminating
    info!("Fetching dropped packet counters before exiting...");
    let total_dropped = ebpf_counters
        .iter()
        .map(RealtimeEbpfCounters::log_totals)
        .sum();

    info!("Total dropped packets before exit: {}", total_dropped);
    for (label, stats) in &source_stats {
        if let Some(stats) = stats.as_ref() {
            log_source_stats(label, stats);
        }
    }

    // Cancel the tasks reading ebpf events
    handle_set.abort_all();
    let reactor_result = reactors.shutdown().await;

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

    capture_result?;
    reactor_result?;
    Ok(total_dropped)
}

fn read_per_cpu_counter(
    counter_array: &PerCpuArray<MapData, u64>,
    index: u32,
    label: &str,
    counter_name: &str,
) -> u64 {
    match counter_array.get(&index, 0) {
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
        let handoff = stats
            .and_then(|stats| stats.ring.as_ref())
            .zip(batch.first())
            .map(|(ring, first)| (ring, batch.len(), first.timestamp_us));
        let send_start = stats.as_ref().map(|_| Instant::now());
        if let Err(e) = shard_senders[shard_index].send(batch).await {
            if let Some(stats) = stats {
                stats.increment_send_errors();
            }
            error!(
                "Failed to send packet batch to shard {}: {}",
                shard_index, e
            );
        } else if let Some((ring, records, first_timestamp_us)) = handoff {
            ring.record_handoff(records, first_timestamp_us);
        }
        if let (Some(stats), Some(send_start)) = (stats, send_start) {
            stats.add_shard_send_wait_ns(elapsed_ns(send_start));
        }
    }
}

async fn enqueue_shard_batch(
    dispatch_sender: &Sender<ShardDispatchBatch>,
    pending_batch: &mut PendingShardBatch,
    stats: Option<&Arc<RealtimeSourceStats>>,
    shard_index: usize,
) {
    if pending_batch.packets.is_empty() {
        return;
    }

    let replacement = pending_batch
        .batch_pool
        .as_ref()
        .and_then(|pool| pool.try_take())
        .unwrap_or_else(|| Vec::with_capacity(pending_batch.packets.capacity()));
    let batch = std::mem::replace(&mut pending_batch.packets, replacement);
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

/// Forwards `aya-log` records from the eBPF program to the userspace logger.
fn spawn_ebpf_logger(bpf: &mut Ebpf) {
    let logger = match EbpfLogger::init(bpf) {
        Ok(logger) => logger,
        Err(e) => {
            debug!("eBPF logger unavailable: {e}");
            return;
        }
    };
    // SAFETY: the logger owns its ring buffer map file descriptor and reports
    // that same descriptor from `as_raw_fd` until it is dropped with the `AsyncFd`.
    let mut logger = match unsafe { AsyncFd::register(logger) } {
        Ok(logger) => logger,
        Err(e) => {
            error!("Failed to poll the eBPF logger: {e}");
            return;
        }
    };

    tokio::spawn(async move {
        loop {
            let Ok(mut guard) = logger.readable_mut().await else {
                return;
            };
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });
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

fn tc_attach_type_label(tc_attach_type: TcAttachType) -> &'static str {
    match tc_attach_type {
        TcAttachType::Ingress => "ingress",
        TcAttachType::Egress => "egress",
    }
}

fn load_classifier(
    object: &str,
    family: &str,
    interface: &str,
    attach_type: TcAttachType,
) -> anyhow::Result<Ebpf> {
    let binary_path = ebpf_object_path(&format!("rustiflow-ebpf-{object}"))?;
    let attach_label = tc_attach_type_label(attach_type);
    info!(
        "Loading {family} eBPF binary {} for {attach_label} on {interface}",
        binary_path.display()
    );
    let mut bpf = Ebpf::load_file(&binary_path).with_context(|| {
        format!(
            "Failed to load eBPF {family} binary from {}",
            binary_path.display()
        )
    })?;

    let interface_name = CString::new(interface)
        .with_context(|| format!("interface name {interface:?} contains a NUL byte"))?;

    spawn_ebpf_logger(&mut bpf);
    match tc::qdisc_add_clsact(&interface_name) {
        Ok(()) => info!("Ensured clsact qdisc on {interface}"),
        Err(e) => debug!("qdisc_add_clsact({interface}): {e:?}"),
    }

    let program: &mut SchedClassifier = bpf
        .program_mut("tc_flow_track")
        .context("missing tc_flow_track classifier")?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("Failed to load {family} tc classifier"))?;
    program
        .attach(
            &interface_name,
            TcAttach::Netlink {
                parent: attach_type.into(),
                options: NlOptions::default(),
            },
        )
        .with_context(|| {
            format!("Failed to attach {family} tc classifier to {attach_label} on {interface}")
        })?;
    info!("Attached {family} tc classifier to {attach_label} on {interface}");

    Ok(bpf)
}
