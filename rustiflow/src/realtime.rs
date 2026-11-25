mod attachments;
mod batch_pool;
mod ebpf_objects;
mod promiscuous;
mod replay;
mod ring_drain;
mod source_reactors;

pub use replay::replay_bench;

use std::collections::VecDeque;
use std::io;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::args::FlowType;
use crate::debug;
use crate::flow_tui::launch_packet_tui;
use crate::output::FlowSink;
use crate::realtime_mode::{PacketGraphMode, PromiscuousMode};
use crate::{
    flow_key::ShardSelector,
    flow_table::{BatchCanonicalizer, FlowTable},
    flows::flow::Flow,
    packet_features::PacketFeatures,
};
use anyhow::Context;
use attachments::Capture;
use batch_pool::BatchPool;
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::{error, info};
use promiscuous::PromiscuousMembership;
use ring_drain::{DrainPolicy, RingStats};
use source_reactors::{
    unexpected_source_exit, ReactorCount, RingSource, RingSourcePipeline, Shutdown,
};
use tokio::sync::watch;
use tokio::{
    signal,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinSet,
    time::MissedTickBehavior,
};

use zerocopy::FromBytes;

#[derive(Default)]
struct RealtimeSourceStats {
    ring: Option<RingStats>,
    events: AtomicU64,
    ring_age_us_log2: [AtomicU64; 32],
    decode_and_shard_ns: AtomicU64,
    dispatch_enqueue_ns: AtomicU64,
    shard_send_wait_ns: AtomicU64,
    total_event_ns: AtomicU64,
    send_errors: AtomicU64,
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

    fn sample_ring_age(&self, event: &[u8]) {
        if !self.events.load(Ordering::Relaxed).is_multiple_of(64) {
            return;
        }
        // Both event ABIs start with a native-endian CLOCK_MONOTONIC timestamp.
        let Some(timestamp) = event.first_chunk::<8>() else {
            return;
        };
        if let Ok(now_us) = read_clock_us(libc::CLOCK_MONOTONIC) {
            let age_us = (now_us as u64).saturating_sub(u64::from_ne_bytes(*timestamp) / 1_000);
            let bucket = age_us.max(1).ilog2().min(31) as usize;
            self.ring_age_us_log2[bucket].fetch_add(1, Ordering::Relaxed);
        }
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
    let ring_age = stats
        .ring_age_us_log2
        .each_ref()
        .map(|bucket| bucket.load(Ordering::Relaxed));
    if ring_age.iter().any(|&count| count != 0) {
        info!("Realtime source {label}: ring_age_us_log2={ring_age:?}");
    }
}

const DEFAULT_SHARD_BATCH_SIZE: usize = 512;
const DEFAULT_SHARD_QUEUE_CAPACITY: usize = 512;
const DEFAULT_SOURCE_DISPATCH_QUEUE_CAPACITY: usize = 1024;

enum PipelineMode {
    Capture,
    Replay(FlowType),
}

/// Queue and batch sizes of the userspace stages behind the event rings.
struct PipelineSettings {
    shard_batch_size: usize,
    shard_queue_capacity: usize,
    source_dispatch_queue_capacity: usize,
    recycle_shard_batches: bool,
    simd_keys: bool,
}

impl PipelineSettings {
    fn from_env(mode: PipelineMode) -> Self {
        let basic_replay = matches!(mode, PipelineMode::Replay(FlowType::Basic));
        let recycle = basic_replay || matches!(mode, PipelineMode::Capture);
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
                .map_or(recycle, |value| value == "1"),
            simd_keys: std::env::var_os("RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS")
                .map_or(basic_replay, |value| value != "0"),
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
            let mut canonicalizer = BatchCanonicalizer::new(settings.simd_keys);
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
                    flow_table
                        .process_batch(&packet_batch, &mut canonicalizer)
                        .await;
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
type DecodeEvent = fn(&[u8], i64) -> Option<PacketFeatures>;

fn decode_ipv4_event(bytes: &[u8], realtime_offset_us: i64) -> Option<PacketFeatures> {
    let event = EbpfEventIpv4::ref_from_bytes(bytes).ok()?;
    Some(PacketFeatures::from_ebpf_event_ipv4(
        event,
        realtime_offset_us,
    ))
}

fn decode_ipv6_event(bytes: &[u8], realtime_offset_us: i64) -> Option<PacketFeatures> {
    let event = EbpfEventIpv6::ref_from_bytes(bytes).ok()?;
    Some(PacketFeatures::from_ebpf_event_ipv6(
        event,
        realtime_offset_us,
    ))
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
        handle_set: &mut JoinSet<anyhow::Result<()>>,
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
    async fn push_event(&mut self, decode: impl FnOnce() -> Option<PacketFeatures>) -> bool {
        let event_start = self.stats.is_some().then(Instant::now);
        let Some(packet_features) = decode() else {
            return false;
        };
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
        true
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
    let settings = PipelineSettings::from_env(PipelineMode::Capture);
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

    let mut capture = Capture::attach(interface, ingress_only)?;
    let (event_sources_v4, event_sources_v6) = capture.take_sources();

    let enable_source_stats = std::env::var_os("RUSTIFLOW_REALTIME_STATS").is_some();
    let mut handle_set = JoinSet::new();
    let mut graph_tasks = JoinSet::new();
    let (packet_graph, packet_rx) = match packet_graph_mode {
        PacketGraphMode::Enabled => {
            let (packet_tx, packet_rx) = watch::channel(Vec::new());
            let packet_graph = PacketGraphState {
                packets_since_tick: Arc::new(AtomicU64::new(0)),
            };
            graph_tasks.spawn(packet_graph.clone().publish_intervals(packet_tx));
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
        result = handle_set.join_next(), if !handle_set.is_empty() => {
            Err(unexpected_source_exit(result))
        }
    };
    graph_tasks.shutdown().await;

    // Detach first so the source tasks can finish draining finite rings.
    let detach_result = capture.detach();
    let shutdown = if detach_result.is_ok() {
        Shutdown::Drain
    } else {
        Shutdown::Abort
    };
    let drain_result = reactors.shutdown(shutdown, &mut handle_set).await;
    for (label, stats) in &source_stats {
        if let Some(stats) = stats.as_ref() {
            log_source_stats(label, stats);
        }
    }

    capture_result?;
    detach_result?;
    let decoded = drain_result?;
    let totals = capture.log_totals()?;
    info!("Total dropped packets before exit: {}", totals.dropped);
    anyhow::ensure!(
        decoded == totals.submitted,
        "realtime capture submitted {} events but decoded {decoded}",
        totals.submitted,
    );
    Ok(totals.dropped)
}

struct ShardDispatchBatch {
    shard_index: usize,
    batch: Vec<PacketFeatures>,
}

fn spawn_source_dispatcher(
    handle_set: &mut JoinSet<anyhow::Result<()>>,
    shard_senders: Vec<Sender<Vec<PacketFeatures>>>,
    source_dispatch_queue_capacity: usize,
    stats: Option<Arc<RealtimeSourceStats>>,
) -> Sender<ShardDispatchBatch> {
    let (dispatch_sender, mut dispatch_receiver) =
        mpsc::channel::<ShardDispatchBatch>(source_dispatch_queue_capacity);

    handle_set.spawn(async move {
        run_source_dispatcher(&shard_senders, &mut dispatch_receiver, stats.as_ref()).await
    });

    dispatch_sender
}

async fn run_source_dispatcher(
    shard_senders: &[Sender<Vec<PacketFeatures>>],
    dispatch_receiver: &mut Receiver<ShardDispatchBatch>,
    stats: Option<&Arc<RealtimeSourceStats>>,
) -> anyhow::Result<()> {
    while let Some(ShardDispatchBatch { shard_index, batch }) = dispatch_receiver.recv().await {
        let handoff = stats
            .and_then(|stats| stats.ring.as_ref())
            .zip(batch.first())
            .map(|(ring, first)| (ring, batch.len(), first.timestamp_us));
        let send_start = stats.as_ref().map(|_| Instant::now());
        if shard_senders[shard_index].send(batch).await.is_err() {
            if let Some(stats) = stats {
                stats.increment_send_errors();
            }
            anyhow::bail!("packet queue for shard {shard_index} closed during dispatch");
        } else if let Some((ring, records, first_timestamp_us)) = handoff {
            ring.record_handoff(records, first_timestamp_us);
        }
        if let (Some(stats), Some(send_start)) = (stats, send_start) {
            stats.add_shard_send_wait_ns(elapsed_ns(send_start));
        }
    }
    Ok(())
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

fn queue_label(label_prefix: &str, index: usize) -> String {
    format!("{label_prefix}-q{index}")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_decoders_require_exactly_one_packed_record() {
        // The producer's IPv4 and IPv6 ABIs use 40 and 72 bytes respectively.
        for (decode, size) in [
            (decode_ipv4_event as DecodeEvent, 40),
            (decode_ipv6_event as DecodeEvent, 72),
        ] {
            let mut storage = [0u8; 74];
            let bytes = &mut storage[1..];
            bytes[..8].copy_from_slice(&12_345_u64.to_ne_bytes());
            assert_eq!(decode(&bytes[..size], 100).unwrap().timestamp_us, 112);
            assert!(decode(&[], 100).is_none());
            assert!(decode(&bytes[..size - 1], 100).is_none());
            assert!(decode(&bytes[..size + 1], 100).is_none());
        }
    }
}
