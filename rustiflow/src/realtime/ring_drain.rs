use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use aya::maps::{MapData, RingBuf};
use log::info;
use tokio::{io::unix::AsyncFd, task::yield_now};

use super::{
    read_clock_us,
    source_reactors::{Shutdown, SourceControl},
    DecodeEvent, PacketGraphState, SourceBatcher, PACKET_GRAPH_RECORD_BATCH,
};
use anyhow::Context;

const RECORD_BUDGET: u64 = 256;
const CLOCK_CHECK_RECORDS: u64 = 32;
const TIME_BUDGET: Duration = Duration::from_micros(250);

#[derive(Clone, Copy)]
pub(super) enum DrainPolicy {
    UntilEmpty,
    Budgeted,
}

impl DrainPolicy {
    pub(super) fn from_env() -> Self {
        match std::env::var("RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET").as_deref() {
            Ok("1") => Self::Budgeted,
            _ => Self::UntilEmpty,
        }
    }

    pub(super) async fn run(
        self,
        ring: AsyncFd<RingBuf<MapData>>,
        batcher: SourceBatcher,
        graph: Option<PacketGraphState>,
        decode: DecodeEvent,
        realtime_offset_us: i64,
        control: SourceControl,
    ) -> anyhow::Result<()> {
        match self {
            Self::UntilEmpty => {
                drain::<false>(ring, batcher, graph, decode, realtime_offset_us, control).await
            }
            Self::Budgeted => {
                drain::<true>(ring, batcher, graph, decode, realtime_offset_us, control).await
            }
        }
    }
}

#[derive(Clone, Copy)]
enum DrainEnd {
    Empty,
    RecordBudget,
    TimeBudget,
}

async fn drain<const BUDGETED: bool>(
    mut ring: AsyncFd<RingBuf<MapData>>,
    batcher: SourceBatcher,
    graph: Option<PacketGraphState>,
    decode: DecodeEvent,
    realtime_offset_us: i64,
    mut control: SourceControl,
) -> anyhow::Result<()> {
    let mut drain = RingDrain {
        batcher,
        graph,
        decode,
        realtime_offset_us,
        warned_invalid_size: false,
        decoded_packets: 0,
    };
    loop {
        tokio::select! {
            biased;
            _ = control.stop.changed() => break,
            result = ring.readable_mut() => {
                let mut guard = result.context("waiting for event ring")?;
                if let Some(stats) = drain.batcher.stats.as_ref().and_then(|stats| stats.ring.as_ref()) {
                    stats.ready.fetch_add(1, Relaxed);
                }
                drain.until_empty::<BUDGETED>(guard.get_inner_mut()).await;
                guard.clear_ready();
            }
        }
    }
    if *control.stop.borrow() == Shutdown::Drain {
        // The producer has been detached. Check the ring directly even
        // if its final records did not trigger another readiness event.
        drain.until_empty::<BUDGETED>(ring.get_mut()).await;
        control
            .decoded_packets
            .fetch_add(drain.decoded_packets, Relaxed);
    }
    Ok(())
}

struct RingDrain {
    batcher: SourceBatcher,
    graph: Option<PacketGraphState>,
    decode: DecodeEvent,
    realtime_offset_us: i64,
    warned_invalid_size: bool,
    decoded_packets: u64,
}

impl RingDrain {
    async fn until_empty<const BUDGETED: bool>(&mut self, ring: &mut RingBuf<MapData>) {
        loop {
            let deadline = BUDGETED.then(|| Instant::now() + TIME_BUDGET);
            let mut records = 0;
            let mut packets = 0;
            let end = loop {
                let Some(event) = ring.next() else {
                    break DrainEnd::Empty;
                };
                if let Some(stats) = &self.batcher.stats {
                    stats.sample_ring_age(&event);
                }
                let size = event.len();
                if self
                    .batcher
                    .push_event(|| {
                        let packet = (self.decode)(&event, self.realtime_offset_us);
                        // Release the slot before an enqueue can block.
                        drop(event);
                        packet
                    })
                    .await
                {
                    packets += 1;
                    if packets % PACKET_GRAPH_RECORD_BATCH == 0 {
                        if let Some(graph) = &self.graph {
                            graph.record_packets(PACKET_GRAPH_RECORD_BATCH);
                        }
                    }
                } else if !self.warned_invalid_size {
                    log::warn!(
                        "Skipping incorrectly sized realtime ring records (first size: {size} bytes)"
                    );
                    self.warned_invalid_size = true;
                }
                records += 1;
                if BUDGETED {
                    if records == RECORD_BUDGET {
                        break DrainEnd::RecordBudget;
                    }
                    if records % CLOCK_CHECK_RECORDS == 0
                        && deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        break DrainEnd::TimeBudget;
                    }
                }
            };

            if let Some(graph) = &self.graph {
                graph.record_packets(packets % PACKET_GRAPH_RECORD_BATCH);
            }
            self.decoded_packets += packets;
            self.batcher.flush().await;
            if let Some(stats) = self
                .batcher
                .stats
                .as_ref()
                .and_then(|stats| stats.ring.as_ref())
            {
                stats.record_drain(end, records);
            }

            if let DrainEnd::Empty = end {
                return;
            }

            // Budget exhaustion says nothing about the ring's readiness.
            // Keep the guard across the yield so unread records can progress
            // even if the producer has stopped notifying.
            yield_now().await;
        }
    }
}

const LATENCY_BUCKETS: usize = 24;

/// Optional live-only counters sampled at the drain and shard handoff boundaries.
#[derive(Default)]
pub(super) struct RingStats {
    realtime_offset_us: i64,
    ready: AtomicU64,
    drains: AtomicU64,
    empty_drains: AtomicU64,
    max_drain: AtomicU64,
    record_limits: AtomicU64,
    time_limits: AtomicU64,
    dispatch_batches: AtomicU64,
    dispatch_events: AtomicU64,
    last_age_us: AtomicU64,
    max_age_us: AtomicU64,
    age_us: [AtomicU64; LATENCY_BUCKETS],
}

impl RingStats {
    pub(super) fn new(realtime_offset_us: i64) -> Self {
        Self {
            realtime_offset_us,
            ..Self::default()
        }
    }

    fn record_drain(&self, end: DrainEnd, records: u64) {
        self.drains.fetch_add(1, Relaxed);
        self.max_drain.fetch_max(records, Relaxed);
        if records == 0 {
            self.empty_drains.fetch_add(1, Relaxed);
        }
        match end {
            DrainEnd::Empty => {}
            DrainEnd::RecordBudget => {
                self.record_limits.fetch_add(1, Relaxed);
            }
            DrainEnd::TimeBudget => {
                self.time_limits.fetch_add(1, Relaxed);
            }
        }
    }

    pub(super) fn record_handoff(&self, records: usize, first_timestamp_us: i64) {
        self.dispatch_batches.fetch_add(1, Relaxed);
        self.dispatch_events.fetch_add(records as u64, Relaxed);

        // Convert the first packet's exported epoch timestamp back to the
        // monotonic clock used by eBPF. Timestamp truncation is at most 1 us.
        if let Ok(now) = read_clock_us(libc::CLOCK_MONOTONIC) {
            let age = (now + self.realtime_offset_us - first_timestamp_us).max(0) as u64;
            let bucket = (age.max(1).ilog2() as usize).min(LATENCY_BUCKETS - 1);
            self.age_us[bucket].fetch_add(1, Relaxed);
            self.last_age_us.store(age, Relaxed);
            self.max_age_us.fetch_max(age, Relaxed);
        }
    }

    pub(super) fn log(&self, label: &str) {
        let ages = self.age_us.each_ref().map(|bucket| bucket.load(Relaxed));
        info!(
            "Ring source {label}: ready={} drains={} empty_drains={} max_drain={} record_limits={} time_limits={} dispatch_batches={} dispatch_events={} last_age_us={} max_age_us={} handoff_hist_us={ages:?}",
            self.ready.load(Relaxed),
            self.drains.load(Relaxed),
            self.empty_drains.load(Relaxed),
            self.max_drain.load(Relaxed),
            self.record_limits.load(Relaxed),
            self.time_limits.load(Relaxed),
            self.dispatch_batches.load(Relaxed),
            self.dispatch_events.load(Relaxed),
            self.last_age_us.load(Relaxed),
            self.max_age_us.load(Relaxed),
        );
    }
}
