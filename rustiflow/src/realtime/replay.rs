//! Synthetic event replay through the realtime userspace pipeline.
//!
//! Events are generated in memory before timing starts, then drained through
//! the same batching, dispatch, shard and export stages as live capture. No
//! eBPF program is loaded, so the result is the userspace ceiling independent
//! of any traffic generator.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::error;
use tokio::task::{JoinHandle, JoinSet};

use super::{
    compute_realtime_offset_us, log_source_stats, queue_label, read_clock_us, spawn_shard_workers,
    FlowTableSettings, PipelineSettings, RealtimeSourceStats, SourceBatcher,
};
use crate::{
    args::{ExportConfig, ReplayBenchArgs},
    export_profile,
    flow_key::ShardSelector,
    flows::flow::Flow,
    output::FlowSink,
    packet_features::PacketFeatures,
    profiling::ProfilingSession,
};

const IPV4_HEADER_BYTES: u16 = 20;
const IPV6_HEADER_BYTES: u16 = 40;
const TCP_HEADER_BYTES: u8 = 20;
const UDP_HEADER_BYTES: u8 = 8;
const TCP_ACK_PSH: u8 = 0x18;
const TCP_WINDOW: u16 = 65_535;
const CLIENT_PORT: u16 = 40_000;
const TCP_SERVER_PORT: u16 = 443;
const UDP_SERVER_PORT: u16 = 4_433;
const REPLAY_SEED: u64 = 0x5eed_f10e;

/// Generates the events, replays them and prints throughput and CPU cost.
///
/// The measured interval runs from the first replayed event until the output
/// writer has closed, so it includes the final export of every open flow.
pub async fn replay_bench<T: Flow>(
    replay_args: &ReplayBenchArgs,
    config: &ExportConfig,
    num_threads: u8,
    exporter: impl FlowSink<T>,
    output_task: JoinHandle<()>,
) -> Result<(), anyhow::Error> {
    let shard_count =
        NonZeroUsize::new(usize::from(num_threads)).context("thread count must be at least 1")?;
    let realtime_offset_us = compute_realtime_offset_us()?;
    let generation_start = Instant::now();
    let events = ReplayEvents::generate(replay_args)?;
    eprintln!(
        "Generated {} {} events for {} flows over {} sources in {:.2} s",
        replay_args.packets,
        events.family_label(),
        replay_args.flows,
        replay_args.sources,
        generation_start.elapsed().as_secs_f64(),
    );

    let profiling_session = ProfilingSession::start_from_env("replay").unwrap_or_else(|err| {
        error!("Error starting profiler: {:?}", err);
        None
    });
    let cpu_start = process_cpu_time()?;
    let wall_start = Instant::now();

    let settings = PipelineSettings::from_env();
    let enable_source_stats = std::env::var_os("RUSTIFLOW_REALTIME_STATS").is_some();
    let shard_selector = ShardSelector::new(shard_count);
    let shard_senders = spawn_shard_workers(
        shard_count,
        settings.shard_queue_capacity,
        &FlowTableSettings {
            active_timeout: config.active_timeout,
            idle_timeout: config.idle_timeout,
            early_export: config.early_export,
            expiration_check_interval: config.expiration_check_interval,
        },
        &exporter,
    );
    // The shard encoders hold their own chunk senders; the writer closes once
    // they finish.
    drop(exporter);

    let mut handle_set = JoinSet::new();
    let mut source_stats = Vec::new();
    let mut new_batcher = |handle_set: &mut JoinSet<()>, label: String| {
        let stats = enable_source_stats.then(|| Arc::new(RealtimeSourceStats::default()));
        source_stats.push((label, stats.clone()));
        SourceBatcher::new(
            handle_set,
            &shard_senders,
            &shard_selector,
            &settings,
            stats,
        )
    };
    match events {
        ReplayEvents::Ipv4(sources) => {
            for (index, events) in sources.into_iter().enumerate() {
                let batcher = new_batcher(&mut handle_set, queue_label("replay-ipv4", index));
                handle_set.spawn(replay_source(
                    events,
                    batcher,
                    replay_args.drain_burst,
                    PacketFeatures::from_ebpf_event_ipv4,
                    realtime_offset_us,
                ));
            }
        }
        ReplayEvents::Ipv6(sources) => {
            for (index, events) in sources.into_iter().enumerate() {
                let batcher = new_batcher(&mut handle_set, queue_label("replay-ipv6", index));
                handle_set.spawn(replay_source(
                    events,
                    batcher,
                    replay_args.drain_burst,
                    PacketFeatures::from_ebpf_event_ipv6,
                    realtime_offset_us,
                ));
            }
        }
    }
    // Only the dispatchers keep the shards' senders, so the shards finish once
    // every source has drained.
    drop(shard_senders);

    while let Some(result) = handle_set.join_next().await {
        if let Err(err) = result {
            error!("Replay task failed: {:?}", err);
        }
    }
    output_task.await.context("output writer task failed")?;

    let wall = wall_start.elapsed();
    let cpu = process_cpu_time()?.saturating_sub(cpu_start);

    if let Some(profiling_session) = profiling_session {
        if let Err(err) = profiling_session.finish() {
            error!("Error finishing profiler: {:?}", err);
        }
    }
    export_profile::log_summary("replay");
    for (label, stats) in &source_stats {
        if let Some(stats) = stats {
            log_source_stats(label, stats);
        }
    }

    let packets = replay_args.packets.get() as f64;
    eprintln!(
        "Replay: packets={} threads={} wall_s={:.3} mpps={:.3} cpu_s={:.3} cpu_ns_per_packet={:.1} cpus_busy={:.2}",
        replay_args.packets,
        num_threads,
        wall.as_secs_f64(),
        packets / wall.as_secs_f64() / 1e6,
        cpu.as_secs_f64(),
        cpu.as_nanos() as f64 / packets,
        cpu.as_secs_f64() / wall.as_secs_f64(),
    );
    Ok(())
}

/// Drains one source's events in bursts, flushing partial batches after each
/// burst as a live source does when its ring runs empty.
async fn replay_source<E: Send + Sync + 'static>(
    events: Vec<E>,
    mut batcher: SourceBatcher,
    drain_burst: NonZeroUsize,
    decode: fn(&E, i64) -> PacketFeatures,
    realtime_offset_us: i64,
) {
    for burst in events.chunks(drain_burst.get()) {
        for event in burst {
            batcher
                .push_event(|| decode(event, realtime_offset_us))
                .await;
        }
        batcher.flush().await;
        // A live source waits for ring readiness between drains.
        tokio::task::yield_now().await;
    }
}

/// Pre-generated events, one list per source. All events of a flow go to the
/// same source, like the eBPF biflow queue selection, but sources are evenly
/// balanced, so queue skew is not modelled.
enum ReplayEvents {
    Ipv4(Vec<Vec<EbpfEventIpv4>>),
    Ipv6(Vec<Vec<EbpfEventIpv6>>),
}

/// One synthetic packet before it is encoded as an IPv4 or IPv6 event.
struct SyntheticPacket {
    timestamp_ns: u64,
    flow: u32,
    forward: bool,
    is_tcp: bool,
    sequence_number: u32,
    sequence_number_ack: u32,
}

impl ReplayEvents {
    /// Spreads packets uniformly at random over the flows. Even flows are TCP
    /// with in-order ACK|PSH data segments in both directions; odd flows are
    /// UDP. Flows never terminate, so they are exported at the end.
    fn generate(replay_args: &ReplayBenchArgs) -> Result<Self, anyhow::Error> {
        let source_count = replay_args.sources.get();
        let packets = replay_args.packets.get();
        let per_source = (packets as usize).div_ceil(source_count);
        let start_ns = read_clock_us(libc::CLOCK_MONOTONIC)? as u64 * 1_000;
        let virtual_pps = replay_args.virtual_pps.get();
        let payload_bytes = replay_args.payload_bytes;

        let mut rng = SplitMix64(REPLAY_SEED);
        // Next sequence number per flow and direction.
        let mut next_sequence: Vec<[u32; 2]> = (0..replay_args.flows)
            .map(|flow| [flow.wrapping_mul(7_919), flow.wrapping_mul(104_729)])
            .collect();
        let synthetic_packets = (0..packets).map(|index| {
            let flow = (rng.next() % u64::from(replay_args.flows)) as u32;
            let forward = rng.next() & 1 == 0;
            let is_tcp = flow.is_multiple_of(2);
            let (sequence_number, sequence_number_ack) = if is_tcp {
                let sequences = &mut next_sequence[flow as usize];
                let (sending, receiving) = if forward { (0, 1) } else { (1, 0) };
                let sequence_number = sequences[sending];
                sequences[sending] = sequence_number.wrapping_add(u32::from(payload_bytes));
                (sequence_number, sequences[receiving])
            } else {
                (0, 0)
            };
            SyntheticPacket {
                timestamp_ns: start_ns
                    + (u128::from(index) * 1_000_000_000 / u128::from(virtual_pps)) as u64,
                flow,
                forward,
                is_tcp,
                sequence_number,
                sequence_number_ack,
            }
        });

        if replay_args.ipv6 {
            let mut sources = vec![Vec::with_capacity(per_source); source_count];
            for packet in synthetic_packets {
                let (client, server) = ipv6_endpoints(packet.flow);
                sources[packet.flow as usize % source_count].push(encode_ipv6(
                    &packet,
                    client,
                    server,
                    payload_bytes,
                ));
            }
            Ok(Self::Ipv6(sources))
        } else {
            let mut sources = vec![Vec::with_capacity(per_source); source_count];
            for packet in synthetic_packets {
                let (client, server) = ipv4_endpoints(packet.flow);
                sources[packet.flow as usize % source_count].push(encode_ipv4(
                    &packet,
                    client,
                    server,
                    payload_bytes,
                ));
            }
            Ok(Self::Ipv4(sources))
        }
    }

    fn family_label(&self) -> &'static str {
        match self {
            Self::Ipv4(_) => "IPv4",
            Self::Ipv6(_) => "IPv6",
        }
    }
}

fn ipv4_endpoints(flow: u32) -> (Ipv4Addr, Ipv4Addr) {
    (
        Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 0, 0, 0)) | flow),
        Ipv4Addr::new(192, 168, 0, 1),
    )
}

fn ipv6_endpoints(flow: u32) -> (Ipv6Addr, Ipv6Addr) {
    (
        Ipv6Addr::from(u128::from(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)) | u128::from(flow)),
        Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 1),
    )
}

/// Transport fields shared by both address families.
struct TransportFields {
    source_port: u16,
    destination_port: u16,
    header_bytes: u8,
    flags: u8,
    window_size: u16,
    protocol: u8,
}

fn transport_fields(packet: &SyntheticPacket) -> TransportFields {
    let (header_bytes, flags, window_size, protocol, server_port) = if packet.is_tcp {
        (
            TCP_HEADER_BYTES,
            TCP_ACK_PSH,
            TCP_WINDOW,
            6,
            TCP_SERVER_PORT,
        )
    } else {
        (UDP_HEADER_BYTES, 0, 0, 17, UDP_SERVER_PORT)
    };
    let (source_port, destination_port) = if packet.forward {
        (CLIENT_PORT, server_port)
    } else {
        (server_port, CLIENT_PORT)
    };
    TransportFields {
        source_port,
        destination_port,
        header_bytes,
        flags,
        window_size,
        protocol,
    }
}

/// Encodes like the eBPF programs: addresses in network order, `length` as the
/// IP total length, `header_length` as the transport header length.
fn encode_ipv4(
    packet: &SyntheticPacket,
    client: Ipv4Addr,
    server: Ipv4Addr,
    payload_bytes: u16,
) -> EbpfEventIpv4 {
    let transport = transport_fields(packet);
    let (source, destination) = if packet.forward {
        (client, server)
    } else {
        (server, client)
    };
    EbpfEventIpv4::new(
        packet.timestamp_ns,
        u32::from(destination).to_be(),
        u32::from(source).to_be(),
        transport.destination_port,
        transport.source_port,
        payload_bytes,
        IPV4_HEADER_BYTES + u16::from(transport.header_bytes) + payload_bytes,
        transport.window_size,
        transport.flags,
        transport.protocol,
        transport.header_bytes,
        packet.sequence_number,
        packet.sequence_number_ack,
        0,
        0,
    )
}

fn encode_ipv6(
    packet: &SyntheticPacket,
    client: Ipv6Addr,
    server: Ipv6Addr,
    payload_bytes: u16,
) -> EbpfEventIpv6 {
    let transport = transport_fields(packet);
    let (source, destination) = if packet.forward {
        (client, server)
    } else {
        (server, client)
    };
    EbpfEventIpv6::new(
        packet.timestamp_ns,
        u128::from(destination).to_be(),
        u128::from(source).to_be(),
        transport.destination_port,
        transport.source_port,
        payload_bytes,
        IPV6_HEADER_BYTES + u16::from(transport.header_bytes) + payload_bytes,
        transport.window_size,
        transport.flags,
        transport.protocol,
        transport.header_bytes,
        packet.sequence_number,
        packet.sequence_number_ack,
        0,
        0,
    )
}

/// Deterministic generator so runs replay identical traffic.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// User plus system CPU time of the whole process.
fn process_cpu_time() -> Result<Duration, anyhow::Error> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: getrusage succeeded and filled the struct.
    let usage = unsafe { usage.assume_init() };
    let timeval = |tv: libc::timeval| {
        Duration::from_secs(tv.tv_sec as u64) + Duration::from_micros(tv.tv_usec as u64)
    };
    Ok(timeval(usage.ru_utime) + timeval(usage.ru_stime))
}
