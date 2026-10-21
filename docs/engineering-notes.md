# Engineering Notes

This file keeps short-lived design choices and execution notes that would make
`AGENTS.md` too long. Newest entries come first. Older entries are condensed to
the decisions and results that still describe the current code.

## 2026-10-22: adversarial flow and parser fixes

Resolved the eight synthetic-event findings documented in
[the adversarial findings record](handoff-realtime-adversarial.md). TCP sequence
arithmetic wraps explicitly, expiration rejects negative elapsed time, and
handshake/close observations survive cross-direction reordering. A first SYN-ACK
identifies the forward endpoint as its destination. Normal three-segment closes
now use `four_way_fin`; genuine simultaneous FIN exchanges remain distinct.

The user selected these policies:

- Preserve late post-close packets in a separate flow.
- Keep bounded streaming timing, with timestamp bounds for duration and zero IAT
  samples for late packets against a nondecreasing reference.
- Bound retransmission history, accepting missed retransmissions into evicted
  ranges. The implementation retains 1,024 merged ranges per direction in an
  ordered map and handles sequence rollover.

The tests that encoded suppression or incorrect close classification were
corrected. The machine-dependent performance assertion was replaced with
bounded-history and overlap tests. All adversarial cases are active.

Also aligned eBPF fragment handling and IPv6 AH/ESP parsing with offline capture.
IPv6 extension interpretation is shared through `common`. Workspace tests,
all-feature Clippy, and both eBPF builds pass. Live veth validation is still
outstanding: this session had no `rustiflow-t0` and no passwordless sudo.

## 2026-10-20: aya 0.14 and network-types 0.2; realtime byte order

Moved to aya 0.14, aya-log 0.3, aya-ebpf 0.2, aya-log-ebpf 0.2 and
network-types 0.2, with bpf-linker 0.12.0 in CI and the images. `common` now
takes aya from crates.io instead of unpinned git, so one aya version is locked.
aya 0.14 also fixes ring buffer consumer ordering in userspace.

network-types 0.2 stores multi-byte header fields as wire-order byte arrays,
which exposed a realtime bug present since `c645b70` (2024-03): the eBPF
programs passed TCP/UDP ports, TCP window and sequence/ack numbers to userspace
in network byte order, and the userspace decoder used them as host order, so
realtime ports read byte-swapped on little-endian hosts. IPv6 addresses were
also reversed (`from_be_bytes` in eBPF, then `to_be` again in userspace). The
offline/realtime parity tests and the replay build events in userspace with the
intended convention, so they did not cover the eBPF side. `EbpfEventIpv4/6`
now document the contract: addresses in wire order in memory, everything else
host order. `common` tests decode wire bytes through the same `NetworkHeader`
accessors the eBPF programs use.

Other changes that came with the bump:

- `Ipv4Hdr::ihl()` now returns bytes, not 32-bit words.
- Protocol, EtherType and IPv6 extension `next_hdr` are read as integers and
  converted with checked accessors instead of loading enums from packet bytes.
- aya-log 0.3 no longer spawns a reader; `spawn_ebpf_logger` drives it.

Realtime ports, window, sequence numbers and IPv6 addresses in datasets
exported before this change are not trustworthy. Not yet validated with a live
realtime run on the veth harness.

## 2026-10-20: realtime userspace replay benchmark

`rustiflow ... replay-bench` (README, "Replay benchmark") generates synthetic
eBPF events in memory and drains them through the realtime userspace pipeline:
per-source batching, dispatcher, shard flow tables, per-shard encoders and the
writer. To keep it on the same code as live capture, `realtime.rs` now shares
`PipelineSettings`, `spawn_shard_workers` and `SourceBatcher` between the ring
drain tasks and the replay; the IPv4 and IPv6 drain loops became one
`drain_ring_source`. The subcommand sits in a CLI-only `CliCommand` wrapper, so
the TUI and config files keep the capture-only `Commands`.

What it does not model: ring-buffer reads and wakeups, the eBPF programs and
the kernel receive path; uneven queue fanout (sources are evenly balanced);
handshakes, teardown and flow churn (flows never terminate). The final export
of all open flows is inside the measured interval.

First observations, Ryzen 9 5950X, no CPU pinning, 30M IPv4 events over 100k
flows, 1400-byte payloads, 8 sources, CSV to `/dev/null`. Run-to-run variation
was about +-3% on repeated 10M-event runs.

| `--threads` | `basic` Mpps | `basic` CPU ns/pkt | `rustiflow` Mpps | `rustiflow` CPU ns/pkt |
| --- | --- | --- | --- | --- |
| 1 | 8.8 | 208 | 2.9 | 440 |
| 2 | 17.4 | 181 | 5.3 | 450 |
| 4 | 35.9 | 172 | 8.4 | 538 |
| 8 | 69.6 | 195 | 12.3 | 712 |
| 12 | 62.3 | 227 | 15.7 | 853 |
| 16 | 61.8 | 228 | 17.2 | 1031 |

- `basic` scales almost linearly to 8 shards and then flattens. With 8
  sources, the source and dispatcher stages are a candidate limit; not yet
  verified.
- `rustiflow` scales sublinearly and its CPU per packet more than doubles from 1
  to 16 shards. With 100k flows of about 1.6 KB each, flow state alone is about
  160 MB, so cache and memory contention are candidates, as are SMT sharing
  (16 shards plus source, dispatcher and encoder tasks on 16 physical cores)
  and the two CCDs. Pinning and `perf` sampling should come before conclusions.
- CPU ns/packet is whole-process CPU, including tokio scheduling and idle
  spinning, so it is an upper bound on the pipeline's own work.

## 2026-10-20: early export on a fixed per-flow schedule

Branch `perf/hot-path-40g`, commits `f426f95` and `8a556aa`.

Previous behavior: on every packet, the flow table compared the flow age,
truncated to whole seconds, with `> N` and exported a clone when it passed.
Nothing recorded earlier exports, so once a flow passed the threshold every
packet produced another row. `N=2` first fired at 3 s, and `0` exported on
every packet after the first second. One UDP flow of 1,000 packets, 10 ms
apart, gave 1 row without early export, 701 rows with `--early-export 2` and 901
with `--early-export 0`. Snapshots were raw clones, so open bulks, the current
active period and the TCP close style were not finalized.

Current behavior:

- Each `FlowEntry` stores its next boundary, first packet + k * N, compared in
  microseconds. The first packet at or after a boundary exports one snapshot.
  Boundaries that pass without packets are skipped.
- Only packets trigger snapshots. Expiration sweeps never do, so a quiet flow
  gets no snapshots until it expires.
- A snapshot is a clone closed with `close_flow(packet timestamp, None)`. Bulks,
  the active period and the close style are complete, and the live flow is
  unaffected. Snapshots keep cause `None`; final rows always carry a real cause.
- The interval is a `NonZeroU64`, so CLI and config-file input reject `0`. In
  the TUI, `0` still means disabled. Startup rejects `N >= active_timeout`.
- The same flow now gives 5 rows with `--early-export 2`: snapshots at 2, 4, 6
  and 8 s, then the final row.
- Offline and realtime share `FlowTable`. A parity test checks that equivalent
  packet sequences produce identical snapshot rows.

Consequences:

- Datasets produced with early export before this change contain repeated
  cumulative rows, roughly one per packet once a flow passed the threshold.
- All March export measurements with `--early-export 5` were dominated by those
  repeats: 0.5-3M rows per 10 s for about 10 long flows. Their per-row costs
  remain useful; their row volumes do not describe the current code. Expect
  about flows * duration / N snapshot rows now.

Not done: per-interval (delta) rows in the NetFlow/IPFIX style. They would need
a per-family statistics reset that keeps TCP and lifecycle state, so they belong
in a separate, explicit mode. No realtime harness run was made for this change.

Validation: `cargo test -p rustiflow` (74 tests) and
`cargo clippy -p rustiflow --all-targets`, plus the 1,000-packet pcap above
through the CLI.

## 2026-10-20: userspace hot-path pass toward 40G

Branch `perf/hot-path-40g`. Userspace only: no eBPF change, and no live
realtime run (no root on the development host). Realtime still needs
validation on the `rustiflow-t0` harness with the 2026-10-18 measurement plan.

Harnesses, all on a Ryzen 9 5950X with outputs compared as sorted row sets:

- Offline: a deterministic synthetic pcap with 2.97M packets and 150k TCP/UDP
  biflows (handshake, data, FIN or RST teardown), run with `perf stat -r 5`.
  This path is bounded by the pcap reader, so it hides shard-side gains.
- In-memory FlowTable replay: 4M packets over 200k concurrent flows, one shard,
  no reader and no channels. This gives ns/packet for the flow-table path.
- Row encoding: one RustiFlow flow encoded 200k times.

| Change | Measurement | Before | After |
| --- | --- | --- | --- |
| Integral `f64` CSV fields use the integer formatter | rustiflow dump time | 1204 ms | 1077 ms |
| `append_to_csv` required for every `FlowFeature` | rustiflow dump time | 1077 ms | 883 ms |
| One canonical-key lookup per packet; no clone on termination | replay, basic | 184 ns/pkt | 175 ns/pkt |
| Seeded foldhash for the flow map and `ShardSelector` | replay, basic / rustiflow | 175 / ~404 ns/pkt | 142 / 357 ns/pkt |
| Sort shutdown exports by `(timestamp, key)` | shutdown with 200k flows, rustiflow | 595 ms | ~124 ms |
| Per-shard CSV encoder tasks feed the writer | offline wall, rustiflow | 1.13 s | 0.74 s |
| Offline packets batched per shard (128 per send) | offline CPU, basic / rustiflow | 2.32 / 3.72 s | 1.13 / 2.54 s |
| Direct digit writer for integral fields | encode one RustiFlow row | 4.57 us | 2.98 us |

The packet-graph change removes a per-event tokio Mutex, sort and watch send.
It is opt-in and was not measured.

Notes:

- Basic shutdown export went from 42 ms to 55 ms with the key sort, since
  120-byte flows were cheap to sort directly. This was accepted.
- The writer is no longer the export ceiling. Rows from one shard keep their
  order; rows from different shards interleave, as before.
- Zero `--threads` is rejected at startup. It used to assert on the first packet.
- The foldhash seeds are random per process and per instance. A remote sender
  cannot precompute collisions, and the shard choice does not correlate with
  bucket choice inside each shard's map.

Measured and rejected:

- Making the FlowTable core synchronous to shrink the per-packet future from
  9.9 KB to 368 B: no cycle or instruction change.
- `lto = "fat"` with `codegen-units = 1`: instructions changed by 1-3% and wall
  time stayed within noise. Not worth about 40 s of extra build time.

Open candidates, with the evidence for each:

- Fractional floats are about 44% of row encoding. A faster shortest-digit
  algorithm would also need Display-identical output.
- The expiration scan iterates every flow each interval. A timer wheel or an
  incremental scan would bound the per-shard stall when tables are large.
- The eBPF programs bump `MATCHED_PACKETS` on every packet, but it always equals
  submitted plus dropped, so it could be derived in userspace. Verify the saving
  with `bpf_stats_enabled`.
- A RustiFlow flow is 1,576 bytes, so with large tables the remaining per-packet
  cost is mostly cache misses on flow state.

## 2026-10-18: proposed packet-rate and CPU-cost measurement plan

Status: planned, not executed. Use the trusted `rustiflow-t0` / `rustiflow-peer`
veth setup to measure software cost and scaling. Physical 40G wire throughput
remains unvalidated. Keep the April results as historical observations; their
headroom loss does not by itself locate the bottleneck in eBPF.

Report sustained clean Mpps, CPU allocation, and component ns/packet. Distinguish
CPU time per packet from reciprocal throughput, which is elapsed time per packet
across all concurrent workers. Derive any equivalent bitrate from an explicit
packet-size distribution and framing convention.

For illustration, with Ethernet frame sizes including FCS, add 20 bytes per
frame for preamble/SFD and inter-frame gap. Required Mpps is
`line_Gbit_s * 1000 / (8 * (mean_frame_bytes + 20))`.

| Line-rate target | 1400-byte frames | 400-byte mean frames | 64-byte frames |
| --- | --- | --- | --- |
| 25 Gbit/s | 2.20 Mpps | 7.44 Mpps | 37.20 Mpps |
| 40 Gbit/s | 3.52 Mpps | 11.90 Mpps | 59.52 Mpps |
| 100 Gbit/s | 8.80 Mpps | 29.76 Mpps | 148.81 Mpps |

The 400-byte mean is illustrative, not a defined IMIX distribution. Generator
payload lengths in B1/B4 are not automatically Ethernet frame lengths. At
4 Mpps, 40 Gbit/s corresponds to 1250 wire bytes per packet under this convention,
or a 1230-byte mean frame. This is a capacity equivalence, not a wire-rate result.

### 1. Establish packetization and CPU placement

- Save the current host and peer RPS/XPS masks, queue counts, offload settings,
  MTU, CPU topology, affinity, and kernel/build versions before changing setup.
- Use bounded `perf` sampling across the existing CPU groups to locate tc/BPF
  and receive processing under B1 and B4 load. Treat RPS placement as a hypothesis
  until samples confirm the executing CPUs. Linux documents RPS as steering
  receive processing through CPU backlog queues in its
  [network scaling guide](https://www.kernel.org/doc/html/latest/networking/scaling.html).
- Restrict host RX RPS to dedicated receive-processing CPUs. Keep generator,
  receive processing, RustiFlow userspace, and control/receiver budgets explicit.
  Inspect peer steering and both traffic directions too. Verify placement again
  after changing masks; process affinity alone does not establish BPF placement.
- Record physical cores and SMT siblings. Avoid accidental sharing between roles.
  Restore settings after experiments. Update the maintained matrix only after
  validating the replacement CPU partition.
- Disable aggregation/segmentation offloads for the packet-rate baseline where
  supported, and verify actual observed packet sizes and counts. The April jumbo
  MTU and enlarged GSO/GRO limits make application bitrate an unreliable proxy
  for classifier invocations. Keep bulk-offload runs as a separate scenario.

### 2. Measure classifier cost

- Start with B1 and B4, for both `basic` and `rustiflow`. Temporarily enable
  `kernel.bpf_stats_enabled=1`, record program IDs and attachment order, and take
  before/after `bpftool prog show` snapshots over the same steady-state interval.
  Restore the previous sysctl value afterward.
- Compute `delta(run_time_ns) / delta(run_cnt)` for each program. Label this
  ns/invocation. Reconcile invocation counts with capture-side packets, including
  packets that visit both IPv4 and IPv6 classifiers. Sum relevant runtime deltas
  and divide by observed packets to obtain combined BPF ns/packet.
- Record instrumentation state and repeat throughput measurements with runtime
  statistics disabled. Runtime accounting is an instrumented average, not an
  exact measurement of the entire datapath cost.
- Independently use `bpftool prog run ... data_in ... repeat N` for crafted TCP
  and UDP packets over IPv4 and IPv6, including IPv6 extension-header cases.
  Provide valid classifier context and maps, verify expected emitted events,
  and keep a consumer draining all relevant rings. Check reservation failures;
  a running consumer alone does not prove the successful-submit path dominated.
  Separate full-ring results from successful-event results. Test-run timing is
  a microbenchmark with cache and scheduling effects, not an ingress ceiling.
  See the kernel's [BPF program execution documentation](https://kernel.org/doc/html/next/bpf/bpf_prog_run.html)
  and [bpftool command reference](https://github.com/torvalds/linux/blob/master/tools/bpf/bpftool/Documentation/bpftool-prog.rst).
- At a fixed achieved packet rate below saturation, compare CPU cycles with and
  without attachment using `perf stat -e cycles -C <receive CPUs>`. Normalize the
  cycle difference by observed packets over matched intervals. Include any other
  CPUs where profiling finds added datapath work, and report run-to-run variation.

### 3. Measure userspace separately

- Process a large, known-count pcap in offline mode with controlled flow mix,
  churn, output mode, and storage/cache state. Report accepted packets/s, CPU
  time, and shard distribution. This measures the offline pipeline, including
  parsing and I/O; it does not establish the realtime consumer ceiling.
- Use `RUSTIFLOW_REALTIME_STATS` to attribute realtime decode, enqueue, and shard
  send waits. Its elapsed-time counters include waits and do not measure all
  shard processing. Do not sum overlapping stage timings into CPU ns/packet.
- For a generator-independent realtime userspace ceiling, use `replay-bench`
  (added 2026-10-20). It replays synthetic events through the
  consumer/dispatcher/shard/export path; ring reads, eBPF and the kernel receive
  path are excluded. Label realtime harness timings as observations at the
  offered rate.

### 4. Run the scaling sweep

- Sweep `--threads 2,4,8,16` with a fixed, sufficient receive CPU budget first.
  Then vary receive CPU allocation with userspace held fixed. Finally test paired
  allocations that fit the host. Record total CPU budgets, queue/ring counts,
  actual affinity, and worker utilization; a thread count is not a core count.
- Use enough independent flows to exercise all shards and queues. Keep packet
  shape, flow count/churn, output mode, and duration fixed within each sweep.
  Include B3/B4 alongside B1, and test realistic churn separately.
- Find the highest sustained clean rate with bounded offered-rate steps. Require
  reconciled sender/receiver/capture counts, zero unexpected kernel/ring/userspace
  losses, and no growing backlog. Zero internal drops alone is insufficient.
- Warm up, repeat each point at least three times, and retain raw counters,
  exact commands, durations, and variability. Mark generator-limited points as
  lower bounds on capacity. Compare throughput with statistics enabled and
  disabled to expose measurement overhead.
- Report observed scaling and saturation before extrapolating. Any projection
  beyond measured cores must state its assumptions, packet mix, and shared
  bottlenecks. Per-core rate multiplied by cores is conditional, not a guarantee.

After these baselines, measure one change at a time: merged IPv4/IPv6 programs,
counter consolidation, ring wakeup batching, per-CPU rings, removal of the extra
userspace hop, and an expiry timer wheel. The single-lookup, hasher and
per-shard export changes landed on 2026-10-20 without a realtime run, so the
first harness baseline already includes them; compare against the April matrix
only with that caveat.
Use component cost and clean Mpps to judge each change against its baseline.

Native XDP performance, hardware RSS, hardware timestamps, and NIC-related NUMA
placement need physical hardware validation. Veth XDP can support correctness
checks; do not present its performance as representative of a NIC. If hardware
becomes available, a suitable dual-port NIC with a compatible DAC provides a
single-host physical path. A mirror/SPAN feed can add realistic flow mix and
churn evidence, with mirror loss accounted for separately.

## 2026-10-15: bulk timing and AuthStorm regeneration

- Bulk state now retains integer microseconds. The idle threshold is exactly
  1,000,000 microseconds, with a new bulk only when the gap is greater.
- Exported duration statistics remain milliseconds, now fractional. Rates use
  packet bytes per second through `safe_per_second_rate`. Identical timestamps
  yield the existing zero-denominator fallback of zero; a positive bulk count
  and zero duration identify an undefined rate rather than no bulk.
- Packet-byte accounting, the four-packet minimum and direction-switch rules
  are unchanged. RustiFlow and CIC share the correction in ordinary and
  contamination-free exports.
- Regression tests fail against the original source and pass after the fix.
  Coverage includes both directions, sub-millisecond and identical timestamps,
  accumulated bulks, exact idle boundaries, direction switches, close, CSV
  serialization and IPv4/IPv6 offline versus eBPF-event feature conversion.
- Timing audit found no further instance of this rate-unit defect. IAT,
  active/idle and directional timing already subtract integer microseconds
  before exporting fractional milliseconds. Other per-second rates consume
  microsecond durations. NF/CIDDS whole-millisecond fields remain their
  existing schema choices; this change does not redefine them.
- AuthStorm regeneration scripts stage a new directory, hash accepted inputs,
  preserve legacy annotations in sidecars, compare flow multisets, and build
  the existing fixed train/test split. The final run preserves the original
  five-thread default. A one-thread exploratory run changed shard-expiration
  statistics and was excluded from the final revision.
- Final staged CSV comparison: 1,172 scenarios, 1,019,250 flows, 18,906,131
  extracted packets; no non-bulk feature or bulk-membership changes and no
  nonfinite rates or zero-duration bulks. The crosswalk assigns 1,019,204 unique matches; 46 rows in
  23 duplicate-identity groups remain explicitly ambiguous. All duplicate rows
  are identical across their native fields, so row-order assignment would invent
  correspondence.
- The final Parquet release is in the AuthStorm dataset at
  `feature-revisions/bulk-us-20261015-default/release/`. Packaging verification
  passes for train 858,081 and test 161,169 rows; nine family replay comparisons
  pass. All 69,520 legacy annotation rows are linked into metadata. The 463
  parser-excluded frames match documented intentional-corruption exceptions.
  Original dataset artifacts remain intact.
- Validation on Linux: `cargo fmt --all -- --check`,
  `cargo check -p rustiflow --locked`, `cargo test -p rustiflow --locked`
  with 66 tests, and `cargo clippy -p rustiflow --all-targets --locked -- -D warnings`.
  No live eBPF attachment test was performed; event conversion is covered
  deterministically and no capture/attach code changed.

## 2026-04-04 and 2026-04-05: local throughput matrix

- The trusted software-path harness is `rustiflow-t0` / `rustiflow-peer` /
  `rustiflow-p0` (see `AGENTS.md`). Its persistent service is tuned for bulk
  throughput rather than realism: 8x8 multiqueue veth matching
  `REALTIME_EVENT_QUEUE_COUNT`, 9000 MTU, `txqueuelen 10000`, widened GSO/GRO
  limits and RPS/XPS spread across CPUs. Application bitrate on it is therefore
  not a proxy for packet rate (see the 2026-10-18 plan).
- A separate multiqueue `pktgen` harness was tried and dropped: its own control
  path flattened around 19.7-22.9 Gbit/s whatever the target. True 40G
  validation is a physical-hardware question.
- 2026-04-04, 24-port `iperf3` fanout: 1400-byte UDP reached 24.72 Gbit/s with
  RustiFlow against a 24.96 Gbit/s control, with 0 internal drops for IPv4 and
  IPv6. 512- and 256-byte UDP were generator-limited before RustiFlow dropped.
  900 s soaks and a short-lived-flow churn soak stayed drop-free.
- 2026-04-05, the maintained matrix in `docs/realtime-throughput-matrix.md`
  (CPUs 0-7 sender, 8-23 RustiFlow, 24-31 receiver; artifacts in
  `target/realtime-matrix/20260405-190241/`). Every capture run had 0 internal
  drops; values are Gbit/s with headroom loss against control:

| Scenario | Control | `basic` | `rustiflow` |
| --- | --- | --- | --- |
| B1 1400-byte UDP, P8, 30 s | 22.2 | 13.9 (-37.4%) | 11.1 (-50.0%) |
| B2 1400-byte UDP near ceiling | 16.7 | 13.4 (-19.8%) | 11.1 (-33.5%) |
| B3 512-byte UDP | 7.27 | 5.21 (-28.3%) | 4.20 (-42.2%) |
| B4 256-byte UDP | 3.68 | 2.11 (-42.7%) | 2.68 (-27.2%) |
| B5 mixed UDP + TCP | 114.37 | 110.94 (-3.0%) | 114.24 (-0.1%) |
| B6 200 short TCP runs (mean) | 94.48 | 94.25 (-0.24%) | 93.78 (-0.74%) |
| B7 900 s 1400-byte UDP soak | 18.8 | 13.7 (-27.1%) | 12.6 (-33.0%) |

B8 (`tcpreplay` of a tiny fixture) is only a parser smoke test. These results
predate the 2026-10-20 userspace changes and do not locate the bottleneck; the
2026-10-18 plan is the next measurement.

## 2026-03: realtime ingestion and export design (condensed)

Detailed March run logs are in git history before this commit. What still holds:

Ingestion semantics:

- Realtime events carry kernel monotonic timestamps and the same
  packet/header/payload length semantics as offline parsing. Timing, IAT,
  active/idle and bulk logic compare integer microseconds and export
  milliseconds.
- Flow lookup and sharding use typed `FlowKey` values; the string flow id is
  only built when a flow is created.
- Offline parsing drops non-first IPv4 and IPv6 fragments, and short
  unsupported frames must not panic the reader.
- `FlowTable` must not overwrite `TcpReset` with `TcpTermination`, and a flow
  terminated by its first packet is exported once.
- Feature decisions from this period, all still current: TCP-only
  retransmission stats in sequence space, ICMP type/code plus echo and error
  counts, handshake and reset lifecycle flags, duplicate ACK and zero-window
  counts, `tcp_close_style` owned by `BasicFlow`, and IP version, scope and
  path-locality columns derived from the shared `IpAddr`. `FeatureStats` keeps
  running variance and derives population std on demand.
- Parity tests feed equivalent offline and realtime packets (IPv4 and IPv6)
  through `PacketFeatures` constructors and `FlowTable`, and compare exports.
  Realtime tuning must not change timestamps, lengths, biflow ownership,
  expiration causes or exported rows.

Realtime ingestion shape, chosen from measurements on the local harness:

- Each IP family emits into 8 ring buffers of 64 MB
  (`REALTIME_EVENT_QUEUE_COUNT`, `REALTIME_EVENT_RINGBUF_BYTES`). The queue is
  chosen in eBPF from a canonical biflow tuple with `hash_combine` over `mix_u32`, so
  both directions land on one queue. The single-ring design was the measured
  bottleneck; 4 queues cut overload drops sharply, 8 removed them on the
  overloaded `-P 8` shape, and the stronger hash fixed visible queue skew.
- Each queue has its own drain task, which batches packets per shard and hands
  them to a per-source dispatcher, so draining never awaits shard-channel sends.
- Programs attach through legacy netlink tc, since `aya`'s automatic TCX attach
  reported success but never ran on the local kernel and veth setup. The
  per-CPU `matched_packets`, `submitted_events` and `dropped_packets` counters
  made that visible. `DROPPED_PACKETS` is the authoritative overload signal; the
  eBPF ring-reservation failure log is `debug!` to avoid log floods.
- Realtime defaults to 12 worker threads, capped at the logical CPU count; pcap
  keeps 5. On 8 x 1.25G 1400-byte UDP, 11 or more threads gave 0 drops at
  about 10 Gbit/s where 4-10 threads did not. Thread count and export volume
  dominated; shard batch size and queue depth were second order and stay
  tunable through `RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE`,
  `RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY` and
  `RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY`.
- A per-CPU perf-event transport was considered as the next escalation and has
  not been needed so far.

Export path:

- Measured with `--early-export 5`, which at the time meant a row per packet
  (see the 2026-10-20 entry). Per row, serialization dominated: about 7-10 us
  for a `rustiflow` row, about 1 us for buffered writes, and about 0.2 us for
  the snapshot clone. Clone cost was never the bottleneck.
- Kept: one reused row buffer per writer and append-style CSV emission for
  features, which 2026-10-20 made mandatory for every `FlowFeature` and moved
  into per-shard encoders.
- Rejected after measurement: a broad leaf `format!` rewrite, a direct-to-writer
  row prototype, and a typed `Snapshot`/`Owned` export split. None gave a
  reliable win.

Profiling hooks: `RUSTIFLOW_REALTIME_STATS=1` (per-source drain and dispatch
timing), `RUSTIFLOW_PROFILE_RESOURCE_SUMMARY=1`,
`RUSTIFLOW_PROFILE_FLAMEGRAPH=<file.svg>` with `RUSTIFLOW_PROFILE_FREQUENCY_HZ`
(needs a build with `--features profiling`, which pulls in pprof), and `RUSTIFLOW_PROFILE_EXPORT_BREAKDOWN=1` (clone, encode and write time).
`scripts/realtime_container_stress.sh` runs the containerized harness baseline.
