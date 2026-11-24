# Engineering Notes

This file keeps short-lived design choices and execution notes that would make
`AGENTS.md` too long. Newest entries come first. Older entries are condensed to
the decisions and results that still describe the current code.

## 2026-11-24. zerocopy wire headers in both ingestion modes

`common::wire` defines the Ethernet, SLL, VLAN, IPv4, IPv6, TCP, UDP and ICMP
headers once, with network-order field types, for the pcap parser and the eBPF
programs. They replace pnet_packet offline and network-types in eBPF, and
zerocopy's `FromBytes` bound replaces the hand-audited `unsafe trait
WireHeader`. Ring records decode through `ref_from_bytes`, which rejects
records of the wrong size, and replay uses the same decoder. Event addresses
are wire-order byte arrays.

A differential run of 2M generated and mutated frames, plus every fixture
export, matched the pnet decoder exactly. Decode cost is unchanged (~55
ns/frame). BPF instruction counts moved by less than 1%. One pre-existing
difference remains: offline ICMP counts 4 header bytes and realtime counts 8,
so `data_length` differs by 4 between the modes.

## 2026-11-24. UNSW-NB15 exporter

RustiFlow derives the 47 unlabeled columns from the feature dictionary and
the thesis algorithms. Offline uses a shared time-ordered connection window
with 99 subsequent completed flows. Live capture uses the preceding 99
completed exports. Only the UNSW-NB15 pcap path copies selected application
payloads. The eBPF events use an existing padding byte for TTL and hop limit.

The CLI fixture checks cross-shard ordering, window boundaries, HTTP and FTP
metadata, TCP setup time, and retransmissions. CSV and Parquet projections
agree. An isolated Linux loopback capture verified both IP families through
the rebuilt TC classifiers. [Feature definitions](unsw-nb15.md)

## 2026-11-24. Default-path CPU and cache profile on rgbcore

Compared `2c877ef` and `2cd5df8` on the Ryzen 9 5950X with generic
x86-64 release builds and Rust 1.99.0. Both builds used default Cargo
features and Parquet to `/dev/null`. The table shows median Mpps over six
alternating pairs after warmup on CPUs 0–5, six physical cores sharing an L3
cache. Offline used five workers and the same 2-million-frame pcap as
nuccore. Replay used six workers and the CLI's default 10 million events,
100,000 flows, and eight sources. Offline times span the whole process.
Replay times start after event generation and end at writer close.

| Features | Offline pcap | IPv4 replay | IPv6 replay |
| --- | ---: | ---: | ---: |
| Basic | 7.35 to 8.52 (+16%) | 39.71 to 41.60 (+5%) | 38.27 to 39.50 (+3%) |
| CIC | 7.54 to 8.66 (+15%) | 12.01 to 15.57 (+30%) | 11.41 to 15.18 (+33%) |
| NFStream | 7.62 to 8.60 (+13%) | 10.57 to 20.10 (+90%) | 10.33 to 18.85 (+82%) |
| RustiFlow | 7.31 to 8.61 (+18%) | 9.98 to 10.06 (+1%) | 9.49 to 9.57 (+1%) |

With unrestricted affinity and 12 replay workers, the IPv4 and IPv6
NFStream medians rose 127% and 122%. CIC rose 38% and 34%. RustiFlow
replay medians moved by 1–5% depending on affinity and IP family, within
the run-to-run spread. The offline gain was consistent across the four
feature sets on CPUs 0–5.

Three paired `perf stat` runs on CPUs 0–5 measured the whole CLI, including
event generation for replay. The AMD cache-miss counts below use the
kernel's generic `cache-misses` event on this host.

| Case | User cycles per input | User cache misses per input | Peak RSS (MiB) |
| --- | ---: | ---: | ---: |
| Offline CIC | 1,135 to 923 | 23.98 to 19.48 | 49 to 44 |
| IPv4 CIC replay | 2,302 to 1,821 | 23.21 to 19.09 | 847 to 769 |
| IPv4 NFStream replay | 2,720 to 1,462 | 27.22 to 12.50 | 870 to 628 |

Calendar date construction took 3.9% of baseline CIC offline user-cycle
samples. The current classic pcap reader skips that conversion for its
unsigned 32-bit seconds field. NFStream's removed header and payload
updates took 13.0% of baseline IPv4 replay samples by themselves. With
fewer measurements per flow, NFStream also spent less overall CPU time
and memory on the same packet stream. Flow-table lookup was the largest
remaining hotspot, at 47.2% of current NFStream replay samples.

The baseline already includes the Basic replay defaults. An eight-round
comparison in the current binary used four workers on CPUs 0–5 and
rotated the order of four settings. With AVX2 flow keys and shard batch
recycling both off, Basic replay reached 27.69 Mpps for IPv4 and 27.50
Mpps for IPv6. The defaults reached 32.94 and 30.27 Mpps respectively.
IPv4 improved in all eight rounds. IPv6 improved in seven.
The AVX2 path checks CPU capability at runtime on x86-64.

Live CIC capture used two workers, split TC ingress, and a temporary veth.
The sender fell short of 650 kpps in the initial probe. The measured
comparison used 300,000 frames per run and a paced 100 kpps. Across six
alternating pairs, capture-process user cycles per frame fell from 5,974
(5,896–6,231) to 5,821 (5,637–5,872). User instructions per frame fell
2.3%. Every measured run submitted all frames with zero eBPF drops and
zero sender failures or retries. The counters cover the sender command and
exclude final export.

Decoded Parquet schemas and rows matched in all 12 comparisons across
offline pcap and both replay families. Replay timestamps were aligned to a
common clock origin. The NFStream millisecond fields matched within one
millisecond after alignment.

Raw timings, perf data, profiles, sender logs, and the scripts are in
`target/amd-default/` on rgbcore.

## 2026-11-24 — Default-path CPU and cache profile on nuccore

Against `2c877ef`, CIC keeps only each direction's header byte total, minimum
header length and first window, and NFStream drops eight feature families
absent from both of its projections, including TCP sequence-range tracking.
The offline reader dispatches decoded frames from one async call site and
skips calendar conversion for classic pcap's unsigned 32-bit seconds. Shard
selection maps the seeded hash with a widening multiply.

Median Mpps on an Intel Core Ultra 7 255H, default workers and features,
Parquet to `/dev/null`, four alternating pairs after warmup.
[Individual repetitions](profiling/nuccore-default-path.csv)

| Features | Offline before | Offline after | IPv4 replay before | IPv4 replay after |
| --- | ---: | ---: | ---: | ---: |
| Basic | 7.92 | 9.10 | 42.50 | 42.49 |
| CIC | 7.48 | 8.72 | 13.60 | 17.29 |
| NFStream | 7.45 | 8.83 | 11.66 | 25.43 |
| RustiFlow | 7.18 | 8.18 | 11.04 | 11.14 |

NFStream IPv4 replay fell from 1,580 to 995 user cycles and from 30.05 to
14.78 cache misses per event, and peak RSS fell from 796 to 582 MiB. Live CIC
capture at 650 kpps went from 3,424 to 3,293 cycles per frame with zero drops.
Skipping the Welford update for samples equal to the mean was slower and was
not kept. Decoded Parquet output matched in all 40 comparisons.

To repeat: build each revision with `cargo build --release --locked -p rustiflow`,
generate input with `python docs/profiling/generate_pcap.py mixed.pcap`, and
alternate `rustiflow -f FEATURES --export-path /dev/null pcap mixed.pcap` or
`... replay-bench` between binaries, optionally under `taskset -c 0-5`.

## 2026-11-24 — Overnight experiments and resulting defaults

Ten experiments are summarized in [profiling/experiments.md](profiling/experiments.md).
The TCP sequence fast path is unconditional. Shard batch recycling is on by
default for live capture and Basic replay, and AVX2 flow keys for Basic replay.
Against `cc0dd0e`, these defaults raised median Basic replay from 28.08 to
35.21 Mpps (IPv4) and 28.17 to 34.31 Mpps (IPv6). Recycling lowered live
capture cost from 3,971 to 3,431 cycles per frame at 650 kpps.

## 2026-11-24 — Parallel Parquet export

Parquet is the default output. Flow-table shards project completed flows into
native column buffers. Each shard submits its first 512 rows for Snappy
compression, then doubles the group size up to 4,096. Groups encode
concurrently while one writer appends them in submission order and writes the
footer. Text uses dictionary encoding, integers and UTC microsecond
timestamps use delta encoding, and doubles use plain encoding. Small groups
keep column-chunk statistics and omit page indexes.

Median milliseconds over eight runs per format, same binary, four workers on
CPUs 0–5. [Raw repetitions](profiling/nuccore-parallel-parquet.csv)

| Features | Workload | CSV ms | Parquet ms |
| --- | --- | ---: | ---: |
| rustiflow | Offline, 2M packets | 254.7 | 255.8 |
| rustiflow | IPv4 replay, 1M events to disk | 296.0 | 244.5 |
| rustiflow | IPv4 replay, 10M events | 1,671.0 | 1,591.5 |
| basic | Offline, 2M packets | 251.4 | 249.5 |
| basic | IPv4 replay, 10M events | 332.5 | 332.5 |

The short replay wrote 35.3 MB of Parquet against 106.5 MB of CSV. The
offline file decoded to the archived fingerprint across all 203 fields. An
earlier single-writer Parquet candidate had been 15% slower offline than CSV.

## 2026-11-06: opt-in promiscuous capture

`realtime --promiscuous` joins a `PACKET_MR_PROMISC` membership on an
`AF_PACKET` socket with protocol 0, which receives no packets. The kernel
reference-counts the membership and drops it on close, including SIGKILL, so
the interface returns to its previous state. The membership is joined before
the classifiers attach and released after they detach
(`rustiflow/src/realtime/promiscuous.rs`). The older approach, setting
`IFF_PROMISC` with `SIOCSIFFLAGS`, never cleared the flag and was not revived.

The option needs `CAP_NET_RAW` and `AF_PACKET`, which the systemd unit now
grants. On the veth harness, `promiscuity` rose by one during capture and
returned to its prior value after SIGINT, SIGKILL, `systemctl stop`, and with
an operator's `promisc on`. After SIGKILL the netlink tc filters stay attached
and must be removed by hand, as before. The effect on a physical NIC's MAC
filter still needs a check on a real tap or SPAN port.

## 2026-11-06: lean, CPU-targeted release build

The release profile uses fat LTO, one codegen unit and stripped symbols. The
`profiling` profile inherits it but keeps symbols and line tables. `pprof` is
behind the optional `profiling` feature, and `pnet` became `pnet_packet`.
`cargo xtask dist --target-cpu` defaults to `x86-64-v3`, recorded in MANIFEST,
and `install.sh` refuses CPUs below it. Unwinding stays enabled so panics still
detach tc classifiers.

LTO's throughput effect was within noise, and stripping shrank the binary from
8.2 to 4.5 MB. `x86-64-v3` gave a consistent 2–3% on the full feature set, and
`native` did not beat it.

## 2026-11-06: deterministic offline expiration and observed idle periods

The user chose to exclude trailing silence from idle statistics and to require
sorted offline exports to match across thread counts.

- Idle samples come only from packet-to-packet gaps above five seconds.
  `ActiveIdleStats::close` finalizes only the observed active period. This
  applies to realtime exports too.
- Offline capture sends ordered expiration messages to every shard on the
  capture-record clock, flushing pending batches first. EOF and corrupt-record
  termination run a final scan at the last readable timestamp, then export
  survivors with Exporter Shutdown. Unsupported frames also advance the clock.
- Sorting is still needed because concurrent export order varies.

On a 1.68M-packet synthetic capture, only the four idle statistics and 495
expiration causes changed, and sorted rows matched at one and eight threads.
Runtime did not regress. A live veth run confirmed that the fixed idle
statistics match the observed 6.1-second gap for both IP families.

## 2026-11-06: pure-Rust capture-file reader

The offline reader uses `pcap-parser` 0.17 instead of linking libpcap. It was
chosen over `pcap-file` for its stable release, single reader for both
formats, and clean `Eof`/`UnexpectedEof` distinction. Link layers are still
guessed per packet. Two `pcap-parser` defects are worked around locally, and
draft upstream reports are in [pcap-parser-issues.md](pcap-parser-issues.md).

The reader reproduces libpcap's default microsecond behavior: finer timestamps
are truncated, frames are cut to the snapshot length (0 or above 262,144 means
262,144), pcapng uses the first interface's snapshot length, `if_tsoffset` is
added, and Simple Packet Blocks are stamped at the interface offset.

Error policy:

- A record cut short by end of file ends the read with a warning and the
  offset. Flows are exported.
- An unframeable record, an obsolete Packet Block, an invalid fractional
  timestamp, or a timestamp outside the exporter's UTC range ends the read with
  an error naming the offset, after exporting earlier packets.
- Pcapng files whose interfaces have different linktypes are accepted, unlike
  libpcap.

Single-thread CSVs for all fixtures were byte-identical to the libpcap build.
Throughput was within 2.3% at one thread and 7–12% faster at five.

## 2026-10-22: adversarial flow and parser fixes

Eight synthetic-event findings were fixed, and all now have active
deterministic tests in `realtime_adversarial_test.rs`. The resulting semantics
are documented in the README under TCP flow lifecycle and out-of-order packet
timing. The user chose these policies:

- Preserve late post-close packets as a separate flow. There are no tombstones.
- Use bounded streaming timing: duration uses timestamp bounds, and late
  packets add zero IAT samples against a nondecreasing reference.
- Bound retransmission history to 1,024 merged ranges per direction in an
  ordered map, accepting misses against evicted ranges.
- A first SYN-ACK identifies its destination as the forward endpoint.

eBPF fragment handling and IPv6 AH/ESP parsing were aligned with offline
parsing through the shared `common::ipv6_extensions`. Neither path reassembles
fragments. The full findings record is in Git history at `2cd5df81`
(`docs/handoff-realtime-adversarial.md`).

## 2026-10-20: aya 0.14 and realtime byte order

Moved to aya 0.14, aya-log 0.3, aya-ebpf 0.2 and network-types 0.2, with
bpf-linker 0.12.0. `common` takes aya from crates.io, so one version is
locked.

network-types 0.2 exposed a realtime bug present since `c645b70` (2024-03).
Ports, TCP window, and sequence and ack numbers reached userspace in network
byte order but were decoded as host order, and IPv6 addresses were reversed.
`EbpfEventIpv4/6` now document the contract: addresses are in wire order and
all other fields in host order. **Realtime ports, windows, sequence numbers and
IPv6 addresses in datasets exported before this change are not trustworthy.**

## 2026-10-20: realtime userspace replay benchmark

`replay-bench` drives synthetic eBPF events through the same per-source
batching, dispatch, shard flow tables and exporter as `realtime`. It does not
model ring reads and wakeups, the eBPF programs, the kernel receive path,
uneven queue fanout, or flow churn. The subcommand lives in a CLI-only
`CliCommand`, so the TUI and config files keep the capture-only `Commands`.

## 2026-10-20: early export on a fixed per-flow schedule

Early export used to emit a raw clone on every packet once a flow passed the
threshold. It now uses a fixed per-flow schedule. Each `FlowEntry` stores its
next boundary (first packet + k·N, in microseconds). The first packet at or
after a boundary exports one finalized snapshot with cause `None`. Expiration
sweeps never trigger snapshots. `N` is a `NonZeroU64` smaller than the active
timeout. **Datasets produced with early export before this change contain
roughly one cumulative row per packet.** Per-interval delta rows in the
NetFlow/IPFIX style were not implemented. They would need a separate mode.

## 2026-10-20: userspace hot-path pass

Kept: integer formatting for integral `f64` CSV fields, mandatory
`append_to_csv` on every `FlowFeature`, one canonical-key lookup per packet,
seeded foldhash for the flow map and shard selector (random per process and
instance), shutdown exports sorted by `(timestamp, key)`, per-shard CSV
encoders, and offline packets batched 128 per shard send. Together these
roughly halved offline CPU time. Zero `--threads` is rejected at startup.

Measured and rejected: a synchronous `FlowTable` core to shrink the per-packet
future (no cycle change).

## 2026-10-15: bulk timing

Bulk state uses integer microseconds. The idle threshold is exactly 1,000,000
µs, and a new bulk starts only when the gap is greater. Durations export as
fractional milliseconds. Rates are packet bytes per second, and identical
timestamps yield the zero-denominator fallback of zero. The four-packet
minimum and direction-switch rules are unchanged. The AuthStorm dataset was
regenerated with this fix under
`feature-revisions/bulk-us-20261015-default/release/`. No non-bulk feature
changed across 1,019,250 flows.

## 2026-04 to 2026-03: realtime ingestion design (condensed)

Earlier run logs, the April veth throughput matrix, and the October
measurement plan are in Git history at `2cd5df81`. The following still
describes the current code.

- Realtime events carry kernel monotonic timestamps and the same length
  semantics as offline parsing. Timing logic compares integer microseconds
  and exports milliseconds.
- Flow lookup and sharding use typed `FlowKey` values. The string flow id is
  built only when a flow is created.
- Each IP family emits into 8 ring buffers of 64 MB. The queue is chosen in
  eBPF from a canonical biflow hash, so both directions share a queue. A
  single ring was the measured bottleneck, and 8 removed overload drops on the
  local harness.
- Each queue has its own drain task that batches per shard and hands off to a
  per-source dispatcher, so draining never awaits shard sends.
- Programs attach through legacy netlink tc, because `aya`'s automatic TCX
  attach reported success but never ran on the local kernel and veth. The
  per-CPU `DROPPED_PACKETS` counter is the authoritative overload signal.
- Realtime defaults to 12 workers, capped at the logical CPU count, and pcap
  to 5. Thread count and export volume dominated. Batch size and queue depth
  are second order and stay tunable through `RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE`,
  `RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY` and
  `RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY`.
- In April, 1400-byte UDP reached 24.7 Gbit/s on the veth harness with zero
  internal drops. True 40G validation needs physical hardware.
- `FlowTable` must not overwrite `TcpReset` with `TcpTermination`, and a flow
  terminated by its first packet is exported once.
- Parity tests feed equivalent offline and realtime packets through
  `PacketFeatures` and `FlowTable` and compare exports.
