# Experiment 1 · Batched biflow canonicalization on nuccore

Available on Linux with AVX2 through
`RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS=1`. The Basic replay gains depended
on long bursts. Full-feature replay gains stayed within run-to-run spread,
live CPU costs rose, and the candidate's scalar path regressed in Basic
replay. Integrated main enables SIMD by default for Basic replay on AVX2 CPUs. When both experiments are enabled, staged flow lookup takes precedence.

Base commit `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. Recent work added a
single canonical map lookup, independent seeded foldhash instances for
sharding and lookup, and parallel Parquet export. The current replay already
uses the same shard workers as live capture. See the [engineering notes](../engineering-notes.md)
and [profiling guide](README.md).

## Hypothesis and profile

Preparing orientations in pairs may lower comparison cost once an existing
realtime shard batch is large enough to amortize the SIMD call. The AVX2
kernel compares two IPv4 or IPv6 address pairs as unsigned bytes, uses the
first differing octet to order each pair, and breaks address ties by port.
Scratch storage belongs to each shard worker. One-packet batches, odd tails,
and mixed-family endpoints use the scalar path. The worker applies the original
packet sequence and runs expiration checks at each original timestamp.
Shard selection still uses the original canonical key and seeded hash.

Fresh baseline profiles sampled userspace P-core cycles with DWARF call
graphs. These are self-cycle percentages. The canonicalization symbol
includes calls from the source and shard stages.

| Input | Samples | Flow-table packet processing | Scalar canonicalization |
| --- | ---: | ---: | ---: |
| Basic IPv4 replay | 1,530 | 37.10% | 9.44% |
| Basic IPv6 replay | 1,793 | 40.49% | 11.97% |
| Full IPv4 replay | 4,540 | 32.88% | 4.69% |
| Full IPv6 replay | 4,542 | 32.67% | 4.83% |
| Live mixed IPv4/IPv6 at 200 kpps | ≈1,000 | 10.84% | 1.86% |

The live drain task was another 10.46%. The experiment targets just the
canonicalization performed by the flow table. The candidate's line-table
build contains `vinserti128`, `vpcmpeqb`, `vpminub`, and `vpmovmskb` in the
runtime-selected kernel. In the four candidate replay profiles, AVX2
comparisons account for 1.08–2.85% of sampled self cycles and the remaining
scalar canonicalization accounts for 2.44–7.19%. Flow-table processing
still leads at 33.73–41.32%. The replay profiles recorded zero lost
samples. The separate candidate live sample at 200 kpps attributed 0.85%
to the AVX2 kernel and 10.66% to ring draining.

## Matched replay

Each case used one warmup per mode, six throughput runs with all six
orders of the three modes, and three separate counter runs with the order
rotated. All used eight sources, four shards, CPUs 0–5 and default Parquet
to `/dev/null`. The long cases used 10 million events and 100,000 possible
flows with a 4,096-event drain burst. Full features use `-f rustiflow`.
Throughput is median Mpps with min–max in parentheses. The candidate scalar
column measures the new binary with the SIMD opt-in unset.

| Replay | Base | AVX2 | Candidate scalar | AVX2 vs. base |
| --- | ---: | ---: | ---: | ---: |
| Basic IPv4 | 30.43 (29.61–31.34) | 34.60 (31.07–35.16) | 28.69 (27.91–29.46) | +13.7% |
| Basic IPv6 | 30.19 (29.11–30.84) | 32.44 (31.40–34.22) | 28.22 (27.26–29.75) | +7.5% |
| Full IPv4 | 6.28 (6.16–6.40) | 6.36 (6.25–6.45) | 6.29 (6.25–6.33) | +1.2% |
| Full IPv6 | 6.21 (6.12–6.26) | 6.25 (6.13–6.30) | 6.15 (6.08–6.20) | +0.7% |

Hardware counts per input event are medians and min–max across three separate
runs. The table lists **base / AVX2 / candidate scalar**. Replay process CPU
time fell from 182.0 to 162.6 ns/event for Basic IPv4 and from 183.3 to 171.2
for Basic IPv6. Full-feature medians moved from 753.3 to 744.5 ns/event
for IPv4 and from 765.5 to 761.2 for IPv6.

| Replay | Userspace cycles/event | Userspace instructions/event |
| --- | ---: | ---: |
| Basic IPv4 | 844.2 (841.9–846.3) / 739.1 (737.8–761.7) / 887.1 (883.4–888.1) | 1061.8 (1061.4–1062.2) / 1037.0 (1036.6–1037.5) / 1124.1 (1123.9–1124.2) |
| Basic IPv6 | 843.3 (825.0–852.2) / 794.7 (781.3–800.5) / 873.1 (858.2–877.3) | 1039.8 (1038.9–1039.8) / 1048.7 (1048.6–1048.7) / 1106.5 (1106.1–1106.7) |
| Full IPv4 | 1945.0 (1926.0–1952.9) / 1684.0 (1681.5–1705.9) / 2024.5 (2018.7–2060.9) | 1944.5 (1943.6–1944.8) / 1922.3 (1921.4–1922.5) / 2006.4 (2006.4–2007.2) |
| Full IPv6 | 1934.2 (1925.5–1961.3) / 1765.4 (1722.8–1783.7) / 2052.7 (2025.7–2064.0) | 1921.5 (1921.2–1922.0) / 1932.2 (1932.2–1932.5) / 1989.1 (1989.0–1989.3) |

### Drain-burst sweep

The sweep used 2 million events and 10,000 possible flows in each Basic
case. The shard batch cap stayed at 128. A source burst may split over four
shards, so these are drain-burst sizes. At burst 1 all batches use scalar
processing. The gain grows as more packets land in each shard batch. IPv4 was already ahead at burst 64.
Both families were ahead at burst 4,096.

| Family | Drain burst | Base Mpps | AVX2 Mpps | Candidate scalar Mpps | AVX2 vs. base | Cycles/event base / AVX2 / scalar |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| IPv4 | 1 | 4.63 (4.58–4.80) | 4.49 (4.42–4.52) | 4.50 (4.37–4.62) | -3.1% | 4902 / 5057 / 5048 |
| IPv6 | 1 | 4.67 (4.65–4.71) | 4.52 (4.42–4.58) | 4.50 (4.33–4.57) | -3.2% | 4892 / 4973 / 5024 |
| IPv4 | 16 | 14.17 (13.87–14.62) | 14.24 (13.59–14.99) | 13.41 (12.99–13.79) | +0.5% | 1502 / 1473 / 1583 |
| IPv6 | 16 | 13.93 (13.60–14.54) | 13.75 (13.51–14.01) | 13.07 (12.86–13.72) | -1.3% | 1470 / 1477 / 1555 |
| IPv4 | 64 | 25.86 (25.32–26.40) | 27.54 (27.08–28.09) | 24.62 (23.13–25.35) | +6.5% | 923 / 862 / 955 |
| IPv6 | 64 | 26.42 (25.55–26.89) | 26.83 (26.43–27.42) | 24.99 (24.67–25.61) | +1.5% | 883 / 855 / 926 |
| IPv4 | 4096 | 34.19 (32.48–36.40) | 43.42 (42.44–45.21) | 32.11 (30.02–33.09) | +27.0% | 643 / 530 / 683 |
| IPv6 | 4096 | 36.23 (35.21–36.78) | 42.37 (40.43–43.73) | 32.81 (32.11–34.15) | +17.0% | 606 / 530 / 653 |

<details>
<summary>Individual throughput repetitions for the 10M-event runs in Mpps</summary>

| Replay | Base | AVX2 | Candidate scalar |
| --- | --- | --- | --- |
| Basic IPv4 | 29.606, 30.769, 30.091, 30.972, 29.843, 31.338 | 34.863, 34.638, 34.233, 34.566, 35.156, 31.068 | 29.211, 28.291, 28.050, 27.912, 29.461, 29.094 |
| Basic IPv6 | 30.835, 29.910, 30.632, 30.462, 29.105, 29.639 | 32.485, 32.175, 34.219, 32.404, 32.467, 31.403 | 28.683, 27.796, 28.472, 29.753, 27.260, 27.959 |
| Full IPv4 | 6.318, 6.273, 6.291, 6.257, 6.160, 6.404 | 6.263, 6.247, 6.445, 6.395, 6.341, 6.375 | 6.330, 6.293, 6.251, 6.287, 6.312, 6.296 |
| Full IPv6 | 6.123, 6.261, 6.211, 6.152, 6.211, 6.261 | 6.141, 6.130, 6.240, 6.264, 6.302, 6.280 | 6.195, 6.134, 6.169, 6.135, 6.081, 6.191 |

</details>

### Isolated transform and offline control

A separate single-core diagnostic reused the actual scalar and AVX2 functions.
Each run materialized 16,777,216 keys with orientations over repeated
4,096-record inputs with pseudorandom address orientation. It used preallocated
output and scratch, one warmup per mode, and four alternating counter runs on CPU 0.
These counts isolate key preparation and its output stores. Median cycles
per key are shown with min–max.

| Keys per batch | IPv4 scalar | IPv4 AVX2 | IPv6 scalar | IPv6 AVX2 |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 77.40 (74.85–79.28) | 27.52 (27.38–28.68) | 50.90 (47.95–51.38) | 33.45 (31.37–35.09) |
| 8 | 67.85 (49.88–72.10) | 17.20 (17.13–17.30) | 47.81 (46.37–49.67) | 17.25 (16.90–17.50) |
| 32 | 74.26 (70.86–76.41) | 17.10 (17.05–17.14) | 49.26 (45.78–79.17) | 18.52 (17.77–18.60) |
| 128 | 74.64 (72.16–76.85) | 16.42 (16.26–17.04) | 47.41 (45.89–49.22) | 17.50 (16.89–17.60) |

The AVX2 path amortized most of its fixed cost by eight keys in this
diagnostic. The pipeline required longer drain bursts for a clear gain.
On the 2-million-packet pcap with full features, six alternating offline
runs measured 7.66 (7.19–7.72) Mpps on base and 7.63 (7.61–7.72) Mpps
on the candidate. Offline still uses scalar lookup. Its whole-command
counts rose from 1,075 to 1,123 cycles and from 1,947 to 2,001
instructions per packet. The comparison captures code generation effects
from the shared flow-table refactor as well as runtime changes.

## Live veth ingress

Each offered rate had four alternating baseline and AVX2 pairs. Both ran
full RustiFlow features with default Parquet to `/dev/null`. Perf counted
the capture process during the sender command, before final export.
Values are median (min–max). These rates are sender-paced local
software-path measurements.

| Offered pps | Mode | Achieved pps | Userspace cycles/frame | Userspace instructions/frame |
| ---: | --- | ---: | ---: | ---: |
| 50,000 | Base | 49,998.71 (49,998.66–49,999.10) | 4,972.4 (4,950.1–5,031.4) | 4,937.6 (4,930.9–4,953.0) |
| 50,000 | AVX2 | 49,998.90 (49,998.71–49,999.95) | 5,149.4 (5,079.6–5,221.2) | 5,074.5 (5,047.0–5,097.7) |
| 200,000 | Base | 199,973.60 (199,970.27–199,980.00) | 3,708.2 (3,573.0–3,897.3) | 3,981.2 (3,859.3–4,206.2) |
| 200,000 | AVX2 | 199,976.80 (199,975.33–199,977.86) | 3,881.6 (3,644.7–4,161.7) | 4,176.4 (3,936.5–4,543.7) |

All 16 runs sent 300,000 frames with zero sender errors. Both classifiers
matched and submitted 150,000 frames each with zero ring drops in each
run. Median userspace cycles/frame rose by 3.6% at 50 kpps and 4.7% at
200 kpps, with overlapping spread at 200 kpps.

Separate instrumented runs at 200 kpps counted 150,000 drained events
from each family and zero dispatch send errors in both modes. Each Parquet
readback contained the same 10,000 flow IDs and 30 packets per flow, split
15 forward and 15 reverse. All 300,000 sent frames reconciled through the
export.

## Correctness

`cargo fmt`, `cargo fmt --all -- --check`, and
`cargo clippy --locked -p rustiflow --all-targets -- -D warnings` passed.
`cargo test --locked -p rustiflow` passed 115 unit and five integration tests
both with the opt-in unset and with it enabled. The SIMD equivalence test
covers unsigned IPv4 and IPv6 byte ordering, the first difference at each
IPv6 octet, forward and reverse endpoints, port ties, mixed families, empty
input and odd tails. The existing replay test exercises three sources and four
shards, with exact packet conservation and zero spurious retransmissions.

Both release binaries emitted identical sorted Parquet readbacks of all
203 fields for the offline pcap, with 10,000 flows and 2 million packets.
The decoded SHA-256 was
`8579cf4b0ef1ca97b5cd9203726d426285c7eade599c271085225cc1c878b549`.
Both families also matched on two single-source, single-shard replay
fixtures using 7-event drain bursts. The 20,000-event fixture delivered
300 flows with 10,031 forward and 9,969 reverse packets. The 120,000-event
fixture used 20,000 virtual pps, 2 s active timeout, 1 s expiration checks,
and 1 s early snapshots. It produced 1,800 rows per family, including
snapshots. All 203 fields matched after subtracting each run's epoch
origin from the two flow timestamps and four directional timestamps,
with the missing-direction sentinel preserved. This retains timing
deltas and the effects of packet order on flow state.

Validation ran on x86-64 Linux, including a run with the scalar fallback
selected. All test captures and senders exited. The namespace list and
`kernel.bpf_stats_enabled=0` matched their pre-test values.

## Reproduction

Nuccore has an Intel Core Ultra 7 255H and Linux `6.18.65-1-lts`. Both
binaries used pinned Rust `1.99.0` with generic x86-64 code generation and
the workspace's fat-LTO profiles. The same release eBPF objects were used
for both live binaries, built with `nightly-2026-10-01` and bpf-linker
`0.12.0`. Perf was `7.3.5` and tcpreplay was `4.6.2`. The P-core
governor was `powersave` with turbo enabled. Raw runs, build logs, scripts,
and decoded files are in this worktree's `target/experiment/`.

Build and archive each revision's binary before building the next. The
profiling binary has release code generation, symbols, and line tables.

```bash
taskset -c 0-5 cargo build --locked --release -p rustiflow
taskset -c 0-5 cargo build --locked --profile profiling -p rustiflow
CARGO_TARGET_DIR="$PWD/target/ebpf-build" taskset -c 6-13 cargo xtask ebpf-ipv4 --release
CARGO_TARGET_DIR="$PWD/target/ebpf-build" taskset -c 6-13 cargo xtask ebpf-ipv6 --release
```

For the replay commands below, use the archived release executable as
`$bin` and set `RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS=1` only in the AVX2
mode. Omit the variable for the baseline and candidate scalar control.
Append `--ipv6` for IPv6. Throughput uses the printed replay interval
through Parquet finalization. Whole-command hardware counters include
event generation. Runs sampled with `perf record` were collected
separately using the corresponding profiling executable.

```bash
taskset -c 0-5 "$bin" -f "$features" --export-path /dev/null --threads 4 \
    replay-bench --packets "$packets" --flows "$flows" --sources 8 --drain-burst "$burst"
taskset -c 0-5 perf stat --no-big-num -x ';' \
    -e cpu_core/cycles/u,cpu_core/instructions/u -- "$bin" -f "$features" \
    --export-path /dev/null --threads 4 replay-bench --packets "$packets" \
    --flows "$flows" --sources 8 --drain-burst "$burst"
sudo -n env RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS=1 taskset -c 0-5 perf record \
    -e cpu_core/cycles/u -F 499 --call-graph dwarf,8192 --no-buildid-cache \
    -o "$data" -- "$profiling_bin" -f "$features" --export-path /dev/null --threads 4 \
    replay-bench --packets 10000000 --flows 100000 --sources 8 --drain-burst 4096
sudo -n perf report -f -i "$data" --stdio --no-children --percent-limit 0.5 -g none
```

The existing deterministic mixed pcap has SHA-256
`601d3d0590117b17e7a420198fe0a4ab058961dbd2bfc0acd360b5a629245661`.
It has 10,000 bidirectional UDP flows, evenly split between IPv4 and IPv6
and between 24- and 448-byte payloads. Offline processes all 2 million
packets. The live harness sends the first 300,000 frames. The replays
generate TCP and UDP in memory with pseudorandom flow and direction,
1 µs virtual spacing, and 1,400-byte transport payloads by default.

```bash
exp="$PWD/target/experiment"
ebpf="$PWD/target/ebpf-build/bpfel-unknown-none/release"
python "$exp/replay_matrix.py" replay-release
bash "$exp/bench_offline.sh"
bash "$exp/bench_transform.sh"
sudo -n env RUSTIFLOW_EBPF_DIR="$ebpf" \
    RUSTIFLOW_PROFILE_BIN="$exp/bin/baseline-release" \
    RUSTIFLOW_PROFILE_CANDIDATE="$exp/bin/candidate-release" \
    bash "$exp/realtime.sh" "$exp/live-paired" "$exp/mixed.pcap" --paired
sudo -n env RUSTIFLOW_EBPF_DIR="$ebpf" RUSTIFLOW_PROFILE_BIN="$exp/bin/candidate" \
    RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS=1 bash docs/profiling/realtime.sh \
    "$exp/sample-live-candidate" "$exp/mixed.pcap" --sample-only
bash "$exp/validate_exports.sh" baseline
bash "$exp/validate_exports.sh" candidate
```

The local realtime script copies the repository harness with paired ordering
and a separate reconciliation pass. It preserves the original veth topology,
two capture shards on CPUs 0–3, sender on CPU 4, ingress-only attach, counter
scope, and shutdown. Each throughput capture uses `/dev/null` and
`perf stat -p "$capture_pid"` counts user cycles and instructions while
`tcpreplay --preload-pcap --pps="$rate" --limit=300000 --intf1=send0` runs.
The reconciliation pass uses `RUSTIFLOW_REALTIME_STATS=1`, writes a regular
Parquet file, then allows a one-second drain before SIGINT. The isolated
transform binary was built with `rustc --edition=2021 -O -C lto=fat
-C codegen-units=1` against the same release dependencies.
