# Experiment 4 · Shard batch buffer reuse on nuccore

Integrated main enables recycling for live capture and Basic replay. At paced live rates the candidate used
3.4–3.6% fewer cycles per frame than baseline. Full-feature replay
throughput stayed within 1.4% of baseline.

Base `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. Each realtime or
replay source currently allocates a replacement `Vec<PacketFeatures>`
whenever it dispatches a nonempty batch. Small ring drains and replay
bursts dispatch partial batches more frequently. Reusing the vectors
could reduce allocator work, especially when the worker completes
batches while the source is still active. Earlier work split ring
draining and dispatch into distinct tasks and found shard batch size
and queue depth secondary to flow processing and export volume.
Experiments 1–3 covered flow keys, TCP sequence tracking and Parquet
statistics. [Engineering notes](../engineering-notes.md) · [Profiling guide](README.md)

The prototype retains up to 32 empty vectors per worker behind a
private pool. Sources take a spare from their destination shard or
allocate at the existing dispatch boundary. The worker returns an empty
vector after processing its batch. Both directions use `try_lock`.
An empty, contended or poisoned pool falls back to allocation, and a
full pool releases excess vectors. The original experiment enabled recycling with
`RUSTIFLOW_EXPERIMENT_RECYCLE_SHARD_BATCHES=1` for capture and replay.

## Replay

Each case replayed 10 million synthetic events, eight sources and
100,000 possible bidirectional flows, with half TCP and half UDP.
The generated events used 1,400-byte payloads and 1 µs virtual spacing.
Both builds used four flow-table workers on CPUs 0–5 and default
Parquet to `/dev/null`. Each case had one warmup per binary, eight
alternating pairs for elapsed throughput and four separately counted
pairs. Throughput includes replay through writer close. Hardware
counters cover the whole process, including event generation. Values
are medians with min–max in parentheses.

| Replay | Baseline Mpps | Candidate Mpps | Change | Baseline cycles/event | Candidate cycles/event |
| --- | ---: | ---: | ---: | ---: | ---: |
| Basic IPv4, burst 4096 | 30.809 (29.802–31.706) | 32.117 (31.235–32.829) | +4.25% | 837.8 (832.0–846.9) | 818.2 (814.9–822.7) |
| Basic IPv4, burst 256 | 26.998 (17.022–27.668) | 25.947 (18.056–30.076) | −3.89% | 927.1 (918.9–930.9) | 842.0 (829.8–873.0) |
| RustiFlow IPv4, burst 4096 | 6.326 (6.165–6.390) | 6.306 (6.268–6.403) | −0.32% | 1955.8 (1921.3–1973.8) | 1896.3 (1886.1–1905.9) |
| RustiFlow IPv4, burst 256 | 6.152 (6.105–6.243) | 6.233 (6.164–6.265) | +1.32% | 1954.0 (1934.9–1960.7) | 1918.6 (1901.4–1935.9) |
| RustiFlow IPv6, burst 4096 | 6.248 (6.199–6.326) | 6.274 (6.225–6.306) | +0.42% | 1874.2 (1826.8–1875.7) | 1835.6 (1779.2–1864.9) |

| Replay | Baseline instructions/event | Candidate instructions/event |
| --- | ---: | ---: |
| Basic IPv4, burst 4096 | 1061.5 (1061.3–1061.7) | 1035.2 (1035.0–1035.4) |
| Basic IPv4, burst 256 | 1079.6 (1079.4–1079.8) | 1050.4 (1050.0–1051.8) |
| RustiFlow IPv4, burst 4096 | 1944.5 (1943.9–1944.7) | 1916.1 (1916.1–1918.1) |
| RustiFlow IPv4, burst 256 | 1968.4 (1968.1–1968.9) | 1939.4 (1938.9–1939.7) |
| RustiFlow IPv6, burst 4096 | 1921.4 (1921.3–1921.7) | 1895.7 (1895.1–1896.0) |

The same candidate executable, with recycling switched off and on,
used the same eight timing pairs and four counter pairs for the three
IPv4 cases below. This controls for the change to borrowed packet
iteration in the candidate's worker.

| Replay | Off Mpps | On Mpps | Off cycles/event | On cycles/event |
| --- | ---: | ---: | ---: | ---: |
| Basic, burst 4096 | 30.463 (28.707–31.303) | 31.666 (30.199–32.354) | 831.6 (826.9–833.4) | 821.3 (819.3–822.4) |
| Basic, burst 256 | 17.828 (17.201–26.866) | 18.910 (17.837–25.260) | 873.2 (780.7–920.6) | 827.6 (824.8–852.0) |
| RustiFlow, burst 4096 | 6.258 (6.155–6.358) | 6.319 (6.250–6.386) | 1894.3 (1858.1–1908.7) | 1903.7 (1880.9–1913.7) |

The on/off instruction changes were under 0.5% in all three cases.
Basic at burst 4096 gained about 4% on both comparisons. Basic at
burst 256 had a wide spread in both comparisons, and full-feature
replay stayed within 1.4% of its respective control.

For 30 million IPv4 events at burst 4096, one warmup per binary and four
alternating pairs measured 20.792 (20.780–20.830) versus 21.045
(21.025–21.185) Mpps for Basic and 6.494 (6.446–6.521) versus 6.524
(6.497–6.556) Mpps for RustiFlow. The Basic gain narrowed to 1.2% on
the larger workload.

## Live veth ingress

Each run sent 2 million mixed-family UDP frames. Capture used two
flow-table workers on CPUs 0–3 and default Parquet to `/dev/null`. The
sender used CPU 4. Three alternating pairs per send rate measured
elapsed throughput, and a separate three pairs measured capture
userspace hardware counts over the sender command, before final
export. The plain runs achieved the sender rates below.

| Sender pacing | Baseline pps | Candidate pps |
| --- | ---: | ---: |
| 200,000 pps | 199,996 (199,996–199,997) | 199,996 (199,996–199,999) |
| 650,000 pps | 649,934 (649,926–649,936) | 649,929 (649,929–649,940) |
| Unpaced | 831,467 (830,352–837,682) | 842,955 (842,241–846,391) |

| Sender pacing | Baseline cycles/frame | Candidate cycles/frame | Baseline instructions/frame | Candidate instructions/frame |
| --- | ---: | ---: | ---: | ---: |
| 200,000 pps | 3438.4 (3411.4–3444.2) | 3315.0 (3306.3–3348.0) | 3664.0 (3647.6–3664.9) | 3479.5 (3477.9–3490.2) |
| 650,000 pps | 3309.1 (3306.6–3343.8) | 3197.5 (3186.5–3220.1) | 3712.2 (3679.5–3719.2) | 3506.3 (3502.4–3536.4) |
| Unpaced | 5614.9 (5612.7–5687.8) | 5277.4 (5225.3–5282.6) | 5386.2 (5374.8–5399.0) | 5012.8 (4987.9–5022.0) |

At the paced rates, median instructions/frame fell 5.0–5.5%. The
unpaced counter passes achieved
0.847–0.855 Mpps for baseline and 0.863–0.883 Mpps for the candidate.
These ranges describe the software sender and capture combination.
In four additional alternating pairs at 650 kpps, turning recycling
on in the same candidate binary lowered median cycles/frame from
3364.4 (3333.4–3448.1) to 3226.6 (3217.6–3234.0) and instructions/frame
from 3682.5 (3646.2–3754.0) to 3530.0 (3525.6–3537.4). Both fell 4.1%.

## CPU and allocation profiles

Separate 999 Hz DWARF runs sampled roughly 6,000–17,000 userspace
events per replay profile and about 7,000 per live profile, with zero
reported sample losses. Flow-table packet processing accounted for
34.2% of baseline full-feature IPv4 replay self cycles and TCP
retransmission tracking for 12.7%. The dispatcher and batch enqueue
symbols summed to 0.20%. In Basic at burst 256 they summed to 1.18%.

The live stack samples offered 1 Mpps and delivered 0.836 Mpps on the
baseline and 0.859 Mpps on the candidate. Mapping libc sample addresses
against the local debug build ID, allocator functions accounted for
5.98% of reported self cycles on baseline and 0.17% on the candidate.
Dispatcher plus enqueue self cycles were 9.33% and 11.81% respectively,
and returning vectors through the pool accounted for 2.52% of candidate
self cycles. These are shares from separately sampled workloads.

Heaptrack traced one million IPv4 events per case. The 10,240-byte
allocation stacks at the dispatch replacement line isolate the old
vector allocations and the candidate's pool misses.

| Replay | Replacement calls, baseline / candidate | All calls, baseline / candidate |
| --- | ---: | ---: |
| Basic, burst 4096 | 8,311 / 7,198 | 427,037 / 425,936 |
| Basic, burst 256 | 15,644 / 9,076 | 434,414 / 427,881 |
| RustiFlow, burst 4096 | 8,306 / 7,304 | 815,088 / 813,849 |
| RustiFlow, burst 256 | 15,644 / 9,965 | 822,511 / 816,601 |

Replacement calls fell 12–13% at burst 4096 and 36–42% at burst 256.
The retained vector storage is at most 320 KiB per shard at the default
batch size. Whole-process peaks reported by heaptrack rose by 6–38 MB
across the eight traces. Those peaks include the in-flight batches, flow
tables, export state and pre-generated events in the instrumented runs.

## Correctness

The existing bounded source and shard queues still carry the only
forward path. A pool contains no packets, owns no queue sender and
cannot keep a worker alive. A source still flushes partial batches in
shard order. A worker still processes each batch in order and uses its
last packet timestamp to export open flows when its input closes.
Live SIGINT still cancels ring readers and dispatchers, so live
reconciliation below stops traffic and allows it to drain before SIGINT.

Both binaries produced the same 203 decoded fields for all 10,000
offline flows, including exact timestamps and 2,000,000 input packets.
The sorted decoded SHA-256 was
`8579cf4b0ef1ca97b5cd9203726d426285c7eade599c271085225cc1c878b549`.
For 120,000-event IPv4 and IPv6 replays, both drain bursts (7 and 257)
used one source, one shard, eight-packet batches and one slot in each
send queue. Active expiration and early exports yielded 1,800 rows
per run. All 203 decoded fields matched after normalizing the six
timestamp fields by the synthetic epoch origin and preserving missing
directions. Source statistics reported 120,000 events and zero send
errors in each run.

Every live run sent and received 2,000,000 frames with zero sender
failures or veth RX drops. Per-family classifiers matched and submitted
1,000,000 events each, with zero ring drops. The dedicated reconciliation
passes at the 1 Mpps target and unpaced rate each drained 1,000,000
events per family with zero send errors. All four Parquet exports
matched the offline fixture's 10,000 flow identifiers, protocols,
address families and both directional packet counts. The temporary veth
namespaces were removed and `kernel.bpf_stats_enabled` ended at its
initial value of 0.

`cargo fmt`, `cargo fmt --all -- --check`, `git diff --check`,
`cargo test --locked -p rustiflow` (114 unit and five integration
tests), and `cargo clippy --locked -p rustiflow --all-targets -- -D warnings`
passed. The default Parquet tail test also runs with recycling enabled
and one-slot queues, reconciling 120,000 packets after writer close.

## Capacity context

The full-feature replay medians spanned 6.15–6.52 million events/s
through the userspace pipeline, including export close. The unpaced
veth passes measured one software sender and two capture workers. For
comparison, 1,518-byte Ethernet frames plus preamble and interframe
gap require 8.13 Mpps at 100 Gbps and 32.51 Mpps at 400 Gbps.

## Reproduction

Nuccore uses an Intel Core Ultra 7 255H on x86-64 Linux
`6.18.65-1-lts`, P-cores 0–5 with the `powersave` governor and turbo
enabled. The userspace binaries use pinned Rust 1.99.0, generic x86-64
code generation and workspace fat LTO. Perf is 7.3.5-2 and tcpreplay is
4.6.2. Both live variants share release classifiers freshly built with
nightly-2026-10-01 and bpf-linker 0.12.0.

Run from the respective source revision and archive it as
`baseline` or `candidate`. Use the release binary for timings and
counters and the profiling binary for stacks and heaptrack.

```bash
export CARGO_TARGET_DIR="$PWD/target"
exp="$PWD/target/exp04"
mkdir -p "$exp/bin"
taskset -c 0-5 cargo build --locked --release -p rustiflow
cp target/release/rustiflow "$exp/bin/$variant-release"
cargo build --locked --profile profiling -p rustiflow
cp target/profiling/rustiflow "$exp/bin/$variant"
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
test -e "$exp/mixed.pcap" || python docs/profiling/generate_pcap.py "$exp/mixed.pcap"
```

The existing pcap is the profiling guide's 2-million-frame mixed IPv4
and IPv6 UDP fixture, SHA-256
`601d3d0590117b17e7a420198fe0a4ab058961dbd2bfc0acd360b5a629245661`.
For replay use feature `basic` or `rustiflow`, burst 4096 or 256, and
append `--ipv6` for IPv6. Use toggle `0` for baseline and `1` for the
candidate. Use the default Parquet output, batch size 128, shard queue
512 and source dispatcher queue 1024, with source statistics disabled.

```bash
export RUSTIFLOW_EXPERIMENT_RECYCLE_SHARD_BATCHES="$toggle"
opts=(-f "$feature" --export-path /dev/null --threads 4 replay-bench
      --flows 100000 --sources 8 --drain-burst "$burst")
events=cpu_core/cycles/u,cpu_core/instructions/u
taskset -c 0-5 "$exp/bin/$variant-release" "${opts[@]}" --packets 10000000
taskset -c 0-5 "$exp/bin/$variant-release" "${opts[@]}" --packets 30000000
taskset -c 0-5 perf stat --no-big-num -x ';' -e "$events" -o "$stat" -- \
    "$exp/bin/$variant-release" "${opts[@]}" --packets 10000000
sudo -n env RUSTIFLOW_EXPERIMENT_RECYCLE_SHARD_BATCHES="$toggle" taskset -c 0-5 \
    perf record -e cpu_core/cycles/u -F 999 --call-graph dwarf,8192 \
    --no-buildid-cache -o "$data" -- "$exp/bin/$variant" "${opts[@]}" --packets 20000000
sudo -n perf report -f -i "$data" --stdio --no-children --percent-limit 0.04 -g none
taskset -c 0-5 heaptrack --record-only -o "$trace" \
    "$exp/bin/$variant" "${opts[@]}" --packets 1000000
heaptrack_print -f "$trace.zst" -n 8 -s 4 -F "$stacks" --flamegraph-cost-type allocations
```

The local live wrapper under `target/exp04/live.sh` follows the
repository's [namespaced veth harness](realtime.sh). Capture uses
`RUSTIFLOW_EBPF_DIR="$PWD/target/bpfel-unknown-none/release"` and the
same recycle toggle. The measured command lines inside the harness
were as follows.

```bash
ip netns exec "$capture_ns" taskset -c 0-3 "$exp/bin/$variant-release" \
    -f rustiflow --export-path /dev/null --threads 2 realtime cap0 --ingress-only
sender=(ip netns exec "$sender_ns" taskset -c 4 tcpreplay --preload-pcap
        "--pps=$rate" --limit=2000000 --intf1=send0 "$exp/mixed.pcap")
"${sender[@]}"
perf stat --no-big-num -x ';' -e "$events" -p "$capture_pid" -o "$stat" -- "${sender[@]}"
perf record -e cpu_core/cycles/u -F 999 --call-graph dwarf,8192 --no-buildid-cache \
    -p "$capture_pid" -o "$data" -- "${sender[@]}"
```

Use `--topspeed` for the unpaced sender. Run `sudo -n bash "$exp/live.sh"
<phase>` with `wall`, `stat`, `stat-control`, `sample`, or `reconcile`.
The control uses the candidate executable for both toggles. The
`sample` phase takes the variant as a second argument and uses
`--pps=1000000` and the profiling binary.
For reconciliation, enable `RUSTIFLOW_REALTIME_STATS=1` and write a
regular Parquet file. Inspect veth interface counters before and after
sending and let capture drain for one second before SIGINT. For bounded
replay validation, use `--threads 1 --early-export 1 --active-timeout 2
--expiration-check-interval 1` and `replay-bench --packets 120000 --flows
300 --sources 1 --virtual-pps 20000 --drain-burst "$burst"`. Set
`RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE=8` and both queue capacities to 1.
Raw repetitions, profiles, scripts, build logs and readbacks are under
`target/exp04/` in this worktree.
