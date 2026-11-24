# Experiment 6 · Bucketed expiry deadlines on nuccore

Retain the opt-in prototype on this branch. With one-second checks,
ordered mostly-live replay rose from 2.098 to 3.018 Mpps and ordered
churn rose from 1.401 to 1.815 Mpps. At the default 60-second cadence,
the eight-source index replay cost 6.8% more cycles per packet and ran
4.6% slower. The frequent-sweep benefit does not justify a default switch.

Base `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. The prior performance
notes identified full-table expiry sweeps as a possible per-shard stall.
Experiment 5 targeted occupied lookups and used separate cardinality
benchmarks. This experiment measures the cost of sweeps with frequent
checks, dormancy and key reuse. [Engineering notes](../engineering-notes.md) · [Profiling guide](README.md)

## Prototype

Build with `--features experiment-deadline-index` to enable one-second
deadline buckets per shard. Each live key has at most one scheduled
bucket. BasicFlow provides the earliest representable timeout from its
first and last packet clocks. Ordinary packet updates leave the bucket
alone because a refresh can only move that deadline later. A sweep
visits buckets through the current second, consults BasicFlow for the
exact timeout and cause, and moves survivors to their new buckets.
TCP termination, timeout replacement and export remove the key from
its bucket. A sweep may still touch a large cohort if deadlines cluster
or the clock jumps.

The existing offline dispatcher still flushes record-ordered packets
before sending each explicit check, including the final check at EOF.
Realtime continues to advance each shard's check schedule from arriving
packets. The per-packet target-flow timeout check and shutdown sort use
the same clocks. The relative order of rows within a sweep can vary,
as it did with the randomly seeded baseline table.

## Workloads and measurements

Nuccore ran x86-64 Linux 6.18.65-1-lts on an Intel Core Ultra 7 255H
with 24 MiB LLC, the powersave governor and turbo enabled. Both
userspace builds used Rust 1.99.0, default target CPU flags, fat LTO
and one codegen unit. Timings used the release binaries. Separate
`perf record` passes used the release-derived `profiling` binaries with
symbols and line tables. Perf was 7.3.5-2 and tcpreplay was 4.6.2.
Both live builds used the same release eBPF objects from
nightly-2026-10-01 and bpf-linker 0.12.0.

The offline and replay runs used CPUs 0–5, four shard workers, the
full RustiFlow feature set and default Snappy Parquet to `/dev/null`.
Offline timings include reader startup and writer close. Replay
throughput starts after event generation and includes writer close.
Counter runs include generation. Each workload had one warmup per
build, six clean timing runs and four separate counter runs, alternating
the order of baseline and candidate.

- Offline mostly-live has 4,194,304 mixed IPv4/IPv6 UDP frames across
  65,536 biflows. Every flow receives a packet every 16 capture seconds.
  The fixture spans 1,024 capture seconds and uses a 120-second idle
  timeout. Its 1-second interval stresses repeated checks and its
  60-second interval is the default control.
- Offline churn has 2,621,440 frames over 192 capture seconds. There are
  32,768 persistent flows and 4,096 short flows per three-second phase.
  Short keys recur every 24 seconds. The 8-second idle timeout and
  1-second check interval let short flows expire between visits.
- Mostly-live IPv4 replay has 12 million events across 262,144 possible
  keys split between TCP and UDP, 1,400-byte payloads, 4,096-event bursts
  and 15,000 virtual pps. It uses the default idle timeout and both check
  intervals. Churn replay uses 8 million events, 10,000 virtual pps, a
  45-second idle timeout and one-second checks. Each replay spans 800
  virtual seconds.
  The ordered controls use one source. The other replays use eight.

Values are medians with minimum–maximum ranges. Counters cover P-core
userspace and use the known input packet count as the denominator.

| Workload | Base Mpps | Index Mpps | Base cycles/packet | Index cycles/packet |
| --- | ---: | ---: | ---: | ---: |
| Offline mostly-live, 1 s | 5.480 (5.289–5.638) | 5.904 (5.691–6.018) | 2,631 (2,611–2,675) | 1,863 (1,855–1,873) |
| Offline mostly-live, 60 s | 6.044 (5.891–6.270) | 5.891 (5.825–6.096) | 1,797 (1,782–1,823) | 1,865 (1,834–1,890) |
| Offline mixed churn, 1 s | 3.579 (3.468–4.208) | 3.623 (3.576–4.235) | 3,001 (2,761–3,290) | 2,858 (2,849–3,100) |
| Replay mostly-live, 1 s | 2.393 (2.374–2.408) | 4.435 (4.400–4.568) | 3,389 (3,359–3,522) | 2,850 (2,772–2,886) |
| Replay mostly-live, 60 s | 4.830 (4.804–4.908) | 4.608 (4.515–4.708) | 2,449 (2,438–2,453) | 2,614 (2,602–2,623) |
| Replay mostly-live, ordered, 1 s | 2.098 (2.060–2.235) | 3.018 (2.953–3.142) | 3,045 (3,029–3,070) | 2,046 (2,032–2,291) |
| Replay mostly-live, ordered, 60 s | 4.080 (3.195–4.174) | 3.133 (3.025–3.841) | 2,051 (1,914–2,186) | 2,067 (2,030–2,291) |
| Replay mixed churn, 1 s | 1.230 (1.168–1.243) | 1.302 (1.179–1.420) | 10,032 (9,376–10,456) | 9,568 (9,111–10,105) |
| Replay mixed churn, ordered, 1 s | 1.401 (1.375–1.413) | 1.815 (1.740–2.139) | 6,327 (6,311–6,362) | 5,144 (5,127–5,348) |

With one-second checks, mostly-live offline instructions per packet
fell from 3,193.0 (3,192.8–3,193.0) to 2,445.4 (2,445.2–2,445.9).
Mostly-live replay fell from 3,618.7 (3,455.6–3,798.3) to 2,795.1
(2,725.0–2,846.4) instructions per event, and reported generic cache
misses fell from 129.25 to 55.00 per event. In offline mixed churn,
instructions rose 5.6% and elapsed-rate ranges overlapped.

Eight independently scheduled sources can bring a shard's clock ahead
of packets still queued from other sources. The diagnostic eight-source
passes exported 334,425 versus 288,575 rows for the one-second mostly-live
replay, and 5,767,685 versus 5,326,805 rows for churn. In the ordered
controls, both builds produced 272,009 mostly-live rows at each cadence
and 1,520,683 churn rows. The one-second index saved 32.8% of cycles per
event for ordered mostly-live and 18.7% for ordered churn. Ordered
60-second cycle and throughput ranges overlapped. Process peak RSS
for the ordered churn diagnostic was 1,367 MiB on the baseline and
1,405 MiB with the index.

Separate DWARF cycle samples put 38.21% of baseline mostly-live replay
cycles in the expiry sweep at one-second checks. The largest entries
were the inlined cause test and saturating elapsed-time calculation.
The corresponding indexed sweep and iterator entries accounted for
1.09%. The offline mostly-live sweep share fell from 16.73% to 1.30%,
and replay and offline churn fell from 9.08% to 1.78% and from 8.11%
to 4.17%, respectively. At 60 seconds, baseline sweeps accounted for
1.29% of mostly-live replay cycles and 1.67% of offline cycles.
The initial registration, due-key lookups, rebucketing
and removal can outweigh that smaller scan cost. The sampled runs
reported zero lost samples.

## Local realtime capture

The paired veth runs used the release objects, two userspace shards,
separate ingress classifiers for IPv4 and IPv6, and one-second checks.
The 1,048,576-frame trace has 65,536 bidirectional UDP flows, split
evenly between IPv4 and IPv6, with 24- and 448-byte payloads. Each case
had a warmup, four clean repetitions and three separate counter
repetitions per build. The steady and unpaced cases keep the default
idle timeout. The churn case sends three 262,144-frame bursts and waits
3.25 seconds between them with a two-second idle timeout. This makes
the next arriving packets trigger expiry of the previous burst's flows.

Rates use eBPF-submitted packets divided by active tcpreplay send time.
The churn rates exclude pauses. The capture-attached counters cover
the sender invocations and interburst gaps and exclude shutdown.
The measured rates cover the one-sender veth software path and the
listed CPU allocation.

| Case | Base Mpps | Index Mpps | Base cycles/accepted packet | Index cycles/accepted packet |
| --- | ---: | ---: | ---: | ---: |
| Continuous, paced | 0.400 (0.400–0.400) | 0.400 (0.400–0.400) | 3,485 (3,458–3,509) | 3,513 (3,467–3,523) |
| Continuous, unpaced | 0.845 (0.838–0.854) | 0.836 (0.833–0.857) | 6,509 (6,440–6,546) | 6,470 (6,304–6,651) |
| Reused flows, paced bursts | 0.400 (0.400–0.400) | 0.400 (0.400–0.400) | 5,497 (5,482–5,593) | 5,842 (5,794–5,891) |

Unpaced rates overlapped. With burst expiry, the index used 6.3%
more cycles per accepted packet. Clean timing and counter runs
recorded zero eBPF drops for both builds. A separate capture-attached
sample put 0.43% of baseline and 0.45% of indexed userspace cycles in
the expiry sweep symbols on the burst fixture, with zero lost samples.

## Correctness and cleanup

Formatting and warning-denying Clippy passed in both feature modes.
The main crate passed 116 unit tests with the feature disabled and
117 with it enabled, plus five integration tests in each build.
The added regressions cover microsecond thresholds, clock reordering,
active-over-idle precedence, TCP reset and key reuse, and timeouts
beyond representable clock bounds.

Sorted Parquet decoding matched all 203 fields between the builds at
one and four workers. Mostly-live produced 65,536 shutdown rows and
mixed churn produced 294,912 rows, including 249,856 idle expirations.
The packet counts totalled 4,194,304 and 2,621,440 respectively.
Single-source IPv4 and IPv6 replay matched all 203 fields after
normalizing the six timestamps to each replay's epoch. Each 120,000-event
run drained every event with zero source send errors and produced
7,199 rows, including 5,699 snapshots and 1,200 active expirations.

In separate live reconciliation runs the churn case sent, received,
matched, submitted, drained and exported 786,432 packets per build,
split equally between IPv4 and IPv6. Both decoded exports had 131,072
idle-timeout rows and 65,536 shutdown rows. The continuous cases
reconciled 1,048,576 packets each. All three cases matched decoded
flow keys, directions, packet counts and causes with zero ring drops.
Classifier filters were empty after each capture and all experiment
namespaces were removed.
`kernel.bpf_stats_enabled` read zero before and after every live phase.

## Reproduction

Build the baseline from the specified base and preserve the executables.
The baseline profiling build was made in this worktree before any edits.
An archived base also provides an isolated source for both builds.
Run the candidate builds from this worktree and use the same release BPF
objects for both variants.

```bash
root="$PWD/target/experiment"
mkdir -p "$root"/{baseline-src,bins,workloads}
git archive 2fbecc3d8c796841d19b6db8edbfba0c7de42e60 | tar -x -C "$root/baseline-src"
for profile in profiling release; do
    CARGO_TARGET_DIR="$PWD/target" taskset -c 0-5 cargo build --offline --locked \
        --profile "$profile" -p rustiflow -j 6 --manifest-path "$root/baseline-src/Cargo.toml"
    cp "target/$profile/rustiflow" "$root/bins/baseline-$profile"
    taskset -c 0-5 cargo build --offline --locked --profile "$profile" \
        -p rustiflow -j 6 --features experiment-deadline-index
    cp "target/$profile/rustiflow" "$root/bins/candidate-$profile"
done
taskset -c 0-5 cargo xtask ebpf-ipv4 --release
taskset -c 0-5 cargo xtask ebpf-ipv6 --release

python -B docs/profiling/deadline_pcap.py mostly-live "$root/workloads/mostly-live.pcap"
python -B docs/profiling/deadline_pcap.py mixed-churn "$root/workloads/mixed-churn.pcap"
python docs/profiling/generate_pcap.py "$root/workloads/wide.pcap" --packets 1048576 --flows 65536
sha256sum "$root"/workloads/*.pcap
```

For each variant and workload, use the following argument arrays and
the repetition schedule above. Omit `--expiration-check-interval 1`
for the default controls. Keep the default runtime queue settings and
disable per-source diagnostics when timing.

```bash
opts=(-f rustiflow --threads 4 --export-path /dev/null)
mostly=(--expiration-check-interval 1 pcap "$root/workloads/mostly-live.pcap")
churn=(--expiration-check-interval 1 --idle-timeout 8 pcap "$root/workloads/mixed-churn.pcap")
replay_live=(--expiration-check-interval 1 replay-bench --packets 12000000 --flows 262144 \
    --sources 8 --drain-burst 4096 --virtual-pps 15000)
replay_churn=(--expiration-check-interval 1 --idle-timeout 45 replay-bench --packets 8000000 \
    --flows 262144 --sources 8 --drain-burst 4096 --virtual-pps 10000)
events=cpu_core/cycles/u,cpu_core/instructions/u,cpu_core/cache-misses/u
variant=baseline
release_bin="$root/bins/$variant-release"
profile_bin="$root/bins/$variant-profiling"
workload=("${mostly[@]}")
stat="$root/mostly.$variant.stat"
data="$root/mostly.$variant.perf.data"

TIMEFORMAT='%3R %3U %3S'
time taskset -c 0-5 "$release_bin" "${opts[@]}" "${workload[@]}"
taskset -c 0-5 perf stat --no-big-num -x ';' -e "$events" -o "$stat" -- \
    "$release_bin" "${opts[@]}" "${workload[@]}"
sudo -n taskset -c 0-5 perf record -e cpu_core/cycles/u -F 799 --call-graph dwarf,8192 \
    --no-buildid-cache -o "$data" -- "$profile_bin" "${opts[@]}" "${workload[@]}"
sudo -n perf report -f -i "$data" --stdio --no-children -g none --sort symbol,srcline
```

Set `--sources 1` in each replay argument array for the ordered controls.

The live wrapper uses the two-netns setup and readiness check with
`cap0` and `send0` on a veth and `net.ipv6.conf.all.disable_ipv6=1`
inside both temporary namespaces. Capture uses CPUs 0–3 and two
shards. The sender uses CPU 4. The commands below run in the root
harness. It waits one second after sending before SIGINT and checks
both classifier attachment and detach. [Realtime harness](realtime.sh)

```bash
export RUSTIFLOW_EBPF_DIR="$PWD/target/bpfel-unknown-none/release" RUST_LOG=info
ip netns exec "$capture_ns" taskset -c 0-3 "$release_bin" -f rustiflow \
    --threads 2 --export-path "$destination" --expiration-check-interval 1 \
    --idle-timeout "$idle" realtime cap0 --ingress-only >"$capture_log" 2>&1 &
capture_pid=$!
sender=(ip netns exec "$sender_ns" taskset -c 4 tcpreplay --preload-pcap --intf1=send0)
"${sender[@]}" --pps=400000 --limit=1048576 "$root/workloads/wide.pcap"
"${sender[@]}" --topspeed --limit=1048576 "$root/workloads/wide.pcap"
for burst in 1 2 3; do
    "${sender[@]}" --pps=400000 --limit=262144 "$root/workloads/wide.pcap"
    if (( burst < 3 )); then sleep 3.25; fi
done
```

Use one of those sender cases per capture. Keep the 120-second idle
timeout for continuous and unpaced traffic. Use two seconds for the
three-burst case. In the separate counter passes, wrap the sender
case in `perf stat --no-big-num -x ';' -e "$events" -p "$capture_pid"
-o "$stat" --`, with the three bursts and pauses in one shell command.
For the sampled churn run, use the profiling binary and wrap the
sender with `perf record -e cpu_core/cycles/u -F 799 --call-graph dwarf,8192
--no-buildid-cache -p "$capture_pid" -o "$data" --`.
For reconciliation set `RUSTIFLOW_REALTIME_STATS=1` and write a regular
Parquet file. Use `ip -n "$capture_ns" -j -s link show dev cap0` before and
after sending to compute the interface RX delta. The local live driver
is `target/experiment/live.sh` and runs via `sudo -n bash`.

Apply the following checks in both feature modes. For full decoded
offline parity, use the offline workload arguments at one and four
threads with a regular Parquet destination. `target/profile-parquet/readback`
in the main checkout emits the header and sorted decoded rows.

```bash
cargo fmt --all -- --check
for variant in baseline candidate; do
    features=()
    if [[ $variant == candidate ]]; then features=(--features experiment-deadline-index); fi
    taskset -c 0-5 cargo test --offline --locked -p rustiflow -j 6 "${features[@]}"
    taskset -c 0-5 cargo clippy --offline --locked -p rustiflow --all-targets -j 6 "${features[@]}" -- -D warnings
done

RUST_LOG=info RUSTIFLOW_REALTIME_STATS=1 taskset -c 0-5 "$release_bin" \
    -f rustiflow --threads 1 --early-export 1 --active-timeout 4 --idle-timeout 1 \
    --expiration-check-interval 1 --export-path "$destination" replay-bench \
    --packets 120000 --flows 300 --sources 1 --drain-burst 7 --virtual-pps 5000
```

Repeat that parity run with `--ipv6`. Subtract the minimum first packet
timestamp in each run from its six timestamp fields, retaining missing
directions. Then compare sorted decoded rows. For the separate replay
resource and export summaries use the timed workload arguments with
`RUST_LOG=info RUSTIFLOW_PROFILE_RESOURCE_SUMMARY=1
RUSTIFLOW_PROFILE_EXPORT_BREAKDOWN=1`.

The fixture hashes, individual measurements in `repetitions.csv`,
perf data, logs, decoded outputs and local drivers are under
`target/experiment/` in this worktree.
