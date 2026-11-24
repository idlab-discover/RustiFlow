# Experiment 3 · Parquet Float64 statistics on nuccore

Retain the prototype as a local Cargo patch for Parquet 60.2.0. The AVX2
reduction saved 47% of cycles per value in isolation and 4.5% of instructions
per input event in export-heavy replay. The replay throughput change was about
1%, within run-to-run spread. The registry dependency remains the default.
[Prototype patch](parquet-60.2.0-f64-avx2.patch)

## Hypothesis and CPU profile

Base `2fbecc3d8c796841d19b6db8edbfba0c7de42e60` already projects finished
flows into typed shard buffers and encodes its 512–4,096-row groups in parallel.
Experiments 1 and 2 covered biflow canonicalization and TCP retransmission
tracking. This experiment targets the contiguous Double column pass that
computes min, max and NaN count before plain encoding and Snappy compression.
[Engineering notes](../engineering-notes.md) · [Profiling guide](README.md)

The first fresh baseline sample attributed 2.54% of export-heavy replay P-core
self cycles to `min_max_f64`, compared with 7.21% in Snappy and 5.67% in
`BatchRow::append`. On the standard pcap the reduction took 0.13%.
Four subsequent DWARF samples per variant put the combined Float64
reduction symbols at 2.10% (1.16–2.44%) baseline and 1.44% (1.35–1.81%)
candidate for export-heavy replay. The offline shares were 0.22%
(0.15–0.29%) and 0.21% (0.12–0.22%). Perf reported zero lost samples.

The scan lives in Parquet's private column encoder. The local dependency
patch dispatches Double statistics to AVX2 on supported x86-64 hosts for
slices of 32 values or more. The kernel reduces four IEEE-ordered
integer keys per vector, masks NaNs out of the bounds, counts them, and
finishes the 0–3-value tail scalarly. An all-NaN slice defers to Parquet's
existing total-order fallback. The original reduction serves shorter inputs
and hosts without AVX2. The existing writer controls page and row group
boundaries, encoding, compression and footer metadata. Disassembly showed
`vpcmpgtq`, `vpblendvb` and `vpsubq` in the candidate kernel.

The isolated diagnostic extracted both kernels from the patched crate and
called them on CPU 0 with the same optimized generic x86-64 code generation.
It scanned 64 deterministic slices of 1,024–1,027 values per iteration, with
mixed float bit patterns including NaNs, zeros, infinities and subnormals.
Each repetition processed 268,828,672 values. One warmup and six alternating
counter pairs gave these medians and min–max ranges.

| Reducer | Cycles/value | Instructions/value |
| --- | ---: | ---: |
| Existing | 3.328 (3.282–3.377) | 21.070 (21.070–21.070) |
| AVX2 dispatch | 1.777 (1.775–1.777) | 4.130 (4.130–4.130) |

## Matched Parquet throughput

Both stripped release executables used four workers on CPUs 0–5, full
`rustiflow` features and default Snappy Parquet. The mixed IPv4/IPv6 UDP
pcap contains 2 million packets across 10,000 flows. The IPv4 replays use
eight sources, 100,000 possible flows and the default 4,096-event drain burst.
Offline and short replay wrote regular files on the same filesystem, with
median sizes of roughly 1.41 and 35.3 MB respectively. Long replay used
`/dev/null`. Offline wall time includes startup and file close. The replay
interval starts after generation and includes writer close. The timing
pass ran two warmups and 16 alternating pairs per case, with eight pairs
for long replay. Values are medians with min–max in parentheses.

| Workload | Baseline Mpps | Candidate Mpps | Change |
| --- | ---: | ---: | ---: |
| 1M replay, regular file | 4.132 (3.690–4.274) | 4.175 (3.922–4.367) | +1.0% |
| 2M pcap, regular file | 7.541 (6.992–7.942) | 7.557 (6.803–7.864) | +0.2% |
| 10M replay, `/dev/null` | 6.268 (6.146–6.309) | 6.238 (6.150–6.329) | −0.5% |

<details>
<summary>Throughput repetitions in Mpps</summary>

| Workload | Variant | Runs in pair order |
| --- | --- | --- |
| 1M replay | Baseline | 4.032, 3.690, 4.016, 4.274, 4.167, 4.132, 4.115, 4.132, 4.184, 4.132, 4.167, 4.149, 4.202, 4.065, 4.115, 4.167 |
| 1M replay | Candidate | 4.115, 4.202, 4.149, 4.184, 4.082, 4.115, 4.184, 4.167, 4.367, 3.922, 4.184, 4.202, 4.115, 4.184, 4.219, 4.082 |
| 2M pcap | Baseline | 7.548, 7.496, 7.529, 7.942, 7.363, 7.503, 7.741, 7.254, 7.582, 7.561, 7.787, 7.556, 7.533, 7.405, 7.758, 6.992 |
| 2M pcap | Candidate | 7.506, 7.554, 7.614, 7.647, 7.864, 7.573, 7.675, 7.561, 6.803, 7.527, 7.554, 7.644, 7.180, 7.551, 7.536, 7.604 |
| 10M replay | Baseline | 6.309, 6.270, 6.146, 6.281, 6.234, 6.277, 6.266, 6.254 |
| 10M replay | Candidate | 6.177, 6.215, 6.150, 6.262, 6.274, 6.184, 6.329, 6.274 |

</details>

Separate `perf stat` runs used eight alternating pairs per case, with
four pairs for long replay. Counters cover whole-process userspace,
including replay generation, divided by input packets or events.

| Workload | Baseline cycles/input | Candidate cycles/input | Baseline instructions/input | Candidate instructions/input |
| --- | ---: | ---: | ---: | ---: |
| 1M replay | 3,574.7 (3,498.8–3,690.2) | 3,620.4 (3,492.9–3,731.8) | 5,132.6 (5,123.8–5,135.7) | 4,902.8 (4,899.3–4,904.6) |
| 2M pcap | 1,076.2 (1,071.4–1,083.0) | 1,075.6 (1,068.1–1,082.4) | 1,946.8 (1,946.1–1,947.1) | 1,935.4 (1,935.1–1,936.2) |
| 10M replay | 1,902.3 (1,894.9–1,913.7) | 1,896.8 (1,894.2–1,903.3) | 1,944.2 (1,944.0–1,944.6) | 1,921.7 (1,921.2–1,921.8) |

Median process CPU cost inside short replay was 1,119.3 ns/event baseline
and 1,113.3 ns/event candidate. The median paired change was −0.1%.
Whole-process cycle and throughput ranges overlap in all three cases.
For scale, 1,518-byte Ethernet frames with preamble
and interframe gap require 8.13 Mpps at 100 Gbps and 32.51 Mpps at 400 Gbps.
Replay and the pcap measure software processing on nuccore.

The separate offline end-of-input diagnostic reused the marker in
`export_tail.py`. After two warmup pairs and twelve timed pairs, the time
from the end-of-input log line to process exit was 11.56 ms (10.38–12.58)
baseline and 11.29 ms (9.53–16.24) candidate.

## Correctness and live reconciliation

Arrow readback matched the schema and all 203 fields of 10,000 offline
rows and 99,994 short-replay rows. The comparison sorted complete rows
to account for concurrent shard submission and checked floating-point
bit patterns. Offline timestamps matched exactly. Replay compared the six
timestamp fields as microsecond offsets from each run's origin and
preserved the missing-direction sentinel. The decoded SHA-256 values were
`200dd7af66165d3f11b39ba5aa7d38a9b462d2a0d9fd60736ed10aa467ae2bfe`
for offline and
`0149f811e4c0c440c6e287dd64332de23505de26b505cfc2000a7c0efe714ded`
for replay. Both readbacks conserve all 2 million offline packets and
all 1 million replay events.

The Double-column regression test decodes 95 Snappy row groups with 1–4,097
values each. It checks actual value bits in file order and column-chunk
min/max bits and NaN counts. Inputs cover the dispatch boundary, vector
tails, signed zeros, subnormals, both infinities, signaling and quiet NaN
payloads, and all-NaN groups. The existing integration tests cover all six
feature sets, both projection modes, empty captures, replay totals and
writer errors.

`cargo test --locked --release -p rustiflow --test parquet_output`
passed all six tests with the registry dependency and with the patch
override. `cargo fmt --all -- --check`, rustfmt on the patched file,
`cargo clippy --locked -p rustiflow --test parquet_output -- -D warnings`,
and `git diff --check` passed.

Two alternating live reconciliation pairs used the existing temporary
namespace and veth harness, two capture workers on CPUs 0–3 and tcpreplay
on CPU 4. The first 300,000 pcap frames achieved 199,974.93–199,995.06 pps
across the four sender-paced runs. Each classifier matched and submitted
150,000 events per run with zero ring drops. Userspace drained both sets
of 150,000 with zero dispatch errors. Each file decoded the same 10,000
flow IDs and counts of 30 packets per flow, split 15 per direction.
The namespace list and `kernel.bpf_stats_enabled=0` matched their
pre-test values.

## Reproduction

Nuccore ran Linux `6.18.65-1-lts` on an Intel Core Ultra 7 255H with the
`powersave` P-core governor and turbo enabled. Both binaries used Rust
`1.99.0`, generic x86-64 code generation and the workspace fat LTO
profiles. The profiling profile inherits release and retains symbols and
line tables. Perf was `7.3.5-2`.

```bash
exp="$PWD/target/experiment"
mkdir -p "$exp"
ln -s /home/strgenix/postdoc/RustiFlow/target/profile-baseline/mixed.pcap "$exp/mixed.pcap"
cargo build --locked --profile profiling -p rustiflow
cp target/profiling/rustiflow "$exp/baseline"
CARGO_TARGET_DIR="$PWD/target/release-build" taskset -c 6-13 \
    cargo build --locked --release -p rustiflow
cp target/release-build/release/rustiflow "$exp/baseline-release"

(
    cp Cargo.lock "$exp/Cargo.lock.registry"
    trap 'cp "$exp/Cargo.lock.registry" Cargo.lock' EXIT
    parquet_src=$(find ~/.cargo/registry/src -maxdepth 2 -type d -name parquet-60.2.0 -print -quit)
    cp -a "$parquet_src" "$exp/parquet-60.2.0"
    patch --fuzz=0 -d "$exp/parquet-60.2.0" -p1 < docs/profiling/parquet-60.2.0-f64-avx2.patch
    config="patch.crates-io.parquet.path=\"$exp/parquet-60.2.0\""
    cargo update --offline --config "$config" -p parquet
    cp Cargo.lock "$exp/Cargo.lock.candidate"
    CARGO_TARGET_DIR="$PWD/target/release-build" taskset -c 6-13 \
        cargo build --locked --release --config "$config" -p rustiflow
    cp target/release-build/release/rustiflow "$exp/candidate-release"
    taskset -c 6-13 cargo build --locked --profile profiling --config "$config" -p rustiflow
    cp target/profiling/rustiflow "$exp/candidate-profiling"
)
```

Use `mode=baseline` or `candidate`. For offline use `pcap "$exp/mixed.pcap"`
and a regular output path. For long replay use 10 million events and
`/dev/null`. The input pcap SHA-256 is
`601d3d0590117b17e7a420198fe0a4ab058961dbd2bfc0acd360b5a629245661`.

```bash
args=(-f rustiflow --export-path "$exp/export-heavy-timed.parquet" --threads 4
      replay-bench --packets 1000000 --flows 100000 --sources 8)
taskset -c 0-5 "$exp/$mode-release" "${args[@]}"
taskset -c 0-5 perf stat --no-big-num -x ';' -e cpu_core/cycles/u,cpu_core/instructions/u \
    -o "$stat" -- "$exp/$mode-release" "${args[@]}"

# Set bin to "$exp/baseline" or "$exp/candidate-profiling" and use a distinct output file.
sudo -n taskset -c 0-5 perf record -e cpu_core/cycles/u -F 1999 \
    --call-graph dwarf,8192 --no-buildid-cache -o "$data" -- "$bin" "${args[@]}"
sudo -n perf report -f -i "$data" --stdio --no-children --percent-limit 0.1 -g none
sudo -n perf report -f -i "$data" --stdio --no-children --percent-limit 0.04 -s srcline,symbol -g none
```

The live runs used the same release objects from pinned nightly
`2026-10-01` and bpf-linker `0.12.0`. The local live script adapts
`realtime.sh` to retain a regular Parquet file and enable source accounting
with `RUSTIFLOW_REALTIME_STATS=1`. It allows one second for drain after
the sender exits, then stops capture with SIGINT. Its sender ran tcpreplay
`4.6.2`.

```bash
for family in ipv4 ipv6; do
    CARGO_TARGET_DIR="$PWD/target/ebpf-build" taskset -c 10-13 \
        cargo xtask "ebpf-$family" --release
done
sudo -n env RUSTIFLOW_EBPF_DIR="$PWD/target/ebpf-build/bpfel-unknown-none/release" \
    RUSTIFLOW_PROFILE_BIN="$exp/baseline-release" \
    RUSTIFLOW_PROFILE_CANDIDATE="$exp/candidate-release" \
    bash "$exp/live.sh" "$exp/live" "$exp/mixed.pcap"
# Inside the sender namespace, on CPU 4
tcpreplay --preload-pcap --pps=200000 --limit=300000 --intf1=send0 "$exp/mixed.pcap"
```

The isolated and end-of-input diagnostics used the local scripts.

```bash
python "$exp/make-reducer-bench.py"
taskset -c 6 rustc --edition=2024 -C opt-level=3 -C codegen-units=1 -C lto=fat \
    "$exp/reducer-bench.rs" -o "$exp/reducer-bench"
taskset -c 0 perf stat --no-big-num -x ';' -e cpu_core/cycles/u,cpu_core/instructions/u \
    -o "$stat" -- "$exp/reducer-bench" "$reducer_mode" # scalar or dispatch
python -B "$exp/tail.py"
```

Local run scripts, build logs, bare timings, counter repetitions,
profiles and decoded files are under `target/experiment/`.
