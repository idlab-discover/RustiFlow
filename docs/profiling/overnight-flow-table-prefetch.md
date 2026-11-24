# Experiment 5 · Staged flow-table lookup on nuccore

Retained as an x86-64 Linux opt-in experiment. At 262,144 full-feature
flows, staging saved 20.5% of cycles in the isolated hit loop and
raised IPv4 and IPv6 replay throughput by 5.2% and 4.8%. At 650 kpps
on veth it used 5.3% more cycles per frame, with overlapping unpaced
rates. The experimental scalar mode also changes the table backing.

On integrated main, add `--features staged-flow-lookup` to the Cargo build
and test commands for the experimental scalar and staged binaries. Default
builds use the standard-library table.

Base `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. Main already canonicalizes
biflow keys, updates occupied entries in place and uses independent
foldhash seeds for the shard selector and each table. Earlier overnight
branches covered key canonicalization, retransmission tracking, Parquet
statistics and shard batch allocation. [Engineering notes](../engineering-notes.md) · [Profiling guide](README.md)

On a large table, an occupied update waits for the SwissTable bucket probe,
the key comparison and then the flow state. Looking up several upcoming
packets together could overlap these loads. The prototype uses hashbrown's
indexed bucket API and stages groups of eight within existing realtime
shard batches. It hashes canonical keys, probes for candidate slots and
emits x86-64 `prefetcht0` for up to four 64-byte-spaced addresses starting
at each found flow. It then applies packets and expiration scans in their
original order. An occupied slot must still match the full canonical key.
A missing or stale hint goes through the authoritative lookup, which also
handles creation. The scratch array owns only keys, hashes and slot hints.
Each table owns one flow per canonical biflow. Partial groups use the
scalar path.

Main is the fresh `std::collections::HashMap` baseline. Scalar uses the
experiment's hashbrown `HashTable` with staging disabled. Staged uses the
same experiment binary with `RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP=1`.
Live capture and userspace replay share the same worker. Offline pcap
uses the scalar lookup and its existing explicit expiration messages.

## CPU and memory profile

The main hit-loop cycle samples assigned 9.39%, 15.27% and 33.39%
of self cycles to the inlined hashbrown bucket comparison at
1,024, 16,384 and 262,144 full-feature flows. Staging brought this line to
2.43%, 6.35% and 13.49%. Separate PEBS user load samples at 262,144
flows found RAM accesses in endpoint equality, flow-direction metadata
and inter-arrival-time feature updates. In four-shard full-feature IPv4
replay, the same main bucket comparison accounted for 1.40%, 9.99%
and 20.38% of self cycles as total cardinality increased. The staged
262,144-flow replay assigned 7.68% to the comparison in the worker.
Perf reported zero lost samples. Disassembly confirmed the emitted
prefetch hints in the staged worker.

## Isolated occupied updates

The ignored hit diagnostic seeds one table, then sends 8,388,608
uniformly selected IPv4 UDP packets in both directions on CPU 2.
It generates packet features in 128-packet groups inside the measured
interval. Perf gates exclude table construction and final export.
Each run verifies one final export per seeded biflow. Each mode had
one warmup, six throughput repetitions and three separate perf stat
repetitions in rotating order. Values are median (min–max).

| Features | Flows | Mode | Mpps | Cycles/packet | Retired L3 misses/packet |
| --- | ---: | --- | ---: | ---: | ---: |
| Basic | 1,024 | main | 16.567 (15.509–20.245) | 247.5 (247.3–247.6) | 0.000 (0.000–0.000) |
| Basic | 1,024 | scalar | 16.465 (11.154–18.030) | 276.1 (276.0–276.1) | 0.000 (0.000–0.000) |
| Basic | 1,024 | staged | 16.988 (8.479–18.997) | 266.4 (266.3–267.0) | 0.000 (0.000–0.000) |
| Basic | 16,384 | main | 14.532 (11.024–17.220) | 278.8 (275.8–288.1) | 0.000 (0.000–0.000) |
| Basic | 16,384 | scalar | 12.508 (7.508–15.877) | 303.4 (299.3–306.3) | 0.000 (0.000–0.000) |
| Basic | 16,384 | staged | 14.289 (8.279–17.718) | 274.1 (273.9–275.0) | 0.000 (0.000–0.000) |
| Basic | 262,144 | main | 4.170 (4.073–4.298) | 529.9 (529.6–570.5) | 2.550 (2.534–2.559) |
| Basic | 262,144 | scalar | 4.263 (4.090–4.312) | 543.1 (535.2–547.6) | 1.794 (1.756–1.800) |
| Basic | 262,144 | staged | 7.474 (6.726–7.640) | 339.4 (338.4–351.5) | 0.955 (0.949–1.004) |
| RustiFlow | 1,024 | main | 8.689 (6.578–12.888) | 386.8 (386.3–392.0) | 0.000 (0.000–0.000) |
| RustiFlow | 1,024 | scalar | 5.912 (5.304–9.783) | 432.6 (427.1–432.8) | 0.000 (0.000–0.000) |
| RustiFlow | 1,024 | staged | 8.767 (7.564–9.904) | 362.5 (362.5–362.8) | 0.000 (0.000–0.000) |
| RustiFlow | 16,384 | main | 4.141 (3.935–4.314) | 602.7 (592.9–643.7) | 1.702 (1.659–1.774) |
| RustiFlow | 16,384 | scalar | 3.888 (3.773–4.093) | 626.3 (624.5–633.8) | 1.891 (1.828–1.915) |
| RustiFlow | 16,384 | staged | 4.679 (4.245–4.940) | 532.1 (531.3–540.6) | 1.204 (1.178–1.298) |
| RustiFlow | 262,144 | main | 2.334 (2.308–2.362) | 973.8 (971.4–983.3) | 9.213 (8.760–9.324) |
| RustiFlow | 262,144 | scalar | 2.320 (2.278–2.348) | 985.5 (979.7–985.7) | 9.053 (9.024–9.058) |
| RustiFlow | 262,144 | staged | 2.913 (2.881–2.924) | 774.3 (774.1–780.3) | 4.992 (4.542–5.112) |

At 262,144 full-feature flows, staging saved 20.5% of cycles and 45.8%
of retired L3 misses per packet versus main. Instructions rose from
902.0 to 1,058.1 per packet. Generic cache misses rose from 35.36
(34.46–36.37) to 38.24 (37.96–39.27) per packet. Retired L2 misses fell from 9.96 (9.49–10.08) to 6.04 (5.62–6.15). The demand-load and
generic counters cover different events. At the same cardinality,
Basic saved 36.0% of cycles. Small Basic tables showed a cycle cost
increase and wide elapsed-rate spread.

## Userspace pipeline

Replay used 12 million synthetic packets per run, eight sources, four
flow-table workers on CPUs 0–5, 4,096-event source bursts and default
Snappy Parquet to `/dev/null`. Half the flows are TCP and half are UDP.
Payloads are 1,400 bytes and virtual spacing is 1 µs. The same repetition
schedule as the hit diagnostic applies. Throughput starts after event
generation and includes writer close. Counters include event generation.

| Features | Flows | Mode | Mpps | Cycles/packet | Retired L3 misses/packet |
| --- | ---: | --- | ---: | ---: | ---: |
| RustiFlow IPv4 | 1,024 | main | 28.294 (23.131–31.703) | 807.5 (797.4–824.2) | 0.016 (0.015–0.016) |
| RustiFlow IPv4 | 1,024 | scalar | 31.526 (27.957–32.391) | 823.6 (808.7–838.8) | 0.015 (0.014–0.016) |
| RustiFlow IPv4 | 1,024 | staged | 31.856 (24.670–34.389) | 761.9 (758.6–771.8) | 0.017 (0.016–0.019) |
| RustiFlow IPv4 | 16,384 | main | 16.345 (15.787–16.555) | 1379.2 (1373.3–1381.7) | 1.299 (1.291–1.314) |
| RustiFlow IPv4 | 16,384 | scalar | 16.490 (16.254–16.684) | 1365.9 (1364.7–1378.1) | 1.308 (1.303–1.344) |
| RustiFlow IPv4 | 16,384 | staged | 17.520 (17.384–17.785) | 1301.2 (1291.7–1304.5) | 0.986 (0.969–0.993) |
| RustiFlow IPv4 | 262,144 | main | 5.299 (5.192–5.414) | 2274.5 (2264.1–2284.9) | 8.238 (8.231–8.250) |
| RustiFlow IPv4 | 262,144 | scalar | 5.415 (5.346–5.533) | 2314.4 (2273.7–2325.3) | 8.192 (8.186–8.211) |
| RustiFlow IPv4 | 262,144 | staged | 5.575 (5.484–5.608) | 2058.6 (1989.8–2092.1) | 6.506 (6.486–6.517) |
| Basic IPv4 | 262,144 | main | 15.790 (15.346–16.151) | 1286.8 (1283.8–1297.5) | 2.518 (2.507–2.535) |
| Basic IPv4 | 262,144 | scalar | 16.846 (15.981–17.306) | 1331.9 (1314.8–1340.6) | 1.961 (1.940–1.966) |
| Basic IPv4 | 262,144 | staged | 26.167 (25.136–26.469) | 905.4 (876.4–957.7) | 1.068 (1.061–1.070) |
| RustiFlow IPv6 | 262,144 | main | 5.184 (5.052–5.268) | 2264.1 (2252.4–2270.3) | 8.142 (8.135–8.156) |
| RustiFlow IPv6 | 262,144 | scalar | 5.229 (5.156–5.326) | 2294.8 (2271.2–2298.7) | 8.104 (8.063–8.141) |
| RustiFlow IPv6 | 262,144 | staged | 5.432 (5.265–5.548) | 1999.9 (1986.3–2021.4) | 6.475 (6.457–6.488) |

At 262,144 flows, staging improved full-feature replay by 5.2% for IPv4
and 4.8% for IPv6, and improved Basic IPv4 by 65.7%. Full-feature IPv4
instructions rose from 2,280.4 (2,280.2–2,280.5) to 2,432.7
(2,432.3–2,432.9) per event. Whole-command full-feature pcap throughput
was 3.957 (3.948–3.967) Mpps on main and 3.956 (3.948–3.964) Mpps
with the scalar table. The scalar pcap cycles were 2,386.1
(2,377.7–2,411.2) per packet versus 2,279.5 (2,231.8–2,353.0)
on main. The pcap used the same four workers, output and repetition schedule.

## Prefetch control

A second local build set only `PREFETCH_BYTES=0` and kept staging enabled.
Disassembly confirmed the absence of `prefetcht0` in that build. The two
binaries had one warmup, four alternating throughput runs and three
separate counter runs on the full-feature workloads.

| Workload | Flows | Mode | Mpps | Cycles/packet | Retired L3 misses/packet |
| --- | ---: | --- | ---: | ---: | ---: |
| Isolated hits | 1,024 | Staged without hints | 10.495 (7.694–13.270) | 366.8 (363.5–366.9) | 0.000 (0.000–0.000) |
| Isolated hits | 1,024 | Staged with hints | 8.944 (6.788–11.208) | 362.6 (362.6–363.1) | 0.000 (0.000–0.000) |
| Isolated hits | 16,384 | Staged without hints | 4.701 (4.572–4.720) | 551.4 (550.6–554.0) | 1.417 (1.380–1.422) |
| Isolated hits | 16,384 | Staged with hints | 4.672 (4.550–4.810) | 551.4 (548.4–564.4) | 1.324 (1.179–1.354) |
| Isolated hits | 262,144 | Staged without hints | 2.633 (2.610–2.647) | 863.1 (847.8–951.8) | 6.115 (5.956–6.121) |
| Isolated hits | 262,144 | Staged with hints | 2.870 (2.838–2.886) | 793.2 (791.9–799.3) | 4.169 (4.146–4.278) |
| IPv4 replay | 262,144 | Staged without hints | 5.415 (5.368–5.464) | 2110.7 (2109.8–2120.7) | 6.974 (6.947–7.021) |
| IPv4 replay | 262,144 | Staged with hints | 5.530 (5.330–5.567) | 2085.2 (2048.5–2103.0) | 6.484 (6.472–6.510) |

With 262,144 flows, the explicit hints saved another 8.1% of hit-loop
cycles and 31.8% of retired L3 misses versus staging alone. The replay
throughput ranges overlapped and the median cycle saving was 1.2%.

## Live veth

A 65,536-biflow pcap contained 1,048,576 mixed IPv4/IPv6 UDP frames,
with alternating directions each pass and 24- or 448-byte payloads.
Its SHA-256 was
`45fa447caf05e882d9a59d6d0d4d9f4a2d305049ec5a910921d781ab408393c1`.
Capture used two flow-table workers on CPUs 0–3. One tcpreplay sender
ran on CPU 4. Both classifiers used the same release objects for
all modes. Each rate and mode had four throughput runs and four
separate counter runs in rotating order. Perf covered capture userspace
during the sender invocation. The final drain and writer close followed
that window. Timed passes used default Parquet to `/dev/null`.

| Offered rate | Mode | Mpps admitted | Cycles/submitted frame | Retired L3 misses/submitted frame |
| --- | --- | ---: | ---: | ---: |
| 650 kpps | main | 0.650 (0.650–0.650) | 3585.9 (3449.1–3634.2) | 8.658 (8.417–8.750) |
| 650 kpps | scalar | 0.650 (0.650–0.650) | 3660.5 (3585.1–4022.5) | 8.960 (8.636–9.261) |
| 650 kpps | staged | 0.650 (0.650–0.650) | 3775.4 (3685.3–4041.8) | 9.185 (9.124–9.363) |
| Unpaced | main | 0.831 (0.817–0.848) | 6336.4 (6318.1–6418.4) | 8.708 (8.609–8.792) |
| Unpaced | scalar | 0.826 (0.820–0.837) | 6444.6 (6410.6–6495.3) | 9.179 (9.130–9.239) |
| Unpaced | staged | 0.827 (0.817–0.833) | 6450.0 (6419.7–6495.1) | 9.241 (9.174–9.282) |

At 650 kpps the staged mode used 5.3% more cycles per submitted frame
than main. Unpaced software rates overlapped across modes at
0.817–0.848 Mpps in the throughput runs. For capacity context, 100 and
400 Gbps at 1,518-byte Ethernet frames plus preamble and interframe gap
require 8.13 and 32.51 Mpps. The replay and veth rates describe nuccore's
userspace and local software capture workloads.

All 54 live passes sent and received all 1,048,576 frames with zero
sender failures or veth RX drops. Each classifier matched and submitted
524,288 frames with zero ring drops. The six separate reconciliation
runs at paced and unpaced rates drained the same counts per family with
zero source send errors. All six decoded Parquet files matched the
offline fixture's 65,536 biflow IDs, protocols, address families and
forward and backward packet counts. Normal shutdown detached both
filters every time. The harness removed the temporary namespaces and
host `kernel.bpf_stats_enabled` was 0 before and after.

## Correctness

The staged lifecycle regression forces table growth before consuming
hints, resets and recreates a biflow in reverse direction, exercises early
export, expires flows both in a sweep and on a hit, and checks the scalar
tail. It compares full exported rows in order. The optimized unit
binary passed 115 tests with the diagnostic ignored. All five Parquet
integration tests passed, including the default Parquet/CSV parity test.
`cargo fmt`, `cargo fmt --all -- --check`, `git diff --check`,
`cargo check --offline --locked -p rustiflow` and
`cargo clippy --offline --locked -p rustiflow --all-targets -- -D warnings`
passed.

Main, scalar and staged emitted the same 203 decoded fields for all
65,536 offline rows, including exact timestamps and 1,048,576 packets.
The sorted decoded SHA-256 was
`b4e0bb314b7a66a636e1948af0ec308dbd04324f1288134dfa9612a4cc3e6b3c`.
A 120,000-event single-source replay for each family used source bursts
of 7 and 257 to exercise partial and full stage groups with one-slot queues.
Each mode exported 1,800 rows with early snapshots and active expiration.
All 203 fields matched after subtracting the synthetic epoch origin
from the six timestamp fields and preserving missing directions. All
120,000 events drained with zero source send errors in every run.

## Reproduction

Nuccore is an Intel Core Ultra 7 255H running x86-64 Linux
6.18.65-1-lts with 24 MiB LLC, the `powersave` governor and turbo enabled.
Rust 1.99.0 built the userspace targets with x86-64-v3 and workspace fat
LTO. Perf was 7.3.5-2 and tcpreplay was 4.6.2. The shared BPF objects used
nightly-2026-10-01 and bpf-linker 0.12.0.

From the baseline and experiment source trees, use the same commands and
archive each executable before switching builds. For the baseline hit diagnostic,
carry over the ignored test and its module declaration and replace
`table.process_batch(&batch).await` with the original per-packet loop
`for packet in &batch { table.process_packet(packet).await; }`.

```bash
export CARGO_TARGET_DIR="$PWD/target"
export RUSTFLAGS='-C target-cpu=x86-64-v3'
cargo build --offline --locked --profile profiling -p rustiflow -j 6
cargo build --offline --locked --release -p rustiflow -j 6
cargo test --offline --locked --profile profiling -p rustiflow --bin rustiflow \
    --no-run -j 6 --message-format=json
unset RUSTFLAGS
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
python docs/profiling/generate_pcap.py target/experiment/wide.pcap \
    --packets 1048576 --flows 65536
```

Archive the test executable from the Cargo JSON `executable` field where
`profile.test` is true. Select main's binaries for the baseline or the
experiment binaries for scalar and staged. Set
`RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP=1` for staged and `0` otherwise.
Use default realtime queue settings. Perf counted P-core userspace
cycles, instructions, generic cache misses and retired L3 and L2 load misses.
At `perf_event_paranoid=2`, recording DWARF stacks used `sudo -n`.
The stat and PEBS passes for the hit diagnostic ran unprivileged.

```bash
export RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP="$toggle"
events=cpu_core/cycles/u,cpu_core/instructions/u,cpu_core/cache-misses/u,cpu_core/mem_load_retired.l3_miss/u,cpu_core/mem_load_retired.l2_miss/u
hit=( "$test_bin" tests::flows::flow_table_hit_bench::flow_table_hit_bench
      --ignored --exact --nocapture )
export RUSTIFLOW_HIT_BENCH_FEATURE="$feature" RUSTIFLOW_HIT_BENCH_FLOWS="$flows"
taskset -c 2 "${hit[@]}"
RUSTIFLOW_HIT_BENCH_PAUSE=1 taskset -c 2 perf stat --no-big-num -x ';' \
    -e "$events" --delay=-1 --control="fifo:$control,$ack" -o "$stat" -- "${hit[@]}"
sudo -n env RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP="$toggle" \
    RUSTIFLOW_HIT_BENCH_PAUSE=1 RUSTIFLOW_HIT_BENCH_FEATURE="$feature" RUSTIFLOW_HIT_BENCH_FLOWS="$flows" \
    taskset -c 2 perf record -e cpu_core/cycles/u \
    -F 999 --call-graph dwarf,8192 --delay=-1 --control="fifo:$control,$ack" \
    --no-buildid-cache -o "$data" -- "${hit[@]}"
RUSTIFLOW_HIT_BENCH_PAUSE=1 taskset -c 2 perf record -e cpu_core/mem-loads,ldlat=30/upp \
    -c 4093 -d -W --sample-mem-info --delay=-1 --control="fifo:$control,$ack" \
    --no-buildid-cache -o "$data" -- "${hit[@]}"

opts=( -f "$feature" --export-path /dev/null --threads 4 replay-bench
       --packets 12000000 --flows "$flows" --sources 8 --drain-burst 4096 )
taskset -c 0-5 "$release_bin" "${opts[@]}"
taskset -c 0-5 perf stat --no-big-num -x ';' -e "$events" -o "$stat" -- "$release_bin" "${opts[@]}"
sudo -n env RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP="$toggle" \
    taskset -c 0-5 perf record -e cpu_core/cycles/u -F 999 --call-graph dwarf,8192 \
    --no-buildid-cache -o "$data" -- "$profile_bin" "${opts[@]}"
sudo -n perf report -f -i "$data" --stdio --no-children -g none --sort symbol,srcline
perf script -i "$load_data" -F ip,sym,srcline,weight,data_src
pcap_opts=( -f rustiflow --export-path /dev/null --threads 4 pcap "$pcap" )
taskset -c 0-5 "$release_bin" "${pcap_opts[@]}"
taskset -c 0-5 perf stat --no-big-num -x ';' -e "$events" -o "$stat" -- "$release_bin" "${pcap_opts[@]}"
```

For the gated hit runs, create the control and acknowledgment FIFOs with
`mkfifo`. When the test emits `HIT_BENCH_READY`, send `enable`, read perf's
acknowledgment, and send a newline to the test's stdin. Repeat with `disable`
and a newline on `HIT_BENCH_DONE`. Add `--ipv6` for IPv6 userspace replay.

The live wrapper under `target/experiment/live.sh` follows the
[temporary veth harness](realtime.sh). It runs under `sudo -n`, verifies
classifier attachment and waits one second after sending before SIGINT.

```bash
export RUSTIFLOW_EBPF_DIR="$PWD/target/bpfel-unknown-none/release" RUST_LOG=info
ip netns exec "$capture_ns" taskset -c 0-3 "$release_bin" -f rustiflow \
    --export-path "$destination" --threads 2 realtime cap0 --ingress-only >"$capture_log" 2>&1 &
capture_pid=$!
sender=( ip netns exec "$sender_ns" taskset -c 4 tcpreplay --preload-pcap
         "--pps=$rate" --limit=1048576 --intf1=send0 "$pcap" )
"${sender[@]}"
perf stat --no-big-num -x ';' -e "$events" -p "$capture_pid" -o "$stat" -- "${sender[@]}"
```

Use `--topspeed` for the unpaced sender. Reconciliation sets
`RUSTIFLOW_REALTIME_STATS=1` and uses a regular Parquet destination.
The decoded-output replay used both address families and each test burst.

```bash
RUST_LOG=info RUSTIFLOW_REALTIME_STATS=1 RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE=16 \
    RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY=1 \
    RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY=1 \
    taskset -c 0-5 "$release_bin" -f rustiflow --threads 1 --early-export 1 \
    --active-timeout 2 --expiration-check-interval 1 --export-path "$output" \
    replay-bench --packets 120000 --flows 300 --sources 1 --drain-burst "$burst" --virtual-pps 20000
cargo test --offline --locked -p rustiflow --test parquet_output -j 6
```

The existing `target/profile-parquet/readback` utility from the main checkout
decoded the regular Parquet files. The raw repetitions, timings, profiles,
build logs, decoder outputs and harness scripts are under `target/experiment/`
in this worktree.
