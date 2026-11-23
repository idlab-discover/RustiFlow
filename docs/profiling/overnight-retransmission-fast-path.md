# Experiment 2 · TCP retransmission tracking on nuccore

Retained on the experiment branch. Median replay throughput improved
15.2–15.6% across both address families and drain bursts.

Base `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. The existing TCP tracker
unwraps sequence numbers and searches, removes, and reinserts tree entries
for contiguous arrivals. Earlier work established the 1,024-range bound
per direction and eviction by lowest sequence. This experiment tests
whether an inline highest range saves that work on ordered TCP traffic.
[Engineering notes](../engineering-notes.md) · [Profiling guide](README.md)

The highest merged half-open range stays inline in unwrapped sequence
space. Equality with its low 32-bit end advances it without a tree
operation, including at rollover and after a gap has been observed. A
segment beyond a gap moves the former highest range into the tree.
Earlier arrivals can merge stored ranges back into the inline range.
Overlap is detected before merging, and eviction still bounds the
combined history to 1,024 ranges. Both versions occupy 40 bytes per
direction on x86-64. Callers use the same feature API.

## CPU profile

Fresh DWARF call graphs at 999 Hz sampled userspace P-core cycles in
separate replay runs with a 4,096-event drain burst. Each profile
collected roughly 7,000–9,000 samples with zero reported losses. The baseline's tracker was
the second-largest self-cycle symbol. The source-line report attributed
6.66% of total IPv4 cycles and 7.31% of total IPv6 cycles to a single
inlined B-tree search line in that symbol.

| Self cycles by symbol | IPv4 base | IPv4 candidate | IPv6 base | IPv6 candidate |
| --- | ---: | ---: | ---: | ---: |
| Tracker | 11.19% | 0.28% | 11.60% | 0.34% |
| Flow-table packet processing | 32.80% | 37.53% | 33.78% | 41.05% |

The baseline tracker symbol was `update_direction`. The candidate's
fast path inlined into the feature's `update` symbol. The source-line
report placed 0.20% and 0.25% of all sampled cycles on its sequence
comparison for IPv4 and IPv6 respectively.

## Userspace replay

The input contains 10 million synthetic events across 100,000 possible
bidirectional flows and eight sources, with half TCP and half UDP by flow.
TCP data is contiguous within each direction. Payloads are 1,400 bytes,
arrivals are spaced at 1 µs virtual time, and each family runs separately.
Both builds use four flow-table workers on CPUs 0–5 and default Parquet to
`/dev/null`. Burst 4,096 is the CLI default, and burst 256 increases the
frequency of partial batches and source yields.

Each case used one warmup per binary, eight alternating pairs for
throughput and four separately counted pairs, also alternating first
position. Throughput and CPU ns/event use the built-in replay interval
through writer close. The hardware counters cover the whole process,
including event generation, divided by 10 million input events.
Values are medians with min–max in parentheses.

| Replay (burst) | Base Mpps | Candidate Mpps | Change | Base CPU ns/event | Candidate CPU ns/event |
| --- | ---: | ---: | ---: | ---: | ---: |
| IPv4 (4,096) | 6.312 (6.189–6.358) | 7.290 (7.200–7.371) | +15.49% | 749.8 (743.6–758.4) | 641.0 (636.3–646.3) |
| IPv6 (4,096) | 6.198 (6.153–6.241) | 7.165 (7.095–7.192) | +15.60% | 765.1 (762.1–777.7) | 662.0 (655.5–668.1) |
| IPv4 (256) | 6.191 (6.072–6.206) | 7.149 (7.080–7.267) | +15.49% | 742.5 (736.2–747.5) | 648.0 (637.5–654.6) |
| IPv6 (256) | 6.139 (6.005–6.170) | 7.072 (6.921–7.119) | +15.20% | 749.8 (740.7–752.6) | 655.1 (647.0–658.8) |

| Replay (burst) | Base cycles/event | Candidate cycles/event | Base instructions/event | Candidate instructions/event |
| --- | ---: | ---: | ---: | ---: |
| IPv4 (4,096) | 1987.4 (1959.3–1993.2) | 1867.7 (1831.0–1876.4) | 1944.5 (1943.8–1944.7) | 1781.1 (1780.8–1781.3) |
| IPv6 (4,096) | 1983.5 (1976.7–1999.4) | 1835.8 (1763.7–1850.3) | 1921.4 (1921.3–1921.5) | 1758.2 (1757.9–1758.7) |
| IPv4 (256) | 1961.9 (1956.3–1966.6) | 1873.0 (1871.2–1894.6) | 1968.6 (1968.1–1968.8) | 1805.1 (1804.7–1806.1) |
| IPv6 (256) | 1988.9 (1950.0–1999.3) | 1860.6 (1855.2–1879.9) | 1946.0 (1945.8–1946.1) | 1783.0 (1782.6–1783.4) |

<details>
<summary>Eight throughput repetitions per variant in Mpps</summary>

| Replay (burst) | Baseline | Candidate |
| --- | --- | --- |
| IPv4 (4,096) | 6.339, 6.358, 6.346, 6.189, 6.195, 6.316, 6.308, 6.294 | 7.236, 7.371, 7.277, 7.358, 7.266, 7.366, 7.200, 7.302 |
| IPv6 (4,096) | 6.226, 6.170, 6.153, 6.212, 6.185, 6.237, 6.165, 6.241 | 7.095, 7.191, 7.161, 7.192, 7.178, 7.170, 7.124, 7.146 |
| IPv4 (256) | 6.072, 6.205, 6.188, 6.206, 6.120, 6.206, 6.083, 6.193 | 7.161, 7.156, 7.089, 7.121, 7.239, 7.080, 7.267, 7.143 |
| IPv6 (256) | 6.134, 6.169, 6.145, 6.034, 6.158, 6.170, 6.009, 6.005 | 7.069, 6.921, 7.116, 7.102, 7.006, 7.054, 7.119, 7.076 |

</details>

## Live veth ingress

Four alternating pairs per offered rate sent 300,000 frames into
ingress-only capture. The capture used two workers on CPUs 0–3 and
wrote default Parquet to `/dev/null`. The sender used CPU 4.
Hardware counters covered capture-process userspace during
`tcpreplay`, before final export. Values are medians with min–max.

| Offered pps | Variant | Achieved pps | Cycles/frame | Instructions/frame |
| ---: | --- | ---: | ---: | ---: |
| 50,000 | Base | 49,998.72 (49,998.65–49,999.02) | 5259.6 (5182.2–5300.8) | 5140.3 (5118.2–5155.8) |
| 50,000 | Candidate | 49,998.71 (49,998.64–49,998.75) | 5081.4 (4998.4–5153.5) | 4980.9 (4957.6–4992.6) |
| 200,000 | Base | 199,977.60 (199,974.40–199,982.26) | 4053.2 (3660.1–4416.2) | 4441.0 (3990.0–4886.9) |
| 200,000 | Candidate | 199,975.46 (199,972.93–199,977.73) | 3614.2 (3561.0–3663.8) | 3878.4 (3870.4–3884.6) |

Median cycles/frame fell 3.4% at 50 kpps and 10.8% at 200 kpps.
At 200 kpps the baseline varied more with run order, and the cycle
ranges overlap slightly. Each sender reported 300,000 successes and
zero failures. Each classifier matched and submitted 150,000 frames
with zero ring drops in all 16 runs.

Separate 200 kpps reconciliation runs enabled source counters and
wrote a regular Parquet file per variant. Both drained 150,000 events
per family with zero dispatch send errors. Both exports had the same
10,000 flow IDs, with 30 packets per flow split 15 in each direction.
The 100 affected TCP flows each recorded one retransmission per
direction, for 200 total. The per-flow packet and retransmission
counts agreed with the offline pcap readback for both variants.
The namespace list and `kernel.bpf_stats_enabled=0` matched their
pre-test values, and all captures and senders exited.

## Correctness

The committed tests cover overlap versus adjacency, out-of-order gap
fill across wrap, history eviction, and SYN and FIN consuming sequence
space with data. The existing tests also cover byte coverage, reuse of
32-bit sequence numbers in later epochs, independent directions, ACK-only
packets, sparse history, packet conservation, and reordered TCP teardown.
A separate differential runner extracted both implementations and
matched all 4 million overlap decisions across 16 deterministic traces
with duplicates, gaps, reverse arrivals, contiguous extensions and
large serial jumps.

All 203 decoded default Parquet fields matched for the 300,000-packet
mixed TCP/UDP pcap and the established 2-million-packet UDP pcap. The
sorted decoded SHA-256 hashes were
`62d5bab81491bd46ae151b822bc1477871a465315901b224355a1044ab70be63` and
`8579cf4b0ef1ca97b5cd9203726d426285c7eade599c271085225cc1c878b549`.
Both families matched on single-source, single-shard replays with
7-event drain bursts. Each 20,000-event fixture exported 300 flows and
conserved all inputs. Each 120,000-event fixture with active expiration
and early snapshots exported 1,800 rows. Replay comparisons normalized
the six timestamp fields by each run's epoch origin, preserving
microsecond intervals and missing-direction sentinels.

`cargo fmt`, `cargo fmt --all -- --check`, `git diff --check`,
`cargo test --locked -p rustiflow` (116 unit and five integration tests),
and `cargo clippy --locked -p rustiflow --all-targets -- -D warnings`
passed.

## Disposition

Cycles per event fell 4.5–7.5%, and instructions per event fell
8.3–8.5%. Replay measures userspace processing through export close. The veth rates are sender-paced, so the live capture
ceiling and physical-link throughput remain unmeasured. For scale,
1,518-byte Ethernet frames with preamble and interframe gap require
8.13 Mpps at 100 Gbps and 32.51 Mpps at 400 Gbps.

## Reproduction

Nuccore ran x86-64 Linux `6.18.65-1-lts` on an Intel Core Ultra 7 255H.
The P-core governor was `powersave` with turbo enabled. Binaries used
Rust `1.99.0`, generic x86-64 code generation and workspace fat LTO.
Perf was `7.3.5-2` and tcpreplay was `4.6.2`. Both variants used the
same release eBPF objects, built with pinned nightly `2026-10-01` and
bpf-linker `0.12.0`.

From this worktree, build and archive the userspace executables at each
revision, substituting `baseline` or `candidate` for `$mode`.

```bash
exp="$PWD/target/retransmission"
mkdir -p "$exp/bin"
for profile in release profiling; do
    taskset -c 0-5 cargo build --locked --profile "$profile" -p rustiflow
    cp "target/$profile/rustiflow" "$exp/bin/$mode-$profile"
done
for family in ipv4 ipv6; do
    CARGO_TARGET_DIR="$PWD/target/ebpf-build" taskset -c 6-13 \
        cargo xtask "ebpf-$family" --release
done
```

Use `--ipv6` for IPv6 and set `burst` to 4,096 or 256. Run the
`perf record` variant separately at burst 4,096 with the profiling
binary, which keeps symbols and line tables.

```bash
replay=(-f rustiflow --export-path /dev/null --threads 4 replay-bench
        --packets 10000000 --flows 100000 --sources 8 --drain-burst "$burst")
taskset -c 0-5 "$exp/bin/$mode-release" "${replay[@]}"
taskset -c 0-5 perf stat --no-big-num -x ';' \
    -e cpu_core/cycles/u,cpu_core/instructions/u -- "$exp/bin/$mode-release" "${replay[@]}"
sudo -n taskset -c 0-5 perf record -e cpu_core/cycles/u -F 999 \
    --call-graph dwarf,8192 --no-buildid-cache -o "$data" -- \
    "$exp/bin/$mode-profiling" "${replay[@]}"
sudo -n perf report -f -i "$data" --stdio --no-children --percent-limit 0.1 -g none
sudo -n perf report -f -i "$data" --stdio --no-children --percent-limit 0.1 \
    --full-source-path -s srcline,symbol -g none
```

The local scripts and all build logs, raw repetitions, profiles, and
decoded files are under `target/retransmission/`. The mixed fixture has
10,000 flows evenly split by family and protocol, with 30 packets per
flow and alternating direction after each round. Timestamps are
spaced at 1 µs. TCP uses 24- and 448-byte payloads and starts close
to rollover. For every fiftieth TCP flow in each family, each direction
sends segment ordinals 0, 1, 3, 2, 3, 4, and then resumes consecutive
ordinals. The resulting pcap SHA-256 is
`c7ef6d84cc34beda3586ec56c47f6de768505a5e091e9362884d9f6f7f80ec9e`.
All traffic ran within temporary namespaces. The pacing, attach,
counters, and cleanup follow the repository harness. Each send used
`tcpreplay --preload-pcap --pps="$rate" --limit=300000 --intf1=send0`.
The separate reconciliation pass enabled `RUSTIFLOW_REALTIME_STATS=1`
and allowed one second of drain before SIGINT. [Live harness](realtime.sh)

```bash
python "$exp/mixed_tcp_pcap.py" "$exp/mixed-tcp.pcap"
bash "$exp/bench.sh"
sudo -n env RUSTIFLOW_EBPF_DIR="$PWD/target/ebpf-build/bpfel-unknown-none/release" \
    RUSTIFLOW_PROFILE_BIN="$exp/bin/baseline-release" \
    RUSTIFLOW_PROFILE_CANDIDATE="$exp/bin/candidate-release" \
    bash "$exp/live.sh" "$exp/live" "$exp/mixed-tcp.pcap"
```

The validation runner uses the existing native Parquet readback tool
and the UDP fixture from the first nuccore baseline.

```bash
export RUSTIFLOW_PARQUET_READER=/home/strgenix/postdoc/RustiFlow/target/profile-parquet/readback
ln -s /home/strgenix/postdoc/RustiFlow/target/profile-baseline/mixed.pcap "$exp/mixed-udp.pcap"
bash "$exp/validate.sh" "$mode"
taskset -c 6 python "$exp/compare_histories.py"
for variant in baseline candidate; do
    "$RUSTIFLOW_PARQUET_READER" "$exp/live/$variant-reconcile.parquet" \
        > "$exp/$variant-reconcile.decoded"
done
python "$exp/check_live.py"
python "$exp/summarize.py"
```
