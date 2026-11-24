# Experiment 8 · Realtime ring drain budget

Measured on nuccore on 2026-11-24 against `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. Earlier work covered ring fanout, shard batch reuse, and dual-stack classifier cost. The hypothesis here was that a continuously readable ring can delay partial-batch delivery and other ready rings. This prototype keeps adaptive eBPF notifications and changes the userspace drain limit.

`RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET=1` selects slices of at most 256 records and checks a 250 µs deadline every 32 records. A slice flushes partial shard batches and yields on exhaustion, holding the readiness guard so the next slice can consume queued records after the sender stops. An empty read flushes immediately and clears readiness. The time budget controls when a running task attempts a flush at the next checkpoint. Time spent queued in the kernel, suspended by the scheduler, or waiting for channel capacity can extend delivery latency. Drain-to-empty is the default.

## Matched capture cost

Rust 1.99.0, optimized x86-64 `profiling` builds with release code generation and line tables, release eBPF from nightly-2026-10-01 with bpf-linker 0.12.0, Linux 6.18.65-1-lts, Intel Core Ultra 7 255H, perf 7.3.5-2, tcpreplay 4.6.2. The capture process ran on CPUs 0–3 with two flow shards. The sender ran on CPU 4, with both veth ends in temporary namespaces. All arms used the same two netlink ingress classifiers and default Parquet to `/dev/null`. The standard fixture was the first 300,000 frames of the existing 2M-frame pcap, split evenly by IP family, with 10,000 bidirectional UDP flows and a mean captured frame size of 288 bytes. The pcap SHA-256 is `601d3d0590117b17e7a420198fe0a4ab058961dbd2bfc0acd360b5a629245661`. [Baseline workload](README.md)

Throughput passes used no source timing, BPF runtime accounting, or probes. `perf stat` measured capture userspace CPU over the sender command, before final export. Values are medians (min–max). The archived baseline and enabled candidate ran in three-run blocks in base/candidate/candidate/base order. The three later control runs used the candidate executable with the budget disabled.

| Offered rate / metric | Fresh base, n=6 | Same build control, n=3 | Budget enabled, n=6 |
| --- | ---: | ---: | ---: |
| 50 kpps, cycles/frame | 4,948 (4,924–4,966) | 5,052 (5,051–5,091) | 5,134 (5,103–5,263) |
| 50 kpps, instructions/frame | 4,922 (4,912–4,955) | 5,028 (5,000–5,046) | 5,143 (5,120–5,165) |
| 200 kpps, cycles/frame | 3,585 (3,541–3,656) | 3,633 (3,623–3,655) | 3,727 (3,657–4,396) |
| 200 kpps, instructions/frame | 3,869 (3,841–3,894) | 3,932 (3,929–3,936) | 4,020 (3,988–4,893) |
| Unpaced Mpps | 0.753 (0.702–0.811) | 0.782 (0.778–0.794) | 0.798 (0.660–0.807) |
| Unpaced, cycles/frame | 5,440 (5,352–5,698) | 5,725 (5,690–5,790) | 5,769 (5,328–5,898) |
| Unpaced, instructions/frame | 5,441 (5,385–5,507) | 5,524 (5,501–5,594) | 5,600 (5,594–5,693) |

All 45 passes achieved the requested paced rates within 27 pps or ran unpaced, and reconciled 300,000 successful sends to 300,000 veth RX packets and 150,000 submitted events per family with zero eBPF drops or veth errors/drops. Candidate capture cycles rose 3.8–4.0% on paced input against the archived base and 1.6–2.6% against the same-build control. The two baseline unpaced block medians moved from 0.713 to 0.805 Mpps, so the overlapping unpaced rates are inconclusive. This short, single-sender software-path test leaves sustained capture and physical wire rate for the 100–400+ Gbps goal unmeasured.

Separate 499 Hz `perf record` passes at 200 kpps recorded zero lost samples. Base userspace self-cycle samples showed flow-table processing at 8.85%, ring drain at 8.75%, source dispatch at 6.26%, shard enqueue at 5.74%, and Tokio I/O readiness at 4.85%. Candidate shares included 8.27% in the drain policy, 2.82% in the Aya ring reader, and 9.01% in the dispatcher. On sender CPU 4, locks, system calls, and scheduling dominated kernel samples, with `ep_poll_callback` at 0.57% base and 0.52% candidate.

## Wakeups, batches, and delivery

The instrumented passes used one executable with the budget off and on, three repeats per rate. Direct registration of a probe on `bpf_ringbuf_notify` returned `EINVAL`. A BTF fentry probe on `ep_poll_callback` counted calls for RustiFlow event-map fds on sender CPU 4. Idle controls recorded zero callbacks to those maps. The userspace counters count `AsyncFd` readiness acquisitions, drain slices, and successful shard-queue handoffs. Handoff age uses the eBPF timestamp of the first event in a batch and includes time in the ring and the dispatch queue. The diagnostics add per-event clocks and atomics.

| Offered rate | Ring callbacks, off / on | Readiness acquisitions, off / on | Shard batches, off / on |
| --- | ---: | ---: | ---: |
| 50 kpps | 253,418 (252,488–259,780) / 252,572 (252,436–252,593) | 253,247 / 252,444 | 275,607 / 274,891 |
| 200 kpps | 186,188 (185,712–188,914) / 187,265 (183,907–191,159) | 185,664 / 186,683 | 231,517 / 232,680 |
| Unpaced | 267,734 (266,313–272,067) / 271,024 (267,851–273,334) | 267,137 / 270,423 | 280,552 / 284,106 |

The drain counts equal readiness acquisitions in these passes. The control averaged 1.12–1.62 events per nonempty drain across rate medians and 1.07–1.30 events per shard batch. No drain hit the budget on this mixed workload. The longest observed drains were 148 records with the budget off and 136 with it on. Every pass reconciled 300,000 submitted, drained and handed-off events with zero send errors or drops. The 200 kpps handoff-age p99 fell in the 32–63 µs bucket in all six runs.

- **Sparse and trailing packets.** Three 20 pps passes per arm each delivered 20 events in 20 shard batches. The maximum handoff age per run ranged from 129–227 µs in the control and 112–161 µs with the budget. The 23-frame fixture additionally exercises two noninitial fragments and one unknown EtherType, with one expected Linux RX drop after TC. The decoded native Parquet files have the same 203 columns and six flows. Each family exported six TCP, three UDP and one ICMP packet.
- **Busy rings after the producer stops.** In three passes per arm, the consumer was stopped for the 100,000-frame burst. Both rings drained all 50,000 records per family from their first readiness acquisition. The candidate used 390 record-budget yields (394 total slices including the two trailing packets), with at most 256 records per slice. Both arms sent 784 shard batches. Each ring later delivered a lone trailing packet after 300 ms of idle. The slower of the two marker handoffs per run took 117–164 µs in the control and 115–141 µs with the budget. Each decoded final timestamp fell inside the marker send window.
- **Ordering and overflow.** A preloaded bidirectional TCP fixture crossed the slice boundary with 2,053 records per family and matching decoded TCP feature values, including handshake and retransmission counts. With the consumer stopped long enough to fill two rings, both arms matched all 2,255,000 received frames and submitted 2,236,961. IPv4 dropped 6,899 of 1,405,000 and IPv6 dropped 11,140 of 850,000. Both arms drained, dispatched, and exported all submitted events after resumption. Across these fixtures the checker compared the full schema and 151 fields per flow, and verified microsecond capture timestamps against the live send windows. It excludes time-derived values from cross-run equality because the send schedules vary.
- **Fairness under a forced backlog.** On one capture CPU with 250,000 IPv4 events queued ahead of a single IPv6 marker on a separate ring, both arms handed off all 250,001 events in each of five runs. After subtracting the paused interval using the decoded marker timestamp and the timestamps bracketing SIGCONT, the median marker handoff was 149–159 µs in the control and 140–151 µs with the budget. The full spread was 136–451 µs and 118–159 µs, respectively. The median intervals overlap.
- **Time limit.** With the same paused workload on one CPU and both queue capacities and the shard batch size set to one, the candidate hit the time limit 30 times and the record limit 954 times. Both arms handed off all 250,001 events with zero drops and matching decoded values.

**Disposition.** Retain as an opt-in prototype on this branch. Paced capture cost increased, the mixed workload rarely built sizable batches, and the forced-backlog test showed overlapping marker delays. The continuity and overflow checks support the bounded drain mechanism and the measured cost favors the default drain-to-empty policy.

Formatting and Clippy passed, along with 31 realtime tests, the replay delivery test, and five Parquet integration tests. The harness verified detached ingress filters, removed the temporary namespaces, and left `kernel.bpf_stats_enabled` at its initial value of 0.

## Reproduce

The archived executable was built before source edits. Afterward it can be reproduced from a source archive under `target/`. The two userspace builds used the same pinned toolchain, profile, and default x86-64 code generation. Both arms loaded the same release eBPF objects with program tags `f6c54130f273749e` and `fd327699513bdb44`.

```bash
run="$PWD/target/ring-exp"
mkdir -p "$run/base-src"
git archive 2fbecc3d8c796841d19b6db8edbfba0c7de42e60 | tar -x -C "$run/base-src"
(cd "$run/base-src" && CARGO_TARGET_DIR="$run/base-target" cargo build --locked --profile profiling -p rustiflow)
cp "$run/base-target/profiling/rustiflow" "$run/base-rustiflow"
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
cargo build --locked --profile profiling -p rustiflow
cp target/profiling/rustiflow "$run/candidate-rustiflow"
pcap=/home/strgenix/postdoc/RustiFlow/target/profile-baseline/mixed.pcap
# Or generate the same file with: python docs/profiling/generate_pcap.py "$run/mixed.pcap"

profile() {
    local kind=$1 mode=$2 out=$3 fixture=$4
    shift 4
    local bin="$run/candidate-rustiflow"
    local -a opts=(-u RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET)
    if [[ $kind == base ]]; then bin="$run/base-rustiflow"; fi
    if [[ $kind == candidate ]]; then opts=(RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET=1); fi
    sudo -n env "${opts[@]}" RUSTIFLOW_PROFILE_BIN="$bin" \
        RUSTIFLOW_PROFILE_CAPTURE_CPUS="${capture_cpus:-0-3}" \
        bash docs/profiling/ring_drain.sh "$mode" "$run/$out" "$fixture" "$@"
}

profile base stat warm-base-200000 "$pcap" 200000
for block in base:1 candidate:1 candidate:4 base:4 control:1; do
    kind=${block%:*}
    first=${block#*:}
    if [[ $block == candidate:1 ]]; then profile candidate stat warm-candidate-200000 "$pcap" 200000; fi
    for rate in 50000 200000 top; do
        for rep in $(seq "$first" "$((first + 2))"); do
            profile "$kind" stat "stat-$kind-$rate-$rep" "$pcap" "$rate"
        done
    done
done
sudo -n env RUSTIFLOW_PROFILE_BIN="$run/base-rustiflow" \
    bash docs/profiling/realtime.sh "$run/sample-base" "$pcap" --sample-only
sudo -n env RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET=1 RUSTIFLOW_PROFILE_BIN="$run/candidate-rustiflow" \
    bash docs/profiling/realtime.sh "$run/sample-candidate" "$pcap" --sample-only
for kind in base candidate; do profile "$kind" kernel "kernel-$kind" "$pcap" 200000; done
for rate in 50000 200000 top; do
    for rep in 1 2 3; do
        for kind in control candidate; do profile "$kind" notify "notify-$kind-$rate-$rep" "$pcap" "$rate"; done
    done
done
```

The sparse, pressure, and ordered TCP passes reuse the experiment 7 packet fixture from `28bafec`. The two-flow pcap generator creates the queued burst and trailing markers. The fairness pcap repeats one IPv4 UDP frame before a single IPv6 marker.

```bash
git show 28bafec:docs/profiling/single_tc_fixture.py >"$run/single_tc_fixture.py"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$run:$PWD/docs/profiling"
python "$run/single_tc_fixture.py" pcap "$run/metadata.pcap"
python "$run/single_tc_fixture.py" pressure "$run/pressure.pcap"
python docs/profiling/generate_pcap.py "$run/backlog.pcap" --packets 100000 --flows 2
python docs/profiling/generate_pcap.py "$run/tail.pcap" --packets 2 --flows 2
python - "$run" <<'PY'
from pathlib import Path
import struct
import sys
from generate_pcap import packet
from single_tc_fixture import PCAP_HEADER, fixture

run = Path(sys.argv[1])
frames = [frame for frame, _ in fixture()]
with (run / "ordered.pcap").open("wb") as out:
    out.write(PCAP_HEADER)
    for stamp, frame in enumerate(frames[:8] + frames[8:10] * 2048 + frames[10:12]):
        out.write(struct.pack("<4I", 1_700_000_000, stamp, len(frame), len(frame)))
        out.write(frame)
with (run / "fair.pcap").open("wb") as out:
    out.write(PCAP_HEADER)
    for flow, count in ((0, 250_000), (1, 1)):
        frame = packet(flow, False)
        record = struct.pack("<4I", 1_700_000_000, 0, len(frame), len(frame)) + frame
        out.write(record * count)
PY

for rep in 1 2 3; do
    for kind in control candidate; do
        profile "$kind" low "low-$kind-$rep" "$run/metadata.pcap" 20
        profile "$kind" backlog "backlog-$kind-$rep" "$run/backlog.pcap" top "$run/tail.pcap"
    done
done
profile base low low-base-1 "$run/metadata.pcap" 20
for kind in control candidate; do
    profile "$kind" backlog "ordered-$kind-1" "$run/ordered.pcap" top
    profile "$kind" pressure "pressure-$kind-1" "$run/pressure.pcap" top
done
capture_cpus=0
for rep in 1 2 3 4 5; do
    for kind in control candidate; do
        profile "$kind" fair "fair-$kind-$rep" "$run/fair.pcap" top
    done
done
unset capture_cpus
for kind in control candidate; do
    opts=(-u RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET)
    if [[ $kind == candidate ]]; then opts=(RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET=1); fi
    sudo -n env "${opts[@]}" RUSTIFLOW_PROFILE_BIN="$run/candidate-rustiflow" RUSTIFLOW_PROFILE_CAPTURE_CPUS=0 \
        RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE=1 RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY=1 \
        RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY=1 \
        bash docs/profiling/ring_drain.sh fair "$run/timer-$kind-1" "$run/fair.pcap" top
done

deps="$PWD/target/profiling/deps"
lib=$(find "$deps" -maxdepth 1 -name 'libparquet-*.rlib')
rustc --edition=2021 -L "dependency=$deps" --extern "parquet=$lib" \
    docs/profiling/check_ring_parquet.rs -o "$run/check_ring_parquet"
for case in low backlog ordered pressure fair; do
    for pass in "$run/$case-candidate-"*; do
        "$run/check_ring_parquet" "$case" "${pass/-candidate-/-control-}" "$pass"
    done
done
"$run/check_ring_parquet" low "$run/low-base-1" "$run/low-candidate-1"
"$run/check_ring_parquet" fair "$run/timer-control-1" "$run/timer-candidate-1"
cargo fmt --all -- --check
cargo test --locked -p rustiflow --bin rustiflow realtime
cargo test --locked -p rustiflow --bin rustiflow replay_bench
cargo test --locked -p rustiflow --test parquet_output
cargo clippy --locked -p rustiflow --bin rustiflow -- -D warnings
```

The per-pass directories under `target/ring-exp/` contain counters, sender and link snapshots, traces, and decoded-output fixtures. `summary.csv` in that directory preserves the individual repetitions.
