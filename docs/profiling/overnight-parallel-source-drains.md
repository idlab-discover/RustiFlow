# Experiment 9 · Dedicated ring source reactors

Measured on nuccore on 2026-11-24 against `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. Earlier work added canonical biflow rings and per-source dispatchers, and experiment 8 measured near-per-event readiness callbacks and tested drain budgets. This experiment tests whether placing each ring and its dispatcher on the same dedicated I/O reactor reduces scheduling overhead while sharing the same CPU budget with the flow shards. [Baseline workloads](README.md)

`RUSTIFLOW_EXPERIMENT_SOURCE_REACTORS=N` assigns the ring sources round-robin to up to `N` single-thread Tokio I/O runtimes. Each ring still has a single reader and its own FIFO dispatcher. The prototype requires `--ingress-only` so both directions of a biflow use the same classifier's ring. The flow shards and Parquet export run on the main runtime. With the setting unset or zero, the sources use the main runtime. The prototype keeps drain-to-empty, queue capacities, event decoding, and the existing stop-and-cancel policy.

## Fixed CPU budget

Linux 6.18.65-1-lts, Intel Core Ultra 7 255H, Rust 1.99.0, and optimized `x86-64-v3` userspace binaries built with the release-derived `profiling` profile and line tables. All arms loaded the same release BPF objects built with nightly-2026-10-01 and bpf-linker 0.12.0. The ingress program tags were `f6c54130f273749e` and `fd327699513bdb44`. Perf 7.3.5-2 and tcpreplay 4.6.2 ran locally.

Capture used P-cores 0–3, two flow shards and default Parquet to `/dev/null`. Both veth ends were in temporary namespaces. The sender was pinned to P-core 4. Main Tokio worker count plus dedicated reactor count was four in every arm. The capture affinity mask allowed all four cores for all capture threads. Each workload used 1 million Ethernet frames across 10,000 bidirectional UDP flows, alternating packet direction for each pass through the relevant flow set.

- Balanced uses the standard fixture with equal IPv4 and IPv6 and equal 24- and 448-byte payloads. It averages 288 bytes per frame. SHA-256 `8d80761edd048b9440bb8ed7f7d5acd140bbf1df014bcc7ba77c5078105eced1`.
- Skew sends 90% of frames from 1,000 IPv4 flows that hash to ring 0. The other 9,000 flows span both families and use the other rings. IPv4 accounts for 95% of frames. Payload sizes are still equally represented, with a mean frame size of 279 bytes. SHA-256 `1bb46eb38658b2db280aabcf88aca38e343ae1d7f83b9ae5dfec5746004af308`. [Fixture generator](generate_skewed_pcap.py)

One warmup per executable and topology preceded five measured runs per workload, rate and topology. The order rotated one position per repetition. Paced input targeted 200 kpps. Unpaced rates are the sender's achieved software-path rates. The table reports median (min–max). Capture userspace hardware counters cover the sender command and a 300 ms drain window before final export. Source timers, probes and BPF runtime accounting were off.

| Input | Main workers + reactors | Paced cycles/frame | Paced instructions/frame | Unpaced Mpps | Unpaced cycles/frame | Unpaced instructions/frame | Unpaced capture switches/frame |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Balanced | 4 + 0 archived | 3,439 (3,401–3,454) | 3,581 (3,581–3,595) | 0.871 (0.866–0.874) | 5,784 (5,683–5,805) | 5,273 (5,256–5,295) | 0.306 (0.304–0.308) |
| Balanced | 4 + 0 same binary | 3,427 (3,405–3,490) | 3,590 (3,575–3,596) | 0.873 (0.863–0.878) | 5,824 (5,701–5,861) | 5,272 (5,186–5,297) | 0.307 (0.301–0.308) |
| Balanced | 3 + 1 | 2,876 (2,855–2,892) | 3,490 (3,473–3,515) | 0.824 (0.823–0.830) | 4,453 (4,438–4,535) | 4,826 (4,750–4,860) | 0.427 (0.423–0.433) |
| Balanced | 2 + 2 | 3,363 (3,355–3,384) | 4,166 (4,136–4,174) | 0.745 (0.739–0.747) | 5,151 (5,094–5,176) | 5,072 (5,037–5,097) | 0.794 (0.783–0.797) |
| Balanced | 1 + 3 | 3,248 (3,240–3,275) | 4,192 (4,186–4,205) | 0.714 (0.702–0.723) | 4,811 (4,782–4,895) | 5,024 (5,005–5,057) | 0.783 (0.778–0.792) |
| Skew | 4 + 0 archived | 1,839 (1,830–1,841) | 2,112 (2,096–2,120) | 1.133 (1.131–1.140) | 3,180 (3,171–3,212) | 3,200 (3,186–3,222) | 0.236 (0.234–0.238) |
| Skew | 4 + 0 same binary | 1,856 (1,849–1,859) | 2,102 (2,095–2,110) | 1.151 (1.142–1.161) | 3,217 (3,179–3,225) | 3,123 (3,116–3,196) | 0.230 (0.230–0.239) |
| Skew | 3 + 1 | 1,885 (1,869–1,904) | 2,255 (2,231–2,276) | 1.015 (0.991–1.033) | 3,297 (3,285–3,388) | 3,382 (3,353–3,438) | 0.408 (0.401–0.427) |
| Skew | 2 + 2 | 1,930 (1,904–1,943) | 2,422 (2,395–2,432) | 0.998 (0.990–1.009) | 3,322 (3,315–3,353) | 3,407 (3,386–3,425) | 0.490 (0.480–0.494) |
| Skew | 1 + 3 | 1,789 (1,785–1,798) | 2,374 (2,372–2,384) | 1.000 (0.998–1.010) | 2,795 (2,786–2,863) | 3,299 (3,270–3,341) | 0.383 (0.374–0.389) |

All 100 runs reconciled 1 million successful sends to 1 million veth RX, classifier matches and submitted events, with zero sender errors, veth errors or drops, and eBPF reservation failures. Paced rates were within 9 pps of 200 kpps. One interrupted harness repetition was rerun after warmup. Only completed runs are counted.

At 200 kpps on balanced traffic, one reactor used 16% fewer capture userspace cycles per frame than the same-binary shared control. Unpaced, it used 24% fewer capture userspace cycles per frame and delivered 6% fewer frames per second. Two or three reactors reduced balanced unpaced delivery by 15–18% and generated about 2.6× the capture context switches. Under skew, all three splits delivered 12–13% fewer frames per second and used more instructions per frame than the same-binary shared control at both rates. These are single-sender veth software-path rates over 1 million frames. Sustained overload and physical wire rate at the 100–400+ Gbps goal remain unmeasured.

## Where the CPU time went

At a matched 200 kpps on balanced input, the separate 499 Hz userspace samples put 12.31% of archived self cycles in the ring drain, 6.39% in dispatch, 4.49% in batch enqueue and 3.35% in Tokio I/O readiness. With one dedicated reactor the shares were 9.89%, 6.03%, 5.40% and 4.24%. At three reactors, dispatch and readiness rose to 8.72% and 4.56%. The unpaced balanced profiles placed 19.13–26.17% of self cycles in these four functions across the four arms. All 20 kernel and userspace profiles recorded zero lost samples.

Three separate unpaced passes per arm counted kernel cycles per submitted frame. The capture counters attach to capture threads. CPU 4 counters include the sender's preload and veth work and any other kernel work on that CPU. Values are median (min–max).

| Input and counter scope | Archived | One reactor | Two reactors | Three reactors |
| --- | ---: | ---: | ---: | ---: |
| Balanced, capture kernel | 2,529 (2,512–2,560) | 3,152 (3,131–3,172) | 4,376 (4,354–4,390) | 3,878 (3,857–3,896) |
| Balanced, CPU 4 kernel | 6,174 (6,155–6,226) | 6,437 (6,426–6,445) | 7,122 (7,043–7,126) | 7,389 (7,354–7,395) |
| Skew, capture kernel | 1,607 (1,592–1,618) | 2,505 (2,498–2,548) | 2,723 (2,659–2,741) | 2,029 (2,012–2,034) |
| Skew, CPU 4 kernel | 5,077 (5,069–5,105) | 5,422 (5,386–5,508) | 5,591 (5,548–5,623) | 5,603 (5,558–5,655) |

One unpaced `bpftrace` pass per arm and workload instrumented `ep_poll_callback` on CPU 4 and restricted the counts to RustiFlow event maps. Idle controls saw zero callbacks, and every measured pass drained 1 million events with zero send errors.

| Input | Archived | One reactor | Two reactors | Three reactors |
| --- | ---: | ---: | ---: | ---: |
| Balanced callbacks | 892,582 | 932,012 | 984,785 | 991,082 |
| Skew callbacks | 367,653 | 405,105 | 448,120 | 461,981 |

The hot ring drained exactly 900,000 events in every skew probe pass. In the balanced unpaced kernel sample on CPU 4, `try_to_wake_up` was below the archived 0.5% reporting threshold and reached 1.21% and 2.34% of self cycles with two and three reactors. The callback increase, context switches, and kernel cycle counts support additional kernel wakeup and scheduling work in the dedicated layouts.

## Correctness and disposition

- The archived build and all three dedicated layouts exported 10,000 flows and 1 million packets per UDP fixture. The decoder checked the full 203-column schema, all 151 stable fields per flow, and first and last microsecond timestamps against each live send window. The offline Parquet exports on the balanced pcap matched across all 203 fields and 10,000 flows, keyed by flow ID.
- The sparse metadata fixture sent 23 frames per arm and exported 20 events across six flows, including TCP, UDP and ICMP for both families. Linux recorded one expected post-TC RX drop in each run. The queued bidirectional TCP fixture exported all 4,106 records with matching order-sensitive TCP features, including handshake and retransmission counts.
- With the capture process paused, the overflow fixture reconciled 2,255,000 successful sends, veth RX and classifier matches in every arm. IPv4 reserved 1,398,101 events and dropped 6,899. IPv6 reserved 838,860 and dropped 11,140. Every arm drained and exported all 2,236,961 submitted events after resumption, with zero userspace send errors.
- Distinct stripped release binaries passed the sparse Parquet readback with two dedicated reactors in the candidate. With the setting unset, their dual-hook smoke tests each matched and submitted ten packets per direction and family with zero eBPF drops. The first release smoke attempt reused the archived binary through a shared Cargo target directory. The isolated rebuild and startup log verified the actual release candidate. The performance runs used distinct profiling binaries and verified the configured topology in every pass.
- Formatting, Clippy with warnings denied, 31 realtime tests, the replay delivery test and five Parquet integration tests passed.

**Disposition.** Retain the ingress-only prototype as an opt-in experiment. The shared runtime stays the default. Every dedicated layout lowered unpaced delivery at the fixed budget and incurred more kernel work per packet. The isolated lower userspace cost of one reactor on balanced traffic is insufficient to justify changing the scheduling policy.

Raw repetitions, profile reports, receiver and classifier logs, and generated fixtures are under `target/exp09/`. The 100 accepted runs are summarized individually in `target/exp09/final-matrix.csv`.

The harness verified filter detachment and removed its namespaces. Final checks found the capture and sender processes cleared and `kernel.bpf_stats_enabled` at its initial value of zero.

## Reproduce

Run from the worktree. The original baseline was built and saved before source edits. The archive below reproduces it after applying the experiment.

```bash
run="$PWD/target/exp09"
mkdir -p "$run/base-src"
git archive 2fbecc3d8c796841d19b6db8edbfba0c7de42e60 | tar -x -C "$run/base-src"
(
    cd "$run/base-src"
    CARGO_TARGET_DIR="$run/base-build" RUSTFLAGS="-C target-cpu=x86-64-v3" \
        cargo build --locked --profile profiling -p rustiflow
)
cp "$run/base-build/profiling/rustiflow" "$run/baseline"
CARGO_TARGET_DIR="$PWD/target/build" RUSTFLAGS="-C target-cpu=x86-64-v3" \
    cargo build --locked --profile profiling -p rustiflow
cp target/build/profiling/rustiflow "$run/final-candidate"
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
export PYTHONDONTWRITEBYTECODE=1
python docs/profiling/generate_pcap.py "$run/balanced.pcap" --packets 1000000
python docs/profiling/generate_skewed_pcap.py "$run/skew.pcap"
```

For stripped-release builds, substitute `--release` for `--profile profiling` and copy the binaries from the resulting `release` directories. Use a separate Cargo target directory for each source tree.

Use the experiment 8 veth harness, changing its packet cap and counting command as below. The harness verifies that the tc filters detach, deletes its namespaces, and restores `kernel.bpf_stats_enabled` if changed.

```bash
git show 6368cbd:docs/profiling/ring_drain.sh |
    sed 's/rf08-/rf09-/g; s/limit=(--limit=300000)/limit=(--limit=1000000)/' \
    >"$run/ring_drain.sh"
```

The `stat` case used this exact counting command with the harness's sender array. That array runs `ip netns exec "$send" taskset -c 4 tcpreplay --preload-pcap --limit=1000000 --intf1=send0 "$pcap"` with `--pps=200000` or `--topspeed`.

```bash
perf stat -x ';' -e cpu_core/cycles/u,cpu_core/instructions/u,context-switches,cpu-migrations \
    -p "$pid" -o "$out/perf.stat" -- bash -c '"$@" && sleep 0.3' _ "${sender[@]}" \
    >"$out/sender.log" 2>&1
```

```bash
pass() {
    local arm=$1 mode=$2 input=$3 rate=$4 output=$5
    local n=$arm bin="$run/final-candidate"
    case $arm in
        base) bin="$run/baseline"; n=0 ;;
        shared) n=0 ;;
    esac
    sudo -n env TOKIO_WORKER_THREADS="$((4 - n))" RUSTIFLOW_EXPERIMENT_SOURCE_REACTORS="$n" \
        RUSTIFLOW_PROFILE_BIN="$bin" \
        bash "$run/ring_drain.sh" "$mode" "$run/$output" "$run/$input.pcap" "$rate"
}
for arm in base 2 shared 1 3; do pass "$arm" stat balanced top "warm-$arm"; done
arms=(base shared 1 2 3)
for rep in {0..4}; do
    for input in balanced skew; do
        for rate in 200000 top; do
            for offset in {0..4}; do
                arm=${arms[(rep + offset) % 5]}
                pass "$arm" stat "$input" "$rate" "final-matrix/$input-$rate-$arm-$((rep + 1))"
            done
        done
    done
done
```

The separate sampling passes used the same harness setup, with the following commands in place of the counting command. Capture samples used both fixtures unpaced and the balanced fixture at 200 kpps. The kernel and `notify` cases in the reused harness ran unpaced. The sender and capture kernel counters each ran unpaced three times per arm and workload.

```bash
perf record -e cpu_core/cycles/u -F 499 --call-graph dwarf,8192 --no-buildid-cache \
    -p "$pid" -o "$out/perf.data" -- "${sender[@]}"
perf report -f -i "$out/perf.data" --stdio --no-children --percent-limit 0.5 -g none
perf stat -x ';' -a -C 4 -e cpu_core/cycles/k,cpu_core/instructions/k \
    -o "$out/perf.stat" -- "${sender[@]}"
perf stat -x ';' -p "$pid" -e cpu_core/cycles/k,cpu_core/instructions/k \
    -o "$out/perf.stat" -- bash -c '"$@" && sleep 0.3' _ "${sender[@]}"
```

The `low`, `backlog` and `pressure` harness cases enable source stats and write a regular Parquet file. Run `low` with both UDP fixtures at 200 kpps, and with the metadata fixture at 20 pps. Run `backlog` for ordered TCP and `pressure` for the overflow fixture, both at `top`.

```bash
git show 28bafec:docs/profiling/single_tc_fixture.py >"$run/single_tc_fixture.py"
export PYTHONPATH="$run:$PWD/docs/profiling"
python "$run/single_tc_fixture.py" pcap "$run/metadata.pcap"
python "$run/single_tc_fixture.py" pressure "$run/pressure.pcap"
python - "$run/ordered.pcap" <<'PY'
import struct
import sys
from single_tc_fixture import PCAP_HEADER, fixture

frames = [frame for frame, _ in fixture()]
with open(sys.argv[1], "wb") as out:
    out.write(PCAP_HEADER)
    for index, frame in enumerate(frames[:8] + frames[8:10] * 2048 + frames[10:12]):
        out.write(struct.pack("<4I", 1_700_000_000, index, len(frame), len(frame)))
        out.write(frame)
PY
git show 6368cbd:docs/profiling/check_ring_parquet.rs >"$run/check_ring_parquet.rs"
deps="$PWD/target/build/profiling/deps"
parquet=$(find "$deps" -maxdepth 1 -name 'libparquet-*.rlib')
rustc --edition=2021 -L "dependency=$deps" --extern "parquet=$parquet" \
    "$run/check_ring_parquet.rs" -o "$run/check_ring_parquet"
for arm in base 1 2 3; do
    pass "$arm" low metadata 20 "decode/metadata-$arm"
    pass "$arm" backlog ordered top "decode/ordered-$arm"
    pass "$arm" pressure pressure top "decode/pressure-$arm"
    "$run/check_ring_parquet" low "$run/decode/metadata-base" "$run/decode/metadata-$arm"
    "$run/check_ring_parquet" ordered "$run/decode/ordered-base" "$run/decode/ordered-$arm"
    "$run/check_ring_parquet" pressure "$run/decode/pressure-base" "$run/decode/pressure-$arm"
done
cargo fmt --all -- --check
export CARGO_TARGET_DIR="$PWD/target/build" RUSTFLAGS="-C target-cpu=x86-64-v3"
cargo test --locked -p rustiflow --bin rustiflow realtime
cargo test --locked -p rustiflow --bin rustiflow replay_bench
cargo test --locked -p rustiflow --test parquet_output
cargo clippy --locked -p rustiflow --bin rustiflow -- -D warnings
```
