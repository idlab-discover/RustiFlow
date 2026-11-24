# Experiment 7 · Single dual-stack ingress classifier

Measured on nuccore on 2026-11-24 against `2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. The existing netlink ingress filters register for all Ethernet protocols. Each frame visits both filters and the nonmatching filter reads the Ethernet header before returning. The hypothesis was that one EtherType dispatch would remove the cost of the second invocation. The candidate reads the header once, dispatches to the same IPv4 or IPv6 parser, and returns `TC_ACT_PIPE`. Each family keeps its event ABI, eight rings, biflow hash, and monotonic timestamp source. The three per-CPU counter maps use a slot per family.

**Disposition.** Retain as an ingress-only opt-in. The candidate cut instrumented classifier runtime by 2.3%, from 763.61 to 746.40 ns per observed frame. The uninstrumented veth burst medians were 0.760 and 0.804 Mpps, with overlapping ranges and smaller separation in the initial matrix. Keep the default two-filter capture path.

## Matched runs

All runs used the same optimized x86-64 userspace binary (`--profile profiling`, derived from `release` with line tables), Rust 1.99.0, default Parquet written to `/dev/null`, two flow workers on CPUs 0–3, and tcpreplay 4.6.2 on CPU 4. Kernel 6.18.65-1-lts, Intel Core Ultra 7 255H, perf 7.3.5-2, bpftool 7.8.0. Both arms used unmodified release eBPF build flags with nightly-2026-10-01 and bpf-linker 0.12.0. The split arm loaded fresh objects built before editing the base tree. The candidate arm loaded the feature-gated dual-stack object.

The [existing replay fixture](generate_pcap.py) SHA-256 is `601d3d0590117b17e7a420198fe0a4ab058961dbd2bfc0acd360b5a629245661`. Each run replayed its first 300,000 Ethernet frames, split equally between IPv4 and IPv6. The input cycles through 10,000 bidirectional UDP flows with 24- and 448-byte payloads and an average captured frame size of 288 bytes. Both ends of each veth were in temporary namespaces. Every measured pass had 300,000 successful sends and 300,000 observed veth RX packets, with zero sender errors and zero veth RX errors or drops. Each family matched and submitted 150,000 events with zero eBPF drops.

| Pass | Metric per observed frame unless specified | Split median (min–max) | Single median (min–max) |
| --- | --- | ---: | ---: |
| 50 kpps fixed | Sender pps | 49,998.80 (49,998.61–49,999.06) | 49,998.69 (49,998.60–49,999.98) |
| 50 kpps fixed | Capture userspace cycles | 4,972 (4,960–5,036) | 4,992 (4,962–5,019) |
| 50 kpps fixed | Capture userspace instructions | 4,959 (4,942–5,058) | 4,995 (4,942–5,127) |
| 200 kpps fixed | Sender pps | 199,976.26 (199,975.60–199,995.06) | 199,975.06 (199,971.33–199,980.00) |
| 200 kpps fixed | Capture userspace cycles | 3,611 (3,568–3,723) | 3,600 (3,557–4,332) |
| 200 kpps fixed | Capture userspace instructions | 3,908 (3,857–4,074) | 3,880 (3,825–4,801) |
| Unpaced burst | Sender Mpps | 0.760 (0.696–0.810) | 0.804 (0.778–0.814) |
| 50 kpps with BPF accounting | Total classifier ns | 763.61 (754.69–797.62) | 746.40 (733.48–772.11) |

Six runs per arm per pass, in groups of three run in split/single/single/split order. The fixed-rate `perf stat` window spans the sender command and excludes the final export. Kernel BPF runtime accounting was off for fixed-rate, burst, and sample passes. The burst measures short software submission on one veth sender. Sustained capacity and physical wire rate for the 100–400+ Gbps goal remain unmeasured.

In the instrumented passes, both split programs ran exactly 300,000 times each. The candidate ran exactly 300,000 times total. Runtime is the sum of the `bpftool prog show` runtime deltas divided by observed RX frames. The split per-invocation medians were 367.07 ns IPv4 and 398.32 ns IPv6. The JIT images were 17,591 + 25,446 bytes for split and 43,180 bytes for single. Individual combined ns/frame measurements were `797.62, 754.69, 763.43, 760.16, 776.93, 763.79` and `747.51, 772.11, 733.48, 745.14, 746.89, 745.92`, respectively. An initial matrix before the missing-object diagnostic change measured 754.92 and 736.89 ns/frame, a 2.4% reduction. Its unpaced medians were 0.798 and 0.803 Mpps, with overlapping ranges. Runtime accounting can perturb short invocations and this measurement covers only the classifiers.

Separate 499 Hz perf samples at 200 kpps had zero reported lost samples. In the split and single userspace reports, flow-table packet processing accounted for 9.02% and 9.97% of self cycles, ring draining for 11.30% and 9.74%, and source dispatch for 6.12% and 4.77%. On the sender CPU at the same rate, kernel samples were dominated by locks, syscalls and scheduling under tcpreplay. The profiles also exposed ring helpers, including reservation at 1.73% in the split report and submission at 1.55% in the single report. The samples show work across sender scheduling, ring draining, and flow processing.

## Correctness

- The [23-frame fixture](single_tc_fixture.py) exercises bidirectional TCP, including a retransmission, UDP, ICMP/ICMPv6, IPv4 options, IPv6 destination options, two non-initial fragments, and one non-IP frame. All 23 frames reached the veth. Linux counted one RX drop after TC for the unknown EtherType in each arm. The split, rebuilt split, and dual-stack objects each produced 20 records, ten per family, with zero eBPF drops. The raw checker matched all non-timestamp bytes to the fixture and found identical queue assignments. It checked per-ring ordering, took both TCP directions through the same family ring, and bounded each monotonic nanosecond timestamp within the live send window.
- The same fixture exercised normal ring drain and default Parquet export. All three paths drained 20 events with zero source send errors. The files decoded to the same 203-column schema and six flows. Each family emitted a six-packet TCP flow, a three-packet UDP flow, and a one-packet ICMP flow. All 151 non-time-derived fields agreed after sorting by flow ID. The other columns depend on actual replay timing, and the raw capture checked live timestamp sourcing independently.
- In a separate ring-pressure run the consumer was suspended while the same IPv4 and IPv6 UDP flows filled one 64 MiB ring per family. Both arms sent and received all 2,255,000 frames with no veth drops. Each matched 1,405,000 IPv4 and 850,000 IPv6 frames. Both submitted 1,398,101 and 838,860, and counted 6,899 and 11,140 drops respectively, for 18,039 total. The normal capture runs had zero eBPF drops.
- The rebuilt default path attached two ingress and two egress filters when invoked without `--ingress-only`. Replaying the fixture in each direction matched and submitted ten events per direction and family. Three extra rebuilt-split runtime passes gave 765.94 ns/frame (765.17–773.84), within the archived split range. All temporary attachments detached on shutdown.

Formatting passed for the workspace and both eBPF manifests. The narrow realtime selection passed 31 tests, Parquet passed five integration tests, and the shared header crate passed four tests. Clippy passed for the RustiFlow binary with warnings denied. Cleanup restored `kernel.bpf_stats_enabled=0` and removed the experiment namespaces.

## Reproduce

Use the same pcap as the [nuccore baseline](README.md), or generate it with `generate_pcap.py`. The baseline objects can be rebuilt from a source archive under `target/` while working on the experiment branch.

```bash
run="$PWD/target/experiment-07"
pcap=/home/strgenix/postdoc/RustiFlow/target/profile-baseline/mixed.pcap
mkdir -p "$run/base-src"
git archive 2fbecc3d8c796841d19b6db8edbfba0c7de42e60 | tar -x -C "$run/base-src"
for family in ipv4 ipv6; do
    (
        cd "$run/base-src/ebpf-$family"
        CARGO_TARGET_DIR="$run/base-ebpf" cargo build --locked \
            --target=bpfel-unknown-none --release -Z build-std=core
    )
    (
        cd "ebpf-$family"
        CARGO_TARGET_DIR="$run/candidate-ebpf" cargo build --locked \
            --target=bpfel-unknown-none --release -Z build-std=core --bin "rustiflow-ebpf-$family"
    )
done
(
    cd ebpf-ipv6
    CARGO_TARGET_DIR="$run/candidate-ebpf" cargo build --locked \
        --target=bpfel-unknown-none --release -Z build-std=core \
        --features dual-stack --bin rustiflow-ebpf-dual-stack
)
CARGO_TARGET_DIR="$run/userspace" cargo build --locked --profile profiling -p rustiflow
```

All measurement modes use the legacy netlink harness. The flag `RUSTIFLOW_EXPERIMENT_SINGLE_TC=1` selects the experimental object with `realtime --ingress-only`. Missing objects and requests for egress produce realtime startup diagnostics. Default installations keep the two per-family objects. Raw perf, tc, bpftool, link and sender logs are in the pass directories below.

```bash
profile() {
    local mode=$1 pass=$2 kind=${2%-*}
    local -a flags=(-u RUSTIFLOW_EXPERIMENT_SINGLE_TC)
    if [[ $kind == candidate ]]; then flags=(RUSTIFLOW_EXPERIMENT_SINGLE_TC=1); fi
    if [[ $kind == split ]]; then kind=candidate; fi
    sudo -n env "${flags[@]}" \
        RUSTIFLOW_PROFILE_BIN="$run/userspace/profiling/rustiflow" \
        RUSTIFLOW_EBPF_DIR="$run/$kind-ebpf/bpfel-unknown-none/release" \
        bash docs/profiling/realtime.sh "$run/$mode-$pass" "$pcap" "--$mode-only"
}
for mode in live runtime topspeed; do
    for pass in base-a candidate-a candidate-b base-b; do profile "$mode" "$pass"; done
done
for kind in base candidate; do
    for scope in sample kernel-sample; do profile "$scope" "$kind"; done
done
profile runtime split
```

The correctness harness needs libbpf for raw ring readback. The Parquet check links against the same workspace dependency used by the profiling binary.

```bash
export PYTHONDONTWRITEBYTECODE=1
python docs/profiling/single_tc_fixture.py pcap "$run/metadata.pcap"
python docs/profiling/single_tc_fixture.py pressure "$run/pressure.pcap"
for mode in raw parquet pressure; do
    for kind in base candidate; do
        sudo -n bash docs/profiling/validate_single_tc.sh \
            "$mode" "$kind" "$run/validate-$mode-$kind" "$run"
    done
done
for mode in raw parquet bidirectional; do
    sudo -n bash docs/profiling/validate_single_tc.sh \
        "$mode" split "$run/validate-$mode-split" "$run"
done
for kind in candidate split; do
    cmp "$run/validate-raw-base/rings.json" "$run/validate-raw-$kind/rings.json"
done
deps="$run/userspace/profiling/deps"
lib=$(find "$deps" -maxdepth 1 -name 'libparquet-*.rlib')
rustc --edition=2021 -L "dependency=$deps" --extern "parquet=$lib" \
    docs/profiling/compare_live_parquet.rs -o "$run/compare_parquet"
for kind in candidate split; do
    "$run/compare_parquet" "$run/validate-parquet-base/flows.parquet" \
        "$run/validate-parquet-$kind/flows.parquet"
done

export CARGO_TARGET_DIR="$run/userspace"
cargo fmt --check
cargo fmt --manifest-path ebpf-ipv4/Cargo.toml -- --check
cargo fmt --manifest-path ebpf-ipv6/Cargo.toml -- --check
cargo test --locked -p rustiflow --bin rustiflow realtime
cargo test --locked -p rustiflow --test parquet_output
cargo test --locked -p common
cargo clippy --locked -p rustiflow --bin rustiflow -- -D warnings
```
