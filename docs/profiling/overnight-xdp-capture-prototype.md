# Experiment 10 · Passive XDP ingress

Measured on nuccore on 2026-11-24 against
`2fbecc3d8c796841d19b6db8edbfba0c7de42e60`. The hypothesis was that an earlier
ingress hook and direct header loads would reduce the cost of producing flow
events. Experiment 7 (`28bafec`) already measured the benefit of collapsing
the two tc classifiers. The single-tc control here uses the same dual-stack
producer as XDP and isolates most of that dispatch difference.

Keep XDP as an ingress-only opt-in on this branch. Both XDP
modes matched tc at fixed rates and lowered time inside the BPF programs.
Both delivered fewer packets per second and used more kernel cycles per frame
in the unpaced veth bursts. Default realtime capture stays on tc.

## Setup and attachment

Linux 6.18.65-1-lts, Intel Core Ultra 7 255H, perf 7.3.5-2, bpftool 7.8.0,
and tcpreplay 4.6.2. Two shards and four Tokio workers ran on CPUs 0–3, the
sender ran on CPU 4, and kernel counters covered P-cores 0–5. Each measurement
sent 300,000 frames from the standard mixed UDP fixture. It contains 10,000
bidirectional flows, equal IPv4 and IPv6 shares, 24- and 448-byte payloads, and
a mean Ethernet frame size of 288 bytes. The shortened pcap SHA-256 is
`ae2bbdef09d4b561b22ceada0ffd1a9ac65fc560e579dad8334a44b4c5fe0eba`.
Both endpoints used fresh namespaces and 1500-byte veth MTUs with GRO, GSO
and TSO disabled. Replay used unaddressed interfaces with host IPv6 disabled.
Counting and sampling runs used default Parquet to `/dev/null`.

- `xdp-driver` attached as driver XDP (netlink mode 1) and `xdp-skb` as
  generic SKB XDP (mode 2). `bpftool net show` confirmed the mode and
  program ID in every pass. Each ran a single program and attached no tc
  filter. The release smoke test verified a BPF link in both XDP modes. The
  tc arms used legacy netlink ingress. The archived and rebuilt
  split arms loaded one classifier per IP family.
- The XDP program always returns `XDP_PASS`, including on parse and ring
  reservation failures. It uses bounded direct reads for linear headers and
  the XDP copy helper for longer offsets or headers outside the linear area.
  Both hooks use the same parser, event layout, canonical biflow queue,
  per-family counters and `bpf_ktime_get_ns` timestamps. The timestamp
  records when the producer ran at its ingress hook.
- Driver attachment changes the veth receive path. The peer reported UDP,
  SCTP, and list segmentation off and fixed after attach. Driver veth RX byte
  accounting excluded the 14-byte Ethernet header. Packet reconciliation
  uses frames, with `rx_queue_0_xdp_packets` as a second driver count. These
  results cover one active software receive queue with standard-MTU,
  untagged packets. NIC RSS, hardware offload, VLAN acceleration,
  multi-buffer jumbo frames, and physical 100–400+ Gbps validation remain open.

## Matched cost and delivery

Values are median (min–max) across five runs per arm and pass, after one
warmup per arm. The starting arm rotated each repetition. All 165 measured replays,
including 50 standard fixed-rate counts and 25 unpaced runs, reconciled
300,000 successful sends, veth TX and RX packets, and submitted events. Each family matched
150,000, with zero sender errors, driver XDP drops, veth errors or drops, and
ring reservation failures. Across all arms, the standard fixed rates were
within 1.4 pps of 50 kpps and 28 pps of 200 kpps.

| Metric per received frame unless specified | Archived split tc | Rebuilt split tc | Single tc | Driver XDP | Generic XDP |
| --- | ---: | ---: | ---: | ---: | ---: |
| 50 kpps capture userspace cycles | 4,957 (4,946–4,971) | 4,967 (4,932–4,973) | 4,962 (4,932–4,968) | 4,975 (4,970–4,999) | 4,987 (4,953–5,013) |
| 200 kpps capture userspace cycles | 3,538 (3,530–3,543) | 3,506 (3,487–3,555) | 3,512 (3,495–3,529) | 3,594 (3,562–3,604) | 3,553 (3,547–3,575) |
| 200 kpps kernel cycles, default pacing | 23,646 (23,576–23,720) | 23,591 (23,528–23,626) | 23,624 (23,431–23,750) | 23,632 (23,568–23,730) | 23,640 (23,557–23,829) |
| 200 kpps kernel cycles, batches of 32 | 10,343 (10,109–10,465) | — | 10,344 (10,209–10,376) | 10,649 (10,578–10,810) | 10,445 (10,415–10,585) |
| 200 kpps BPF runtime, ns | 524.85 (516.93–527.93) | 523.54 (518.44–526.99) | 503.49 (499.07–507.82) | 474.96 (473.55–483.54) | 465.35 (462.94–468.22) |
| Unpaced delivered Mpps | 0.885 (0.878–0.890) | 0.891 (0.880–0.898) | 0.904 (0.886–0.906) | 0.835 (0.831–0.846) | 0.865 (0.860–0.875) |
| Unpaced kernel cycles | 10,839 (10,796–10,942) | 10,935 (10,864–11,041) | 10,832 (10,748–10,861) | 11,273 (10,894–11,336) | 11,165 (11,032–11,183) |

The BPF runtime row uses separate `kernel.bpf_stats_enabled=1` runs. Each
archived and rebuilt split program ran 300,000 times. The single-tc and XDP
programs each ran 300,000 times total. Time in BPF fell 9.5% in driver mode and
11.3% in generic mode relative to archived tc, or 5.7% and 7.6% against the
single-tc control. The unpaced runs are short software submissions by a single
sender. Driver and generic delivery rates were 5.7% and 2.3% below archived
tc, respectively.

The default paced kernel totals were dominated by sender pacing. Separate
499 Hz kernel samples show `__schedule` at 5.5–6.1% of self cycles across
the four sampled arms, alongside syscall entry and scheduler locks.
The 20 batch-paced runs used `--timer=nano --pps-multi=32` and achieved
199,962.8–199,976.3 pps with zero loss. At that pace, driver XDP used 3.0% more kernel cycles per frame than
archived tc. Generic XDP was 1.0% higher with overlapping ranges. At this
pace, cumulative samples put 26.7% of driver kernel cycles under
`veth_xdp_rcv_skb` and 22.0% of generic cycles under
`bpf_prog_run_generic_xdp`. The archive put 24.2% under `tcf_classify`.
These stacks include descendants. The higher whole-kernel cost persisted
in the unpaced runs, even with a cheaper BPF producer.

The 200 kpps userspace samples put 10.6–11.3% of self cycles in the ring
drain and 6.2–7.2% in the dispatcher. Flow-table processing accounted for
7.5–10.0%. All 12 perf recordings reported zero lost samples.

Separate five-second `bpftool prog profile` windows at 50 kpps counted about
217k–221k invocations each. The split result adds the per-invocation costs
of its two classifiers because both visited every frame.

| BPF-only hardware counts | Cycles/frame | Instructions/frame |
| --- | ---: | ---: |
| Archived tc | 4,141 (4,133–4,165) | 3,397 (3,384–3,401) |
| Single tc | 3,855 (3,844–3,873) | 2,553 (2,551–2,553) |
| Driver XDP | 3,718 (3,705–3,726) | 2,202 (2,201–2,206) |
| Generic XDP | 3,684 (3,654–3,700) | 2,187 (2,186–2,188) |

Three repetitions per hardware-count row. A helper-only XDP build ran three
extra 200 kpps accounting passes per mode. It used 506.24 ns/frame
(503.73–508.54) in driver mode and 495.70 (493.89–506.66) in generic mode.
Direct loads saved about 6% against that exploratory build.

## Correctness and latency

- The 23-frame metadata fixture included bidirectional TCP with a
  retransmission, UDP, ICMP, IPv4 options, IPv6 destination options,
  noninitial fragments and an unsupported EtherType. Every arm received all
  23 frames, submitted the same 20 records, and counted the same one
  downstream RX drop for the unknown EtherType. The libbpf reader compared
  all non-timestamp bytes and queue assignments, checked TCP order, and
  bounded each monotonic timestamp by the send window. Replacing one IPv6
  destination options header with a 272-byte header also passed and exercised
  the copy helper at a transport offset above 255 bytes.
- Three 200 kpps diagnostic runs per rebuilt mode sampled every 64th event
  in each ring. All 12 runs drained all 300,000 events with zero dispatch
  send errors. In every run the 4,696 samples gave p50 in 8–15 µs and p99 in
  32–63 µs from the BPF record timestamp to its userspace read. The samples
  start at the capture hook and exclude shard and export time.
- Live Parquet decoded to the same 203-column schema and all 151 stable
  fields, keyed by flow ID. The sparse fixture had six flows and the
  paced fixture had 10,000 with 30 packets each. Decoded first and last
  timestamps were within each live send window. Timing-derived fields
  depend on the send schedule.

- The stripped-release traffic check delivered 200 of 200 echo replies per
  IP family in each arm. Mean IPv4/IPv6 round-trip times in that pass were
  25/34 µs for archived tc, 33/37 µs for single tc, 34/38 µs for driver XDP
  and 32/41 µs for generic XDP.
- With the consumer stopped and two 64 MiB rings filled, each arm sent,
  received and matched 2,255,000 frames without veth loss. IPv4 submitted
  1,398,101 and dropped 6,899. IPv6 submitted 838,860 and dropped 11,140.
  All four arms drained and exported all 2,236,961 submitted records after
  resumption, with identical stable Parquet fields and no dispatch errors.
- The rebuilt default loaded both tc families on ingress and egress and
  submitted ten records per family and direction. Driver XDP on loopback
  returned `EOPNOTSUPP`. A second attach to the occupied veth returned
  `EBUSY` and preserved the existing program ID. Missing objects, invalid
  modes and requests for experimental egress gave startup diagnostics.
  The existing realtime CLI logs these errors and exits with status zero.

Formatting passed for the workspace and both eBPF manifests. Binary Clippy
passed with warnings denied. The narrow realtime, Parquet integration and
common suites passed 31, five and four tests, respectively. Distinct stripped
x86-64 release binaries and release eBPF objects without the BTF override
passed the live smoke checks. The last cleanup restored
`kernel.bpf_stats_enabled=0` and removed all experiment namespaces and
processes.

## Reproduce

Run from the experiment worktree. The two userspace builds use the pinned Rust
1.99.0 toolchain and the default x86-64 code generation. The `profiling` profile
inherits release optimizations and keeps symbols and line tables. The eBPF
builds use nightly-2026-10-01, bpf-linker 0.12.0, and matching BTF flags.

```bash
run="$PWD/target/xdp-experiment"
base=2fbecc3d8c796841d19b6db8edbfba0c7de42e60
mkdir -p "$run"/{base-src,base-ebpf,candidate-ebpf}
git archive "$base" | tar -x -C "$run/base-src"
(cd "$run/base-src" && CARGO_TARGET_DIR="$run/base-build" cargo build --locked --profile profiling -p rustiflow)
CARGO_TARGET_DIR="$run/candidate-build" cargo build --locked --profile profiling -p rustiflow
cp "$run/base-build/profiling/rustiflow" "$run/base-rustiflow"
cp "$run/candidate-build/profiling/rustiflow" "$run/candidate-rustiflow"

export CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf"
for arm in base candidate; do
    src=$PWD
    if [[ $arm == base ]]; then src="$run/base-src"; fi
    export CARGO_TARGET_DIR="$run/$arm-ebpf-build"
    for family in ipv4 ipv6; do
        (cd "$src/ebpf-$family" && cargo build --locked --release)
        cp "$CARGO_TARGET_DIR/bpfel-unknown-none/release/rustiflow-ebpf-$family" "$run/$arm-ebpf/"
    done
done
(cd ebpf-ipv6 && cargo build --locked --release --features xdp-experiment --bin rustiflow-ebpf-ingress-experiment)
cp "$CARGO_TARGET_DIR/bpfel-unknown-none/release/rustiflow-ebpf-ingress-experiment" "$run/candidate-ebpf/"
unset CARGO_TARGET_DIR CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS

export PYTHONDONTWRITEBYTECODE=1
python docs/profiling/generate_pcap.py "$run/mixed-300k.pcap" --packets 300000
git show 28bafec:docs/profiling/single_tc_fixture.py >"$run/single_tc_fixture.py"
PYTHONPATH="$PWD/docs/profiling" python "$run/single_tc_fixture.py" pcap "$run/metadata.pcap"
PYTHONPATH="$PWD/docs/profiling" python "$run/single_tc_fixture.py" pressure "$run/pressure.pcap"
```

The generator's first 300,000 frames are the same as in the standard 2M-frame
fixture. The experiment used `tcpdump -r mixed.pcap -c 300000 -w "$run/mixed-300k.pcap"`
to cap preload work. Use the archived build for `base` and the rebuilt default objects for `split`.
The other arms use the same candidate binary with an experimental attachment.

```bash
pass() {
    local phase=$1 rate=$2 rep=$3 arm=$4 directory=$5
    shift 5
    sudo -n env RUSTIFLOW_XDP_PPS="$rate" "$@" bash docs/profiling/xdp_capture.sh \
        "$phase" "$arm" "$run/matrix-final/$directory/$rate/$rep/$arm" "$run/mixed-300k.pcap"
}
rotate() {
    local phase=$1 rate=$2 reps=$3 directory=$4
    shift 4
    local pos rep arm
    for ((rep=1; rep<=reps; rep++)); do
        for ((pos=0; pos<${#arms[@]}; pos++)); do
            arm=${arms[((pos + rep - 1) % ${#arms[@]})]}
            if [[ $phase == latency && $arm == base ]]; then continue; fi
            pass "$phase" "$rate" "$rep" "$arm" "$directory" "$@"
        done
    done
}
arms=(base split single-tc xdp-driver xdp-skb)
for arm in "${arms[@]}"; do pass stat 200000 warm "$arm" stat; done
rotate stat 50000 5 stat
for phase in stat runtime burst; do rotate "$phase" 200000 5 "$phase"; done
rotate latency 200000 3 latency
arms=(base single-tc xdp-driver xdp-skb)
for phase in kernel-sample user-sample; do
    for arm in "${arms[@]}"; do pass "$phase" 200000 1 "$arm" "$phase"; done
done
rotate stat 200000 5 nano RUSTIFLOW_XDP_PPS_MULTI=32
for arm in "${arms[@]}"; do
    pass kernel-sample 200000 1 "$arm" nano-kernel RUSTIFLOW_XDP_PPS_MULTI=32
done
for rep in 1 2 3; do
    pass bpf-counters 50000 "$rep" base bpf-counters-base-ipv4 RUSTIFLOW_XDP_PROFILE_INDEX=1
    for arm in "${arms[@]}"; do pass bpf-counters 50000 "$rep" "$arm" bpf-counters; done
done
python docs/profiling/summarize_xdp.py "$run/matrix-final" >"$run/final.csv"
```

Raw repetitions and counters are in `target/xdp-experiment/matrix-final/`
and `target/xdp-experiment/final.csv`. The harness saves attachment modes,
BPF and link counters, sender and capture logs, and perf reports. Perf counting
uses kernel-only P-core 0–5 events and capture-process userspace events. Profile
windows cover the sender command and its preload. Final Parquet writes occur
after the window. Each run restores the BPF runtime accounting setting and
removes its two namespaces. The raw validation consumes the event rings with
libbpf while the RustiFlow consumer is paused.

```bash
for arm in base single-tc xdp-driver xdp-skb; do
    for phase in raw parquet ping pressure; do
        fixture=metadata
        if [[ $phase == pressure ]]; then fixture=pressure; fi
        sudo -n bash docs/profiling/xdp_capture.sh "$phase" "$arm" \
            "$run/validate-$phase-$arm" "$run/$fixture.pcap"
    done
    cmp "$run/validate-raw-base/rings.json" "$run/validate-raw-$arm/rings.json"
done
sudo -n bash docs/profiling/xdp_capture.sh bidirectional split \
    "$run/default-dual-hook" "$run/metadata.pcap"
```

For the stripped release check, repeat the userspace builds with `--release`
and independent Cargo target directories. Build the eBPF objects with the BTF
override unset. Use `RUSTIFLOW_PROFILE_BIN` and `RUSTIFLOW_XDP_EBPF_DIR` to
supply those artifacts to the harness. The Parquet decoder was reused from
`6368cbd:docs/profiling/check_ring_parquet.rs`, with a mixed case expecting
10,000 flows of 30 packets. The preliminary paced block was excluded after
an in-place edit interrupted one pass. The recorded matrix ran
from a frozen copy of the harness. The helper-only diagnostic used the same
BTF build without the direct-load branch in `load_header` and three
`runtime` passes per XDP mode at 200 kpps.
