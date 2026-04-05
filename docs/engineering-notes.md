# Engineering Notes

This file keeps short-lived design choices and execution notes that would make
`AGENTS.md` too long.

## 2026-03-25

- Use branch `codex/ingestion-semantics-foundation` for the AGENTS-driven
  improvement track instead of landing exploratory changes directly on `main`.
- Prefer performance-aware correctness for ingestion work so foundational
  metadata changes do not need to be redone later.
- Realtime packet events now carry kernel monotonic timestamps and aligned
  packet/header/payload length semantics. Stabilize and measure before adding
  more event fields.
- Timing and IAT features now preserve sub-millisecond precision internally.
- Retransmission work should stay bounded: fix non-TCP false positives, move
  beyond exact duplicate sequence numbers, and leave richer TCP quality signals
  such as duplicate ACKs and handshake analysis for later checklist items.
- Retransmission stats now stay TCP-only and count overlap in TCP sequence
  space, including SYN and FIN sequence-number use, instead of only exact
  duplicate sequence numbers.
- Active/idle tracking now compares thresholds in microseconds before converting
  to exported millisecond values, and subflow counting now represents actual
  subflows instead of only counting gap boundaries after the first packet.
- ICMP stats now keep the original first seen type and code, but also track
  echo request and reply counts plus error and destination-unreachable counts
  across ICMPv4 and ICMPv6 traffic.
- TCP lifecycle export now distinguishes observed handshake completion from
  resets seen before or after that observed handshake, so richer flow schemas
  do not have to infer lifecycle quality from flag totals alone.
- RustiFlow export now includes duplicate ACK counts, zero-window
  observations, and `tcp_close_style`. Duplicate ACKs currently mean repeated
  pure ACKs with the same ACK number and advertised window; zero-window events
  count TCP packets advertising a zero receive window; close style stays rooted
  in `BasicFlow` lifecycle state so timeout/reset/FIN semantics are not
  reimplemented in exporter code.
- `nf_flow` now exports `ip_version` without expanding the eBPF event payload.
  The value is derived from the normalized `IpAddr` already shared by offline
  and realtime ingestion, and fixture-backed tests lock down the IPv4 path
  while direct flow construction locks down the IPv6 path.
- Internal sharding and flow-table lookup now use typed `FlowKey` values
  instead of rebuilding formatted strings on the hot path. String flow ids are
  still created when a new flow is instantiated for export compatibility.
- `FeatureStats` now keeps running variance state (`m2`) and derives standard
  deviation on demand instead of updating `std` itself on every packet.
  Dedicated tests now lock down population-std semantics, order invariance, and
  merged directional variance behavior.
- Realtime packet-graph mode is now explicit and testable. When the graph is
  disabled, RustiFlow no longer constructs the packet-count watch channel or
  mutex-protected counter state, so high-throughput runs skip that observability
  plumbing entirely instead of merely branching around it in the loop body.
- RustiFlow now exports `ip_version`, `source_ip_scope`,
  `destination_ip_scope`, and `path_locality` derived from the normalized
  `IpAddr` endpoints already shared by offline and realtime ingestion. The
  adversarial test matrix covers private/shared/link-local/loopback/multicast
  cases across IPv4 and IPv6 so these coarse path signals do not depend on
  extra kernel event fields.
- `FlowTable` now keeps the ordinary existing-flow update path in place instead
  of removing and reinserting the map entry on every packet. Table-level tests
  now lock down two semantics that matter for that optimization: replacing an
  expired flow with a fresh flow on the same key, and early export that keeps
  the live flow resident for later final export.
- Current test-hardening focus is to add adversarial deterministic cases before
  more feature work: false handshake completion, teardown edge cases, parser
  rejection behavior, and tiny fixture assertions that prove exported
  lifecycle semantics.
- Test hardening already exposed two parser quirks worth locking down: short
  unsupported offline frames must not panic the reader, and non-first IPv6
  fragments should be dropped instead of being treated like fresh transport
  headers.
- Test hardening also exposed a real `FlowTable` lifecycle bug: packet-driven
  termination export could overwrite `TcpReset` with `TcpTermination`, and a
  first-packet-terminated flow could be left behind for duplicate export.
- The next adversarial test layer should prefer integrated semantics over raw
  test count: simultaneous close teardown, contiguous-versus-overlapping TCP
  segments, and wrapper-level feature coordination in `RustiFlow`.
- That test layer exposed another real parser bug: offline IPv4 parsing was
  treating non-first IPv4 fragments as if they started with a fresh transport
  header. Non-first IPv4 fragments should now be dropped while first fragments
  still parse their transport header normally.

## 2026-03-27

- `rgbcore` now has a persistent local software-path performance harness for
  RustiFlow realtime testing:
  - host namespace capture side: `rustiflow-t0`
  - peer namespace: `rustiflow-peer`
  - peer interface inside that namespace: `rustiflow-p0`
  - addressing: `10.203.0.1/30` on `rustiflow-t0` and `10.203.0.2/30` on
    `rustiflow-p0`
- This harness is intended to isolate RustiFlow software-path performance from
  physical LAN limits. It is valid for stressing local realtime ingestion, but
  it is not a replacement for true physical wire-rate validation on real NICs.
- Realtime capture baseline command on `rgbcore`:
  `RUST_LOG=info cargo xtask run --release -- -f basic -o csv --export-path /dev/null --performance-mode --threads 32 realtime rustiflow-t0 --ingress-only`
- Peer-side traffic generation baseline command:
  `sudo ip netns exec rustiflow-peer iperf3 -s -B 10.203.0.2`
- Large-packet UDP stress baseline:
  `iperf3 -c 10.203.0.2 -B 10.203.0.1 -u -b 1G -l 1400 -t 30`
- Result for that large-packet run: `iperf3` sustained `1.00 Gbit/s` and
  RustiFlow reported `Total dropped packets: 0` on shutdown.
- Small-packet UDP stress command used for PPS pressure:
  `iperf3 -c 10.203.0.2 -B 10.203.0.1 -u -b 1G -l 256 -t 30`
- Result for the `256`-byte run with RustiFlow enabled: about `630 Mbit/s`,
  small `iperf3` receiver loss, and RustiFlow still reported `0` dropped
  packets.
- Control result for the same `256`-byte run with RustiFlow disabled: about
  `614 Mbit/s` with similarly small `iperf3` receiver loss.
- Current interpretation: the small-packet ceiling observed in this harness is
  in the `iperf3`/kernel UDP packets-per-second path, not in RustiFlow's eBPF
  event ingestion path. The local evidence currently supports that RustiFlow
  can keep up with `1 Gbit/s` realtime traffic for larger UDP datagrams in the
  software-path harness without reporting internal packet drops.

## 2026-03-30

- Local container-based realtime stress testing is now the preferred workflow
  on `rgbcore` instead of direct binary execution.
- The working setup depends on three pieces:
  - the persistent local harness from `2026-03-27` (`rustiflow-t0`,
    `rustiflow-peer`, `rustiflow-p0`)
  - a long-lived `iperf3` server inside `rustiflow-peer` bound to `10.203.0.2`
  - privileged host-network RustiFlow containers built from `Dockerfile` or
    `Dockerfile-slim`
- With that setup in place, the containerized end-to-end loop can be driven
  independently from `rgbcore`:
  - start RustiFlow in a privileged host-network container on `rustiflow-t0`
  - generate reverse-mode UDP traffic with `iperf3 -R` so the hot stream is
    ingress on `rustiflow-t0`
  - stop the container with `docker kill -s INT ...` so RustiFlow prints its
    dropped-packet summary before exit
- Verified containerized cases:
  - `rustiflow:test-slim`, `1G`, `1400`-byte UDP, one processing thread:
    `0` RustiFlow drops and the exported CSV contains the expected large UDP
    flow
  - `rustiflow:test-slim`, target `2.5G`, `1400`-byte UDP, one processing
    thread: achieved about `2.19 Gbit/s`, repeated ring-buffer reservation
    failures, and `201510` dropped packets reported by RustiFlow
  - `rustiflow:test-full`, `1G`, `1400`-byte UDP, one processing thread:
    `0` RustiFlow drops
- Current operational pain point: when the realtime path starts dropping at
  high rate, the eBPF-side `error!` log on ring-buffer reservation failure
  floods container logs and makes result collection noisy.
- `scripts/realtime_container_stress.sh` now standardizes the local
  containerized realtime baseline on `rgbcore`. It starts a privileged
  RustiFlow container on `rustiflow-t0`, drives reverse-mode `iperf3` traffic
  against `10.203.0.2`, interrupts RustiFlow cleanly with `SIGINT`, and prints
  the receiver bitrate plus `Total dropped packets before exit`.
- That log has been demoted from `error!` to `debug!` in both eBPF programs.
  The authoritative overload signal remains the `DROPPED_PACKETS` counter
  consumed by userspace and reported at shutdown, so container logs stay quiet
  while the dropped-packet summary remains accurate.
- Slim-image thread matrix on the fixed `iperf3 -u -b 2.5G -l 1400 -R`
  workload:
  - `--threads 1`: receiver bitrate about `2.21 Gbit/s`, dropped packets
    `261634`
  - `--threads 2`: receiver bitrate about `2.26 Gbit/s`, dropped packets
    `277063`
  - `--threads 4`: receiver bitrate about `2.20 Gbit/s`, dropped packets
    `199182`
  - `--threads 8`: receiver bitrate about `2.24 Gbit/s`, dropped packets
    `272799`
- Ring-buffer-size experiment:
  - increasing both realtime eBPF ring buffers from `20 MB` to `64 MB` had a
    large effect on the single-flow case
  - with `--threads 4` and `iperf3 -u -b 2.5G -l 1400 -P 1 -R`, receiver
    bitrate improved to about `2.32 Gbit/s` and RustiFlow reported `0` dropped
    packets
  - with `--threads 4` and `iperf3 -u -b 2.5G -l 1400 -P 8 -R`, the harness
    still achieved about `14.8 Gbit/s` aggregate and RustiFlow still dropped
    about `9182037` packets
  - current interpretation: extra ring-buffer capacity materially improves
    burst absorption and the moderate single-flow case, but it does not remove
    the real ingestion ceiling once the single userspace drain path is driven
    far beyond what it can sustainably consume
- Realtime drain-path instrumentation now logs per-source shutdown stats from
  `rustiflow/src/realtime.rs`: total events, decode-and-shard time, shard-send
  wait time, and total per-event time.
- The instrumentation perturbs absolute throughput enough that the raw
  `iperf3` rates should not be treated as new baselines, but the ratios are
  still useful for locating the bottleneck.
- On the active `ingress-ipv4` source, shard-send wait time dominated
  decode-and-shard time in both inspected cases:
  - `-P 1`, `2.5G`, `--threads 4`, `5s`: about `565620` events, `65 ms`
    decode-and-shard time, `74 ms` shard-send wait time
  - `-P 8`, `2.5G`, `--threads 4`, `5s`: about `4760253` events, `507 ms`
    decode-and-shard time, `1363 ms` shard-send wait time
- Current interpretation: the single userspace drain task is real bottleneck
  surface, and a large part of its hot-path cost is awaiting shard-channel
  capacity rather than only decoding eBPF events. That supports redesigning
  realtime ingestion so packet draining and dispatch can parallelize more
  effectively before work reaches the flow-table shards.
- Realtime dispatch now batches packets per shard before sending them into the
  flow-table workers instead of awaiting one channel send per packet.
- This batching change improved the moderate single-flow case without changing
  the public flow semantics:
  - `64 MB` ring buffer, `--threads 4`, `iperf3 -u -b 2.5G -l 1400 -P 1 -R`:
    about `2.27 Gbit/s`, `0` dropped packets
- The same batching change only modestly improved the overloaded multi-flow
  case:
  - `64 MB` ring buffer, `--threads 4`, `iperf3 -u -b 2.5G -l 1400 -P 8 -R`:
    about `14.4 Gbit/s`, `8929817` dropped packets
- Current interpretation: per-packet dispatch overhead mattered, but the
  current architecture is still limited by a single ingress ring-buffer drain
  task under very high aggregate load. The remaining redesign target is still a
  more parallel ingress structure, not only better batching.
- Realtime redesign options considered:
  - Option 1: keep the current event model, but split the hot ingress source
    into multiple eBPF event maps and drain them in parallel from userspace
    before handing work to the flow-table shards
  - Option 2: replace the current ring-buffer transport with a transport that
    more naturally supports parallel userspace consumption, most likely a
    per-CPU perf-event style design
- Option 1 assessment:
  - lower-risk extension of the current architecture
  - keeps `PacketFeatures`, flow semantics, and most userspace processing
    structure intact
  - directly targets the measured bottleneck without a transport rewrite
  - still requires careful fanout design and more eBPF/userspace map plumbing
- Option 2 assessment:
  - stronger long-term scalability story
  - cleaner fit for parallel userspace draining
  - materially more invasive because it changes both eBPF emission and
    userspace event transport
  - higher semantic and validation risk than Option 1
- Current branch decision:
  - pursue Option 1 first on `codex/ingestion-throughput-parallellization`
  - keep Option 2 as the likely next escalation if Option 1 does not improve
    the overloaded multi-flow ingress case enough
- Option 1 is now implemented for the hot IPv4 realtime path:
  - the eBPF IPv4 program now emits into four fixed ring buffers
    (`EVENTS_IPV4_0` through `EVENTS_IPV4_3`) instead of one shared
    `EVENTS_IPV4` map
  - queue selection happens in eBPF from a canonical biflow-style IPv4
    endpoint ordering so both directions of the same flow land on the same
    queue
  - userspace now loads and drains those four IPv4 ring buffers as independent
    Tokio tasks before handing work to the existing shard workers
  - IPv6 remains on the old single-queue path for now; this first pass is
    deliberately bounded to the proven hot path and should not be treated as a
    full transport redesign
- Validation of the implemented Option 1 shape on `rustiflow:test-slim`,
  `rustiflow-t0`, `--threads 4`:
  - single-flow ingress case, `iperf3 -u -b 2.5G -l 1400 -P 1 -R`, `10s`:
    receiver bitrate about `2.18 Gbit/s`, `0` dropped packets
  - multi-flow ingress case, `iperf3 -u -b 2.5G -l 1400 -P 8 -R`, `10s`:
    receiver bitrate between about `15.7` and `16.3 Gbit/s`, dropped packets
    between about `641688` and `1233317`
  - compared with the earlier single-ring-buffer result on the same
    `-P 8` shape (`14.4 Gbit/s`, `8929817` dropped packets), the multi-queue
    ingress design materially reduced overload drops
- A short stats-enabled `-P 8`, `5s` run also confirms that the new userspace
  drain path is genuinely parallel rather than just cosmetically split:
  - `ingress-ipv4-q0`: `829312` events
  - `ingress-ipv4-q1`: `2600892` events
  - `ingress-ipv4-q2`: `2662511` events
  - `ingress-ipv4-q3`: `813676` events
  - all four IPv4 drain tasks were active, and RustiFlow reported `0` dropped
    packets for that shorter run
- Current interpretation after Option 1:
  - the original single-source bottleneck was real
  - bounded multi-queue ingress fanout buys substantial headroom on the
    overloaded IPv4 multi-flow case
  - distribution across the four queues is not perfectly even, so there is
    still room to tune the fanout function or escalate to the Option 2
    transport rewrite later if needed
- Follow-up adversarial 10 Gbit/s work on the same slim-container IPv4 path
  now shows a practical zero-drop operating point for larger packets:
  - `8 x 1.25G`, `1400`-byte UDP, `--threads 4`: about `9.99 Gbit/s`,
    `275442` dropped packets
  - `8 x 1.25G`, `1400`-byte UDP, `--threads 8`: about `9.99 Gbit/s`,
    `178257` dropped packets
  - `8 x 1.25G`, `1400`-byte UDP, `--threads 10`: about `9.99 Gbit/s`,
    `229803` dropped packets
  - `8 x 1.25G`, `1400`-byte UDP, `--threads 11`: repeated `9.99 Gbit/s`,
    `0` dropped packets
  - `8 x 1.25G`, `1400`-byte UDP, `--threads 12`: `9.99 Gbit/s`,
    `0` dropped packets
  - `8 x 1.25G`, `1400`-byte UDP, `--threads 16`: `9.98 Gbit/s`,
    `0` dropped packets
- IPv6 now mirrors the bounded Option 1 ingress design as well:
  - the IPv6 eBPF program emits into four fixed ring buffers using the same
    canonical biflow-style queue selection pattern as IPv4
  - userspace drains those four IPv6 queues in parallel before handing work to
    the existing shard workers
- Realtime attach debugging on the local Arch `rustiflow-t0` harness found a
  separate issue from the queue design:
  - `aya`'s automatic `SchedClassifier::attach()` path reported success but, on
    this kernel and veth setup, the TCX-attached programs never executed
  - the added per-CPU eBPF counters (`matched_packets`, `submitted_events`,
    `dropped_packets`) made this visible immediately because both IPv4 and IPv6
    stayed at `0` despite successful traffic on the harness
  - forcing legacy netlink tc attach from userspace restored execution on the
    local harness, after which the IPv6 counters tracked the live traffic as
    expected
- IPv6 validation after forcing legacy netlink tc attach on the same slim
  container workflow:
  - `8 x 1.25G`, `1400`-byte UDP, `10s`, `--threads 4`, reverse IPv6 traffic:
    `9.99 Gbit/s`, `0` RustiFlow drops
  - `8 x 1.25G`, `1400`-byte UDP, `10s`, `--threads 12`, reverse IPv6 traffic:
    `9.99 Gbit/s`, `0` RustiFlow drops
  - `8 x 1.25G`, `512`-byte UDP, `10s`, `--threads 12`, reverse IPv6 traffic:
    about `5.83 Gbit/s`, `0` RustiFlow drops
- Current interpretation of the IPv6 result:
  - the bounded multi-queue ingress design now holds for both IPv4 and IPv6 on
    the local software-path harness
  - the local `512`-byte IPv6 case is not presently exposing a RustiFlow drop
    point; the traffic generator or receive path gives out first while
    RustiFlow still reports `0` drops
- More adversarial 10 Gbit/s shapes with `--threads 11`:
  - `16 x 625M`, `1400`-byte UDP: `10.0 Gbit/s`, `0` dropped packets
  - `8 x 1.25G`, `1024`-byte UDP: `9.90 Gbit/s`, `0` dropped packets
  - `8 x 1.25G`, `512`-byte UDP: only about `5.77 Gbit/s` achieved and
    `1171091` dropped packets
  - the same `512`-byte case with `--threads 16` still only reached about
    `5.86 Gbit/s`, though dropped packets fell to `489178`
- Current interpretation:
  - after Option 1, the IPv4 realtime path can now sustain about `10 Gbit/s`
    without internal drops for larger-packet UDP workloads when given at least
    `11` worker threads in this local harness
  - the next remaining pressure point is packet-per-second intensity rather
    than only aggregate bitrate; the `512`-byte case is still a clear failure
    mode even with more threads
- Additional hot-path knob ranking on the improved IPv4 ingress path:
  - dominant runtime knobs:
    - worker thread count
    - feature/export cost (`basic` vs `rustiflow`)
    - early export cadence
  - secondary userspace knobs:
    - shard batch size
    - shard queue capacity
  - already-proven eBPF / transport knobs from earlier work:
    - ring-buffer count / parallel ingress queues
    - ring-buffer byte size
- Measured on the `8 x 1.25G`, `1400`-byte UDP, `15s` ingress case:
  - `rustiflow`, `--threads 10`, `--early-export 5`, current defaults:
    about `9.98 Gbit/s`, `3190699` dropped packets
  - same traffic, `--early-export 0`:
    about `9.99 Gbit/s`, `0` dropped packets
  - same traffic, `basic`, `--threads 11`, `--early-export 5`:
    about `9.99 Gbit/s`, `0` dropped packets
  - same traffic, `rustiflow`, `--threads 11`, `--early-export 5`:
    still vulnerable to multi-million drops on longer runs
- Runtime batch / queue-depth experiments on the same stressed
  `rustiflow`, `--threads 10`, `--early-export 5`, `15s` case:
  - default batch `128`, queue capacity `512`: `3190699` drops
  - batch `32`: `2821050` drops
  - batch `256`: `2723922` drops
  - queue capacity `2048`: `2670573` drops
  - batch `256` plus queue capacity `2048`: `1737472` drops
- Current interpretation of the knob sweep:
  - worker count and early-export behavior dominate the outcome much more than
    local batching tweaks
  - larger batches and deeper shard queues help, but they do not rescue a
    configuration that is already overloaded by richer flow work plus frequent
    early export
  - `--threads 5` is not a sensible realtime high-throughput default for the
    current architecture; it is too low relative to the measured `10 Gbit/s`
    operating point
  - the realtime default thread policy is now `12`, still capped at the
    number of logical CPUs, while offline pcap keeps the historical default of
    `5`
  - validation of the new realtime default on `rustiflow:test-slim` with no
    explicit `--threads`, `8 x 1.25G`, `1400`-byte UDP, `15s`, ingress:
    `9.99 Gbit/s`, `0` dropped packets
  - using all logical CPUs by default was unnecessary for the current `10G`
    target in this harness; a bounded default keeps the out-of-box realtime
    behavior aligned with the proven zero-drop operating point without jumping
    straight to the machine maximum
  - `early_export = None` remains the sane throughput default; short periodic
    export intervals should be treated as an observability tradeoff, not as a
    neutral setting
  - shard batch size and queue capacity are worth keeping tunable as advanced
    knobs, but they are second-order compared with threads and export cadence
- Semantic parity between offline and realtime ingestion now has explicit test
  coverage for the changed structure:
  - constructor-level parity tests compare `PacketFeatures` built from parsed
    IPv4/IPv6 packets against `PacketFeatures` built from equivalent eBPF
    events, including timestamps, packet lengths, flags, sequence numbers, and
    biflow-defining endpoint fields
  - flow-level parity tests feed equivalent offline and realtime packet
    sequences into `FlowTable` and verify matching bidirectional exports and
    matching idle-timeout expiration behavior
  - this keeps the ingestion redesign grounded in the invariant that, once a
    packet is normalized into `PacketFeatures`, flow ownership, expiration, and
    exporter output stay aligned across both ingestion modes
- Narrow validation for that semantic-parity work:
  - `cargo test -p rustiflow packet_features_test -- --nocapture`
  - `cargo test -p rustiflow flow_table_test -- --nocapture`
  - `cargo check -p rustiflow`
- First bounded follow-up on the new parallelization phase:
  - added a per-source dispatch stage in `rustiflow/src/realtime.rs` so the
    ring-buffer drain tasks no longer await shard-channel sends directly
  - each realtime source now batches packets, enqueues shard work into a
    bounded per-source dispatch queue, and a separate dispatcher task performs
    the shard-channel `send().await`
- Immediate validation on the local slim-container harness:
  - `10G`, `1400`-byte UDP, `-P 8`, `--threads 12`, `--early-export 0`:
    about `12.7 Gbit/s`, `0` RustiFlow drops
  - overloaded ingress case, `2.5G`, `1400`-byte UDP, `-P 8`,
    `--threads 4`, `--early-export 5`: about `13.2 Gbit/s`,
    `608731` RustiFlow drops
- Refined source stats on a short stats-enabled overloaded run show the first
  checklist item is materially complete:
  - `ingress-ipv4-q0`: `avg_event_us=0.209`,
    `avg_enqueue_wait_us=0.059`, `avg_shard_send_wait_us=0.148`
  - `ingress-ipv4-q2`: `avg_event_us=0.218`,
    `avg_enqueue_wait_us=0.085`, `avg_shard_send_wait_us=0.080`
  - `ingress-ipv4-q3`: `avg_event_us=0.222`,
    `avg_enqueue_wait_us=0.117`, `avg_shard_send_wait_us=0.233`
- Current interpretation:
  - the source tasks are now spending much less time blocked on downstream
    backpressure than in the earlier inline-send design
  - the remaining hot wait has shifted into the dispatcher-to-shard stage,
    which is exactly the next place to optimize
  - queue balance is still imperfect under some `iperf3` multi-flow shapes, so
    queue-count and fanout tuning remain worthwhile next experiments
- Follow-up answer to the next checklist item, using the same slim-container
  harness and hot workloads:
  - clean `10G` case, `1400`-byte UDP, `-P 8`, `--threads 12`,
    `--early-export 0`:
    - repeated runs stayed at `10.9` to `12.7 Gbit/s`
    - RustiFlow still reported `0` dropped packets
  - overloaded ingress case, target `2.5G` per stream, `1400`-byte UDP,
    `-P 8`, `--threads 4`, `--early-export 5`:
    - recent runs landed between about `11.0` and `13.2 Gbit/s`
    - RustiFlow drops fell between `0` and `608731`
    - compared with the earlier pre-dispatch-decoupling baseline on the same
      general shape (`641688` to `1233317` drops, but at higher achieved
      bitrate around `15.7` to `16.3 Gbit/s`), the drop count generally
      improved, but the load generator no longer drove quite as much traffic
- Current interpretation of the hot-case comparison:
  - the drain/dispatch split is not a clean across-the-board throughput win
  - it does preserve the proven zero-drop operating point for the clean `10G`
    case
  - on the overloaded multi-flow case it appears to trade lower drop counts for
    somewhat lower achieved bitrate, so the next experiments need to determine
    whether that reflects healthier backpressure or simply a different upstream
    bottleneck
- Re-evaluated queue parallelism by increasing
  `REALTIME_EVENT_QUEUE_COUNT` from `4` to `8` for both IPv4 and IPv6 ringbuf
  sources:
  - clean `10G` case, `1400`-byte UDP, `-P 8`, `--threads 12`,
    `--early-export 0`: `9.96 Gbit/s`, `0` dropped packets
  - overloaded ingress case, target `2.5G` per stream, `1400`-byte UDP,
    `-P 8`, `--threads 4`, `--early-export 5`: `10.3 Gbit/s`,
    `0` dropped packets
  - relative to the earlier `4`-queue version on the same overloaded shape,
    the `8`-queue version bought real headroom: the same workload no longer
    overran RustiFlow internally
- Short stats-enabled run on the `8`-queue build:
  - `ingress-ipv4-q0`: `1114790` events
  - `ingress-ipv4-q1`: `1733000` events
  - `ingress-ipv4-q5`: `1136284` events
  - `ingress-ipv4-q6`: `565056` events
  - `ingress-ipv4-q2`, `q3`, `q4`, and `q7`: `no events drained`
- Current interpretation of the `8`-queue result:
  - increasing queue count beyond `4` does buy real headroom on the current
    architecture and was worth doing before considering a more invasive
    transport rewrite
  - queue usage is still visibly skewed under the existing `iperf3` multi-flow
    stress case, so fanout quality remains an active bottleneck even after the
    headroom gain from `8` queues
- Explicit queue-balance follow-up after the `8`-queue change:
  - switched the queue-selection hash in both eBPF programs from the earlier
    XOR-and-rotate tuple combiner to a stronger canonical-tuple
    `hash_combine` + `fmix32` style finalization
  - this kept biflow-stable queue selection but improved spread for the
    observed reverse-UDP `iperf3` flow set
- Short stats-enabled overloaded run with the revised fanout:
  - `ingress-ipv4-q1`: `1174440` events
  - `ingress-ipv4-q2`: `562581` events
  - `ingress-ipv4-q3`: `566039` events
  - `ingress-ipv4-q4`: `550207` events
  - `ingress-ipv4-q5`: `566313` events
  - `ingress-ipv4-q6`: `1135669` events
  - only `q0` and `q7` stayed idle on this run, versus four idle queues under
    the previous fanout
- Hot-case check after the fanout revision:
  - overloaded ingress case, target `2.5G` per stream, `1400`-byte UDP,
    `-P 8`, `--threads 4`, `--early-export 5`: `9.77 Gbit/s`,
    `0` dropped packets
  - clean `10G` case, `1400`-byte UDP, `-P 8`, `--threads 12`,
    `--early-export 0`: `9.67 Gbit/s`, `0` dropped packets
- Current interpretation of the fanout experiment:
  - queue-balance quality improved materially and no longer shows the earlier
    obvious four-queue skew
  - the current architecture now has more usable parallel ingress width before
    a transport rewrite is justified
  - some skew remains, so fanout quality is not "solved forever", but this
    bounded experiment did move the real bottleneck forward
- Semantic-parity guard for the newer realtime-only tuning steps:
  - existing parity coverage already protected constructor-level normalization
    for IPv4 and IPv6, and flow/export parity for IPv4
  - added the missing IPv6 flow-level parity tests so the mirrored IPv6
    multi-queue path is covered at the same level:
    - offline/realtime IPv6 bidirectional export parity
    - offline/realtime IPv6 idle-expiration parity
  - this keeps the newer queue-count, fanout, and dispatch changes grounded in
    the rule that realtime parallelization must not change timestamps, packet
    lengths, biflow ownership, expiration causes, or exported flow contents
- Narrow validation for the semantic-parity guard:
  - `cargo test -p rustiflow packet_features_test -- --nocapture`
  - `cargo test -p rustiflow flow_table_test -- --nocapture`
  - `cargo check -p rustiflow`

## 2026-03-31

- First bounded profiling pass on the current parallel realtime path used the
  local `rustiflow-t0` harness with the existing userspace profiling hooks:
  - `RUSTIFLOW_REALTIME_STATS=1` for per-source drain/dispatch timing in
    `rustiflow/src/realtime.rs`
  - `RUSTIFLOW_PROFILE_RESOURCE_SUMMARY=1` for process CPU/RSS/context-switch
    summaries
  - `RUSTIFLOW_PROFILE_FLAMEGRAPH=...svg` for userspace flamegraph output
- Workload shape for the main bounded comparisons:
  - ingress IPv4 only on `rustiflow-t0`
  - reverse UDP traffic from the local namespace peer
  - `iperf3 -c 10.203.0.2 -B 10.203.0.1 -u -b 1.25G -l 1400 -P 8 -t 10 -R -p 5201`
  - container image `rustiflow:test-slim`
  - `--threads 12`
- `basic` with no `--early-export` flag:
  - receiver bitrate about `9.85 Gbit/s`
  - RustiFlow dropped packets `0`
  - process summary: about `17.7 s` user CPU, `6.0 s` sys CPU, max RSS about
    `2.19 GB`
  - per-source stats show the clean `10G` operating point is no longer
    dominated by shard-send wait:
    - active queues stayed around `0.10` to `0.12 us` average enqueue wait
    - active queues stayed around `0.11` to `0.18 us` average shard-send wait
    - decode-and-shard stayed around `0.22` to `0.23 us` average event cost
  - current interpretation:
    - on the proven `10G` case, the parallel ingress path is comfortably past
      the earlier multi-millisecond backpressure regime
    - the remaining sampled hot userspace work is mostly inside the source task
      / batching path rather than export
- `rustiflow` with `--early-export 5` on the same traffic shape:
  - receiver bitrate about `9.99 Gbit/s`
  - RustiFlow dropped packets `0`
  - process summary: about `21.4 s` user CPU, `6.9 s` sys CPU, max RSS about
    `2.28 GB`
  - exported CSV volume rose sharply to about `636590` lines and about
    `625 MB` in a `10 s` run
  - per-source stats moved back into a materially slower regime:
    - average enqueue wait about `1.67` to `5.20 us`
    - average shard-send wait about `1.81` to `5.26 us`
    - average total event cost about `1.73` to `5.03 us`
  - the userspace flamegraph on this export-heavy run shows the export subtree
    is now a real cost center:
    - `rustiflow::output::OutputWriter::<T>::write_flow` occupied about `35%`
      inclusive sampled width
    - `RustiFlow::dump` directly underneath it also occupied about `35%`
      inclusive sampled width
    - formatting-heavy feature dumps such as payload and window-size stats were
      visible hot subtrees under `dump`
  - current interpretation:
    - export formatting and serialization are now confirmed costs under high
      export pressure; they are no longer merely speculative redesign targets
    - the dispatcher/backpressure path still matters, but on this shape export
      work is large enough that snapshot / CSV redesign questions should now be
      evidence-driven rather than deferred as unmeasured risk
- `rustiflow` with no `--early-export` flag on the same traffic shape:
  - receiver bitrate about `9.98 Gbit/s`
  - RustiFlow dropped packets `0`
  - process summary: about `18.1 s` user CPU, `5.9 s` sys CPU, max RSS about
    `2.19 GB`
  - exported CSV volume collapsed back to only the final-flow output: about
    `10` lines and about `15 KB`
  - per-source stats returned to the same low-wait regime as the `basic`
    no-early-export case:
    - average enqueue wait about `0.09` to `0.12 us`
    - average shard-send wait about `0.11` to `0.17 us`
    - average total event cost about `0.21` to `0.22 us`
  - the no-early-export flamegraph no longer shows `OutputWriter::write_flow`
    or `RustiFlow::dump` as meaningful hot subtrees
  - instead, the visible sampled work is concentrated in:
    - realtime source-task batching (`enqueue_pending_batches` /
      `enqueue_shard_batch`)
    - dispatcher tasks spawned by `spawn_source_dispatcher`
    - `FlowTable::process_packet` / `process_existing_flow`
    - `RustiFlow::update_flow`
  - current interpretation:
    - at the proven `10G` operating point, richer feature extraction by itself
      is not the main remaining limiter
    - the large extra CPU cost seen with `--early-export 5` is primarily export
      pressure rather than inherent `RustiFlow` feature-update cost
    - this gives a cleaner priority order for follow-up work:
      measure export-path redesign options first, and only revisit cheaper
      running-statistics implementations if later profiling still shows the
      feature modules hot after export pressure is removed
- Export-cost isolation follow-up with `basic --early-export 5` on the same
  `10G` shape:
  - receiver bitrate about `9.96 Gbit/s`
  - RustiFlow dropped packets `0`
  - process summary: about `20.6 s` user CPU, `6.7 s` sys CPU, max RSS about
    `2.31 GB`
  - exported output grew to about `2296493` CSV lines and about `326 MB`
  - per-source waits clearly rose relative to the no-early-export `basic`
    baseline:
    - average enqueue wait about `1.34` to `4.27 us`
    - average shard-send wait about `2.27` to `4.37 us`
  - the flamegraph confirms that periodic export alone is enough to create a
    visible export subtree even for the cheap schema:
    - `OutputWriter::write_flow` occupied about `7.3%` inclusive sampled width
    - `BasicFlow::dump` occupied about `7.0%` inclusive sampled width
    - timestamp / formatting work under `BasicFlow::dump` was visible, but much
      smaller than the richer `RustiFlow::dump` export tree
- Current interpretation after the export-cost isolation pass:
  - export pressure by itself is a real limiter even for `basic`
  - richer exporter formatting in `rustiflow` magnifies that cost sharply:
    - `basic --early-export 5`: about `7%` sampled export subtree
    - `rustiflow --early-export 5`: about `35%` sampled export subtree
  - line count alone is not the right proxy for export cost:
    - `basic --early-export 5` emitted more lines than `rustiflow --early-export 5`
    - but `rustiflow --early-export 5` still produced the much hotter export
      flamegraph because each serialized record is substantially heavier
  - the next export-path experiments should focus on reducing per-record
    formatting / serialization cost before redesigning ingestion again for the
    clean `10G` operating point
- First bounded export-path mitigation on `2026-03-31`:
  - changed `OutputWriter` to write the serialized flow string directly with
    `write_all()` plus `\n` instead of going back through `writeln!`
  - rewrote top-level `BasicFlow` and `RustiFlow` CSV assembly to build one
    output buffer directly instead of creating `Vec<String>` plus `join(",")`
  - validation:
    - `cargo fmt`
    - `cargo test -p rustiflow flow_table_test -- --nocapture`
    - `cargo check -p rustiflow`
    - `cargo clippy -p rustiflow --all-targets`
- Reprofile of the same hot case after that bounded export change:
  - workload unchanged: `rustiflow`, `--early-export 5`, `10G`, `1400`-byte
    UDP, `-P 8`, `--threads 12`, ingress on `rustiflow-t0`
  - receiver bitrate stayed at about `9.99 Gbit/s`
  - RustiFlow dropped packets stayed at `0`
  - process summary improved from about `21.4 s` user / `6.9 s` sys CPU to
    about `19.4 s` user / `6.4 s` sys CPU
  - flamegraph comparison:
    - before: `OutputWriter::write_flow` and `RustiFlow::dump` each occupied
      about `35%` inclusive sampled width
    - after: the same subtree fell to about `28%` inclusive sampled width
    - payload/window-size dump helpers are still visible hot leaves underneath
      `RustiFlow::dump`
  - current interpretation:
    - the bounded CSV-assembly cleanup produced a real but not decisive win
    - export formatting remains a major cost center under periodic export even
      after removing obvious top-level string assembly overhead
    - the next profitable layer is likely inside the heavier feature dump
      helpers themselves, or a more structural change to how CSV rows are
      emitted, rather than another ingress redesign
- Follow-up bounded experiment on the shared feature dump helpers:
  - tried replacing several feature-level `format!` / nested `dump_values()`
    paths with append-style `String` assembly in shared `FeatureStats`,
    `PayloadLengthStats`, `WindowSizeStats`, `PacketLengthStats`,
    `HeaderLengthStats`, `IATStats`, `ActiveIdleStats`, `BulkStats`,
    `TimingStats`, and `TcpFlagStats`
  - reprofiled the same `rustiflow --early-export 5`, `10G`, `-P 8`,
    `--threads 12` case:
    - receiver bitrate stayed about `9.99 Gbit/s`
    - RustiFlow dropped packets stayed at `0`
    - process summary came back at about `21.6 s` user / `7.2 s` sys CPU
    - CSV output was about `712,637` lines / `734 MB`
  - current interpretation:
    - this second-pass feature-dump refactor did not show a reliable win on the
      same hot case
    - output volume also varied upward enough that the run is not cleaner than
      the earlier `opt1` result
    - keep the earlier top-level CSV assembly cleanup, but do not keep this
      wider feature-dump rewrite as a trusted optimization
    - the next export-path work should target a more structural bottleneck than
      replacing additional leaf `format!` calls one by one
- Export-breakdown measurement for the first structural checklist item:
  - added an opt-in userspace export breakdown behind
    `RUSTIFLOW_PROFILE_EXPORT_BREAKDOWN=1`
  - current instrumentation records:
    - flow snapshot clone time inside `FlowTable::apply_packet_to_flow`
    - row serialization time inside `OutputWriter::write_flow` around
      `dump()` / `dump_without_contamination()`
    - buffered write time for the serialized row bytes
  - reran the same rebuilt `rustiflow:test-slim` hot case:
    - `rustiflow`, `--early-export 5`, `10G`, `1400`-byte UDP, `-P 8`,
      `--threads 12`, ingress on `rustiflow-t0`
    - receiver bitrate about `9.98 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `20.0 s` user CPU / `6.3 s` sys CPU, max RSS about
      `2.28 GB`
    - exported output about `474,875` rows / `489 MB`
  - measured export split on that run:
    - `clone_count=474,866`
    - flow snapshot clone time about `92 ms` total
    - row serialization (`dump`) time about `5,030 ms` total
    - buffered write time about `561 ms` total
  - current interpretation:
    - at the proven `10G` early-export operating point, snapshot ownership cost
      is not the main export bottleneck
    - per-row serialization dominates clone cost by roughly two orders of
      magnitude on the measured hot case
    - buffered row writes are visible but still much smaller than `dump()`
    - the next structural export experiment should focus on avoiding or
      reshaping full-row string serialization, not on clone elimination first
- First bounded direct-to-writer CSV prototype:
  - added `write_csv_row` / `write_csv_row_without_contamination` on the hot
    `BasicFlow` and `RustiFlow` exporters so `OutputWriter` could emit rows
    directly to the buffered writer instead of first building one full row
    `String`
  - reran the same rebuilt `rustiflow:test-slim` hot case with export
    breakdown enabled:
    - receiver bitrate about `9.99 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `19.6 s` user CPU / `7.0 s` sys CPU, max RSS about
      `2.27 GB`
    - exported output about `526,580` rows / `542 MB`
    - measured export breakdown:
      - `clone_count=526,571`
      - clone time about `97 ms`
      - export-path timed section about `5,954 ms`
      - trailing newline write about `12 ms`
  - current interpretation:
    - this first direct-to-writer version did not produce a clean trusted win
      over the prior row-string path on the same hot case
    - output volume varied upward, and total export-path time did not fall in a
      way strong enough to justify keeping the added complexity
    - revert this prototype and keep looking for a more structural reduction in
      per-row serialization cost
- Accepted follow-up export-path change: reuse one top-level row buffer per
  `OutputWriter` instead of allocating a fresh row `String` on every export:
  - kept the existing row-assembly semantics and feature `dump()` calls, but
    added append-style flow methods so `OutputWriter` can clear and reuse an
    owned `String` buffer for each row
  - reran the same rebuilt `rustiflow:test-slim` hot case with export
    breakdown enabled:
    - `rustiflow`, `--early-export 5`, `10G`, `1400`-byte UDP, `-P 8`,
      `--threads 12`, ingress on `rustiflow-t0`
    - receiver bitrate about `9.99 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `19.1 s` user CPU / `6.3 s` sys CPU, max RSS about
      `2.27 GB`
    - exported output about `524,089` rows / `540 MB`
    - measured export breakdown:
      - `clone_count=524,080`
      - clone time about `89 ms`
      - row serialization (`dump`) time about `4,807 ms`
      - buffered write time about `545 ms`
  - normalized comparison against the earlier `breakdown2` row-string baseline:
    - dump cost fell from about `10.59 us` per row to about `9.17 us` per row
    - write cost fell from about `1.18 us` per row to about `1.04 us` per row
    - total CPU time fell from about `55.3 us` per row to about `48.4 us` per
      row
  - current interpretation:
    - reusing the top-level export row buffer is a clean trusted win even
      though the sampled run exported more rows than the earlier baseline
    - the gain is meaningfully smaller than a full serialization redesign, but
      it removes one recurring allocation layer without changing export
      semantics
    - the remaining structural export bottleneck is still inside per-feature
      serialization work rather than snapshot cloning or top-level row writes
- Evaluation of a typed snapshot-vs-owned export message at the channel
  boundary:
  - tried a bounded `ExportedFlow::{Snapshot, Owned}` split so early export
    could keep sending cloned snapshots while terminated / expired / shutdown
    flows moved out of the shard without cloning
  - this was the most plausible safe substitute for a borrow-based export view,
    because the current writer task consumes exports asynchronously over
    `mpsc`; that boundary needs owned data and does not permit borrowing flow
    state out of the shard task
  - validation was clean:
    - `cargo fmt`
    - `cargo check -p rustiflow`
    - `cargo test -p rustiflow flow_table_test -- --nocapture`
    - `cargo test -p rustiflow pcap_fixture_test -- --nocapture`
    - `cargo clippy -p rustiflow --all-targets`
  - reran the same rebuilt `rustiflow:test-slim` hot case with export
    breakdown enabled:
    - `rustiflow`, `--early-export 5`, `10G`, `1400`-byte UDP, `-P 8`,
      `--threads 12`, ingress on `rustiflow-t0`
    - receiver bitrate about `9.98 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `20.0 s` user CPU / `6.7 s` sys CPU, max RSS about
      `2.29 GB`
    - exported output about `603,424` rows / `621 MB`
    - measured export breakdown:
      - `clone_count=603,415`
      - clone time about `122 ms`
      - row serialization (`dump`) time about `5,348 ms`
      - buffered write time about `628 ms`
  - current interpretation:
    - on the proven hot case, the typed ownership split does not materially
      change what the exporter is paying for
    - only `9` of `603,424` exported rows were owned final exports; the rest
      were still early-export snapshots, so clone elimination on termination
      paths is not where the current pressure lives
    - a borrow-based export view is not compatible with the present
      cross-task writer architecture without a larger ownership and scheduling
      redesign
    - revert the typed ownership split and keep the conclusion in notes rather
      than carrying extra plumbing that does not improve the measured hot path
- Remaining hot-family identification after the accepted top-level row-buffer
  reuse:
  - inspected the kept `rusti-10g-ee5-reuse1.svg` hot-case flamegraph and the
    `RustiFlow::dump` call structure
  - the feature families still showing up materially as direct dump leaves were:
    - `BulkStats` about `3.1%`
    - `PacketLengthStats` about `3.0%`
    - `WindowSizeStats` about `2.5%`
    - `PayloadLengthStats` about `2.4%`
    - `IATStats` about `2.3%`
    - `TcpFlagStats` about `2.2%`
  - smaller but still visible families included `HeaderLengthStats` and
    `ActiveIdleStats`, while the colder families did not justify another broad
    rewrite
- Accepted targeted dump-path change for those first-tier families:
  - added append-style CSV emission to `FeatureStats` and `FlowFeature`, but
    only overrode it for the six feature families still showing up materially
    in the flamegraph:
    `BulkStats`, `PacketLengthStats`, `WindowSizeStats`,
    `PayloadLengthStats`, `IATStats`, and `TcpFlagStats`
  - `RustiFlow::dump` and the contamination-free dump path now append those
    fields directly into the shared row buffer instead of allocating one
    intermediate feature `String` for each of them
  - validation:
    - `cargo fmt`
    - `cargo check -p rustiflow`
    - `cargo clippy -p rustiflow --all-targets`
    - `cargo test -p rustiflow pcap_fixture_test -- --nocapture`
    - `cargo test -p rustiflow nf_flow_test -- --nocapture`
  - reran the same rebuilt `rustiflow:test-slim` hot case with export
    breakdown enabled:
    - `rustiflow`, `--early-export 5`, `10G`, `1400`-byte UDP, `-P 8`,
      `--threads 12`, ingress on `rustiflow-t0`
    - receiver bitrate about `9.91 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `20.2 s` user CPU / `7.1 s` sys CPU, max RSS about
      `2.29 GB`
    - exported output about `700,668` rows / `721 MB`
    - measured export breakdown:
      - `clone_count=700,659`
      - clone time about `121 ms`
      - row serialization (`dump`) time about `5,110 ms`
      - buffered write time about `790 ms`
  - normalized comparison against `rusti-10g-ee5-reuse1`:
    - dump cost fell from about `9.17 us` per row to about `7.29 us` per row
    - total CPU time fell from about `48.4 us` per row to about `38.8 us` per
      row
    - the targeted feature families no longer appeared as standalone hot dump
      leaves in the new flamegraph
  - current interpretation:
    - the targeted append-path change is worth keeping
    - the flamegraph-guided approach worked better than the earlier broad
      feature-dump rewrite because it cut one allocation layer only where the
      profile still showed meaningful cost
    - the next export work should re-run the comparison matrix
      (`basic --early-export 5`, `rustiflow --early-export 5`, and a
      no-early-export control) before picking the next colder feature family
- Post-change export-heavy comparison matrix on the current kept codepath:
  - workload shape kept constant for all three runs:
    `10G`, `1400`-byte UDP, `-P 8`, `10s`, `--threads 12`, ingress on
    `rustiflow-t0`, containerized `rustiflow:test-slim`
  - `basic --early-export 5`:
    - receiver bitrate about `9.98 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `19.3 s` user CPU / `6.1 s` sys CPU, max RSS about
      `2.26 GB`
    - exported output about `3,085,329` rows / `459 MB`
    - export breakdown:
      - `clone_count=3,085,320`
      - clone time about `350 ms`
      - row serialization (`dump`) time about `1,849 ms`
      - buffered write time about `634 ms`
  - `rustiflow --early-export 5` after the targeted hot-family change:
    - receiver bitrate about `9.91 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `20.2 s` user CPU / `7.1 s` sys CPU, max RSS about
      `2.29 GB`
    - exported output about `700,668` rows / `721 MB`
    - export breakdown:
      - `clone_count=700,659`
      - clone time about `121 ms`
      - row serialization (`dump`) time about `5,110 ms`
      - buffered write time about `790 ms`
    - this run saw noticeably higher `iperf3` receiver loss than the other two
      matrix runs, so the export-timer normalization is the stronger signal
      than raw loss percentage here
  - `rustiflow` with no `--early-export`:
    - receiver bitrate about `9.98 Gbit/s`
    - RustiFlow dropped packets `0`
    - process summary about `17.0 s` user CPU / `6.1 s` sys CPU, max RSS about
      `2.19 GB`
    - exported output about `9` rows / `11 KB`
    - export breakdown:
      - `clone_count=0`
      - clone time `0 ms`
      - row serialization (`dump`) time about `0.097 ms`
      - buffered write time about `0.030 ms`
  - current interpretation after the matrix rerun:
    - the current structural export work continues to preserve the practical
      `10G` operating point with `0` RustiFlow drops across the matrix
    - export pressure is still the dominant differentiator:
      the no-early-export control nearly removes export cost entirely, while
      both `--early-export 5` cases spend real time in serialization
    - `basic --early-export 5` remains much cheaper per exported row than
      `rustiflow --early-export 5`, but the gap is narrower after the targeted
      hot-family append-path change
    - the next export-path target should come from a colder second tier under
      `RustiFlow::dump`, not from revisiting snapshot cloning or whole-pipeline
      ownership changes
- One accidental command detail also matters operationally:
  - passing `--early-export 0` does not disable early export; it produces
    effectively continuous early export because the CLI passes `Some(0)`
  - on the same `10G` shape with `basic`, that setting still produced `0`
    RustiFlow drops but exploded output to about `5.85 million` CSV lines and
    about `832 MB` in `10 s`
  - for throughput experiments, disabling early export still means omitting the
    flag entirely rather than passing `0`

## 2026-04-04

- Completed a local `25G`-target realtime matrix on the `rustiflow-t0`
  software-path harness using 24-port `iperf3` fanout for both IPv4 and IPv6.
  Large-packet UDP (`1400` bytes) now repeatedly reaches near-line-rate local
  control throughput (`24.96 Gbit/s`) and RustiFlow stays close to it with `0`
  internal drops (`24.72 Gbit/s` to `/dev/null`, `24.76 Gbit/s` with normal
  final CSV output). PPS-heavier UDP remains limited by the local
  generator/harness before RustiFlow drops (`512` bytes about `9.93 Gbit/s`
  control, `8.97 Gbit/s` with RustiFlow; `256` bytes about `4.70 Gbit/s` with
  RustiFlow and still `0` drops). Bounded mixed-workload, short-lived-flow
  churn, and `900 s` soak runs also stayed clean: IPv4 soak about
  `22.32 Gbit/s`, IPv6 soak about `23.92 Gbit/s`, and a disk-backed churn soak
  exported `14,276` CSV lines / about `18.3 MB` with `0` dropped packets.

## 2026-04-05

- Explored a separate local multiqueue `pktgen` harness on `rgbcore` as a
  bounded attempt to push beyond the existing `iperf3` software-path setup.
- The dedicated local `pktgen` harness used:
  - host interface `rustiflow-pg0`
  - peer namespace `rustiflow-pktgen`
  - peer interface `rustiflow-pg1`
  - multiqueue veth with `8` RX and `8` TX queues on both ends
  - separate addressing from the original `iperf3` harness:
    `10.204.0.1/30` and `10.204.0.2/30`
- Bounded `pktgen` control runs worked reliably after switching from infinite
  `count 0` operation to finite packet counts derived from target rate,
  duration, and packet size.
- However, the local control ceiling stayed well below the intended `40G`
  target:
  - earlier best `8`-queue control runs were only about `22.5` to
    `22.9 Gbit/s`
  - later control sweeps on the same software-path harness flattened around
    `19.7 Gbit/s` regardless of whether the target was `25G`, `30G`, `35G`, or
    `40G`
  - reducing to `4` queues made the control path materially worse, about
    `10 Gbit/s`
  - slightly larger packets (`1500` bytes) helped only modestly, reaching
    about `20.9 Gbit/s`
- Interpretation from the control sweeps:
  - the local multiqueue veth plus `pktgen` path itself is the bottleneck
  - the target-rate knob is no longer the limiting factor once the harness
    reaches that software-path ceiling
  - this makes the local `pktgen` harness unsuitable as a credible proxy for
    true `40G` wire-rate validation of the current RustiFlow architecture
- RustiFlow comparison runs on that harness also did not justify keeping the
  experiment as a maintained workflow:
  - containerized `null` runs with `8` queues and a `25G` target were around
    `18.9 Gbit/s` with `0` dropped packets
  - a rebuilt host `release` binary pinned with `taskset` to CPUs `8-15` and
    `--threads 8` was comparable, about `18.0 Gbit/s` with `0` dropped
    packets
  - host-mode `taskset` plus host RX `RPS` was better than `taskset` alone,
    but neither path changed the underlying local control ceiling enough to
    make the setup useful for a `40G` answer
- Conclusion:
  - keep the original `rustiflow-t0` / `rustiflow-peer` / `rustiflow-p0`
    harness as the trusted local software-path validation environment
  - do not keep the local `pktgen` harness workflow or helper files in-tree
  - treat true `40G` validation for the current tc/eBPF realtime path as a
    physical-hardware problem rather than a local veth virtualization problem
- Updated the persistent local `rustiflow-swtest-veth.service` harness to bias
  for bulk local throughput rather than realism:
  - explicit `8x8` multiqueue veth on both ends, matching the current
    userspace/eBPF `REALTIME_EVENT_QUEUE_COUNT`
  - jumbo `9000` MTU and `txqueuelen 10000` on both ends
  - widened veth `gso`/`gro` ceilings (`262144`) on both ends
  - host and peer `RPS`/`XPS` fanout spread evenly across the available local
    CPUs
  - keep in mind this increases throughput bias and can make the local harness
    less representative of real NIC packetization behavior
- Added a structured local harness regression matrix in
  `docs/realtime-throughput-matrix.md`, including fixed CPU partitioning and
  scenario bundles for control, `basic`, and `rustiflow` runs on the trusted
  local software-path harness.
- Validated the full local harness matrix end to end on the trusted
  `rustiflow-t0` / `rustiflow-peer` software-path rig using the fixed CPU split
  documented in `docs/realtime-throughput-matrix.md`:
  - sender / generator CPUs `0-7`
  - RustiFlow CPUs `8-23`
  - control / receiver CPUs `24-31`
  - raw artifacts stored in `target/realtime-matrix/20260405-190241/`
- Summary of the completed matrix:
  - `B1` steady large-packet UDP baseline (`1400` bytes, `P8`, `30 s`):
    control `22.2 Gbit/s`; `basic` `13.9 Gbit/s` with `0` drops and `37.4%`
    headroom loss; `rustiflow` `11.1 Gbit/s` with `0` drops and `50.0%`
    headroom loss
  - `B2` large-packet UDP near local ceiling (best bounded control from the
    sweep): control `16.7 Gbit/s`; `basic` `13.4 Gbit/s` with `0` drops and
    `19.8%` headroom loss; `rustiflow` `11.1 Gbit/s` with `0` drops and
    `33.5%` headroom loss
  - `B3` small-packet UDP PPS stress (`512` bytes): control `7.27 Gbit/s`;
    `basic` `5.21 Gbit/s` with `0` drops and `28.3%` headroom loss;
    `rustiflow` `4.20 Gbit/s` with `0` drops and `42.2%` headroom loss
  - `B4` smaller-packet UDP PPS stress (`256` bytes): control `3.68 Gbit/s`;
    `basic` `2.11 Gbit/s` with `0` drops and `42.7%` headroom loss;
    `rustiflow` `2.68 Gbit/s` with `0` drops and `27.2%` headroom loss
  - `B5` mixed UDP plus TCP: control `114.37 Gbit/s` total
    (`udp=7.37`, `tcp=107.00`); `basic` `110.94 Gbit/s` with `0` drops and
    `3.0%` headroom loss; `rustiflow` `114.24 Gbit/s` with `0` drops and
    `0.1%` headroom loss
  - `B6` short-lived TCP flow churn (`200` short reverse-TCP runs): control
    average `94.48 Gbit/s`; `basic` average `94.25 Gbit/s` with `0` drops and
    `0.24%` headroom loss; `rustiflow` average `93.78 Gbit/s` with `0` drops
    and `0.74%` headroom loss
  - `B7` long soak (`900 s` large-packet UDP): control `18.8 Gbit/s`;
    `basic` `13.7 Gbit/s` with `0` drops and `27.1%` headroom loss;
    `rustiflow` `12.6 Gbit/s` with `0` drops and `33.0%` headroom loss
  - `B8` local replay fallback using `rustiflow/tests/data/nmap_udp_version.pcap`
    looped through `tcpreplay`: control `241.85 Mbit/s`; `basic`
    `258.92 Mbit/s` with `0` drops; `rustiflow` `239.68 Mbit/s` with `0`
    drops. This is only a bounded parser / replay smoke test, not a
    representative throughput trace. `tcpreplay` also emitted repeated decode
    warnings about the tiny trace lacking enough bytes for an ICMP header.
- Takeaways from the full matrix:
  - the trusted local harness is credible as a software-path regression rig in
    the approximate `20-25G` large-packet range, not as a true `40G`
    wire-rate validator
  - large-packet and PPS-heavy reverse UDP cases still give up substantial
    headroom under both `basic` and `rustiflow`, even though all completed
    capture runs stayed at `0` internal dropped packets
  - mixed TCP / UDP and short-lived TCP churn stay much closer to control on
    this host than the pure reverse-UDP cases
  - the `900 s` soak stayed stable and drop-free, but still showed material
    headroom loss versus control
