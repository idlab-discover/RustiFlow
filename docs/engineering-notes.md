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
