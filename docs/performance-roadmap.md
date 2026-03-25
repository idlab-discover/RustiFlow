# Performance Roadmap

This file tracks performance work for pushing RustiFlow beyond already-successful
`10Gbps` realtime capture.

Use this as an execution checklist, not as a design essay.

## Ground Rules

- [ ] Measure before and after every meaningful optimization.
- [ ] Prefer hot-path wins over broad rewrites.
- [ ] Do not trade away feature correctness for speed without making that trade explicit.
- [ ] Keep performance work in clean, bounded commits.
- [ ] After recent ingestion-semantics fixes, stabilize and measure before expanding the eBPF event payload further.

## Phase 0: Baseline And Profiling

- [ ] Establish a repeatable Linux benchmark setup on a real target machine.
- [ ] Capture baseline numbers for:
  - packets per second
  - dropped packets
  - CPU usage by userspace and kernel path
  - active flow count
  - export throughput
- [ ] Collect flamegraphs or equivalent profiling for:
  - realtime ingest
  - flow-table updates
  - export path
- [ ] Separate ingress-only and ingress+egress benchmark modes.

Why this matters:
The current implementation already performs well. Past this point, guessing is expensive.

## Phase 1: Biggest Likely Wins

### 1. Typed Flow Keys

- [ ] Replace string-based packet keys with compact typed keys.
- [ ] Remove repeated `String` creation from:
  - `flow_key()`
  - `flow_key_bwd()`
  - `biflow_key()`
- [ ] Use typed keys in shard selection and flow-table lookup.
- [ ] Keep string formatting only for export.

Primary files:

- `rustiflow/src/packet_features.rs`
- `rustiflow/src/flow_table.rs`
- `rustiflow/src/realtime.rs`

Expected value:
Very high. This is a likely hot-path allocation and hashing tax.

### 2. Cheaper Running Statistics

- [ ] Replace per-update standard deviation work with a running variance form such as Welford.
- [ ] Store enough state to compute `std` at dump/close time.
- [ ] Benchmark impact across heavily used feature families.

Primary files:

- `rustiflow/src/flows/features/util.rs`
- `rustiflow/src/flows/features/*.rs`

Expected value:
High. Many feature modules pay this cost on every packet.

### 3. Realtime Timestamp Fix

- [ ] Carry capture timestamps from kernel to userspace instead of calling `Utc::now()` per event.
- [ ] Keep timestamp semantics aligned with offline mode as much as possible.
- [ ] Re-benchmark after this change because it affects both correctness and overhead.

Primary files:

- `common/src/lib.rs`
- `ebpf-ipv4/src/main.rs`
- `ebpf-ipv6/src/main.rs`
- `rustiflow/src/packet_features.rs`

Expected value:
High. Improves correctness and removes per-event userspace time acquisition.

## Phase 2: Hot-Path Structural Cleanup

### 4. FlowTable Access Patterns

- [ ] Reduce repeated hashing and key rebuilding in flow lookup.
- [ ] Avoid `contains_key` plus `remove` plus `insert` churn where possible.
- [ ] Revisit direction resolution after typed keys are introduced.

Primary file:

- `rustiflow/src/flow_table.rs`

Expected value:
High once typed keys exist.

### 5. Export Without Cloning Full Flow State

- [ ] Reduce or remove full-flow cloning for early export and termination export.
- [ ] Consider separating mutable hot-path state from export snapshots.
- [ ] Measure clone cost for `RustiFlow` specifically before redesigning too far.

Primary files:

- `rustiflow/src/flow_table.rs`
- `rustiflow/src/flows/flow.rs`
- `rustiflow/src/flows/*.rs`

Expected value:
Medium to high depending on export rate and flow size.

### 6. Performance Mode Should Mean Performance

- [ ] Make sure high-throughput runs bypass packet-TUI work completely.
- [ ] Audit mutexes, watch channels, and per-packet UI accounting in performance-sensitive modes.
- [ ] Keep observability available, but not in the critical path by default.

Primary files:

- `rustiflow/src/realtime.rs`
- `rustiflow/src/packet_counts.rs`
- `rustiflow/src/flow_tui.rs`

Expected value:
Medium to high for very fast realtime capture.

## Phase 3: Throughput Scaling

### 7. Batching Between Stages

- [ ] Benchmark per-packet `mpsc` overhead.
- [ ] Try batched ring-buffer draining.
- [ ] Try batched shard submission.
- [ ] Keep changes narrow until measurement proves batching is worth the complexity.

Primary file:

- `rustiflow/src/realtime.rs`

Expected value:
Medium, possibly high at very large packet rates.

### 8. Faster Internal Hashing

- [ ] Benchmark a faster internal hasher after typed keys are in place.
- [ ] Prefer a fast non-adversarial hasher only for internal packet-processing paths.
- [ ] Keep any public or security-sensitive hashing decisions separate.

Primary files:

- `rustiflow/src/realtime.rs`
- `rustiflow/src/flow_table.rs`

Expected value:
Medium. Probably not worth doing first.

### 9. Smarter Expiration Scheduling

- [ ] Benchmark expiration scans at high concurrent flow counts.
- [ ] If scans become costly, evaluate timing buckets or a timer wheel.
- [ ] Do not build a more complex expiry structure before profiling says the scan is a real bottleneck.

Primary file:

- `rustiflow/src/flow_table.rs`

Expected value:
Medium, but workload-dependent.

## Phase 4: Export Path Optimization

### 10. Cheaper Serialization

- [ ] Measure cost of giant `format!`-based CSV assembly.
- [ ] Consider more streaming-oriented serialization for high export rates.
- [ ] Keep export-path changes isolated from flow semantics.

Primary files:

- `rustiflow/src/output.rs`
- `rustiflow/src/flows/*.rs`

Expected value:
Medium. Important once export volume becomes the limiter.

## Operational Metrics To Add

- [ ] Per-source ring buffer drain rate
- [ ] Per-shard queue depth or backlog
- [ ] Active flow count over time
- [ ] Export throughput and export lag
- [ ] Dropped packet counters split by ingress/egress and IPv4/IPv6
- [ ] A lightweight performance summary mode for realtime runs

Why this matters:
If RustiFlow is going to chase higher link rates, it needs good self-observability.

## Deferred Stress Testing Notes

- [ ] Remember that `10Gbps+` software-path testing is possible without a physical external link.
- [ ] Prefer doing this on an actual Linux development machine instead of macOS.
- [ ] Treat software-only stress testing as useful for RustiFlow and eBPF/userspace throughput, but not as a full substitute for real NIC validation.

Practical options for later:

- `veth` pair + network namespaces + RustiFlow on one side
- Linux `pktgen` for high packet-rate stress
- TRex for more realistic replay and traffic profiles
- MoonGen for high-rate scripted generation

What this is good for:

- packet-rate pressure
- flow-table pressure
- eBPF event rate
- userspace queueing and dropped packets
- export throughput

What this does not fully prove:

- physical NIC behavior
- PCIe and DMA effects
- hardware offloads
- real RSS / hardware queue behavior

## Not Early Priorities

- [ ] Do not start with micro-optimizing individual feature modules before fixing keying and stats math.
- [ ] Do not move large parts of flow aggregation into eBPF without profiling evidence.
- [ ] Do not do broad architecture rewrites before collecting hard measurements.
- [ ] Do not let exporter churn distract from realtime hot-path costs.

## Current Best Order

- [ ] Phase 0: Baseline and profiling
- [ ] Phase 1.1: Typed flow keys
- [ ] Phase 1.2: Cheaper running statistics
- [ ] Phase 1.3: Kernel-carried timestamps
- [ ] Phase 2.4: FlowTable access cleanup
- [ ] Phase 2.5: Export without cloning
- [ ] Phase 2.6: Strict performance mode
- [ ] Phase 3.7: Batching
- [ ] Phase 3.8: Faster hashing
- [ ] Phase 3.9: Smarter expiration scheduling
- [ ] Phase 4.10: Serialization optimization

## Progress Notes

- Use short dated notes here when a measurement or optimization changes priorities.
- If a planned optimization turns out not to matter, mark it done and note that it was ruled out.
- 2026-03-25: Decision: stabilize and measure after the current timestamp and length/header-length alignment work before adding more packet metadata to eBPF events.
