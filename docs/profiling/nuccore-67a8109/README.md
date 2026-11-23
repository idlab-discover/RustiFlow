# RustiFlow profiling baseline on nuccore

Measured 2026-11-23 against source commit `67a8109d173eba2bb8b3f190ee8a1b178ce566c0`. Userspace used the release-optimized `profiling` Cargo profile with line tables. Both eBPF objects used the `release` profile. See [environment and checksums](environment.txt) and [reproduction commands](../README.md).

## Offline and synthetic replay

Five runs per case after one warmup, with four flow workers on CPUs 0–5. Output was CSV directed to `/dev/null`, so metrics include serialization and writes to the sink. Throughput and replay CPU cost entries show median (min–max). Instruction and cycle counts are medians normalized by input packet/event count. Counters cover userspace for the whole command. [Individual repetitions](userspace.csv)

| Input | Feature set | Whole command Mpps | Replay phase Mpps | Replay CPU ns/event | Whole command cycles/input | Whole command instructions/input |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Offline dual-stack UDP | basic | 7.52 (6.69–7.72) | — | — | 854 | 1,396 |
| Offline dual-stack UDP | rustiflow | 7.69 (7.66–7.78) | — | — | 1,073 | 2,003 |
| Replay IPv4 TCP/UDP | basic | 18.38 (17.04–18.55) | 29.80 (28.89–29.91) | 186.8 (185.0–190.3) | 850 | 1,068 |
| Replay IPv4 TCP/UDP | rustiflow | 5.28 (5.21–5.34) | 5.99 (5.92–6.07) | 778.2 (765.0–780.5) | 2,030 | 2,350 |
| Replay IPv6 TCP/UDP | basic | 17.18 (15.87–17.36) | 30.64 (30.22–30.76) | 180.2 (179.3–182.4) | 826 | 1,048 |
| Replay IPv6 TCP/UDP | rustiflow | 5.09 (5.02–5.15) | 5.92 (5.88–5.96) | 786.1 (779.2–790.4) | 1,986 | 2,331 |

Whole-command time includes process setup, input generation in replay, and shutdown. The built-in replay timer starts after event generation and includes final CSV export. The offline run used 2 million UDP packets and 10,000 flows. Each replay used 10 million events and 100,000 flows, with a mix of TCP and UDP. These inputs exercise different code paths and have different flow lifetimes. The two offline feature sets took similar wall time on this input even though `rustiflow` consumed about 26% more cycles and 43% more instructions. Measure queue and worker utilization before attributing the shared wall time to a particular stage.

### CPU samples

Self percentages refer to sampled user CPU cycles. The optimized build inlines work into the enclosing symbols, so use source annotation before attributing the full symbol cost to an individual operation.

| Symbol | Offline | Replay IPv4 | Replay IPv6 |
| --- | ---: | ---: | ---: |
| `FlowTable::process_packet_without_expiration_scan` | 29.34% | 32.22% | 32.44% |
| `FlowTable::apply_packet_to_flow` | 3.25% | 6.29% | 6.26% |
| `ShardDispatcher::dispatch` | 12.93% | — | — |
| `CaptureReader::next_packet` | 6.11% | — | — |
| `LegacyPcapReader::next` | 5.18% | — | — |
| `RetransmissionStats::update_direction` | — | 10.61% | 11.22% |
| `replay_source` | — | 6.11% | 7.21% |
| Float formatting `format_shortest_opt` | below 1% | 4.79% | 5.38% |
| `FlowKey::canonicalize` | 5.43% | 4.71% | 4.67% |
| `IATStats::update` | 4.07% | 3.54% | 3.37% |
| `PayloadLengthStats::update` | 3.71% | 3.97% | 4.09% |

Offline canonicalization sums the main-thread and worker entries for the same symbol. Retransmission tracking appears in the TCP/UDP replay, where every even flow carries in-order TCP data, while the offline fixture carries UDP. A dash indicates the path is outside the workload. Separate sampling runs used 499 Hz and recorded zero lost samples. The offline report has 639 samples and each replay report about 4,000.

- Offline [self](offline-rustiflow.hotspots.txt) and [cumulative](offline-rustiflow.cumulative.txt)
- IPv4 replay [self](replay4-rustiflow.hotspots.txt) and [cumulative](replay4-rustiflow.cumulative.txt)
- IPv6 replay [self](replay6-rustiflow.hotspots.txt) and [cumulative](replay6-rustiflow.cumulative.txt)

## Live ingress and classifiers

Both veth endpoints were in temporary network namespaces. In each run, `tcpreplay` sent 300,000 frames from CPU 4. The receiver used two flow workers on CPUs 0–3. All six runs had zero sender errors and reconciled exactly to 150,000 matched and submitted events per classifier, with zero eBPF drops. Userspace counters include the lifetime of the sender command, including its pcap preload, and exclude the final shutdown export. [Individual repetitions](live.csv)

| Offered pps | Achieved pps median (min–max) | Userspace cycles per frame | Userspace instructions per frame |
| ---: | ---: | ---: | ---: |
| 50,000 | 49,999.13 (49,998.74–49,999.92) | 4,959 (4,954–5,009) | 4,954 (4,947–4,962) |
| 200,000 | 199,978.53 (199,976.93–199,979.60) | 3,622 (3,617–3,626) | 3,845 (3,826–3,882) |

The per-frame userspace cost was lower at 200 kpps. Batch fill and wakeup frequency are worth measuring independently before attributing the difference to either. The separate 200 kpps CPU sample reconciled all 300,000 events with zero drops and had roughly 1,000 samples with no losses. Its leading self costs were `drain_ring_source` (10.76%), the flow-table packet processing function (10.51%), and `spawn_source_dispatcher` (7.97%). `enqueue_shard_batch` contributed 5.13% and Tokio I/O readiness contributed 4.17%. [Live self profile](receive-sample.hotspots.txt) · [Live cumulative profile](receive-sample.cumulative.txt)

### eBPF runtime and instruction counts

The default release objects ran in two instrumented 50 kpps passes with kernel BPF runtime accounting enabled. Both classifiers saw every frame and each submitted half the stream, so the runtime measurements include matching and non-matching invocations. The sum gives about **753–757 ns of instrumented classifier runtime per offered frame**. [Kernel runtime deltas and code sizes](classifiers.csv)

| Classifier | ns per invocation, two runs | JIT code bytes | BTF diagnostic cycles per invocation | BTF diagnostic instructions per invocation |
| --- | ---: | ---: | ---: | ---: |
| IPv4 | 359.91, 362.32 | 17,591 | 2,055 | 1,664 |
| IPv6 | 393.47, 394.29 | 25,446 | 2,228 | 1,887 |

`bpftool prog profile` initially returned `doesn't have valid btf` for the default objects. Separate release builds with `-C debuginfo=2 -C link-arg=--btf` attached and produced hardware counters in 5-second windows at 50 kpps. Their program tags and JIT sizes differ from the default objects (18,199 bytes IPv4, 26,876 bytes IPv6), so compare those counters only with candidates built and measured with the same flags. Normalize to the profiler's invocation count, which covers the sampled portion of each stream. [Raw hardware counter output](bpftool-profile.txt)

The live workload was UDP over veth ingress at two fixed rates. It leaves open the effects of NIC receive, TCP, egress, offloads, saturation, and kernel datapath work outside the classifier. For end-to-end kernel cost, add a paired attachment-off/on experiment at a matched rate.

## Allocations and export

Heaptrack was run separately for the full offline fixture and a shorter IPv4 replay with 1 million events and 100,000 flows. The sample uses the same feature set, output sink, and CPU affinity as the CPU profiles. Heaptrace timing includes substantial instrumentation overhead.

| Workload | Allocation calls | Temporary allocations | Peak tracked heap |
| --- | ---: | ---: | ---: |
| Offline UDP, 10,000 flows | 66,586 | 42,589 | 41.01 MB |
| IPv4 replay, 100,000 flows | 612,829 | 378,819 | 411.24 MB |

Flow-table allocation stacks appear in both reports. Event generation and the tenfold flow count also contribute to replay's memory footprint. Use fixed flow and packet counts when comparing allocation and peak-memory changes. [Offline heaptrack totals](heaptrack-offline.txt) · [Replay heaptrack totals](heaptrack-replay4.txt)

RustiFlow's export instrumentation recorded 27.35 ms of CSV encoding for 10,000 offline rows written to a regular file, and 468.25 ms for 100,000 IPv4 replay rows written to `/dev/null`. Both runs recorded zero clone operations. The offline CSV was checked across two exports: 10,000 unique UDP flows with 200 packets each, half IPv4 and half IPv6, and identical SHA-256 after sorting rows. [Export and resource diagnostics](export-instrumentation.txt) · [Offline CSV verification](offline-validation.txt)

## Where to start comparing branches

- Use cycles per packet across offline and both replay cases for changes around the flow table, key canonicalization, and feature updates.
- Use the TCP/UDP replay for retransmission tracking and a separately controlled export workload for formatting. Preserve the CSV fingerprint for the unchanged UDP fixture.
- Use offline throughput and dispatcher samples for reader or sharding changes. These stages remain visible in the CPU profile even when wall time is similar across feature sets.
- Use the fixed-rate receive samples for ring draining, dispatch, and wakeups. Keep live sender success, submitted events, and loss alongside CPU measurements.
- Use default-object runtime and JIT size for classifier changes, and keep BTF hardware-counter comparisons in their own matched build configuration.
