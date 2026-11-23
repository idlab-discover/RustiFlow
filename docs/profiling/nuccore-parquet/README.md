# Parquet writer profile on nuccore

The single-writer Parquet candidate adds a measurable export bottleneck. Across five matched runs with full RustiFlow features, offline throughput fell 15% and replay throughput fell 13–14%. The previous CSV executable reproduced the earlier baseline on this host. These measurements serve as the starting point for optimizing the branch.

## Offline and replay

Measured on 2026-11-23. The candidate is the writer committed in `cf49bfb`, profiled from its working tree over `1040b8d`. The control is the archived executable from `67a8109`, verified against its published SHA-256. Both used the optimized Cargo profiling profile, four workers, CPUs 0–5 and `/dev/null`. Each case had one warmup and five measured repetitions. The deterministic offline pcap contained 2 million packets across 10,000 flows. The IPv4 and IPv6 replays each used 10 million events across 100,000 flows. [Host, toolchains and binary hashes](environment.txt) · [Previous baseline](../nuccore-67a8109/README.md)

Throughput is median (min–max) in millions of packets or events per second. Offline throughput covers the whole command. Replay throughput excludes event generation and includes export and finalization. Hardware counters cover the whole command in both cases and are medians per input. [CSV control repetitions](csv-control.csv) · [Parquet repetitions](userspace.csv)

| Input | Features | Prior CSV Mpps | Parquet Mpps | Change | Cycles/input CSV / Parquet | Instructions/input CSV / Parquet |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| offline | basic | 7.60 (7.19–7.87) | 7.25 (6.62–7.38) | -4.7% | 858 / 871 | 1396 / 1393 |
| offline | rustiflow | 7.75 (7.66–7.84) | 6.58 (6.54–6.80) | -15.1% | 1074 / 1104 | 2004 / 2025 |
| replay4 | basic | 29.78 (29.48–30.18) | 27.55 (26.71–27.82) | -7.5% | 844 / 860 | 1068 / 1066 |
| replay4 | rustiflow | 5.95 (5.92–5.98) | 5.16 (5.10–5.25) | -13.2% | 2021 / 1993 | 2351 / 2139 |
| replay6 | basic | 30.40 (29.98–30.70) | 27.92 (27.46–28.49) | -8.1% | 827 / 841 | 1048 / 1046 |
| replay6 | rustiflow | 5.92 (5.84–5.95) | 5.08 (5.03–5.13) | -14.2% | 1940 / 1894 | 2332 / 2116 |

Full-feature IPv4 replay used 778.0 ns of process CPU per event with CSV and 782.3 ns with Parquet, even as elapsed time increased. The whole-command instruction count fell by 9%. The largest sampled CPU symbol remained flow-table packet processing at 29.45% offline, 31.30% in IPv4 replay and 33.35% in IPv6 replay. A large CPU sample share and a long wall-clock shutdown tail measure different things. [Offline samples](offline-rustiflow.hotspots.txt) · [IPv4 samples](replay4-rustiflow.hotspots.txt) · [IPv6 samples](replay6-rustiflow.hotspots.txt)

## Time spent finishing exports

A second comparison wrote regular files and rotated the order of the old CSV binary, current CSV and current Parquet. Each had a warmup and five measured runs. For offline capture the parent timestamped the existing end-of-input log message and process exit. This interval includes outstanding shard work, final export and process teardown. The shorter replay used 1 million events and 100,000 possible flows, increasing the number of exported records per input event. Timings include closing the file and writing the footer. Filesystem durability after a power loss was outside the measurement. [Measurements](export-heavy.csv) · [Reproduction script](../export_tail.py)

| Writer | Offline end-of-input to exit, ms | Short replay phase, ms | Short replay CPU, ns/event | Offline file, MB | Short replay file, MB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Prior CSV | 11.7 (9.9–12.2) | 298 (295–314) | 1,239 | 8.67 | 106.51 |
| Current CSV | 13.7 (11.0–23.3) | 306 (289–324) | 1,288 | 8.67 | 106.51 |
| Current Parquet | 35.6 (35.3–36.1) | 562 (549–581) | 1,289 | 0.70 | 33.10 |

Switching only the output format in the current binary increased median short-replay elapsed time by 84% with essentially identical aggregate CPU time. CSV encodes records in per-shard tasks. Parquet routes completed flows through one bounded queue to a single task that projects fields, encodes and compresses columns, and finalizes the file. The timing and CPU measurements are consistent with this serial work extending the critical path.

In separate instrumented runs, projecting 10,000 offline rows took 9.6 ms and writing batches plus finalization took 22.4 ms. For the 10-million-event IPv4 replay these totals were 99.7 ms and 262.4 ms for 100,000 rows. Both runs recorded zero flow clones. Parquet write time includes encoding and compression as well as I/O. CSV encoding time in the prior report sums work across concurrent shard tasks. [Export timing and resource counters](export-instrumentation.txt)

Two independently written Parquet files yielded the previous fixture's exact SHA-256 after decoding fields with Rust's Arrow reader, formatting timestamp and numeric values as in CSV, sorting the data lines and prepending the original schema names. This checks every exported value for 10,000 unique flows with 200 packets each. Cross-shard ordering can change compressed file size between runs. [Readback fingerprints](offline-validation.txt)

## Allocations

Heaptrack covered the same offline workload and the shorter 1-million-event IPv4 replay as the prior baseline. Counts include the whole process. Replay allocated more often while using less peak tracked heap. [Offline totals](heaptrack-offline.txt) · [Replay totals](heaptrack-replay4.txt)

| Workload | Allocation calls, prior CSV / Parquet | Temporary allocations, prior CSV / Parquet | Peak heap MB, prior CSV / Parquet |
| --- | ---: | ---: | ---: |
| Offline | 66,586 / 124,623 | 42,589 / 49,306 | 41.01 / 62.29 |
| Short IPv4 replay | 612,829 / 1,102,403 | 378,819 / 440,144 | 411.24 / 384.22 |

## Live ingress and classifiers

All six veth runs sent 300,000 packets with zero sender errors. Each classifier matched and submitted 150,000 packets with zero drops. The sampling interval covers the sender command and ends before final export. These fixed-rate runs validate receive behavior up to 200 kpps on this harness. They do not establish sustained capacity during heavy concurrent flow expiration. [Live repetitions](live.csv)

| Offered pps | Median achieved pps | Userspace cycles/frame, prior CSV / Parquet | Userspace instructions/frame, prior CSV / Parquet |
| ---: | ---: | ---: | ---: |
| 50,000 | 49,999 | 4,959 / 5,009 | 4,954 / 4,940 |
| 200,000 | 199,975 | 3,622 / 3,664 | 3,845 / 3,861 |

The separate 200 kpps sample recorded zero lost CPU samples. Flow-table packet processing accounted for 11.77% of sampled self cycles and ring draining for 9.73%. [Live self profile](receive-sample.hotspots.txt) · [Live cumulative profile](receive-sample.cumulative.txt)

The release eBPF objects matched the previous checksums, program tags and JIT sizes. With kernel runtime accounting enabled, the two passes measured 363.6–367.7 ns per IPv4 invocation and 392.7–399.5 ns per IPv6 invocation. The separate BTF objects measured about 2,056 cycles and 1,666 instructions per IPv4 invocation and 2,187 cycles and 1,888 instructions per IPv6 invocation. Both hardware profiles completed with the BTF objects. The default objects lack the BTF required by that diagnostic. [Classifier runtime and sizes](classifiers.csv) · [Hardware counts](bpftool-profile.txt)
