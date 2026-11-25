# Performance experiments

Ten experiments ran on nuccore on 2026-11-24 against `2fbecc3d`. Each was
measured against that base with matched builds, CPU affinity, and inputs. Full
reports, including raw tables and exact reproduction commands, are in Git
history: `git show 2cd5df81:docs/profiling/overnight-<name>.md`.

| # | Experiment | Status | Switch |
| --- | --- | --- | --- |
| 1 | Batched AVX2 biflow keys | Default for Basic replay on AVX2 | `RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS=0/1` |
| 2 | Inline highest TCP sequence range | Default | none |
| 3 | AVX2 Parquet Float64 statistics | Not integrated | none |
| 4 | Shard batch buffer recycling | Default for live capture and Basic replay | `RUSTIFLOW_EXPERIMENT_RECYCLE_SHARD_BATCHES=0/1` |
| 5 | Staged, prefetched flow-table lookup | Opt-in, x86-64 | feature `staged-flow-lookup` + `RUSTIFLOW_EXPERIMENT_STAGED_FLOW_LOOKUP=1` |
| 6 | Bucketed expiry deadline index | Opt-in | feature `experiment-deadline-index` |
| 7 | Single dual-stack tc classifier | Opt-in, `--ingress-only` | `RUSTIFLOW_EXPERIMENT_SINGLE_TC=1` |
| 8 | Bounded ring drain budget | Opt-in | `RUSTIFLOW_EXPERIMENT_RING_DRAIN_BUDGET=1` |
| 9 | Dedicated ring source reactors | Opt-in, `--ingress-only` | `RUSTIFLOW_EXPERIMENT_SOURCE_REACTORS=N` |
| 10 | Passive XDP ingress | Opt-in, `--ingress-only` | `RUSTIFLOW_EXPERIMENT_INGRESS=xdp-driver` or `xdp-skb` |

## Results

1. **AVX2 flow keys.** Basic replay gains depended on long bursts. Full-feature
   replay gains stayed within run-to-run spread, and live capture cost rose.
   Integrated main enables it only for Basic replay. Staged lookup takes
   precedence when both are on.
2. **TCP sequence fast path.** The highest merged range stays inline, so
   in-order segments skip tree operations, including across rollover. Median
   full-feature replay improved 15.2–15.6% for both address families. The
   1,024-range bound and lowest-first eviction are unchanged.
3. **Parquet Float64 statistics.** An AVX2 reduction patched into Parquet 60.2.0
   saved 47% of cycles per value in isolation and 4.5% of instructions per
   event in export-heavy replay. Replay throughput moved about 1%, within
   spread. Only the Snappy round-trip regression test was kept. The patch is
   in Git history at `78ff4b46`.
4. **Batch buffer recycling.** Each shard keeps up to 32 empty batch vectors
   (at most 320 KiB with the 128-packet batches used in the experiment).
   Paced live capture used 3.4–3.6% fewer cycles per frame. Full-feature replay
   stayed within 1.4%.
5. **Staged lookup.** Groups of eight packets are hashed and probed and their
   flows are prefetched before being applied in order. At 262,144 flows it
   saved 20.5% of cycles in the isolated hit loop and raised replay 4.8–5.2%.
   At 650 kpps on veth it used 5.3% more cycles per frame. It also switches
   the table to hashbrown's `HashTable`.
6. **Deadline index.** With one-second expiration checks, ordered mostly-live
   replay rose from 2.10 to 3.02 Mpps and churn from 1.40 to 1.82 Mpps. At the
   default 60-second interval it cost 6.8% more cycles per packet and ran 4.6%
   slower.
7. **Single tc classifier.** One EtherType dispatch cut instrumented classifier
   time 2.3%, from 763.6 to 746.4 ns per frame. Unpaced veth medians, 0.760
   and 0.804 Mpps, had overlapping ranges.
8. **Ring drain budget.** Slices of at most 256 records with a 250 µs flush
   deadline. Paced capture cost rose, mixed traffic rarely built large batches,
   and marker delays overlapped. Drain-to-empty stays the default.
9. **Source reactors.** Rings and their dispatchers on up to `N` single-thread
   runtimes, with the CPU budget held fixed. Every layout lowered unpaced
   delivery and added kernel work per packet.
10. **XDP ingress.** The program always returns `XDP_PASS`. Both modes matched tc
    at fixed rates and spent less time inside BPF. In unpaced veth bursts, both
    delivered fewer packets per second and used more kernel cycles per frame.
    These results cover one software receive queue. NIC RSS, offloads, and
    physical-rate validation remain open.

## Building the experimental eBPF objects

Experiments 7 and 10 load separate objects. Point `RUSTIFLOW_EBPF_DIR` at the
directory that holds them:

```bash
cd ebpf-ipv6
cargo build --locked --release --features dual-stack --bin rustiflow-ebpf-dual-stack
cargo build --locked --release --features xdp-experiment --bin rustiflow-ebpf-ingress-experiment
# Objects land in target/bpfel-unknown-none/release/
```

## Scripts

| Script | Used for |
| --- | --- |
| `deadline_pcap.py` | Experiment 6 workloads: mostly-live and mixed-churn pcaps |
| `generate_skewed_pcap.py` | Experiment 9 skewed source fanout |
| `ring_drain.sh`, `check_ring_parquet.rs` | Experiments 8 and 9 live runs and Parquet continuity checks |
| `single_tc_fixture.py`, `validate_single_tc.sh`, `compare_live_parquet.rs` | Experiment 7 correctness fixture and split/dual comparison |
| `xdp_capture.sh`, `summarize_xdp.py` | Experiment 10 live runs and summaries |
| `flow_table_hit_bench` (ignored Rust test) | Experiment 5 isolated occupied-update loop. Run with `cargo test --release -p rustiflow --features staged-flow-lookup -- --ignored flow_table_hit_bench --nocapture`; `RUSTIFLOW_HIT_BENCH_FEATURE`, `_FLOWS`, `_BATCHES` and `_PAUSE` select the workload |
