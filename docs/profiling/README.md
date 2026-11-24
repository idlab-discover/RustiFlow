# RustiFlow profiling

Scripts and workloads for measuring RustiFlow's CPU, allocation, and live
capture costs. [Experiments](experiments.md) summarizes the ten 2026-11
optimization experiments and their opt-in switches. Dated results are in the
[engineering notes](../engineering-notes.md).

## Baseline workflow

Run from the repository root. Pin timings to one set of physical cores (on nuccore, CPUs 0–5 are its six P-cores). Use the same Rust toolchains, packet counts, flow counts, worker counts, and output destination for before/after comparisons. The scripts are Bash and take an output directory and a pcap path.

```bash
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
cargo build --locked --profile profiling -p rustiflow

mkdir -p target/profile-baseline
python docs/profiling/generate_pcap.py target/profile-baseline/mixed.pcap
sha256sum target/profile-baseline/mixed.pcap

bash docs/profiling/userspace.sh target/profile-baseline/userspace target/profile-baseline/mixed.pcap
sudo bash docs/profiling/realtime.sh target/profile-baseline/realtime target/profile-baseline/mixed.pcap
bash docs/profiling/allocations.sh target/profile-baseline/allocations target/profile-baseline/mixed.pcap
```

The profiling scripts default to Parquet. Set `RUSTIFLOW_PROFILE_FORMAT=csv` to
reproduce the historical CSV runs. Set `RUSTIFLOW_PROFILE_BIN` to an absolute
path to compare an archived executable. Pass these variables through `sudo env`
when running the live harness.

The deterministic pcap defaults to 2 million Ethernet packets, spread evenly over 10,000 bidirectional UDP flows. IPv4 and IPv6 are equally represented, as are 24- and 448-byte UDP payloads. Endpoints and ports are stable per flow, packet direction alternates after every 10,000 packets, and pcap timestamps are 1 µs apart. The entire file is read offline. Live tests send the first 300,000 frames into a temporary veth with both endpoints in network namespaces. This measures the local software path. The live script temporarily changes `kernel.bpf_stats_enabled` for its instrumented passes and restores the previous setting on exit.

The userspace script runs one warmup and five measured repetitions per case. It records CPU call stacks separately with `perf record` using DWARF and the symbol-preserving Cargo profile. Samples use `sudo` on this host because unprivileged recording failed at `perf_event_paranoid=2`; userspace hardware counting worked without it. It is normal for the whole-command times and counters for replay to include event generation while the built-in replay summary excludes it. Use the same denominator and measurement interval when comparing changes.

Keep profiles, build objects, generated pcaps, and heap traces under `target/`. Record conclusions in the engineering notes, and commit only the compact CSVs those notes cite. For each prospective optimization, establish the expected metric and run the baseline and candidate under the same host conditions. Check exact output on a deterministic fixture and report throughput, CPU cost, capture loss, and run-to-run spread where applicable.

## Additional profiles and compact records

For a live userspace stack sample, run the realtime script with a separate output directory and append `--sample-only`. To reproduce classifier hardware counts with BTF, stage separate objects:

```bash
btf_target="$PWD/target/profile-baseline/btf-target"
for family in ipv4 ipv6; do
    (
        cd "ebpf-$family"
        CARGO_TARGET_DIR="$btf_target" \
        CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf" \
        cargo build --locked --target=bpfel-unknown-none --release -Z build-std=core
    )
done
sudo env RUSTIFLOW_EBPF_DIR="$btf_target/bpfel-unknown-none/release" \
    bash docs/profiling/realtime.sh target/profile-baseline/realtime-btf \
    target/profile-baseline/mixed.pcap --instrumented-only
```

Use the summarizers to convert raw results into CSV:

```bash
python docs/profiling/summarize_userspace.py target/profile-baseline/userspace \
    > target/profile-baseline/userspace.csv
python docs/profiling/summarize_realtime.py target/profile-baseline/realtime \
    target/profile-baseline/summary
```

Reproduce the offline CSV fingerprint and export diagnostics with:

```bash
RUST_LOG=info RUSTIFLOW_PROFILE_RESOURCE_SUMMARY=1 RUSTIFLOW_PROFILE_EXPORT_BREAKDOWN=1 \
    taskset -c 0-5 target/profiling/rustiflow -f rustiflow -o csv \
    --export-path target/profile-baseline/offline.csv --header --threads 4 \
    pcap target/profile-baseline/mixed.pcap
{
    head -n 1 target/profile-baseline/offline.csv
    tail -n +2 target/profile-baseline/offline.csv | LC_ALL=C sort
} | sha256sum
```

To compare the regular-file export tail, supply the archived CSV binary and a
profiling build of the candidate. The script runs one warmup and five measured
repetitions per writer, rotating their order, and writes its measurements to
`export-heavy.csv` in the output directory.

```bash
python docs/profiling/export_tail.py target/profile-parquet/baseline-rustiflow \
    target/profiling/rustiflow target/profile-baseline/mixed.pcap target/profile-parquet/tail
```

To compare CSV and Parquet in the same executable, omit the archived binary.
The matrix adds basic features for the offline capture and replays 10 million
IPv4 and IPv6 events to `/dev/null` with each feature set. The offline capture
and the short, export-heavy IPv4 replay write regular files. An even run count
gives each format the same number of first and second runs after warmup.

```bash
python docs/profiling/export_tail.py --matrix --runs 8 target/profiling/rustiflow \
    target/profile-baseline/mixed.pcap target/parquet-parity/final
```

The output directory contains the final regular files and all repetitions in
`writer-matrix.csv`. Use `command_s` for whole-command offline timing and
`replay_s` for replay timing including file close.
