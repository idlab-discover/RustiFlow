#!/usr/bin/env bash
# Run from the repository root after building --profile profiling.
set -euo pipefail
unset RUST_LOG RUSTIFLOW_REALTIME_STATS RUSTIFLOW_PROFILE_FLAMEGRAPH
out=${1:?usage: userspace.sh OUTPUT_DIRECTORY PCAP}
pcap=${2:?usage: userspace.sh OUTPUT_DIRECTORY PCAP}
mkdir -p "$out"
bin=target/profiling/rustiflow
cpus=0-5
events=cpu_core/cycles/u,cpu_core/instructions/u,cpu_core/branch-misses/u,cpu_core/cache-misses/u
for workload in offline replay4 replay6; do
    case "$workload" in
        offline) input=(pcap "$pcap") ;;
        replay4) input=(replay-bench --packets 10000000 --flows 100000 --sources 8) ;;
        replay6) input=(replay-bench --packets 10000000 --flows 100000 --sources 8 --ipv6) ;;
    esac
    for feature in basic rustiflow; do
        prefix="$out/$workload-$feature"
        args=("$bin" -f "$feature" -o csv --export-path /dev/null --threads 4 "${input[@]}")
        taskset -c "$cpus" "${args[@]}" >"$prefix.warmup.txt" 2>&1
        for run in 1 2 3 4 5; do
            TIMEFORMAT=%R
            { time taskset -c "$cpus" perf stat -x ';' -e "$events" -o "$prefix.$run.stat" -- "${args[@]}" >"$prefix.$run.txt" 2>&1; } 2>"$prefix.$run.wall"
        done
        if [[ $feature == rustiflow ]]; then
            sudo -n taskset -c "$cpus" perf record -e cpu_core/cycles/u -F 499 --call-graph dwarf,8192 --no-buildid-cache -o "$prefix.perf.data" -- "${args[@]}" >"$prefix.record.txt" 2>&1
            sudo -n perf report -f -i "$prefix.perf.data" --stdio --no-children --percent-limit 1 -g none >"$prefix.hotspots.txt"
            sudo -n perf report -f -i "$prefix.perf.data" --stdio --children --percent-limit 3 -g none >"$prefix.cumulative.txt"
        fi
    done
done
