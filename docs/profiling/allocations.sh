#!/usr/bin/env bash
# Run from the repository root after building --profile profiling.
set -euo pipefail
out=${1:?usage: allocations.sh OUTPUT_DIRECTORY PCAP}
pcap=${2:?usage: allocations.sh OUTPUT_DIRECTORY PCAP}
mkdir -p "$out"
bin=target/profiling/rustiflow
opts=(-f rustiflow -o csv --export-path /dev/null --threads 4)
for workload in offline replay4; do
    case "$workload" in
        offline) input=(pcap "$pcap") ;;
        replay4) input=(replay-bench --packets 1000000 --flows 100000 --sources 8) ;;
    esac
    prefix="$out/$workload"
    taskset -c 0-5 heaptrack --record-only -o "$prefix.heaptrack" "$bin" "${opts[@]}" "${input[@]}" >"$prefix.log" 2>&1
    traces=("$prefix.heaptrack".{gz,zst})
    for trace in "${traces[@]}"; do
        if [[ -f $trace ]]; then
            heaptrack_print -f "$trace" -n 6 -s 3 >"$prefix.txt"
            break
        fi
    done
    [[ -s "$prefix.txt" ]]
done
