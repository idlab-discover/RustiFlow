#!/usr/bin/env bash
# Run from the repository root with sudo -n. See overnight-ring-wakeup-coalescing.md.
set -euo pipefail
mode=${1:?usage: ring_drain.sh MODE OUTPUT_DIRECTORY PCAP [PPS|top] [TAIL_PCAP]}
out=${2:?specify an output directory}
pcap=$(realpath "${3:?specify a pcap}")
rate=${4:-top}
tail_pcap=${5:-}
if [[ -n $tail_pcap ]]; then tail_pcap=$(realpath "$tail_pcap"); fi
bin=${RUSTIFLOW_PROFILE_BIN:-"$PWD/target/profiling/rustiflow"}
capture_cpus=${RUSTIFLOW_PROFILE_CAPTURE_CPUS:-0-3}
export RUSTIFLOW_EBPF_DIR=${RUSTIFLOW_EBPF_DIR:-"$PWD/target/bpfel-unknown-none/release"}
export RUST_LOG=info
unset RUSTIFLOW_REALTIME_STATS RUSTIFLOW_PROFILE_FLAMEGRAPH
limit=(--limit=300000)
pace=(--topspeed)
if [[ $rate != top ]]; then pace=("--pps=$rate"); fi
output=/dev/null
case $mode in
    stat|kernel) ;;
    notify) export RUSTIFLOW_REALTIME_STATS=1 ;;
    low|backlog|pressure|fair)
        export RUSTIFLOW_REALTIME_STATS=1
        limit=()
        output="$out/flows.parquet"
        ;;
    *) exit 2 ;;
esac

mkdir -p "$out"
cap=rf08-cap-$BASHPID
send=rf08-send-$BASHPID
pid=
paused=
stats_before=$(sysctl -n kernel.bpf_stats_enabled)
stats_changed=0
cleanup() {
    if [[ -n $pid ]]; then
        if [[ -n $paused ]]; then kill -CONT "$pid" 2>/dev/null || true; fi
        kill -INT "$pid" 2>/dev/null || true
        wait "$pid" || true
    fi
    ip netns del "$cap" 2>/dev/null || true
    ip netns del "$send" 2>/dev/null || true
    if (( stats_changed )); then sysctl -qw "kernel.bpf_stats_enabled=$stats_before"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip netns add "$cap"
ip netns add "$send"
ip link add cap0 netns "$cap" type veth peer name send0 netns "$send"
for ns in "$cap" "$send"; do
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done
ip -n "$cap" link set cap0 address 02:00:00:00:00:02 up
ip -n "$send" link set send0 address 02:00:00:00:00:01 up
if [[ $stats_before != 0 ]]; then
    sysctl -qw kernel.bpf_stats_enabled=0
    stats_changed=1
fi

ip netns exec "$cap" taskset -c "$capture_cpus" "$bin" -f rustiflow --export-path "$output" \
    --threads 2 realtime cap0 --ingress-only >"$out/capture.log" 2>&1 &
pid=$!
for _ in {1..100}; do
    kill -0 "$pid" 2>/dev/null || { cat "$out/capture.log"; exit 1; }
    if rg -q 'Waiting for Ctrl-C' "$out/capture.log"; then break; fi
    sleep 0.05
done
rg -q 'Waiting for Ctrl-C' "$out/capture.log"
ip netns exec "$cap" tc filter show dev cap0 ingress >"$out/ingress.tc"
ip -n "$cap" -s -j link show dev cap0 >"$out/link-before.json"

sender=(ip netns exec "$send" taskset -c 4 tcpreplay --preload-pcap
        "${pace[@]}" "${limit[@]}" --intf1=send0 "$pcap")
date +%s%6N >"$out/send-start.us"
case $mode in
    stat)
        perf stat -x ';' -e cpu_core/cycles/u,cpu_core/instructions/u -p "$pid" \
            -o "$out/perf.stat" -- "${sender[@]}" >"$out/sender.log" 2>&1
        ;;
    kernel)
        perf record -a -C 4 -e cpu_core/cycles/k -F 499 --call-graph fp --no-buildid-cache \
            -o "$out/perf.data" -- "${sender[@]}" >"$out/sender.log" 2>"$out/record.log"
        perf report -f -i "$out/perf.data" --stdio --no-children --percent-limit 0.5 -g none \
            >"$out/hotspots.txt"
        ;;
    notify)
        # Count epoll callbacks for RustiFlow event-map fds on the sender CPU.
        # Check the file operations before interpreting private_data as a map.
        probe='
        fentry:ep_poll_callback /cpu == 4/ {
            $entry = (struct eppoll_entry *)((uint64)args.wait - (uint64)offsetof(struct eppoll_entry, wait));
            $file = $entry->base->ffd.file;
            if ((uint64)$file->f_op == kaddr("bpf_map_fops")) {
                $map = (struct bpf_map *)$file->private_data;
                if (strncmp(str($map->name), "EVENTS_IPV", 10) == 0) {
                    @notifications[str($map->name)] = count();
                }
            }
        }'
        printf -v replay_command '%q ' "${sender[@]}"
        bpftrace -q -e "$probe" -c 'sleep 0.3' >"$out/idle-wakeups.txt" 2>"$out/idle-trace.log"
        bpftrace -q -e "$probe" -c "$replay_command" >"$out/wakeups.txt" 2>"$out/trace.log"
        # bpftrace and its replay child share stdout.
        cp "$out/wakeups.txt" "$out/sender.log"
        rg -q 'Successful packets:' "$out/sender.log"
        ;;
    low)
        "${sender[@]}" >"$out/sender.log" 2>&1
        ;;
    backlog|pressure|fair)
        kill -STOP "$pid"
        paused=1
        for _ in {1..100}; do
            if rg -q $'^State:\tT' "/proc/$pid/status"; then break; fi
            sleep 0.01
        done
        rg -q $'^State:\tT' "/proc/$pid/status"
        "${sender[@]}" >"$out/sender.log" 2>&1
        if [[ $mode == fair ]]; then
            python - "$pid" >"$out/resume.us" <<'PYRESUME'
import os
import signal
import sys
from time import time_ns

before = time_ns() // 1_000
os.kill(int(sys.argv[1]), signal.SIGCONT)
print(before, time_ns() // 1_000)
PYRESUME
        else
            kill -CONT "$pid"
        fi
        paused=
        ;;
esac

date +%s%6N >"$out/send-end.us"
if [[ -n $tail_pcap ]]; then
    sleep 0.3
    date +%s%6N >"$out/tail-start.us"
    ip netns exec "$send" taskset -c 4 tcpreplay --preload-pcap --pps=20 \
        --intf1=send0 "$tail_pcap" >"$out/tail-sender.log" 2>&1
    date +%s%6N >"$out/tail-end.us"
fi
ip -n "$cap" -s -j link show dev cap0 >"$out/link-after.json"
case $mode in
    pressure) sleep 4 ;;
    fair) sleep 0.8 ;;
    *) sleep 0.3 ;;
esac
kill -INT "$pid"
wait "$pid"
pid=
ip netns exec "$cap" tc filter show dev cap0 ingress >"$out/detached.tc"
[[ ! -s "$out/detached.tc" ]]
