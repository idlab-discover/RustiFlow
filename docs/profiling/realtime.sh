#!/usr/bin/env bash
# Run as root from the repository root after building the userspace and eBPF binaries.
set -euo pipefail
out=${1:?usage: realtime.sh OUTPUT_DIRECTORY PCAP}
pcap=$(realpath "${2:?usage: realtime.sh OUTPUT_DIRECTORY PCAP}")
mode=${3:-}
mkdir -p "$out"
bin=${RUSTIFLOW_PROFILE_BIN:-"$PWD/target/profiling/rustiflow"}
export RUSTIFLOW_EBPF_DIR=${RUSTIFLOW_EBPF_DIR:-"$PWD/target/bpfel-unknown-none/release"}
export RUST_LOG=info
unset RUSTIFLOW_REALTIME_STATS RUSTIFLOW_PROFILE_FLAMEGRAPH
capture_ns=rf-capture-$BASHPID
sender_ns=rf-sender-$BASHPID
capture_pid=
profile_pid=
stats_before=$(sysctl -n kernel.bpf_stats_enabled)
changed_stats=0
cleanup() {
    if [[ -n "$profile_pid" ]]; then
        kill -TERM "$profile_pid" 2>/dev/null || true
        wait "$profile_pid" || true
    fi
    if [[ -n "$capture_pid" ]]; then
        kill -INT "$capture_pid" 2>/dev/null || true
        wait "$capture_pid" || true
    fi
    if (( changed_stats )); then sysctl -qw "kernel.bpf_stats_enabled=$stats_before"; fi
    ip netns del "$capture_ns" 2>/dev/null || true
    ip netns del "$sender_ns" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip netns add "$capture_ns"
ip netns add "$sender_ns"
ip link add cap0 netns "$capture_ns" type veth peer name send0 netns "$sender_ns"
for ns in "$capture_ns" "$sender_ns"; do
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done
ip -n "$capture_ns" link set cap0 address 02:00:00:00:00:02 up
ip -n "$sender_ns" link set send0 address 02:00:00:00:00:01 up
if [[ $stats_before != 0 ]]; then
    changed_stats=1
    sysctl -qw kernel.bpf_stats_enabled=0
fi

send() {
    ip netns exec "$sender_ns" taskset -c 4 tcpreplay --preload-pcap --pps="$1" --limit=300000 --intf1=send0 "$pcap"
}

start_capture() {
    local prefix=$1
    ip netns exec "$capture_ns" taskset -c 0-3 "$bin" -f rustiflow -o "${RUSTIFLOW_PROFILE_FORMAT:-parquet}" \
        --export-path /dev/null --threads 2 realtime cap0 --ingress-only >"$prefix.capture" 2>&1 &
    capture_pid=$!
    for _ in {1..100}; do
        kill -0 "$capture_pid" 2>/dev/null || { cat "$prefix.capture"; return 1; }
        if [[ -f "$prefix.capture" ]] && grep -q 'Waiting for Ctrl-C' "$prefix.capture"; then break; fi
        sleep 0.05
    done
    grep -q 'Waiting for Ctrl-C' "$prefix.capture"
    ip netns exec "$capture_ns" tc filter show dev cap0 ingress >"$prefix.tc"
    ip -n "$capture_ns" -s -j link show dev cap0 >"$prefix.link-before"
}

stop_capture() {
    local prefix=$1
    ip -n "$capture_ns" -s -j link show dev cap0 >"$prefix.link-after"
    kill -INT "$capture_pid"
    wait "$capture_pid"
    capture_pid=
}

if [[ $mode == --sample-only || $mode == --kernel-sample-only ]]; then
    prefix="$out/receive-sample"
    start_capture "$prefix"
    if [[ $mode == --sample-only ]]; then
        sample=(-e cpu_core/cycles/u -p "$capture_pid" --call-graph dwarf,8192)
    else
        sample=(-e cpu_core/cycles/k -C 4 --call-graph fp)
    fi
    perf record "${sample[@]}" -F 499 --no-buildid-cache -o "$prefix.perf.data" -- \
        ip netns exec "$sender_ns" taskset -c 4 tcpreplay --preload-pcap \
        --pps=200000 --limit=300000 --intf1=send0 "$pcap" >"$prefix.sender" 2>"$prefix.record"
    sleep 0.2
    stop_capture "$prefix"
    perf report -f -i "$prefix.perf.data" --stdio --no-children --percent-limit 1 -g none >"$prefix.hotspots.txt"
    perf report -f -i "$prefix.perf.data" --stdio --children --percent-limit 3 -g none >"$prefix.cumulative.txt"
    exit 0
fi

if [[ $mode == --topspeed-only ]]; then
    for run in 1 2 3; do
        prefix="$out/topspeed-$run"
        start_capture "$prefix"
        ip netns exec "$sender_ns" taskset -c 4 tcpreplay --preload-pcap \
            --topspeed --limit=300000 --intf1=send0 "$pcap" >"$prefix.sender" 2>&1
        sleep 0.2
        stop_capture "$prefix"
    done
    exit 0
fi

if [[ $mode == --runtime-only ]]; then
    # Runtime accounting is separate from the fixed-rate perf stat runs.
    changed_stats=1
    sysctl -qw kernel.bpf_stats_enabled=1
    for run in 1 2 3; do
        prefix="$out/runtime-$run"
        start_capture "$prefix"
        mapfile -t ids < <(sed -nE 's/.* id ([0-9]+) .*/\1/p' "$prefix.tc")
        [[ ${#ids[@]} -gt 0 ]]
        for id in "${ids[@]}"; do bpftool -j prog show id "$id"; done >"$prefix.before"
        send 50000 >"$prefix.sender" 2>&1
        sleep 0.2
        for id in "${ids[@]}"; do bpftool -j prog show id "$id"; done >"$prefix.after"
        stop_capture "$prefix"
    done
    exit 0
fi

if [[ $mode != --instrumented-only ]]; then
    for rate in 50000 200000; do
        for run in 1 2 3; do
            prefix="$out/live-$rate-$run"
            start_capture "$prefix"
            # Count userspace capture cycles over the sender command.
            perf stat -x ';' -e cpu_core/cycles/u,cpu_core/instructions/u -p "$capture_pid" \
                -o "$prefix.stat" -- bash -c 'ip netns exec "$1" taskset -c 4 tcpreplay --preload-pcap --pps="$2" --limit=300000 --intf1=send0 "$3"' _ "$sender_ns" "$rate" "$pcap" >"$prefix.sender" 2>&1
            sleep 0.2
            stop_capture "$prefix"
        done
    done
fi
if [[ $mode == --live-only ]]; then exit 0; fi

changed_stats=1
sysctl -qw kernel.bpf_stats_enabled=1
for family in ipv4 ipv6; do
    prefix="$out/instrumented-$family"
    start_capture "$prefix"
    # RustiFlow attaches IPv4 first, then IPv6. tc lists in reverse priority order.
    mapfile -t ids < <(sed -nE 's/.* id ([0-9]+) .*/\1/p' "$prefix.tc")
    [[ ${#ids[@]} == 2 ]]
    first_program=$(grep -F 'Attached IPv4 tc classifier' "$prefix.capture")
    [[ -n $first_program ]]
    program=${ids[0]}
    if [[ $family == ipv4 ]]; then program=${ids[1]}; fi
    for id in "${ids[@]}"; do bpftool -j prog show id "$id"; done >"$prefix.before"
    bpftool prog dump jited id "$program" opcodes >"$prefix.jit" 2>"$prefix.jit-error" || true
    bpftool prog profile id "$program" duration 5 cycles instructions >"$prefix.profile" 2>&1 &
    profile_pid=$!
    send 50000 >"$prefix.sender" 2>&1
    if wait "$profile_pid"; then echo 0; else echo "$?"; fi >"$prefix.profile-status"
    profile_pid=
    for id in "${ids[@]}"; do bpftool -j prog show id "$id"; done >"$prefix.after"
    sleep 0.2
    stop_capture "$prefix"
done
