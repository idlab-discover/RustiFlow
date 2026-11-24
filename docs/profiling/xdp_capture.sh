#!/usr/bin/env bash
# Run from the repository root with sudo. See overnight-xdp-capture-prototype.md.
set -euo pipefail

mode=${1:?usage: xdp_capture.sh MODE ARM OUTPUT_DIRECTORY PCAP}
arm=${2:?specify base, split, single-tc, xdp-driver or xdp-skb}
out=${3:?specify an output directory}
pcap=$(realpath "${4:?specify a pcap}")
run=${RUSTIFLOW_XDP_RUN_DIR:-"$PWD/target/xdp-experiment"}
rate=${RUSTIFLOW_XDP_PPS:-200000}
capture_pid=
profile_pid=
paused=
stats_before=$(sysctl -n kernel.bpf_stats_enabled)
stats_wanted=0
cap=rf-xdp-cap-$BASHPID
sender=rf-xdp-src-$BASHPID
limit=(--limit=300000)
pace=(--pps="$rate")
capture_out=/dev/null
capture_flags=(--ingress-only)
export RUST_LOG=info TOKIO_WORKER_THREADS=4
unset RUSTIFLOW_EXPERIMENT_INGRESS RUSTIFLOW_REALTIME_STATS RUSTIFLOW_PROFILE_FLAMEGRAPH
case $mode in
    stat|kernel-sample|user-sample) ;;
    runtime) stats_wanted=1 ;;
    latency)
        export RUSTIFLOW_REALTIME_STATS=1
        capture_out="$out/flows.parquet"
        ;;
    bpf-counters) ;;
    burst) pace=(--topspeed) ;;
    raw|parquet|bidirectional)
        limit=()
        pace=(--pps=1000)
        if [[ $mode != raw ]]; then
            export RUSTIFLOW_REALTIME_STATS=1
            capture_out="$out/flows.parquet"
        fi
        if [[ $mode == bidirectional ]]; then capture_flags=(); fi
        ;;
    pressure)
        limit=()
        export RUSTIFLOW_REALTIME_STATS=1
        capture_out="$out/flows.parquet"
        ;;
    ping) ;;
    *) echo "Unknown mode: $mode" >&2; exit 2 ;;
esac
case $arm in
    base)
        bin="$run/base-rustiflow"
        export RUSTIFLOW_EBPF_DIR=${RUSTIFLOW_XDP_EBPF_DIR:-"$run/base-ebpf"}
        ;;
    split|single-tc|xdp-driver|xdp-skb)
        bin="$run/candidate-rustiflow"
        export RUSTIFLOW_EBPF_DIR=${RUSTIFLOW_XDP_EBPF_DIR:-"$run/candidate-ebpf"}
        if [[ $arm != split ]]; then export RUSTIFLOW_EXPERIMENT_INGRESS=$arm; fi
        ;;
    *) echo "Unknown arm: $arm" >&2; exit 2 ;;
esac
bin=${RUSTIFLOW_PROFILE_BIN:-$bin}
mkdir -p "$out"

stop_capture() {
    if [[ -n $capture_pid ]]; then
        if [[ -n $paused ]]; then kill -CONT "$capture_pid" 2>/dev/null || true; fi
        local pid=$capture_pid
        kill -INT "$pid" 2>/dev/null || true
        for _ in {1..200}; do
            if ! kill -0 "$pid" 2>/dev/null; then break; fi
            sleep 0.05
        done
        if kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid"; fi
        capture_pid=
        wait "$pid"
    fi
}

cleanup() {
    if [[ -n $profile_pid ]]; then
        kill -TERM "$profile_pid" 2>/dev/null || true
        wait "$profile_pid" || true
    fi
    stop_capture || true
    if [[ $stats_before != "$stats_wanted" ]]; then
        sysctl -qw "kernel.bpf_stats_enabled=$stats_before"
    fi
    ip netns del "$cap" 2>/dev/null || true
    ip netns del "$sender" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ip netns add "$cap"
ip netns add "$sender"
ip link add cap0 netns "$cap" type veth peer name send0 netns "$sender"
for endpoint in "$cap:cap0" "$sender:send0"; do
    ns=${endpoint%:*}
    dev=${endpoint#*:}
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$ns" ethtool -K "$dev" gro off gso off tso off
    ip -n "$ns" link set dev "$dev" addrgenmode none
done
ip -n "$cap" link set cap0 address 02:00:00:00:00:02 up
ip -n "$sender" link set send0 address 02:00:00:00:00:01 up
if [[ $stats_before != "$stats_wanted" ]]; then
    sysctl -qw "kernel.bpf_stats_enabled=$stats_wanted"
fi

ip netns exec "$cap" taskset -c 0-3 "$bin" -f rustiflow \
    --export-path "$capture_out" --threads 2 realtime cap0 "${capture_flags[@]}" \
    >"$out/capture.log" 2>&1 &
capture_pid=$!
for _ in {1..120}; do
    kill -0 "$capture_pid" 2>/dev/null || { cat "$out/capture.log"; exit 1; }
    if grep -q 'Waiting for Ctrl-C' "$out/capture.log"; then break; fi
    sleep 0.05
done
grep -q 'Waiting for Ctrl-C' "$out/capture.log"
ip netns exec "$cap" tc filter show dev cap0 ingress >"$out/ingress.tc"
ip netns exec "$cap" tc filter show dev cap0 egress >"$out/egress.tc"
ip netns exec "$cap" bpftool -j net show dev cap0 >"$out/net.json"
ip -n "$cap" -d -j link show dev cap0 >"$out/mode.json"
ip netns exec "$cap" ethtool -k cap0 >"$out/offloads.txt"
ip netns exec "$sender" ethtool -k send0 >"$out/sender-offloads.txt"
if [[ $arm == xdp-* ]]; then
    [[ ! -s "$out/ingress.tc" ]]
    expected_mode=driver
    if [[ $arm == xdp-skb ]]; then expected_mode=generic; fi
    jq -er --arg mode "$expected_mode" \
        '.[].xdp[] | select(.devname == "cap0" and .mode == $mode) | .id' \
        "$out/net.json" >"$out/program-ids"
else
    sed -nE 's/.* id ([0-9]+) .*/\1/p' "$out/ingress.tc" >"$out/program-ids"
fi
[[ -s "$out/program-ids" ]]
mapfile -t ids <"$out/program-ids"
if [[ $arm == base || $arm == split ]]; then
    [[ ${#ids[@]} == 2 ]]
else
    [[ ${#ids[@]} == 1 ]]
fi

if [[ $mode == raw || $mode == pressure ]]; then
    kill -STOP "$capture_pid"
    paused=1
    for _ in {1..100}; do
        if grep -q $'^State:\tT' "/proc/$capture_pid/status"; then break; fi
        sleep 0.01
    done
    grep -q $'^State:\tT' "/proc/$capture_pid/status"
fi

snapshot() {
    ip -n "$cap" -s -j link show dev cap0 >"$out/link-$1.json"
    ip -n "$sender" -s -j link show dev send0 >"$out/sender-link-$1.json"
    ip netns exec "$cap" ethtool -S cap0 >"$out/ethtool-$1.txt"
    if [[ $mode == runtime ]]; then
        for id in "${ids[@]}"; do bpftool -j prog show id "$id"; done >"$out/program-$1.jsonl"
    fi
}

if [[ -n ${RUSTIFLOW_XDP_PPS_MULTI:-} ]]; then
    pace+=(--timer=nano --pps-multi="$RUSTIFLOW_XDP_PPS_MULTI")
fi
sender_command=(ip netns exec "$sender" taskset -c 4 timeout 45 tcpreplay
    --preload-pcap "${pace[@]}" "${limit[@]}" --intf1=send0 "$pcap")
snapshot before
case $mode in
    stat|burst)
        perf stat -C 0-5 -A -x ';' -e cpu_core/cycles/k,cpu_core/instructions/k \
            -o "$out/kernel.stat" -- \
            perf stat -p "$capture_pid" -x ';' -e cpu_core/cycles/u,cpu_core/instructions/u \
            -o "$out/user.stat" -- "${sender_command[@]}" >"$out/replay.log" 2>&1
        ;;
    kernel-sample)
        perf record -C 0-5 -e cpu_core/cycles/k -F 499 --call-graph fp --no-buildid-cache \
            -o "$out/receive.perf.data" -- "${sender_command[@]}" >"$out/replay.log" 2>"$out/perf.log"
        ;;
    user-sample)
        perf record -p "$capture_pid" -e cpu_core/cycles/u -F 499 --call-graph dwarf,8192 \
            --no-buildid-cache -o "$out/receive.perf.data" -- "${sender_command[@]}" \
            >"$out/replay.log" 2>"$out/perf.log"
        ;;
    bpf-counters)
        program_index=${RUSTIFLOW_XDP_PROFILE_INDEX:-0}
        timeout 10 bpftool -j prog profile id "${ids[program_index]}" duration 5 cycles instructions \
            >"$out/bpf-counters.json" 2>"$out/bpf-counters.log" &
        profile_pid=$!
        sleep 0.3
        "${sender_command[@]}" >"$out/replay.log" 2>&1
        status=0
        wait "$profile_pid" || status=$?
        profile_pid=
        printf '%s\n' "$status" >"$out/bpf-counters.status"
        ;;
    ping)
        if [[ $arm == xdp-* ]]; then
            ip netns exec "$cap" bpftool -j link show | \
                jq --argjson id "${ids[0]}" '[.[] | select(.prog_id == $id)]' >"$out/xdp-link.json"
        fi
        for ns in "$cap" "$sender"; do
            ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
        done
        ip -n "$cap" address add 198.18.240.2/30 dev cap0
        ip -n "$sender" address add 198.18.240.1/30 dev send0
        ip -n "$cap" -6 address add fd42:f10::2/64 dev cap0 nodad
        ip -n "$sender" -6 address add fd42:f10::1/64 dev send0 nodad
        for address in 198.18.240.1 fd42:f10::1; do
            ip -n "$cap" neigh replace "$address" lladdr 02:00:00:00:00:01 dev cap0 nud permanent
        done
        for address in 198.18.240.2 fd42:f10::2; do
            ip -n "$sender" neigh replace "$address" lladdr 02:00:00:00:00:02 dev send0 nud permanent
            ip netns exec "$sender" taskset -c 4 ping -n -q -c 200 -i 0.01 -w 5 "$address"
        done >"$out/ping.log"
        ;;
    *)
        start=$(python -c 'from time import monotonic_ns; print(monotonic_ns())')
        date +%s%6N >"$out/send-start.us"
        "${sender_command[@]}" >"$out/replay.log" 2>&1
        if [[ $mode == bidirectional ]]; then
            ip netns exec "$cap" taskset -c 4 timeout 45 tcpreplay --preload-pcap \
                "${pace[@]}" --intf1=cap0 "$pcap" >"$out/egress-replay.log" 2>&1
        fi
        # Allow asynchronously received veth frames to finish before comparing counters.
        sleep 0.2
        end=$(python -c 'from time import monotonic_ns; print(monotonic_ns())')
        date +%s%6N >"$out/send-end.us"
        ;;
esac
sleep 0.25
snapshot after
if [[ $mode == raw ]]; then
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/docs/profiling" \
        python "${RUSTIFLOW_XDP_RAW_CHECKER:-$run/single_tc_fixture.py}" rings "$out/program-ids" "$start" "$end" >"$out/rings.json"
fi
if [[ $mode == pressure ]]; then
    kill -CONT "$capture_pid"
    paused=
    # Give the resuming pipeline time to drain the two full rings.
    sleep 4
fi
stop_capture
ip netns exec "$cap" bpftool -j net show dev cap0 >"$out/detached.json"
ip netns exec "$cap" tc filter show dev cap0 ingress >"$out/detached-ingress.tc"
ip netns exec "$cap" tc filter show dev cap0 egress >"$out/detached-egress.tc"
[[ ! -s "$out/detached-ingress.tc" && ! -s "$out/detached-egress.tc" ]]
jq -e 'all(.[].xdp[]; .devname != "cap0")' "$out/detached.json" >/dev/null
if [[ $mode == *-sample ]]; then
    perf report -f -i "$out/receive.perf.data" --stdio --no-children --percent-limit 0.5 -g none \
        >"$out/self.txt"
    perf report -f -i "$out/receive.perf.data" --stdio --children --percent-limit 2 \
        >"$out/cumulative.txt"
fi
