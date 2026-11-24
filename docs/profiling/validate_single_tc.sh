#!/usr/bin/env bash
# Run from the repository root with sudo. See overnight-single-tc-classifier.md.
set -euo pipefail
mode=${1:?usage: validate_single_tc.sh MODE OBJECTS OUTPUT_DIRECTORY RUN_DIRECTORY}
kind=${2:?specify base, split, or candidate objects}
out=${3:?specify an output directory}
run_dir=${4:?specify the experiment build directory}
case $mode in
    raw|parquet|pressure|bidirectional) ;;
    *) exit 2 ;;
esac
mkdir -p "$out"
export RUST_LOG=info
case $kind in
    base) object_dir=base-ebpf ;;
    split|candidate) object_dir=candidate-ebpf ;;
    *) exit 2 ;;
esac
export RUSTIFLOW_EBPF_DIR="$run_dir/$object_dir/bpfel-unknown-none/release"
unset RUSTIFLOW_EXPERIMENT_SINGLE_TC RUSTIFLOW_REALTIME_STATS
if [[ $kind == candidate ]]; then export RUSTIFLOW_EXPERIMENT_SINGLE_TC=1; fi
cap=rf-validate-cap-$BASHPID
send=rf-validate-src-$BASHPID
pid=
paused=
cleanup() {
    if [[ -n $pid ]]; then
        if [[ -n $paused ]]; then kill -CONT "$pid" 2>/dev/null || true; fi
        kill -INT "$pid" 2>/dev/null || true
        wait "$pid" || true
    fi
    ip netns del "$cap" 2>/dev/null || true
    ip netns del "$send" 2>/dev/null || true
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
capture_flags=(--ingress-only)
capture_path=/dev/null
pcap="$run_dir/metadata.pcap"
replay_flags=(--pps=1000)
if [[ $mode == parquet || $mode == bidirectional ]]; then
    capture_path="$out/flows.parquet"
    export RUSTIFLOW_REALTIME_STATS=1
fi
if [[ $mode == bidirectional ]]; then capture_flags=(); fi
if [[ $mode == pressure ]]; then
    pcap="$run_dir/pressure.pcap"
    replay_flags=(--topspeed)
fi
ip netns exec "$cap" taskset -c 0-3 "$run_dir/userspace/profiling/rustiflow" -f rustiflow \
    --export-path "$capture_path" --threads 2 realtime cap0 "${capture_flags[@]}" >"$out/capture.log" 2>&1 &
pid=$!
for _ in {1..100}; do
    kill -0 "$pid" 2>/dev/null || { cat "$out/capture.log"; exit 1; }
    if [[ -f "$out/capture.log" ]] && grep -q 'Waiting for Ctrl-C' "$out/capture.log"; then break; fi
    sleep 0.05
done
grep -q 'Waiting for Ctrl-C' "$out/capture.log"
ip netns exec "$cap" tc filter show dev cap0 ingress >"$out/ingress.tc"
ip netns exec "$cap" tc filter show dev cap0 egress >"$out/egress.tc"
sed -nE 's/.* id ([0-9]+) .*/\1/p' "$out/ingress.tc" >"$out/program-ids"
ip -n "$cap" -s -j link show dev cap0 >"$out/link-before.json"
if [[ $mode == raw || $mode == pressure ]]; then
    kill -STOP "$pid"
    paused=1
    for _ in {1..100}; do
        if grep -q $'^State:\tT' "/proc/$pid/status"; then break; fi
        sleep 0.01
    done
    grep -q $'^State:\tT' "/proc/$pid/status"
fi
start=$(python -c 'from time import monotonic_ns; print(monotonic_ns())')
ip netns exec "$send" taskset -c 4 tcpreplay --preload-pcap "${replay_flags[@]}" \
    --intf1=send0 "$pcap" >"$out/sender.log" 2>&1
if [[ $mode == bidirectional ]]; then
    ip netns exec "$cap" taskset -c 4 tcpreplay --preload-pcap "${replay_flags[@]}" \
        --intf1=cap0 "$pcap" >"$out/sender-egress.log" 2>&1
fi
end=$(python -c 'from time import monotonic_ns; print(monotonic_ns())')
ip -n "$cap" -s -j link show dev cap0 >"$out/link-after.json"
if [[ $mode == raw ]]; then
    PYTHONDONTWRITEBYTECODE=1 python docs/profiling/single_tc_fixture.py rings \
        "$out/program-ids" "$start" "$end" >"$out/rings.json"
fi
if [[ -n $paused ]]; then
    kill -CONT "$pid"
    paused=
fi
sleep 0.3
kill -INT "$pid"
wait "$pid"
pid=
ip netns exec "$cap" tc filter show dev cap0 ingress >"$out/detached-ingress.tc"
ip netns exec "$cap" tc filter show dev cap0 egress >"$out/detached-egress.tc"
[[ ! -s "$out/detached-ingress.tc" && ! -s "$out/detached-egress.tc" ]]

check_counters() {
    local label=$1 matched=$2 submitted=$3 dropped=$4
    rg -Fq "counters $label: matched_packets=$matched, submitted_events=$submitted, dropped_packets=$dropped" \
        "$out/capture.log"
}
if [[ $mode == pressure ]]; then
    expected_rx=2255000
    expected_rx_drops=0
    check_counters ingress-ipv4 1405000 1398101 6899
    check_counters ingress-ipv6 850000 838860 11140
    rg -Fq 'Total dropped packets before exit: 18039' "$out/capture.log"
else
    expected_rx=23
    # Linux counts the fixture's unknown EtherType in rx_dropped after TC.
    expected_rx_drops=1
    check_counters ingress-ipv4 10 10 0
    check_counters ingress-ipv6 10 10 0
fi
if [[ $mode == bidirectional ]]; then
    check_counters egress-ipv4 10 10 0
    check_counters egress-ipv6 10 10 0
fi
rg -q "Successful packets:\s+$expected_rx$" "$out/sender.log"
rg -q 'Failed packets:\s+0$' "$out/sender.log"
python - "$out/link-before.json" "$out/link-after.json" "$expected_rx" "$expected_rx_drops" <<'PY'
import json
from pathlib import Path
import sys

before, after = (json.loads(Path(path).read_text())[0]["stats64"]["rx"] for path in sys.argv[1:3])
assert after["packets"] - before["packets"] == int(sys.argv[3])
assert before["errors"] == after["errors"]
assert after["dropped"] - before["dropped"] == int(sys.argv[4])
PY
