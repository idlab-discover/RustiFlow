#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/realtime_container_stress.sh [OPTIONS]

Run the local containerized RustiFlow realtime stress harness on rgbcore.

This script assumes:
- the persistent local test harness exists
- rustiflow-t0 is the host-side capture interface
- an iperf3 server is already running inside rustiflow-peer on 10.203.0.2:5201

Options:
  --image NAME         Docker image to run (default: rustiflow:test-slim)
  --container NAME     Container name prefix (default: rustiflow-stress)
  --features NAME      Flow type to export (default: rustiflow)
  --interface NAME     Capture interface (default: rustiflow-t0)
  --threads N          RustiFlow worker threads (default: 4)
  --bitrate RATE       iperf3 UDP target bitrate (default: 2.5G)
  --length BYTES       iperf3 UDP payload length (default: 1400)
  --parallel N         iperf3 parallel streams (default: 1)
  --duration SEC       iperf3 run duration in seconds (default: 15)
  --export-path PATH   CSV export path inside the host filesystem
                       (default: target/realtime-stress/rustiflow-stress.csv)
  -h, --help           Show this help text

Example:
  scripts/realtime_container_stress.sh --threads 4 --bitrate 2.5G --parallel 1
EOF
}

image="rustiflow:test-slim"
container_prefix="rustiflow-stress"
features="rustiflow"
interface="rustiflow-t0"
threads=4
bitrate="2.5G"
length=1400
parallel=1
duration=15
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
export_path="$repo_root/target/realtime-stress/rustiflow-stress.csv"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)
            image="$2"
            shift 2
            ;;
        --container)
            container_prefix="$2"
            shift 2
            ;;
        --features)
            features="$2"
            shift 2
            ;;
        --interface)
            interface="$2"
            shift 2
            ;;
        --threads)
            threads="$2"
            shift 2
            ;;
        --bitrate)
            bitrate="$2"
            shift 2
            ;;
        --length)
            length="$2"
            shift 2
            ;;
        --parallel)
            parallel="$2"
            shift 2
            ;;
        --duration)
            duration="$2"
            shift 2
            ;;
        --export-path)
            export_path="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required" >&2
    exit 1
fi

if ! command -v iperf3 >/dev/null 2>&1; then
    echo "error: iperf3 is required" >&2
    exit 1
fi

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "error: docker image not found: $image" >&2
    exit 1
fi

container_name="${container_prefix}-${threads}t-${parallel}p"
if [[ "$export_path" != /* ]]; then
    export_path="$repo_root/$export_path"
fi
export_dir="$(dirname "$export_path")"

cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -f "$export_path"
mkdir -p "$export_dir"
docker rm -f "$container_name" >/dev/null 2>&1 || true

docker run -d \
    --name "$container_name" \
    --privileged \
    --network host \
    -v "$export_dir:/tmp" \
    "$image" \
    -f "$features" \
    -o csv \
    --header \
    --export-path "/tmp/$(basename "$export_path")" \
    --performance-mode \
    --threads "$threads" \
    --early-export 5 \
    realtime "$interface" --ingress-only >/dev/null

sleep 2

iperf_output="$(
    iperf3 \
        -c 10.203.0.2 \
        -B 10.203.0.1 \
        -u \
        -b "$bitrate" \
        -l "$length" \
        -P "$parallel" \
        -t "$duration" \
        -R
)"

docker kill -s INT "$container_name" >/dev/null
sleep 1
logs="$(docker logs --tail 100 "$container_name" 2>&1)"

if [[ "$parallel" -eq 1 ]]; then
    receiver_line="$(printf '%s\n' "$iperf_output" | awk '/receiver$/ {line=$0} END {print line}')"
    receiver_bitrate="$(printf '%s\n' "$receiver_line" | awk '{print $7 " " $8}')"
else
    receiver_line="$(printf '%s\n' "$iperf_output" | awk '/SUM.*receiver$/ {line=$0} END {print line}')"
    receiver_bitrate="$(printf '%s\n' "$receiver_line" | awk '{print $6 " " $7}')"
fi

dropped_packets="$(printf '%s\n' "$logs" | sed -n 's/.*Total dropped packets before exit: //p' | tail -n1)"

printf 'image: %s\n' "$image"
printf 'interface: %s\n' "$interface"
printf 'threads: %s\n' "$threads"
printf 'bitrate_target: %s\n' "$bitrate"
printf 'parallel_streams: %s\n' "$parallel"
printf 'udp_length: %s\n' "$length"
printf 'duration_s: %s\n' "$duration"
printf 'receiver_bitrate: %s\n' "${receiver_bitrate:-missing}"
printf 'dropped_packets: %s\n' "${dropped_packets:-missing}"
printf 'export_path: %s\n' "$export_path"
