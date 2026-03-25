#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/concap_smoke.sh [CONCAP_DIR] [SCENARIO_FILE]

Run a tiny ConCap scenario, then reprocess the downloaded pcap with the current
local RustiFlow checkout.

Arguments:
  CONCAP_DIR      Path to the ConCap repository (default: ../concap)
  SCENARIO_FILE   Scenario YAML filename from ConCap example/scenarios
                  (default: nmap-tcp-syn-version.yaml)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
concap_dir="${1:-"$repo_root/../concap"}"
scenario_file="${2:-nmap-tcp-syn-version.yaml}"
scenario_name="${scenario_file%.yaml}"
smoke_dir="$concap_dir/rustiflow-smoke"
completed_dir="$smoke_dir/completed/$scenario_name"
pcap_path="$completed_dir/dump.pcap"
output_csv="$completed_dir/rustiflow-current.csv"

if [[ ! -x "$concap_dir/concap" ]]; then
    echo "error: expected ConCap binary at $concap_dir/concap" >&2
    exit 1
fi

if [[ ! -f "$concap_dir/example/scenarios/$scenario_file" ]]; then
    echo "error: missing scenario file $concap_dir/example/scenarios/$scenario_file" >&2
    exit 1
fi

mkdir -p "$smoke_dir/scenarios" "$smoke_dir/processingpods" "$smoke_dir/completed"
rm -rf "$completed_dir"
cp "$concap_dir/example/scenarios/$scenario_file" "$smoke_dir/scenarios/"
cp "$concap_dir/example/processingpods/rustiflow.yaml" "$smoke_dir/processingpods/"

echo "Running ConCap scenario $scenario_file"
"$concap_dir/concap" -d "$smoke_dir" -s "$scenario_file" -w 1

if [[ ! -f "$pcap_path" ]]; then
    echo "error: expected downloaded pcap at $pcap_path" >&2
    exit 1
fi

echo "Reprocessing $pcap_path with current local RustiFlow"
cargo run -p rustiflow -- \
    -f rustiflow \
    --header \
    --idle-timeout 120 \
    --active-timeout 3600 \
    --output csv \
    --export-path "$output_csv" \
    pcap "$pcap_path"

python3 - "$output_csv" <<'PY'
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
with path.open() as handle:
    rows = list(csv.reader(handle))

header = rows[0]
widths = {len(row) for row in rows[1:]}

print(f"Current RustiFlow rows: {len(rows) - 1}")
print(f"Current RustiFlow columns: {len(header)}")
print(f"Stable row width: {widths == {len(header)}}")
PY
