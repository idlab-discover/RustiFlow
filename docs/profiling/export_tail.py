#!/usr/bin/env python3
"""Compare CSV and Parquet through file close, optionally including an archived CSV binary."""

import argparse
import csv
import os
import re
import subprocess
from pathlib import Path
from time import monotonic_ns


def measure(binary, fmt, workload, path, pcap, features="rustiflow"):
    cmd = ["taskset", "-c", "0-5", binary, "-f", features, "-o", fmt,
           "--export-path", path, "--threads", "4"]
    if workload == "offline":
        cmd.extend(["pcap", pcap])
    else:
        packets = "1000000" if workload == "replay4" else "10000000"
        cmd.extend(["replay-bench", "--packets", packets, "--flows", "100000", "--sources", "8"])
        if workload == "replay6-long":
            cmd.append("--ipv6")

    env = dict(os.environ, RUST_LOG="rustiflow::pcap=debug")
    start = monotonic_ns()
    with subprocess.Popen(cmd, env=env, stderr=subprocess.PIPE, text=True) as child:
        finished_reading = None
        replay = None
        for line in child.stderr:
            if "Finished reading the pcap file" in line:
                finished_reading = monotonic_ns()
            if line.startswith("Replay:"):
                replay = re.search(r"wall_s=([\d.]+).*cpu_ns_per_packet=([\d.]+)", line)
        if child.wait():
            raise RuntimeError(f"failed command: {cmd}")
    end = monotonic_ns()
    if workload == "offline":
        if finished_reading is None:
            raise ValueError("missing end-of-input marker")
        return (end - start) / 1e9, (end - finished_reading) / 1e6, "", ""
    if replay is None:
        raise ValueError("missing replay summary")
    return (end - start) / 1e9, "", *replay.groups()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old_binary", type=Path, nargs="?", help="archived CSV control")
    parser.add_argument("candidate_binary", type=Path)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--matrix", action="store_true",
                        help="include basic features and 10M-event IPv4 and IPv6 replays")
    parser.add_argument("--runs", type=int, default=5, help="measured runs per writer after warmup")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    args.directory.mkdir(parents=True, exist_ok=True)
    writers = [("current-csv", args.candidate_binary, "csv"),
               ("current-parquet", args.candidate_binary, "parquet")]
    if args.old_binary:
        writers.insert(0, ("old-csv", args.old_binary, "csv"))
    cases = [("offline", "rustiflow"), ("replay4", "rustiflow")]
    if args.matrix:
        cases += [("offline", "basic")]
        cases += [(workload, features) for workload in ("replay4-long", "replay6-long")
                  for features in ("basic", "rustiflow")]
    filename = "writer-matrix.csv" if args.matrix else "export-heavy.csv"
    with (args.directory / filename).open("w") as file:
        results = csv.writer(file, lineterminator="\n")
        headers = ["workload", "writer", "run", "command_s", "offline_tail_ms",
                   "replay_s", "replay_cpu_ns_per_packet", "bytes"]
        results.writerow(headers + (["features"] if args.matrix else []))
        for workload, features in cases:
            prefix = f"{workload}-{features}" if args.matrix else workload
            for run in range(args.runs + 1):
                offset = run % len(writers)
                for name, binary, fmt in writers[offset:] + writers[:offset]:
                    path = args.directory / f"{prefix}-{name}.{fmt}"
                    if workload.endswith("-long"):
                        path = Path(os.devnull)
                    timings = measure(binary, fmt, workload, path, args.pcap, features)
                    if run:
                        size = "" if workload.endswith("-long") else path.stat().st_size
                        results.writerow([workload, name, run, *timings, size]
                                         + ([features] if args.matrix else []))
                file.flush()


if __name__ == "__main__":
    main()
