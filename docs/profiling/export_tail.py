#!/usr/bin/env python3
"""Compare the old and current writers on regular files, including offline shutdown."""

import argparse
import csv
import os
import re
import subprocess
from pathlib import Path
from time import monotonic_ns


def measure(binary, fmt, workload, path, pcap):
    cmd = ["taskset", "-c", "0-5", binary, "-f", "rustiflow", "-o", fmt,
           "--export-path", path, "--threads", "4"]
    if workload == "offline":
        cmd.extend(["pcap", pcap])
    else:
        cmd.extend(["replay-bench", "--packets", "1000000", "--flows", "100000", "--sources", "8"])

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
    parser.add_argument("old_binary", type=Path)
    parser.add_argument("candidate_binary", type=Path)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    writers = [("old-csv", args.old_binary, "csv"),
               ("current-csv", args.candidate_binary, "csv"),
               ("current-parquet", args.candidate_binary, "parquet")]
    with (args.directory / "export-heavy.csv").open("w") as file:
        results = csv.writer(file, lineterminator="\n")
        results.writerow(("workload", "writer", "run", "command_s", "offline_tail_ms",
                          "replay_s", "replay_cpu_ns_per_packet", "bytes"))
        for workload in ("offline", "replay4"):
            for run in range(6):
                offset = run % len(writers)
                for name, binary, fmt in writers[offset:] + writers[:offset]:
                    path = args.directory / f"{workload}-{name}.{fmt}"
                    timings = measure(binary, fmt, workload, path, args.pcap)
                    if run:
                        results.writerow((workload, name, run, *timings, path.stat().st_size))


if __name__ == "__main__":
    main()
