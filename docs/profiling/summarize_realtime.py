#!/usr/bin/env python3
"""Convert realtime.sh sender, capture, and kernel reports to CSV."""

import argparse
import csv
import json
import re
from pathlib import Path


def match(pattern, text):
    result = re.search(pattern, text, re.MULTILINE)
    if result is None:
        raise ValueError(f"Missing {pattern!r}")
    return result.groups()


def kernel_programs(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "live.csv").open("w") as out:
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(("target_pps", "run", "actual_pps", "sent", "send_errors",
                         "ipv4_matched", "ipv4_submitted", "ipv4_dropped", "ipv6_matched",
                         "ipv6_submitted", "ipv6_dropped", "userspace_cycles", "userspace_instructions"))
        for capture in sorted(args.directory.glob("live-*.capture")):
            _, rate, run = capture.stem.split("-")
            sender = capture.with_suffix(".sender").read_text()
            capture_log = capture.read_text()
            perf = capture.with_suffix(".stat").read_text()
            writer.writerow((
                rate, run,
                *match(r"Rated: .* ([\d.]+) pps", sender),
                *match(r"Successful packets:\s+(\d+)", sender),
                *match(r"Failed packets:\s+(\d+)", sender),
                *(value for family in ("ipv4", "ipv6") for value in match(
                    rf"counters ingress-{family}: matched_packets=(\d+), submitted_events=(\d+), dropped_packets=(\d+)",
                    capture_log)),
                *match(r"^(\d+);;cpu_core/cycles/u;", perf),
                *match(r"^(\d+);;cpu_core/instructions/u;", perf),
            ))
    with (args.output / "classifiers.csv").open("w") as out:
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(("pass", "family", "tag", "program_id", "delta_invocations",
                         "delta_runtime_ns", "ns_per_invocation", "xlated_bytes", "jit_bytes"))
        for snapshot in sorted(args.directory.glob("instrumented-*.after")):
            before = kernel_programs(snapshot.with_suffix(".before"))
            after = kernel_programs(snapshot)
            tc = snapshot.with_suffix(".tc").read_text()
            ids = list(reversed(re.findall(r" id (\d+) ", tc)))
            family_by_id = dict(zip(map(int, ids), ("ipv4", "ipv6"), strict=True))
            for start, end in zip(before, after, strict=True):
                assert start["id"] == end["id"] and start["tag"] == end["tag"]
                invocations = end["run_cnt"] - start.get("run_cnt", 0)
                runtime = end["run_time_ns"] - start.get("run_time_ns", 0)
                writer.writerow((snapshot.stem, family_by_id[end["id"]], end["tag"], end["id"],
                                 invocations, runtime, f"{runtime / invocations:.3f}",
                                 end["bytes_xlated"], end["bytes_jited"]))


if __name__ == "__main__":
    main()
