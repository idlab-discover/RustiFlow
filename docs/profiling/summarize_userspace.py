#!/usr/bin/env python3
"""Convert userspace.sh result files to one CSV row per repetition."""

import argparse
import csv
import re
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    writer = csv.writer(sys.stdout, lineterminator="\n")
    counters = ("cycles", "instructions", "branch-misses", "cache-misses")
    writer.writerow(
        ("workload", "features", "run", "wall_s", *counters, "replay_wall_s", "replay_mpps",
         "replay_cpu_ns_per_packet")
    )
    for stat in sorted(args.directory.glob("*.stat")):
        case, run, _ = stat.name.split(".")
        workload, feature = case.split("-")
        perf = {}
        for line in stat.read_text().splitlines():
            fields = line.split(";")
            if len(fields) >= 3:
                perf[fields[2].split("/")[1]] = int(fields[0])
        replay = re.search(
            r"wall_s=([\d.]+) mpps=([\d.]+) cpu_s=[\d.]+ cpu_ns_per_packet=([\d.]+)",
            stat.with_suffix(".txt").read_text(),
        )
        writer.writerow(
            (workload, feature, run, stat.with_suffix(".wall").read_text().strip(),
             *(perf[counter] for counter in counters), *(replay.groups() if replay else ("", "", "")))
        )


if __name__ == "__main__":
    main()
