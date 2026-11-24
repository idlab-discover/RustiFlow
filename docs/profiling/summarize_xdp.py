#!/usr/bin/env python3
"""Reconcile each xdp_capture.sh replay and emit one CSV row per repetition."""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from summarize_realtime import kernel_programs, match


FAMILIES = ("ipv4", "ipv6")


def link_counter(directory, prefix, direction, counter):
    def read(when):
        return json.loads((directory / f"{prefix}-{when}.json").read_text())[0]["stats64"][
            direction
        ][counter]

    return read("after") - read("before")


def ethtool_deltas(directory):
    def read(when):
        return {
            key: int(value)
            for key, value in re.findall(
                r"^\s+(\w+): (\d+)$",
                (directory / f"ethtool-{when}.txt").read_text(),
                re.MULTILINE,
            )
        }

    before, after = read("before"), read("after")
    return {
        suffix: sum(value - before[key] for key, value in after.items() if key.endswith(suffix))
        for suffix in ("_xdp_packets", "_xdp_drops", "_xdp_redirect", "_xdp_tx")
    }


def perf_counter(directory, filename, event):
    path = directory / filename
    if not path.exists():
        return None
    counts = []
    for line in path.read_text().splitlines():
        if ";" not in line:
            continue
        fields = line.split(";")
        if filename == "kernel.stat":
            cpu = fields.pop(0)
        else:
            cpu = "capture process"
        count, _, name, _, running, *_ = fields
        if name == event:
            if float(running) < 95:
                raise ValueError(f"{path}: {event} ran only {running}% on {cpu}")
            counts.append(int(count))
    return sum(counts) if counts else None


def ring_quantiles(capture):
    histograms = [json.loads(data) for data in re.findall(r"ring_age_us_log2=(\[[^\n]+\])", capture)]
    if not histograms:
        return None, None, None
    histogram = [sum(bucket) for bucket in zip(*histograms, strict=True)]
    total = sum(histogram)

    def quantile(percent):
        accumulated = 0
        for bucket, count in enumerate(histogram):
            accumulated += count
            if 100 * accumulated >= total * percent:
                lower = 1 << bucket if bucket else 0
                return f"{lower}-{(2 << bucket) - 1}"
        raise ValueError("empty latency histogram")

    return total, quantile(50), quantile(99)


def row(directory):
    replay = (directory / "replay.log").read_text()
    capture = (directory / "capture.log").read_text()
    counters = {
        family: tuple(map(int, match(
            rf"counters ingress-{family}: matched_packets=(\d+), submitted_events=(\d+), dropped_packets=(\d+)",
            capture,
        )))
        for family in FAMILIES
    }
    sent = int(match(r"Successful packets:\s+(\d+)", replay)[0])
    receiver = link_counter(directory, "link", "rx", "packets")
    tx = link_counter(directory, "sender-link", "tx", "packets")
    matched, submitted, dropped = map(sum, zip(*counters.values(), strict=True))
    if matched != submitted + dropped:
        raise ValueError(f"{directory}: inconsistent BPF counters {counters}")
    drained = [int(count) for count in re.findall(r"Realtime source .*: events=(\d+)", capture)]
    samples, p50, p99 = ring_quantiles(capture)
    xdp = ethtool_deltas(directory)

    runtime = []
    invocations = []
    program_after = directory / "program-after.jsonl"
    if program_after.exists():
        for before, after in zip(
            kernel_programs(directory / "program-before.jsonl"),
            kernel_programs(program_after),
            strict=True,
        ):
            if before["id"] != after["id"] or before["tag"] != after["tag"]:
                raise ValueError(f"{directory}: program changed during measurement")
            runtime.append(after["run_time_ns"] - before.get("run_time_ns", 0))
            invocations.append(after["run_cnt"] - before.get("run_cnt", 0))

    phase, rate, repetition, arm = directory.parts[-4:]
    result = dict(
        phase=phase, rate=rate, repetition=repetition, arm=arm,
        pps=float(match(r"Rated: .* ([\d.]+) pps", replay)[0]),
        sent=sent, tx=tx, rx=receiver,
        send_errors=int(match(r"Failed packets:\s+(\d+)", replay)[0]),
        rx_errors=link_counter(directory, "link", "rx", "errors"),
        rx_drops=link_counter(directory, "link", "rx", "dropped"),
        ipv4_matched=counters["ipv4"][0],
        ipv6_matched=counters["ipv6"][0],
        submitted=submitted, ring_drops=dropped,
        driver_seen=xdp["_xdp_packets"], driver_xdp_drops=xdp["_xdp_drops"],
        driver_xdp_redirect=xdp["_xdp_redirect"], driver_xdp_tx=xdp["_xdp_tx"],
        drained=sum(drained) if drained else None,
        send_failures=sum(map(int, re.findall(r"send_errors=(\d+)", capture))) if drained else None,
        bpf_invocations=" ".join(map(str, invocations)),
        bpf_ns_per_rx=round(sum(runtime) / receiver, 3) if runtime and receiver else None,
        samples=samples, age_p50_us=p50, age_p99_us=p99,
    )
    for scope, modifier in (("kernel", "k"), ("user", "u")):
        for event in ("cycles", "instructions"):
            count = perf_counter(directory, f"{scope}.stat", f"cpu_core/{event}/{modifier}")
            result[f"{scope}_{event}_per_rx"] = round(count / receiver, 2) if count is not None and receiver else None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    args = parser.parse_args()
    rows = [row(log.parent) for log in sorted(args.matrix.glob("*/*/*/*/detached.json"))]
    if not rows:
        parser.error("no completed runs in the matrix")
    writer = csv.DictWriter(sys.stdout, list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


if __name__ == "__main__":
    main()
