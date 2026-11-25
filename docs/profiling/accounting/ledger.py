"""Join a quiescent two-family fixture interval to its independent reference and closed export.

On a shared physical link, use counters.py alone until an independent source and
a comparable packet cohort are available. A driver counter and a softnet drop
may refer to other traffic. A readable empty Parquet file has zero rows.
"""

import argparse
import json
from pathlib import Path
import re


def read(directory, name):
    return json.loads((directory / name).read_text())


def outcomes(log):
    totals = {}
    for family, matched, submitted, dropped in re.findall(
        r"eBPF counters ingress-ipv([46]): matched_packets=(\d+), submitted_events=(\d+), dropped_packets=(\d+)", log
    ):
        if family in totals or int(matched) != int(submitted) + int(dropped):
            raise ValueError("ambiguous or inconsistent terminal TC outcomes")
        totals[family] = dict(matched=int(matched), submitted=int(submitted), ring_drop=int(dropped))
    if totals.keys() != {"4", "6"}:
        raise ValueError("missing terminal split ingress outcomes")
    return totals


def source_events(log):
    events = {k: {} for k in ("4", "6")}
    for family, queue, count in re.findall(
        r"Realtime source ingress-ipv([46])-q(\d+): (?:events=(\d+)|no events drained)", log
    ):
        if queue in events[family]:
            raise ValueError("duplicate source")
        events[family][queue] = int(count or 0)
    return {f: sum(v.values()) if set(v) == set(map(str, range(8))) else None
            for f, v in events.items()}


def file_counts(directory):
    fields = ("packet_count", "packet_len_total", "payload_len_total")
    all_counts = {f: 0 for f in ("4", "6")}
    target = {f: dict.fromkeys(fields, 0) for f in all_counts}
    addresses = {"4": ("198.18.9.2", "198.18.10.2"), "6": ("fd09:1::2", "fd09:2::2")}
    rows = 0
    for line in (directory / "export.tsv").read_text().splitlines():
        row = {k: json.loads(v) for k, v in (s.split("=", 1) for s in line.split("\t"))}
        f = str(row["ip_version"])
        all_counts[f] += row["packet_count"]
        if ((row["source_ip"], row["destination_ip"]) == addresses[f]
                and (row["source_port"], row["destination_port"], row["protocol"]) == (30000, 31000, 17)):
            for field in fields:
                target[f][field] += int(row[field])
        rows += 1
    return rows, all_counts, target


def assess(directory):
    sender = read(directory, "sender.json")
    reference = json.loads((directory / "reference.log").read_text().splitlines()[-1])
    interval = read(directory, "interval.json")
    counters = interval["deltas"]
    log = (directory / "capture.log").read_text()
    tc = outcomes(log)
    decoded = source_events(log)
    rows, exported, target = file_counts(directory)
    offered = sender["packets_per_family"]
    other = sender["other_frames"] if interval["identity"][3] == "cap0" else 0
    shape_file = directory / "shapes.json"
    shapes = json.loads(shape_file.read_text()) if shape_file.exists() else None
    aggregate = any(v["gso_skbs"] for v in shapes or [])
    inline_tag = any(v["ethertype"] == "802.1Q" for v in shapes or [])
    findings = []
    reference_complete = (reference["frames"] == {"4": offered, "6": offered}
                          and reference["socket_drops"] == 0)
    hardware = {k: v for k, v in counters.items() if k.startswith("driver.") and v
                and k.endswith(("missed_errors", "no_buffer_count", "_drops", "_alloc_failed"))}
    # A nonzero device-wide counter is an observation. Family attribution needs a matched cohort.
    if hardware:
        findings.append("driver reports receive pressure")
    rx = counters.get("link.rx.packets")
    scoped_rx = rx - other if rx is not None else None
    matched = sum(v["matched"] for v in tc.values())
    mixed_export = any(target[f]["packet_count"] != exported[f] for f in tc)
    map_disagreement = any(counters[key] != v for f in tc for outcome, v in tc[f].items()
                           if (key := f"tc.ipv{f}.{outcome}") in counters and counters[key] is not None)
    incomplete_maps = bool(read(directory, "before.json")["tc_epochs"]) and any(
        counters.get(f"tc.ipv{f}.{outcome}") is None for f in tc for outcome in tc[f])
    if not reference_complete:
        findings.append("independent frame truth incomplete")
    elif mixed_export or reference["socket_packets"] != sum(reference["frames"].values()):
        findings.append("other IP traffic in observation window")
    elif map_disagreement or incomplete_maps:
        findings.append("TC interval cannot be joined to capture epoch")
    elif scoped_rx is None:
        findings.append("link interval unavailable")
    else:
        if scoped_rx < 2 * offered:
            findings.append("coarser count by capture link RX")
            if aggregate:
                findings.append("multi-segment skbs confirmed at TC")
        elif scoped_rx > 2 * offered:
            findings.append("additional link units beyond the known offer")
        if matched < scoped_rx:
            if inline_tag:
                findings.append("inline VLAN at TC EtherType check")
            elif aggregate:
                findings.append("aggregation between link RX accounting and TC")
            else:
                findings.append("fewer parsed TC matches than scoped link RX units")
        elif matched > scoped_rx:
            findings.append("TC matches exceed scoped link RX units")
        elif matched == 2 * offered and any(v["matched"] != offered for v in tc.values()):
            findings.append("family counts diverge by TC match")
    if any(v["ring_drop"] for v in tc.values()):
        findings.append("TC ring reservation loss")
    if any(decoded[f] is not None and decoded[f] != tc[f]["submitted"] for f in tc):
        findings.append("submitted versus decoded mismatch")
    if any(exported[f] != tc[f]["submitted"] for f in tc):
        findings.append("post-submission export mismatch")
    for f in tc:
        tc[f]["decoded"] = decoded[f]
        tc[f]["all_exported"] = exported[f]
        tc[f]["fixture_exported"] = target[f]
    return dict(first_observation=next(iter(findings), "counts reconcile"), observations=findings,
                families=tc, sent_per_family=offered, other_frames_at_hook=other,
                reference_complete=reference_complete, reference=reference,
                parquet_rows=rows, tc_shapes=shapes, interval=interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(assess(args.directory), indent=2))
