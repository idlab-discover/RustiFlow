"""Locate the first observed count difference in a capture interval.

Pass a counters.py delta JSON file and optional independent evidence, or a
completed fixture directory. Unknown and mixed cohorts preclude attributing
link discrepancies. Only a drained interval can reconcile terminal exports.
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


def explain(interval, evidence, tc, shapes=None, epoch_ok=True):
    d = interval["deltas"]
    pressure = {k: v for k, v in d.items() if v and (
        k == "link.rx.missed_errors" or k.startswith("driver.") and
        k.endswith(("missed_errors", "no_buffer_count", "_drops", "_alloc_failed")))}
    queues = {m[1] for k in d if (m := re.match(r"driver\.rx_queue_(\d+)_", k))}
    queue_packets = [d.get(f"driver.rx_queue_{q}_packets") for q in queues]
    queue_total = sum(queue_packets) if queue_packets and None not in queue_packets else None
    findings = ["device reports receive pressure"] if pressure else []
    notes = []
    scope = evidence.get("scope", "unknown")
    if scope not in ("isolated", "mixed", "unknown"):
        raise ValueError("expected isolated, mixed or unknown scope")
    truth = evidence.get("reference_frames", {})
    decoded = evidence.get("decoded", {})
    exported = evidence.get("exported", {})
    appended = evidence.get("appended_packets", {})
    other = evidence.get("other_link_units")
    for counts in (truth, decoded, exported, appended):
        if not isinstance(counts, dict) or counts.keys() - {"4", "6"}:
            raise ValueError("expected per-family count object")
    for v in (other, *truth.values(), *decoded.values(), *exported.values(), *appended.values()):
        if v is not None and (type(v) is not int or v < 0):
            raise ValueError("expected nonnegative integer count or null")

    rx = d.get("link.rx.packets")
    rx_bounds = interval.get("link_rx_delta_bounds")
    matches = [v["matched"] for v in tc.values()]
    tc_in_bracket = None
    if rx_bounds and scope == "isolated" and other is not None and None not in matches and epoch_ok:
        tc_in_bracket = rx_bounds[0] <= sum(matches) + other <= rx_bounds[1]
    if scope == "mixed":
        notes.append("other traffic in observation window")
    elif scope != "isolated" or other is None or any(truth.get(f) is None for f in tc):
        notes.append("independent comparable frame cohort unavailable")
    elif not epoch_ok:
        notes.append("TC interval cannot be joined to capture epoch")
    elif rx is None:
        notes.append("link interval unavailable")
    elif rx < other:
        notes.append("excluded link units exceed observed RX")
    else:
        lo, hi = (v - other for v in (rx_bounds or [rx, rx]))
        total = sum(truth.values())
        aggregate = any(v["gso_skbs"] for v in shapes or [])
        inline_tag = any(v["ethertype"] == "802.1Q" for v in shapes or [])
        if hi < total:
            findings.append("fewer units by capture link RX than independent frames")
            if aggregate:
                findings.append("multi-segment skbs confirmed at TC")
        elif lo > total:
            findings.append("additional link units beyond the known offer")
        if None in matches:
            notes.append("parsed TC match interval unavailable")
        elif sum(matches) < lo:
            if inline_tag:
                findings.append("inline VLAN at TC EtherType check")
            elif aggregate:
                findings.append("aggregation observed between link RX accounting and TC")
            else:
                findings.append("fewer parsed TC matches than scoped link RX units")
        elif sum(matches) > hi:
            findings.append("TC matches exceed scoped link RX units")
        elif sum(matches) == total and any(tc[f]["matched"] != truth[f] for f in tc):
            findings.append("family counts diverge by TC match")

    if epoch_ok and any(v["ring_drop"] for v in tc.values()):
        findings.append("TC ring reservation loss")
    drained = evidence.get("drained", False)
    if type(drained) is not bool:
        raise ValueError("expected boolean drained flag")
    if drained and epoch_ok:
        for f, kernel in tc.items():
            submitted = kernel["submitted"]
            if submitted is not None and decoded.get(f) is not None and decoded[f] != submitted:
                findings.append(f"IPv{f} submitted versus decoded mismatch")
        for f, kernel in tc.items():
            if exported.get(f) is None:
                continue
            if decoded.get(f) is not None:
                if exported[f] != decoded[f]:
                    findings.append(f"IPv{f} decoded versus exported mismatch")
            elif kernel["submitted"] is not None and exported[f] != kernel["submitted"]:
                findings.append(f"IPv{f} post-submission export mismatch")
        if any(decoded.get(f) is None or exported.get(f) is None for f in tc):
            notes.append("per-family decode or file totals unavailable")
    else:
        notes.append("terminal decode and export comparison unavailable")
    first = next(iter(findings), notes[0] if notes else "observed counts reconcile")
    balances = {}
    for f, kernel in tc.items():
        n = decoded.get(f)
        sub = kernel["submitted"] if epoch_ok else None
        groups = appended.get(f)
        balances[f] = dict(submitted_minus_decoded=None if None in (sub, n) else sub - n,
                           decoded_minus_appended=None if None in (n, groups) else n - groups)
    return dict(first_observation=first, observations=findings, limits=notes, interval_balances=balances,
                device_pressure=pressure, reported_queue_packet_sum=queue_total,
                tc_plus_other_within_link_bracket=tc_in_bracket)


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
    reference_complete = (reference["frames"] == {"4": offered, "6": offered}
                          and reference["socket_drops"] == 0)
    scope = "isolated" if reference_complete else "unknown"
    if any(target[f]["packet_count"] != exported[f] for f in tc) or (
            reference["socket_packets"] != sum(reference["frames"].values())):
        scope = "mixed"
    with_maps = bool(read(directory, "before.json")["tc_epochs"])
    epoch_ok = not with_maps or all(counters.get(f"tc.ipv{f}.{k}") == v
                                    for f in tc for k, v in tc[f].items())
    evidence = dict(scope=scope, reference_frames=reference["frames"], other_link_units=other,
                    drained=True, decoded=decoded, exported=exported)
    result = explain(interval, evidence, tc, shapes, epoch_ok)
    for f in tc:
        tc[f]["decoded"] = decoded[f]
        tc[f]["all_exported"] = exported[f]
        tc[f]["fixture_exported"] = target[f]
    return dict(**result,
                families=tc, sent_per_family=offered, other_frames_at_hook=other,
                reference_complete=reference_complete, reference=reference,
                parquet_rows=rows, tc_shapes=shapes, interval=interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="delta JSON or completed fixture directory")
    parser.add_argument("--evidence", type=Path, help="optional cohort and terminal counts for a delta")
    args = parser.parse_args()
    if args.input.is_dir():
        if args.evidence:
            parser.error("fixture directories already supply the evidence")
        result = assess(args.input)
    else:
        interval = json.loads(args.input.read_text())
        evidence = json.loads(args.evidence.read_text()) if args.evidence else {}
        tc = {f: {k: interval["deltas"].get(f"tc.ipv{f}.{k}") for k in ("matched", "submitted", "ring_drop")}
              for f in ("4", "6")}
        result = dict(**explain(interval, evidence, tc), families=tc, interval=interval, evidence=evidence)
    print(json.dumps(result, indent=2))
