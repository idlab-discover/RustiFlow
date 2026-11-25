"""Read-only Linux capture accounting. Take two samples in the capture namespace.

Optional --split-tc reads the pinned RustiFlow split ingress map layout. Run
'delta BEFORE AFTER' on the two JSON files. Nulls and issues identify fields
outside the observable interval. All source observations are sequential.
"""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise ValueError(f"{args}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def attached_ids(dev):
    filters = json.loads(command("tc", "-j", "filter", "show", "dev", dev, "ingress"))
    return [str(item["options"]["prog"]["id"]) for item in filters
            if item.get("kind") == "bpf" and "prog" in item.get("options", {})]


def tc_counters(dev):
    programs = attached_ids(dev)
    helper = Path(__file__).resolve().parents[3] / "target/accounting/read_maps"
    counts = {}
    epochs = {}
    for line in command(helper, *programs).splitlines():
        family, outcome, prog, ident, *values = line.split()
        key = f"tc.ipv{family}.{outcome}"
        if key in epochs:
            raise ValueError("ambiguous split ingress classifier set")
        epochs[key] = [int(prog), int(ident)]
        counts[key] = {str(cpu): int(value) for cpu, value in enumerate(values)}
    if len(epochs) != 4 or attached_ids(dev) != programs:
        raise ValueError("missing, changed or unsupported split TC counter maps")
    return counts, epochs


def snapshot(dev, split_tc, bracket_rx=False):
    begin = time.monotonic_ns()
    link, = json.loads(command("ip", "-j", "-s", "-s", "link", "show", "dev", dev))
    ident = [Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
             os.stat("/proc/self/ns/net").st_ino, link["ifindex"], dev, link.get("address")]
    counts = {f"link.rx.{key}": value for key, value in link.get("stats64", {}).get("rx", {}).items()}
    issues = []
    epochs = {}
    # A queue may expose drops without a packet counter. Preserve this distinction.
    netdev = Path("/sys/class/net") / dev
    try:
        if (netdev / "ifindex").read_text().strip() == str(link["ifindex"]):
            for queue in (netdev / "queues").glob("rx-[0-9]*"):
                index = int(queue.name.split("-")[1])
                for suffix in ("packets", "bytes", "drops", "alloc_failed"):
                    counts[f"driver.rx_queue_{index}_{suffix}"] = None
    except OSError as exc:
        issues.append(f"queue inventory unavailable: {exc}")
    try:
        for line in command("ethtool", "-S", dev).splitlines():
            match = re.fullmatch(r"\s*(rx_(?:missed_errors|no_buffer_count|queue_\d+_(?:packets|bytes|drops|alloc_failed))):\s*(\d+)\s*", line)
            if match:
                counts["driver." + match[1]] = int(match[2])
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        issues.append(str(exc))
    try:
        softnet = {}
        for line in Path("/proc/net/softnet_stat").read_text().splitlines():
            fields = [int(v, 16) for v in line.split()]
            if len(fields) < 13:
                raise ValueError("softnet CPU identifiers unavailable")
            for col, name in enumerate(("processed", "dropped", "time_squeeze")):
                softnet.setdefault("softnet." + name, {})[str(fields[12])] = fields[col]
        counts.update(softnet)
    except (OSError, ValueError) as exc:
        issues.append(str(exc))
    if split_tc:
        try:
            tc, epochs = tc_counters(dev)
            counts.update(tc)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            issues.append(str(exc))
    rx_end = None
    if bracket_rx:
        last, = json.loads(command("ip", "-j", "-s", "link", "show", "dev", dev))
        if (last["ifindex"], last.get("address")) != (link["ifindex"], link.get("address")):
            raise ValueError("link changed during RX bracket")
        rx_end = last.get("stats64", {}).get("rx", {}).get("packets")
    if socket.if_nametoindex(dev) != link["ifindex"]:
        raise ValueError("interface changed during observation")
    return dict(identity=ident, start_ns=begin, end_ns=time.monotonic_ns(),
                counts=counts, tc_epochs=epochs, issues=issues, rx_end=rx_end)


def difference(before, after):
    if before["identity"] != after["identity"]:
        raise ValueError("boot, namespace or interface identity changed")
    if after["start_ns"] < before["end_ns"]:
        raise ValueError("samples overlap or run backwards")
    first, last = before["counts"], after["counts"]
    issues = before["issues"] + after["issues"]
    deltas = {}
    fields = first.keys() | last.keys() | {"driver.rx_missed_errors", "driver.rx_no_buffer_count"}
    reset = {}
    for key in sorted(first.keys() & last.keys()):
        group = key.split(".", 1)[0]
        a, b = first[key], last[key]
        if group in ("driver", "link") and isinstance(a, int) and isinstance(b, int) and b < a:
            reset[group] = f"{key} decreased; rebaseline {group} counters"
        if group == "softnet" and isinstance(a, dict) and isinstance(b, dict):
            if a.keys() != b.keys() or any(b[c] < v for c, v in a.items()):
                reset[group] = f"{key} CPU set or epoch changed"
    packet_key = "link.rx.packets"
    x, y = first.get(packet_key), last.get(packet_key)
    xe, ye = before.get("rx_end"), after.get("rx_end")
    if any(a is not None and b is not None and b < a for a, b in ((x, xe), (xe, y), (y, ye))):
        reset["link"] = "link RX decreased across bracket; rebaseline link counters"
    bounds = [y - xe, ye - x] if None not in (x, xe, y, ye) and "link" not in reset else None
    for key in sorted(fields):
        a, b = first.get(key), last.get(key)
        if a is None or b is None:
            issue = "unavailable"
        elif key.split(".", 1)[0] in reset:
            issue = reset[key.split(".", 1)[0]]
        elif before["tc_epochs"].get(key) != after["tc_epochs"].get(key):
            issue = "program or map replaced"
        elif isinstance(a, dict) and isinstance(b, dict):
            if a.keys() != b.keys():
                issue = "CPU set changed"
            elif any(b[c] < v for c, v in a.items()):
                issue = "per-CPU counter decreased"
            else:
                deltas[key] = sum(b[c] - v for c, v in a.items())
                continue
        elif b < a:
            issue = "counter decreased"
        else:
            deltas[key] = b - a
            continue
        issues.append(f"{key}: {issue}")
        deltas[key] = None
    for family in (4, 6):
        prefix = f"tc.ipv{family}."
        sub, drop = (deltas.get(prefix + k) for k in ("submitted", "ring_drop"))
        deltas[prefix + "matched"] = None if None in (sub, drop) else sub + drop
    return dict(identity=before["identity"], elapsed_bounds_ns=[
        after["start_ns"] - before["end_ns"], after["end_ns"] - before["start_ns"]],
        deltas=deltas, link_rx_delta_bounds=bounds, issues=issues)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="cmd", required=True)
    take = commands.add_parser("snapshot")
    take.add_argument("dev")
    take.add_argument("--split-tc", action="store_true")
    take.add_argument("--bracket-rx", action="store_true", help="bound link RX units during sequential reads")
    diff = commands.add_parser("delta")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    args = parser.parse_args()
    result = (snapshot(args.dev, args.split_tc, args.bracket_rx) if args.cmd == "snapshot" else
              difference(json.loads(args.before.read_text()), json.loads(args.after.read_text())))
    print(json.dumps(result, indent=2, sort_keys=True))
