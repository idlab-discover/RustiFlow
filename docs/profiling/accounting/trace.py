"""Holdout with independent L2 frame truth from the shared little-endian Ethernet pcap."""

import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

from counters import difference
from ledger import outcomes, source_events
from run import BUILD, CAP, SEND, child, local, ready, run, sample, write


def slice_trace(source, outfile, count):
    truth = {family: dict(packets=0, ethernet_bytes=0, ip_bytes=0) for family in ("4", "6")}
    with source.open("rb") as src, outfile.open("xb") as dest:
        header = src.read(24)
        assert header[:4] == bytes.fromhex("4d3cb2a1") and struct.unpack_from("<I", header, 20)[0] == 1
        dest.write(header)
        for _ in range(count):
            record = src.read(16)
            size, wire = struct.unpack_from("<II", record, 8)
            frame = src.read(size)
            assert len(frame) == size == wire
            family = {bytes.fromhex("0800"): "4", bytes.fromhex("86dd"): "6"}[frame[12:14]]
            length = int.from_bytes(frame[16:18], "big") if family == "4" else 40 + int.from_bytes(frame[18:20], "big")
            assert length <= size - 14
            truth[family]["packets"] += 1
            truth[family]["ethernet_bytes"] += size
            truth[family]["ip_bytes"] += length
            dest.write(record)
            dest.write(frame)
    return truth


def export_totals(parquet):
    packets = {"4": 0, "6": 0}
    sizes = dict(packets)
    rows = run([BUILD / "accounting/read_export", parquet]).splitlines()
    for line in rows:
        row = {k: json.loads(v) for k, v in (s.split("=", 1) for s in line.split("\t"))}
        family = str(row["ip_version"])
        packets[family] += row["packet_count"]
        sizes[family] += int(row["packet_len_total"])
    return dict(rows=len(rows), packets=packets, ip_bytes=sizes)


def trial(directory, setting, pcap, truth):
    directory.mkdir()
    run(local(SEND, "ethtool", "-K", "send0", "gso", setting, "tx-udp-segmentation", setting))
    run(local(CAP, "ethtool", "-K", "cap0", "gro", setting, "rx-udp-gro-forwarding", "on"))
    parquet = directory / "flows.parquet"
    env = dict(os.environ, RUST_LOG="info", RUSTIFLOW_REALTIME_STATS="1",
               RUSTIFLOW_EBPF_DIR=str(BUILD / "bpfel-unknown-none/release"))
    capture = local(CAP, "taskset", "-c", "0-3", BUILD / "profiling/rustiflow", "-f", "rustiflow",
                    "-o", "parquet", "--threads", "2", "--export-path", parquet, "realtime", "cap0", "--ingress-only")
    log = directory / "capture.log"
    with child(capture, log, env) as proc:
        ready(proc, log, "Waiting for Ctrl-C")
        before = sample(directory, "before", True)
        (directory / "sender.log").write_text(run(local(SEND, "taskset", "-c", "4", "tcpreplay",
            "--preload-pcap", "--pps=32000", "--intf1=send0", pcap), stderr=subprocess.STDOUT))
        after = sample(directory, "after", True)
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=15) == 0, log.read_text()
    interval = difference(before, after)
    write(directory / "interval.json", interval)
    delta = interval["deltas"]
    assert delta["link.rx.packets"] == sum(v["packets"] for v in truth.values())
    tc, decoded = outcomes(log.read_text()), source_events(log.read_text())
    exported = export_totals(parquet)
    write(directory / "export.json", exported)
    for f, v in truth.items():
        assert v["packets"] == delta[f"tc.ipv{f}.matched"] == tc[f]["submitted"] == decoded[f] == exported["packets"][f]
        assert tc[f]["ring_drop"] == 0 and exported["ip_bytes"][f] == v["ip_bytes"]


if __name__ == "__main__":
    root = BUILD / "accounting" / sys.argv[2]
    root.mkdir()
    pcap = root / "slice.pcap"
    truth = slice_trace(Path(sys.argv[1]), pcap, 32000)
    write(root / "truth.json", truth)
    for ns, dev in ((CAP, "cap0"), (SEND, "send0")):
        run(["ip", "-n", ns, "link", "set", dev, "mtu", "2000"])
        run(local(ns, "sysctl", "-qw", f"net.ipv6.conf.{dev}.disable_ipv6=1"))
    time.sleep(.3)
    for rep in range(4):
        for state in (("off", "on") if rep % 2 == 0 else ("on", "off")):
            trial(root / f"{rep}-{state}", state, pcap, truth)
