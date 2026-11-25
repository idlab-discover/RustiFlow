"""Profiling-only barrier samples of decoded events and appended Parquet groups."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess as sp
import sys
import time

from counters import difference
from ledger import explain, outcomes, source_events
from run import BUILD, CAP, SEND, child, local, ready, run, sample, watch_close, write
from trace import export_totals


def progress(proc, pidfd, log):
    pattern = r"Accounting sample decoded=(\[[^\]]+\]) appended=(None|Some\(\[[^\]]+\]\))"
    previous = len(re.findall(pattern, log.read_text()))
    begin = time.monotonic_ns()
    signal.pidfd_send_signal(pidfd, signal.SIGUSR1)
    until = time.monotonic() + 3
    while proc.poll() is None and time.monotonic() < until:
        messages = re.findall(pattern, log.read_text())
        if len(messages) == previous + 1:
            raw_decoded, raw_appended = messages[-1]
            decoded = json.loads(raw_decoded)
            appended = None if raw_appended == "None" else json.loads(raw_appended[5:-1])
            return dict(start_ns=begin, end_ns=time.monotonic_ns(), decoded=decoded, appended=appended)
        time.sleep(.002)
    raise TimeoutError("userspace accounting reply")


def trial(directory, pcap_dir, mode, binary):
    directory.mkdir()
    parquet = directory / "flows.parquet"
    log = directory / "capture.log"
    truth = json.loads((pcap_dir / "truth.json").read_text())
    env = dict(os.environ, RUST_LOG="info", RUSTIFLOW_REALTIME_STATS="1",
               RUSTIFLOW_EBPF_DIR=str(BUILD / "bpfel-unknown-none/release"))
    if mode == "probe":
        env["RUSTIFLOW_PROBE_COUNTS"] = "1"
    args = local(CAP, "taskset", "-c", "0-3", binary, "-f", "rustiflow", "-o", "parquet",
                 "--export-path", parquet, "--threads", "2", "--active-timeout", "30", "--idle-timeout",
                 "1", "--expiration-check-interval", "1", "realtime", "cap0", "--ingress-only")
    with ExitStack() as cleanup:
        proc = cleanup.enter_context(child(args, log, env))
        ready(proc, log, "Waiting for Ctrl-C")
        fd = watch_close(parquet)
        cleanup.callback(os.close, fd)
        pidfd = os.pidfd_open(proc.pid)
        cleanup.callback(os.close, pidfd)
        previous = sample(directory, "start", True)
        last = None
        if mode == "probe":
            # Signal only the registered profiling build via this process handle.
            assert Path(f"/proc/{proc.pid}/exe").resolve() == binary.resolve()
            ready(proc, log, "Accounting probe listening for SIGUSR1")
            last = progress(proc, pidfd, log)
            assert last["decoded"] == [0, 0] and last["appended"] == [0, 0, 0]
        phases = []
        for index in range(3):
            sent = run(local(SEND, "taskset", "-c", "4", "tcpreplay", "--preload-pcap",
                             "--pps=100000", "--intf1=send0", pcap_dir / "slice.pcap"), stderr=sp.STDOUT)
            assert re.search(r"Successful packets:\s+32000$", sent, re.M)
            (directory / f"phase-{index}.sender").write_text(sent)
            end = time.monotonic()
            current = sample(directory, f"after-{index}", True)
            interval = difference(previous, current)
            phase = {"interval": interval}
            d = interval["deltas"]
            assert d["link.rx.packets"] == 32000
            for f, t in truth.items():
                assert d[f"tc.ipv{f}.matched"] == d[f"tc.ipv{f}.submitted"] == t["packets"]
            if mode == "probe":
                now = progress(proc, pidfd, log)
                phase["progress"] = now
                for k in ("decoded", "appended"):
                    phase[k + "_delta"] = [a-b for a,b in zip(now[k], last[k], strict=True)]
                assert phase["decoded_delta"] == [truth[f]["packets"] for f in ("4", "6")]
                counts = {f: {k: d[f"tc.ipv{f}.{k}"] for k in ("matched", "submitted", "ring_drop")}
                          for f in ("4", "6")}
                evidence = dict(scope="isolated", other_link_units=0, drained=False,
                                reference_frames={f: t["packets"] for f,t in truth.items()},
                                decoded=dict(zip(("4", "6"), phase["decoded_delta"], strict=True)),
                                appended_packets=dict(zip(("4", "6"), phase["appended_delta"][1:], strict=True)))
                phase["accounting"] = explain(interval, evidence, counts)
                last = now
            phases.append(phase)
            previous = current
            if index < 2:
                time.sleep(max(0, end + 1.6 - time.monotonic()))
        write(directory / "phases.json", phases)
        proc.send_signal(signal.SIGINT)
        assert select.select([fd], [], [], 10)[0] and proc.wait(timeout=10) == 0
    totals = export_totals(parquet)
    write(directory / "export.json", totals)
    tc, source = outcomes(log.read_text()), source_events(log.read_text())
    for f, t in truth.items():
        assert tc[f]["submitted"] == source[f] == totals["packets"][f] == 3 * t["packets"]
        assert tc[f]["ring_drop"] == 0 and totals["ip_bytes"][f] == 3 * t["ip_bytes"]
    if mode == "probe":
        footer, = re.findall(r"Accounting footer appended=Some\((\[[^\]]+\])\)", log.read_text())
        assert json.loads(footer) == [totals["rows"], totals["packets"]["4"], totals["packets"]["6"]]


def fallback(directory, probe, feature, switch):
    directory.mkdir()
    log = directory / "capture.log"
    parquet = directory / "flows.parquet"
    env = dict(os.environ, RUST_LOG="info", RUSTIFLOW_REALTIME_STATS="1", RUSTIFLOW_PROBE_COUNTS=switch,
               RUSTIFLOW_EBPF_DIR=str(BUILD / "bpfel-unknown-none/release"))
    args = local(CAP, "taskset", "-c", "0-3", probe, "-f", feature, "-o", "parquet", "--export-path",
                 parquet, "--threads", "2", "realtime", "cap0", "--ingress-only")
    with child(args, log, env) as proc:
        ready(proc, log, "Waiting for Ctrl-C")
        if switch == "1":
            ready(proc, log, "Accounting probe listening for SIGUSR1")
            assert Path(f"/proc/{proc.pid}/exe").resolve() == probe.resolve()
            fd = os.pidfd_open(proc.pid)
            try:
                value = progress(proc, fd, log)
                assert value["decoded"] == [0, 0] and value["appended"] is None
            finally:
                os.close(fd)
        else:
            assert "Accounting probe listening" not in log.read_text()
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=10) == 0
    assert parquet.read_bytes()[-4:] == b"PAR1"


if __name__ == "__main__":
    pcap_dir = Path(sys.argv[1]).resolve()
    probe = Path(sys.argv[2]).resolve()
    out = BUILD / "accounting" / sys.argv[3]
    out.mkdir()
    for ns, dev in ((CAP, "cap0"), (SEND, "send0")):
        run(["ip", "-n", ns, "link", "set", dev, "mtu", "2000"])
        run(local(ns, "sysctl", "-qw", f"net.ipv6.conf.{dev}.disable_ipv6=1"))
    run(local(CAP, "ethtool", "-K", "cap0", "gro", "off"))
    run(local(SEND, "ethtool", "-K", "send0", "gso", "off", "tx-udp-segmentation", "off"))
    time.sleep(.25)
    for rep in range(4):
        for mode in (("base", "probe") if rep % 2 == 0 else ("probe", "base")):
            print(rep, mode, flush=True)
            trial(out / f"{rep}-{mode}", pcap_dir, mode, probe if mode == "probe" else BUILD / "profiling/rustiflow")

    fallback(out / "explicit-zero", probe, "rustiflow", "0")
    fallback(out / "unsupported-columns", probe, "basic", "1")
