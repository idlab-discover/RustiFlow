"""Bracket a continuous raw-frame replay with quiescent endpoint or periodic samples."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess as sp
import sys
import time

from counters import difference, snapshot
from ledger import explain, outcomes, source_events
from run import BUILD, CAP, HERE, PERF, SEND, child, local, process_cpu_ns, ready, run, watch_close, write
from trace import export_totals


def collect(mode, path):
    # One resident process on the controller CPU. Only this lab collector waits for stdin.
    with path.open("x") as sink:
        def take():
            print(json.dumps(snapshot("cap0", True, bracket_rx=True)), file=sink, flush=True)
        take()
        print("ready", flush=True)
        deadline = time.monotonic() + .25
        while not select.select([sys.stdin], [], [], max(0, deadline-time.monotonic()) if mode == "periodic" else None)[0]:
            take()
            deadline = max(time.monotonic(), deadline + .25)
        take()


def sender(directory, pcap, pid=None):
    replay = local(SEND, "taskset", "-c", "4", "tcpreplay", "--preload-pcap", "--loop=40",
                   "--intf1=send0", "--topspeed" if pid is None else "--pps=320000", pcap)
    args = replay if pid is None else ["perf", "stat", "-x", ";", "-e", PERF, "-p", str(pid),
                                       "-o", directory / "perf.stat", "--", *replay]
    log = run(args, stderr=sp.STDOUT)
    (directory / "sender.log").write_text(log)
    for label, n in (("Successful packets", 1280000), ("Failed packets", 0), ("Truncated packets", 0),
                     ("Retried packets (ENOBUFS)", 0), ("Retried packets (EAGAIN)", 0)):
        if not re.search(re.escape(label) + rf":\s+{n}$", log, re.M):
            raise ValueError(log)


def trial(directory, pcap, mode, truth):
    directory.mkdir()
    if mode == "detached":
        x = snapshot_in_cap()
        sender(directory, pcap)
        y = snapshot_in_cap()
        d = difference(x, y)
        assert d["deltas"]["link.rx.packets"] == 1280000
        write(directory / "interval.json", d)
        return
    parquet = directory / "flows.parquet"
    log = directory / "capture.log"
    env = dict(os.environ, RUST_LOG="info", RUSTIFLOW_REALTIME_STATS="1",
               RUSTIFLOW_EBPF_DIR=str(BUILD / "bpfel-unknown-none/release"))
    capture = local(CAP, "taskset", "-c", "0-3", BUILD / "profiling/rustiflow", "-f", "rustiflow",
                    "-o", "parquet", "--export-path", parquet, "--threads", "2", "realtime", "cap0", "--ingress-only")
    samples = directory / "samples.jsonl"
    with ExitStack() as cleanup:
        proc = cleanup.enter_context(child(capture, log, env))
        ready(proc, log, "Waiting for Ctrl-C")
        fd = watch_close(parquet)
        cleanup.callback(os.close, fd)
        exit_fd = os.pidfd_open(proc.pid)
        cleanup.callback(os.close, exit_fd)
        observer = sp.Popen(local(CAP, "python3", HERE / "moving.py", "collect", mode, samples),
                            stdin=sp.PIPE, stdout=sp.PIPE, text=True)
        try:
            if not select.select([observer.stdout], [], [], 10)[0] or observer.stdout.readline().strip() != "ready":
                raise RuntimeError("collector failed to start")
            cpu_start = process_cpu_ns(proc.pid)
            start = time.monotonic()
            sender(directory, pcap, proc.pid)
            observer.communicate("stop\n", timeout=10)
            if observer.returncode:
                raise RuntimeError("collector failed")
        finally:
            if observer.poll() is None:
                observer.kill()
            observer.wait()
        stop = time.monotonic()
        proc.send_signal(signal.SIGINT)
        assert select.select([fd], [], [], 10)[0]
        close = time.monotonic()
        assert struct.unpack_from("iIII", os.read(fd, 4096))[1] == 8
        if not select.select([exit_fd], [], [], 10)[0]:
            raise TimeoutError("capture exit")
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        assert proc.returncode == 0
        cpu_ns = (usage.ru_utime + usage.ru_stime) * 1e9 - cpu_start
    write(directory / "times.json", dict(command_close=close-start, sigint_close=close-stop, cpu_ns=cpu_ns))
    boundaries = [json.loads(line) for line in samples.read_text().splitlines()]
    total = difference(boundaries[0], boundaries[-1])
    write(directory / "interval.json", total)
    tc = outcomes(log.read_text())
    decoded = source_events(log.read_text())
    export = export_totals(parquet)
    write(directory / "export.json", export)
    for f, expected in truth.items():
        n = 40 * expected["packets"]
        assert total["deltas"][f"tc.ipv{f}.matched"] == tc[f]["matched"] == tc[f]["submitted"] == decoded[f] == export["packets"][f] == n
        assert tc[f]["ring_drop"] == 0 and export["ip_bytes"][f] == 40 * expected["ip_bytes"]
    assert total["link_rx_delta_bounds"] == [1280000, 1280000]
    windows = []
    for a, b in zip(boundaries, boundaries[1:]):
        if not all(s["rx_end"] > s["counts"]["link.rx.packets"] for s in (a,b)):
            continue  # Sender active at both ends of this window.
        interval = difference(a, b)
        delta = interval["deltas"]
        maps = {f: {k: delta[f"tc.ipv{f}.{k}"] for k in tc[f]} for f in tc}
        match = sum(x["matched"] for x in maps.values())
        check = explain(interval, dict(scope="isolated", other_link_units=0), maps)
        windows.append(dict(link_rx=delta["link.rx.packets"], matched=match,
                            bounds=interval["link_rx_delta_bounds"],
                            inside=check["tc_plus_other_within_link_bracket"]))
    write(directory / "active-windows.json", windows)


def snapshot_in_cap():
    return json.loads(run(local(CAP, "python3", HERE / "counters.py", "snapshot", "cap0")))


if __name__ == "__main__":
    if sys.argv[1] == "collect":
        collect(sys.argv[2], Path(sys.argv[3]))
    else:
        pcap_dir = Path(sys.argv[1]).resolve()
        truth = json.loads((pcap_dir / "truth.json").read_text())
        pcap = pcap_dir / "slice.pcap"
        out = BUILD / "accounting" / sys.argv[2]
        out.mkdir()
        for ns, dev in ((CAP, "cap0"), (SEND, "send0")):
            run(["ip", "-n", ns, "link", "set", dev, "mtu", "2000"])
            run(local(ns, "sysctl", "-qw", f"net.ipv6.conf.{dev}.disable_ipv6=1"))
        run(local(CAP, "ethtool", "-K", "cap0", "gro", "off"))
        run(local(SEND, "ethtool", "-K", "send0", "gso", "off", "tx-udp-segmentation", "off"))
        time.sleep(.25)
        for rep in range(5):
            trial(out / f"{rep}-detached", pcap, "detached", truth)
        for rep in range(5):
            for mode in (("ends", "periodic") if rep % 2 == 0 else ("periodic", "ends")):
                print(rep, mode, flush=True)
                trial(out / f"{rep}-{mode}", pcap, mode, truth)
