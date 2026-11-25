"""Run from the worktree via topology.sh. All measurements go under target/."""

import argparse
import contextlib
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess as sp
import time

from counters import difference

HERE = Path(__file__).resolve().parent
ROOT = Path.cwd()
BUILD = ROOT / "target"
CAP, SEND, SINK = (os.environ[key] for key in ("CAP", "SEND", "SINK"))
PERF = "task-clock,cpu_core/cycles/u,cpu_core/mem_load_retired.l3_miss/u"
CONFIGS = [
    ("plain", "off", "off"), ("plain", "off", "on"),
    ("plain", "on", "off"), ("plain", "on", "on"),
    ("tag", "off", "off"), ("tag", "on", "on"),
    ("stack", "off", "off"), ("stack", "on", "on"),
]


def run(args, timeout=45, **kw):
    return sp.check_output(args, text=True, timeout=timeout, **kw)


def local(ns, *args):
    return ["ip", "netns", "exec", ns, *args]


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


@contextlib.contextmanager
def child(args, log, env=None):
    with log.open("w") as output:
        proc = sp.Popen(args, stdout=output, stderr=sp.STDOUT, env=env)
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def ready(proc, log, marker):
    deadline = time.monotonic() + 8
    while marker not in log.read_text():
        if proc.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError(f"{proc.args}: readiness failed: {log.read_text()}")
        time.sleep(.005)


def sample(directory, name, maps, dev="cap0"):
    args = ["python3", HERE / "counters.py", "snapshot", dev]
    if maps:
        args.append("--split-tc")
    data = json.loads(run(local(CAP, *args)))
    write(directory / f"{name}.json", data)
    if maps and not data["tc_epochs"]:
        raise ValueError(data["issues"])
    return data


def watch_close(path):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1")
    if libc.inotify_add_watch(fd, os.fsencode(path), 8) < 0:
        os.close(fd)
        raise OSError(ctypes.get_errno(), "inotify_add_watch")
    return fd


def process_cpu_ns(pid):
    clock_id = ctypes.c_int()
    error = ctypes.CDLL(None).clock_getcpuclockid(pid, ctypes.byref(clock_id))
    if error:
        raise OSError(error, "clock_getcpuclockid")
    return time.clock_gettime_ns(clock_id.value)


def trial(directory, settings, mode, groups, hook="cap0", vlan_accel=None):
    directory.mkdir()
    run([HERE / "configure.sh", *settings])
    if vlan_accel is not None:
        run(local(SEND, "ethtool", "-K", "send0", "txvlan", vlan_accel, "tx-vlan-stag-hw-insert", vlan_accel))
        run(local(CAP, "ethtool", "-K", "cap0", "rxvlan", vlan_accel, "rx-vlan-stag-hw-parse", vlan_accel))
    time.sleep(.25)  # let address-change multicast finish before attaching TC
    for ns, dev in ((CAP, "cap0"), (SEND, "send0"), (CAP, "exit0"), (SINK, "sink0")):
        (directory / f"{dev}.features").write_text(run(local(ns, "ethtool", "-k", dev)))
    sender = local(SEND, "taskset", "-c", "4", "python3", HERE / "fixture.py", "send", str(groups))
    if mode == "headroom":
        before = json.loads(run(["ip", "-n", SINK, "-j", "-s", "link", "show", "sink0"]))[0]
        offered = json.loads(run(sender + ["--rate", "0"]))
        after = json.loads(run(["ip", "-n", SINK, "-j", "-s", "link", "show", "sink0"]))[0]
        offered["sink_rx_delta"] = after["stats64"]["rx"]["packets"] - before["stats64"]["rx"]["packets"]
        write(directory / "sender.json", offered)
        return
    diagnostic = mode in ("maps", "shape", "pressure", "background", "steps")
    if mode == "background":
        sender.append("--background")
    env = dict(os.environ, RUST_LOG="info", RUSTIFLOW_EBPF_DIR=str(BUILD / "bpfel-unknown-none/release"))
    if diagnostic:
        env["RUSTIFLOW_REALTIME_STATS"] = "1"
    parquet = directory / "flows.parquet"
    capture = local(CAP, "taskset", "-c", "0-3", BUILD / "profiling/rustiflow", "-f", "rustiflow",
                    "-o", "parquet", "--export-path", parquet, "--threads", "2", "realtime",
                    hook, "--ingress-only")
    with contextlib.ExitStack() as stack:
        proc = stack.enter_context(child(capture, directory / "capture.log", env))
        ready(proc, directory / "capture.log", "Waiting for Ctrl-C")
        close_fd = watch_close(parquet)
        stack.callback(os.close, close_fd)
        if mode == "shape":
            run(local(CAP, "tc", "filter", "add", "dev", hook, "ingress", "pref", "10", "bpf",
                      "da", "obj", BUILD / "accounting/shape.bpf.o", "sec", "classifier"))
        if mode == "pressure":
            proc.send_signal(signal.SIGSTOP)
            deadline = time.monotonic() + 2
            while not all("\nState:\tT" in path.read_text()
                          for path in Path(f"/proc/{proc.pid}/task").glob("*/status")):
                if time.monotonic() >= deadline:
                    raise TimeoutError("waiting for all capture threads to stop")
                time.sleep(.001)
        before = sample(directory, "before", diagnostic, hook)
        if mode == "background":
            idle = sample(directory, "idle-before", False, "lo")
        ref = stack.enter_context(child(local(SINK, "taskset", "-c", "5", "python3", HERE / "fixture.py",
                                              "receive", str(3 * groups if mode == "steps" else groups)), directory / "reference.log"))
        ready(ref, directory / "reference.log", "ready")
        cmd = ["perf", "stat", "-x", ";", "-e", PERF, "-p", str(proc.pid), "-o", directory / "perf.stat",
               "--", *sender]
        cpu_start = process_cpu_ns(proc.pid)
        exit_fd = os.pidfd_open(proc.pid)
        stack.callback(os.close, exit_fd)
        if mode == "steps":
            # Three distinct quiet-boundary samples within one attachment and one file.
            phase_start = before
            offers = []
            for phase in range(3):
                if phase == 1:
                    run(local(CAP, "ethtool", "-K", "cap0", "gro", "on"))
                if phase == 2:
                    run(local(SEND, "ethtool", "-K", "send0", "gso", "on", "tx-udp-segmentation", "on"))
                offers.append(json.loads(run(sender + ["--offset", str(phase * groups)])))
                phase_end = sample(directory, f"phase-{phase}", True, hook)
                write(directory / f"interval-{phase}.json", difference(phase_start, phase_end))
                phase_start = phase_end
            write(directory / "offers.json", offers)
            offered = dict(start=offers[0]["start"],
                           packets_per_family=sum(v["packets_per_family"] for v in offers),
                           other_frames=sum(v["other_frames"] for v in offers))
        else:
            offered = json.loads(run(cmd, timeout=max(45, 30 + groups / 1000)))
        if diagnostic:
            after = sample(directory, "after", True, hook)
        if mode == "background":
            idle_end = sample(directory, "idle-after", False, "lo")
            write(directory / "idle-interval.json", difference(idle, idle_end))
        if mode == "shape":
            write(directory / "shapes.json", json.loads(run(local(CAP, "python3", HERE / "shapes.py", hook))))
        stop = time.monotonic()
        proc.send_signal(signal.SIGINT)
        if mode == "pressure":
            proc.send_signal(signal.SIGCONT)
        if not select.select([close_fd], [], [], 10)[0]:
            raise TimeoutError("Parquet close")
        close = time.monotonic()
        if struct.unpack_from("iIII", os.read(close_fd, 4096))[1] != 8:
            raise ValueError("unexpected inotify event")
        if not select.select([exit_fd], [], [], 10)[0]:
            raise TimeoutError("capture exit")
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        if proc.returncode != 0:
            raise RuntimeError((directory / "capture.log").read_text())
        cpu_to_exit = (usage.ru_utime + usage.ru_stime) * 1e9 - cpu_start
        if not diagnostic:
            after = sample(directory, "after", False, hook)
        if ref.wait(timeout=5) != 0:
            raise RuntimeError((directory / "reference.log").read_text())
    if mode == "shape":
        run(local(CAP, "tc", "filter", "del", "dev", hook, "ingress", "pref", "10"))
    if "ERROR" in (directory / "capture.log").read_text():
        raise ValueError("capture logged an error")
    write(directory / "interval.json", difference(before, after))
    write(directory / "sender.json", offered)
    write(directory / "times.json", dict(sigint_close=close-stop, send_close=close-offered["start"],
                                         cpu_ns_sender_command_to_exit=cpu_to_exit))
    (directory / "export.tsv").write_text(run([BUILD / "accounting/read_export", parquet]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("headroom", "maps", "rate", "shape", "paired", "pressure", "background", "vlan", "steps"))
    parser.add_argument("campaign")
    parser.add_argument("--groups", type=int, default=1000)
    parser.add_argument("--reps", type=int, default=4)
    args = parser.parse_args()
    if args.groups < 1 or args.reps < 0:
        parser.error("expected positive groups and nonnegative repetitions")
    out = BUILD / "accounting" / args.campaign
    out.mkdir()
    for rep in range(args.reps + 1):
        if args.stage == "vlan":
            for vlan in ("tag", "stack"):
                configs = [("cap0", "on"), ("cap0", "off"), ("tag17", "off")]
                for hook, accel in (configs if rep % 2 == 0 else reversed(configs)):
                    trial(out / f"{rep}-{vlan}-{hook}-{accel}", (vlan, "off", "off"),
                          "shape", args.groups, hook, accel)
            continue
        configs = CONFIGS[:1] if args.stage in ("pressure", "background", "steps") else CONFIGS
        for settings in (configs if rep % 2 == 0 else reversed(configs)):
            label = "-".join([str(rep), *settings])
            print(label, flush=True)
            modes = ("rate", "maps") if args.stage == "paired" else (args.stage,)
            for mode in (modes if rep % 2 == 0 else reversed(modes)):
                trial(out / f"{label}-{mode}", settings, mode, args.groups)
