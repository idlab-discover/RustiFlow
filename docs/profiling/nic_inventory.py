#!/usr/bin/env python3
"""Read a Linux capture interface's capabilities in the caller's network namespace."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


def query(argv, *, text=False):
    """Keep successful partial replies with their diagnostics (e.g. GETWOL denied)."""
    result = {"source": argv, "value": None}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                              env={**os.environ, "LC_ALL": "C"}, timeout=2)
        if proc.stderr.strip():
            result["diagnostic"] = proc.stderr.strip()
        if proc.returncode:
            result["exit_code"] = proc.returncode
        if text:
            if proc.returncode == 0:
                result["value"] = proc.stdout.strip()
        else:
            rows = json.loads(proc.stdout)
            if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict):
                if rows[0].get("ifname") == argv[-1]:
                    result["value"] = rows[0]
            if result["value"] is None:
                result.setdefault("diagnostic", "no matching device reply")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result.setdefault("diagnostic", str(exc))
    return result


def select(reply, keys):
    if reply["value"] is not None:
        reply["value"] = {key: reply["value"].get(key) for key in keys}
    return reply


def sysfs(root, names):
    values, errors = {}, {}
    for name in names:
        try:
            values[name] = (root / name).read_text().strip()
        except OSError as exc:
            values[name] = None
            errors[name] = exc.strerror
    return {"source": str(root), "value": values, "errors": errors}


def pci_parent(base, rtnl_parent):
    parent = base / "device"
    try:
        device = parent.resolve(strict=True)
        subsystem = (device / "subsystem").resolve(strict=True).name
    except OSError as exc:
        return {"source": str(parent), "value": None, "diagnostic": exc.strerror}
    if subsystem != "pci" or rtnl_parent not in (None, device.name):
        return {"source": str(parent), "value": None, "diagnostic": "no matching PCI parent"}

    result = sysfs(device, ["vendor", "device", "current_link_width", "max_link_width",
                            "current_link_speed", "max_link_speed"])
    result["value"]["bdf"] = device.name
    try:
        result["value"]["driver"] = (device / "driver").resolve(strict=True).name
    except OSError as exc:
        result["value"]["driver"] = None
        result["errors"]["driver"] = exc.strerror
    return result


def inventory(name):
    index = socket.if_nametoindex(name)
    ns = {"source": "/proc/self/ns/net", "value": None}
    try:
        ns["value"] = os.readlink(ns["source"])
    except OSError as exc:
        ns["diagnostic"] = exc.strerror
    link = query(["ip", "-j", "-d", "link", "show", "dev", name])
    attrs = link["value"] or {}
    kind = attrs.get("linkinfo", {}).get("info_kind")
    link_keys = ("ifindex", "link_type", "link_index", "link_netnsid", "master",
                 "mtu", "min_mtu", "max_mtu", "parentbus", "parentdev",
                 "num_rx_queues", "num_tx_queues")
    report = {"interface": name, "ifindex": {"source": "if_nametoindex", "value": index},
              "netns": ns,
              "rtnetlink": select(link, link_keys)}
    if link["value"] is not None:
        if attrs.get("ifindex") != index:
            raise OSError("RTM_GETLINK and socket interface indices differ")
        link["value"]["info_kind"] = kind

    base = Path("/sys/class/net") / name
    netdev = sysfs(base, ["ifindex", "iflink", "mtu", "type", "carrier", "speed", "duplex",
                          "phys_port_name", "phys_switch_id"])
    virtual = False
    if netdev["value"]["ifindex"] == str(index):
        report["sysfs"] = netdev
        try:
            resolved = base.resolve(strict=True)
            netdev["resolved_path"] = str(resolved)
            virtual = resolved.is_relative_to("/sys/devices/virtual/net")
        except OSError as exc:
            netdev["errors"]["resolved_path"] = exc.strerror
        report["pci"] = pci_parent(base, attrs.get("parentdev"))
        try:
            lowers = sorted(p.name[6:] for p in base.iterdir() if p.name.startswith("lower_"))
            report["lower_devices"] = {"source": str(base / "lower_*"), "value": lowers}
        except OSError as exc:
            report["lower_devices"] = {"source": str(base), "value": None, "diagnostic": exc.strerror}
    else:
        for field in ("sysfs", "pci", "lower_devices"):
            report[field] = {"source": str(base), "value": None,
                             "diagnostic": "sysfs ifindex unavailable or differs from socket"}
    # A PCI parent can be shared (e.g. representors). A veth iflink is a peer.
    if attrs.get("link_type") == "loopback" or (report["sysfs"]["value"] or {}).get("type") == "772":
        attachment = "loopback"
    elif kind == "veth":
        attachment = "veth"
    elif (report["lower_devices"]["value"] or
          kind in ("vlan", "bond", "bridge", "macvlan", "ipvlan", "team")):
        attachment = "stacked"
    elif report["pci"]["value"]:
        attachment = "pci-backed"
    elif virtual:
        attachment = "virtual"
    else:
        attachment = None
    report["attachment"] = {"source": "rtnetlink, sysfs and PCI parent above", "value": attachment}

    def ethtool(*opts):
        return query(["ethtool", "--json", *opts, name])

    report["link_modes"] = select(ethtool(), ("speed", "duplex", "lanes", "link-detected",
                                              "supported-link-modes", "advertised-link-modes"))
    # Preserve the original readbacks, including driver-specific unknown sentinels.
    link_speed = {"source": None, "value": None}
    for source, values in (("link_modes", report["link_modes"]), ("sysfs", report["sysfs"])):
        mbps = (values["value"] or {}).get("speed")
        if str(mbps).isdecimal() and 0 < int(mbps) < 0xffffffff:
            link_speed = {"source": f"{source}.speed (Mb/s)", "value": int(mbps) * 1_000_000}
            break
    report["reported_speed_bps"] = link_speed
    report["channels"] = ethtool("-l")
    report["descriptors"] = ethtool("-g")
    report["coalescing"] = ethtool("-c")
    report["offloads"] = ethtool("-k")
    # Only these RSS attributes may escape the probe. Never serialize raw stdout.
    report["rss"] = select(ethtool("-x"), ("rss-indirection-table", "rss-hash-function",
                                           "rss-input-transformation"))
    fields = {}
    for proto in ("tcp4", "udp4", "tcp6", "udp6"):
        reply = query(["ethtool", "-n", name, "rx-flow-hash", proto], text=True)
        if reply["value"] is not None:
            header, *lines = reply["value"].splitlines() or [""]
            if header.endswith("fields for computing Hash flow key:"):
                reply["value"] = [line.strip() for line in lines if line.strip()]
            else:
                reply.update(value=None, diagnostic="unrecognized rx-flow-hash reply")
        fields[proto] = reply
    report["rss_fields"] = fields
    if socket.if_nametoindex(name) != index:
        raise OSError("interface changed during inventory")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface", help="capture netdev in the current namespace")
    name = parser.parse_args().interface
    if name.startswith("-") or name in (".", "..") or "/" in name:
        parser.error("expected a network interface name")
    try:
        result = inventory(name)
    except OSError as exc:
        sys.exit(f"{name}: {exc}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
