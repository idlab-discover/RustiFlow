"""Read the map of the private TC shape observer selected by its program ID."""

import json
import struct
import subprocess
import sys


def dump(dev):
    def query(*args):
        return json.loads(subprocess.check_output(args, text=True, timeout=8))

    filters = query("tc", "-j", "filter", "show", "dev", dev, "ingress")
    prog, = [f["options"]["prog"]["id"] for f in filters if f.get("pref") == 10
             and f.get("options", {}).get("prog", {}).get("name") == "rf09_shape"]
    handle = query("bpftool", "-j", "prog", "show", "id", str(prog))
    ident, = handle["map_ids"]
    rows = query("bpftool", "-j", "map", "dump", "id", str(ident))
    shapes = []
    for row in rows:
        key = struct.unpack("=I", bytes(int(b, 16) for b in row["key"]))[0]
        values = [struct.unpack("=4Q", bytes(int(b, 16) for b in v["value"])) for v in row["values"]]
        skbs, gso, segments, size_512 = map(sum, zip(*values))
        if skbs:
            shapes.append(dict(metadata=["none", "802.1Q", "802.1ad", "other"][key // 6],
                               ethertype=["unreadable", "IPv4", "IPv6", "802.1Q", "0x88b5", "other"][key % 6],
                               skbs=skbs, gso_skbs=gso, segments=segments, size_512=size_512))
    return shapes


if __name__ == "__main__":
    print(json.dumps(dump(sys.argv[1])))
