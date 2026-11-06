#!/usr/bin/env python3
"""Generate the capture-format fixtures in rustiflow/tests/data/.

Every fixture re-encodes the packets of nmap_tcp_syn_version.pcap, a
little-endian, microsecond, Ethernet classic pcap, so each one must export
exactly the flows of that file:

- *_nsec.pcap: nanosecond timestamps with sub-microsecond noise, which must
  truncate away.
- *_be.pcap: big-endian classic pcap.
- *_two_if.pcapng: two interfaces with if_tsresol 6 (the default, omitted)
  and 9, packets alternating between them, plus a block of an unknown type.
- *_sll.pcap: Linux cooked capture (SLL), every other frame 802.1Q-tagged.
- *_vlan.pcap: Ethernet with an 802.1Q tag on every frame.
- *_truncated.pcap: the original plus one packet of an extra flow, cut off
  inside its record.
- *_be_binary_tsresol.pcapng: a big-endian section with a binary if_tsresol
  (2^-20 s), an if_tsoffset, and a Simple Packet Block carrying an ARP frame.

With --edge-cases DIR it also writes files used only for differential checks
against a libpcap-based build; they are not committed.

Uses only the Python standard library. Output is deterministic.
"""

import argparse
import struct
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "rustiflow" / "tests" / "data"
BASE = "nmap_tcp_syn_version"

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
MAGIC_USEC = 0xA1B2C3D4
MAGIC_NSEC = 0xA1B23C4D


def read_classic(path):
    """Return (linktype, [(ts_sec, ts_usec, frame)]) of a LE microsecond pcap."""
    raw = path.read_bytes()
    magic, _, _, _, _, _, linktype = struct.unpack_from("<IHHiIII", raw, 0)
    assert magic == MAGIC_USEC, "base fixture must be little-endian microsecond pcap"
    packets, pos = [], 24
    while pos < len(raw):
        sec, usec, caplen, _ = struct.unpack_from("<IIII", raw, pos)
        packets.append((sec, usec, raw[pos + 16 : pos + 16 + caplen]))
        pos += 16 + caplen
    return linktype, packets


def classic(packets, linktype, endian="<", magic=MAGIC_USEC, frac=None, snaplen=65535):
    """Encode a classic pcap. frac(i, usec) gives the stored fraction."""
    out = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
    for i, (sec, usec, frame) in enumerate(packets):
        fraction = frac(i, usec) if frac else usec
        out += struct.pack(endian + "IIII", sec, fraction, len(frame), len(frame))
        out += frame
    return bytes(out)


def pad4(data):
    return data + b"\0" * (-len(data) % 4)


def ng_block(block_type, body, endian="<"):
    body = pad4(body)
    length = 12 + len(body)
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def ng_option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + pad4(value)


def ng_shb(endian="<"):
    return ng_block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def ng_idb(linktype, tsresol=None, tsoffset=None, snaplen=65535, endian="<"):
    options = b""
    if tsresol is not None:
        options += ng_option(9, bytes([tsresol]), endian)
    if tsoffset is not None:
        options += ng_option(14, struct.pack(endian + "q", tsoffset), endian)
    if options:
        options += struct.pack(endian + "HH", 0, 0)
    return ng_block(1, struct.pack(endian + "HHI", linktype, 0, snaplen) + options, endian)


def ng_epb(if_id, units, frame, endian="<"):
    body = struct.pack(endian + "IIIII", if_id, units >> 32, units & 0xFFFFFFFF, len(frame), len(frame))
    return ng_block(6, body + frame, endian)


def to_units(sec, usec, units_per_second, offset_seconds=0):
    """Timestamp in interface units; sub-unit noise for resolutions above us.

    The microsecond fraction is rounded up, so that truncating back to
    microseconds, as libpcap does, recovers it exactly for any resolution of at
    least one microsecond, binary ones included.
    """
    units = (sec - offset_seconds) * units_per_second - (-usec * units_per_second // 1_000_000)
    if units_per_second > 1_000_000:
        units += (sec * 7 + usec) % (units_per_second // 1_000_000)
    return units


def sll(frame, vlan_tag):
    """Ethernet frame -> Linux cooked capture frame, optionally VLAN-tagged."""
    src, ethertype, payload = frame[6:12], frame[12:14], frame[14:]
    header = struct.pack(">HHH", 0, 1, 6) + src + b"\0\0"
    if vlan_tag:
        return header + b"\x81\x00" + struct.pack(">H", 203) + ethertype + payload
    return header + ethertype + payload


def vlan(frame):
    return frame[:12] + b"\x81\x00" + struct.pack(">H", 203) + frame[12:]


def extra_udp_frame():
    """One UDP packet from a flow that is not in the base fixture."""
    payload = b"rustiflow-truncated-record"
    udp = struct.pack(">HHHH", 40000, 53, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 99, 0, 1]), bytes([10, 99, 0, 2]))
    return b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00" + ip + udp


def committed_fixtures(packets):
    two_if = bytearray(ng_shb())
    two_if += ng_idb(LINKTYPE_ETHERNET)  # if_tsresol omitted: microseconds
    two_if += ng_block(0x80000BAD, b"unknown block type, must be skipped")
    two_if += ng_idb(LINKTYPE_ETHERNET, tsresol=9)
    for i, (sec, usec, frame) in enumerate(packets):
        if_id = i % 2
        two_if += ng_epb(if_id, to_units(sec, usec, 10 ** (6 + 3 * if_id)), frame)

    offset_seconds = 1_000_000
    be_binary = bytearray(ng_shb(">"))
    be_binary += ng_idb(LINKTYPE_ETHERNET, tsresol=0x80 | 20, tsoffset=offset_seconds, endian=">")
    for sec, usec, frame in packets:
        be_binary += ng_epb(0, to_units(sec, usec, 1 << 20, offset_seconds), frame, ">")
    arp = b"\xff" * 6 + b"\x02\0\0\0\0\x01" + b"\x08\x06" + bytes(28)
    be_binary += ng_block(3, struct.pack(">I", len(arp)) + arp, ">")

    last_sec, last_usec, _ = packets[-1]
    with_extra = classic(packets + [(last_sec + 1, last_usec, extra_udp_frame())], LINKTYPE_ETHERNET)

    return {
        f"{BASE}_nsec.pcap": classic(
            packets, LINKTYPE_ETHERNET, magic=MAGIC_NSEC,
            frac=lambda i, usec: usec * 1000 + (i * 137) % 1000),
        f"{BASE}_be.pcap": classic(packets, LINKTYPE_ETHERNET, endian=">"),
        f"{BASE}_two_if.pcapng": bytes(two_if),
        f"{BASE}_be_binary_tsresol.pcapng": bytes(be_binary),
        f"{BASE}_sll.pcap": classic(
            [(s, u, sll(f, vlan_tag=i % 2 == 1)) for i, (s, u, f) in enumerate(packets)],
            LINKTYPE_LINUX_SLL),
        f"{BASE}_vlan.pcap": classic([(s, u, vlan(f)) for s, u, f in packets], LINKTYPE_ETHERNET),
        # Cut inside the extra record's frame bytes.
        f"{BASE}_truncated.pcap": with_extra[:-20],
    }


def edge_case_fixtures(packets):
    """Adversarial files for differential runs against a libpcap build."""
    eth = LINKTYPE_ETHERNET
    files = {}

    # Snapshot length shorter than the stored frames: libpcap cuts them.
    files["snaplen_shorter_than_caplen.pcap"] = classic(packets, eth, snaplen=54)

    # A corrupt capture length in the middle of the file.
    good = classic(packets, eth)
    record = bytearray(classic(packets[:1], eth)[24:])
    struct.pack_into("<I", record, 8, 0x00100000)
    # Insert it on a record boundary halfway, so complete records surround it.
    pos, cut = 24, len(good) // 2
    while True:
        caplen = struct.unpack_from("<I", good, pos + 8)[0]
        if pos + 16 + caplen > cut:
            break
        pos += 16 + caplen
    files["corrupt_caplen_mid_file.pcap"] = good[:pos] + bytes(record) + good[pos:]

    # Big-endian pcapng with if_tsoffset, binary if_tsresol, and an SPB.
    offset_seconds = 1_000_000
    ng = bytearray(ng_shb(">"))
    ng += ng_idb(eth, tsresol=0x80 | 20, tsoffset=offset_seconds, endian=">")
    for sec, usec, frame in packets:
        ng += ng_epb(0, to_units(sec, usec, 1 << 20, offset_seconds), frame, ">")
    ng += ng_block(3, struct.pack(">I", len(packets[0][2])) + packets[0][2], ">")
    files["pcapng_be_binary_tsresol_tsoffset_spb.pcapng"] = bytes(ng)

    # Two sections; the second restarts interface numbering.
    two_sections = bytearray()
    half = len(packets) // 2
    for chunk, resol in ((packets[:half], 3), (packets[half:], 9)):
        two_sections += ng_shb() + ng_idb(eth, tsresol=resol)
        for sec, usec, frame in chunk:
            two_sections += ng_epb(0, to_units(sec, usec, 10**resol), frame)
    files["pcapng_two_sections.pcapng"] = bytes(two_sections)

    # pcapng cut inside the last block.
    files["pcapng_truncated.pcapng"] = committed_fixtures(packets)[f"{BASE}_two_if.pcapng"][:-10]

    # Header only, and no capture header at all.
    files["header_only.pcap"] = classic([], eth)
    files["not_a_capture.pcap"] = b"this is not a capture file\n" * 4
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--edge-cases", type=Path, metavar="DIR",
                        help="also write uncommitted differential-test files to DIR")
    args = parser.parse_args()

    linktype, packets = read_classic(DATA_DIR / f"{BASE}.pcap")
    assert linktype == LINKTYPE_ETHERNET
    for name, data in committed_fixtures(packets).items():
        (DATA_DIR / name).write_bytes(data)
        print(f"wrote {DATA_DIR / name} ({len(data)} bytes)")
    if args.edge_cases:
        args.edge_cases.mkdir(parents=True, exist_ok=True)
        for name, data in edge_case_fixtures(packets).items():
            (args.edge_cases / name).write_bytes(data)
            print(f"wrote {args.edge_cases / name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
