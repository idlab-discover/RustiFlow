#!/usr/bin/env python3
"""Generate a live TC fixture and check its raw IPv4/IPv6 ring records."""

import argparse
import ctypes as c
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess

from generate_pcap import checksum, packet


PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def fixture():
    macs = bytes.fromhex("020000000002020000000001")
    for packet_index in range(11):
        for family in (4, 6):
            source, destination = map(ipaddress.ip_address, (
                ("198.18.241.9", "198.18.241.10") if family == 4
                else ("fd42:641::9", "fd42:641::a")
            ))
            source_port, dest_port = 50000, 443
            if packet_index in (1, 5, 7):
                source, destination = destination, source
                source_port, dest_port = dest_port, source_port
            window = flags = seq = ack = icmp_type = icmp_code = 0
            if packet_index < 6:
                proto = 6
                flags = (2, 18, 16, 24, 24, 24)[packet_index]
                seq = (0x01020304, 0x0A0B0C0D, 0x01020305,
                       0x01020305, 0x01020305, 0x0A0B0C0E)[packet_index]
                ack = (0, 0x01020305, 0x0A0B0C0E,
                       0x0A0B0C0E, 0x0A0B0C0E, 0x01020316)[packet_index]
                window = 29200
                length = 24 if flags & 2 else 20
                body = bytes(17 if packet_index in (3, 4) else 11 if packet_index == 5 else 0)
                header = struct.pack("!HHIIBBHHH", source_port, dest_port, seq,
                                     ack, length // 4 << 4, flags, window, 0, 0)
                if length == 24:
                    header += bytes.fromhex("020405b4")
                sum_offset = 16
            elif packet_index < 9:
                proto, length, sum_offset = 17, 8, 6
                body = bytes((24, 448, 8)[packet_index - 6])
                header = struct.pack("!HHHH", source_port, dest_port, length + len(body), 0)
            else:
                proto, length, sum_offset = (1 if family == 4 else 58), 8, 2
                icmp_type, icmp_code = (3, 4) if family == 4 else (2, 0)
                source_port = dest_port = 0
                body = bytes(48)
                header = struct.pack("!BBHI", icmp_type, icmp_code, 0, 1280)

            src, dst = source.packed, destination.packed
            transport_len = length + len(body)
            pseudo = b""
            if family == 6:
                pseudo = src + dst + struct.pack("!I3xB", transport_len, proto)
            elif proto != 1:
                pseudo = src + dst + struct.pack("!BBH", 0, proto, transport_len)

            transport_sum = checksum(pseudo + header + body)
            header = header[:sum_offset] + struct.pack("!H", transport_sum) + header[sum_offset + 2:]
            skip = packet_index == 10
            ttl = 64
            if family == 4:
                ethertype = 0x0800
                options = bytes.fromhex("01010000") if packet_index == 0 else b""
                total_len = 20 + len(options) + transport_len
                ip_header = struct.pack("!BBHHHBBH", 0x45 + len(options) // 4, 0,
                                        total_len, 1, int(skip), ttl, proto, 0)
                ip_header += src + dst + options
                ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
            else:
                ethertype = 0x86DD
                next_header, extension = proto, b""
                if packet_index in (0, 6):
                    next_header, extension = 60, bytes([proto]) + bytes(7)
                if skip:
                    next_header, extension = 44, struct.pack("!BBHI", proto, 0, 8, 1)
                payload_len = len(extension) + transport_len
                total_len = 40 + payload_len
                ip_header = struct.pack("!IHBB", 6 << 28, payload_len, next_header, ttl)
                ip_header += src + dst + extension

            wire = macs + struct.pack("!H", ethertype) + ip_header + header + body
            record = dst + src + struct.pack(
                "<5H3B2I3B", dest_port, source_port, len(body), total_len, window,
                flags, proto, length, seq, ack, icmp_type, icmp_code, ttl,
            )
            if family == 6:
                record += bytes(8)
            yield wire, None if skip else record
    yield macs + bytes.fromhex("88b5") + bytes(46), None


def write_pcap(path):
    with path.open("wb") as out:
        out.write(PCAP_HEADER)
        for index, (frame, _) in enumerate(fixture()):
            out.write(struct.pack("<4I", 1_700_000_000, index * 1000, len(frame), len(frame)))
            out.write(frame)


def write_pressure_pcap(path):
    with path.open("wb") as out:
        out.write(PCAP_HEADER)
        for flow, count in ((0, 1_405_000), (1, 850_000)):
            frame = packet(flow, False)
            record = struct.pack("<4I", 1_700_000_000, 0, len(frame), len(frame)) + frame
            chunks, remainder = divmod(count, 10_000)
            for _ in range(chunks):
                out.write(record * 10_000)
            out.write(record * remainder)


def event_maps(program_path):
    def query(*args):
        return json.loads(subprocess.check_output(["bpftool", "-j", *args]))

    for program_id in map(int, program_path.read_text().split()):
        program = query("prog", "show", "id", str(program_id))
        for map_id in program["map_ids"]:
            info = query("map", "show", "id", str(map_id))
            if info["name"].startswith("EVENTS_IPV"):
                yield info["name"], map_id


def check_rings(program_path, start, end):
    lib = c.CDLL("libbpf.so.1", use_errno=True)
    callback_type = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_size_t)
    lib.bpf_map_get_fd_by_id.argtypes = [c.c_uint]
    lib.bpf_map_get_fd_by_id.restype = c.c_int
    lib.ring_buffer__new.argtypes = [c.c_int, callback_type, c.c_void_p, c.c_void_p]
    lib.ring_buffer__new.restype = c.c_void_p
    lib.ring_buffer__consume.argtypes = [c.c_void_p]
    lib.ring_buffer__consume.restype = c.c_int
    lib.ring_buffer__free.argtypes = [c.c_void_p]
    all_records = []
    queues = {}
    names = set()
    for name, map_id in event_maps(program_path):
        assert name not in names, name
        names.add(name)
        events = []

        @callback_type
        def receive(_context, address, size):
            events.append(c.string_at(address, size))
            return 0

        fd = lib.bpf_map_get_fd_by_id(map_id)
        if fd < 0:
            raise OSError(c.get_errno(), f"opening eBPF map {map_id}")
        try:
            ring = lib.ring_buffer__new(fd, receive, None, None)
            if not ring:
                raise OSError(c.get_errno(), f"opening ring {name}")
            try:
                assert lib.ring_buffer__consume(ring) == len(events), name
            finally:
                lib.ring_buffer__free(ring)
        finally:
            os.close(fd)

        timestamps = []
        for event in events:
            assert len(event) == (40 if "IPV4" in name else 72), (name, len(event))
            timestamp, = struct.unpack_from("<Q", event)
            assert start <= timestamp <= end, (name, timestamp, start, end)
            timestamps.append(timestamp)
            record = event[8:]
            all_records.append((timestamp, record))
            queues.setdefault(record, set()).add(name)
        assert timestamps == sorted(timestamps), name
    assert len(names) == 16, names
    expected = [record for _, record in fixture() if record is not None]
    actual = [record for _, record in sorted(all_records)]
    assert len(actual) == len(expected), (len(actual), len(expected))
    assert actual == expected, [(a.hex(), b.hex()) for a, b in zip(actual, expected, strict=True)]
    for tcp_records in (expected[0:12:2], expected[1:12:2]):
        assert len(set.union(*(queues[record] for record in tcp_records))) == 1
    print(json.dumps([sorted(queues[record]) for record in actual]))


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("pcap").add_argument("path", type=Path)
    commands.add_parser("pressure").add_argument("path", type=Path)
    rings = commands.add_parser("rings")
    rings.add_argument("program_ids", type=Path)
    rings.add_argument("start", type=int)
    rings.add_argument("end", type=int)
    args = cli.parse_args()
    if args.command == "pcap":
        write_pcap(args.path)
    elif args.command == "pressure":
        write_pressure_pcap(args.path)
    else:
        check_rings(args.program_ids, args.start, args.end)


if __name__ == "__main__":
    main()
