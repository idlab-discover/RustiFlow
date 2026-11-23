#!/usr/bin/env python3
"""Write a deterministic Ethernet pcap containing bidirectional UDP flows."""

import argparse
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def packet(flow, reverse):
    ipv6 = flow % 2
    macs = (bytes.fromhex("020000000001"), bytes.fromhex("020000000002"))
    source_mac, destination_mac = macs[::-1] if reverse else macs
    if ipv6:
        addresses = ("fd42:641::1", "fd42:641::2")
        family, ethertype = socket.AF_INET6, 0x86DD
    else:
        addresses = ("198.18.241.1", "198.18.241.2")
        family, ethertype = socket.AF_INET, 0x0800
    source, destination = (
        socket.inet_pton(family, address)
        for address in (addresses[::-1] if reverse else addresses)
    )
    ports = (10000 + flow // 2, 20000 + flow // 2)
    if reverse:
        ports = ports[::-1]
    payload = bytes(24 if flow % 4 < 2 else 448)
    length = 8 + len(payload)
    udp = struct.pack("!4H", *ports, length, 0)
    if ipv6:
        ip = struct.pack("!IHBB", 6 << 28, length, 17, 64) + source + destination
        pseudo = source + destination + struct.pack("!I3xB", length, 17)
    else:
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + length, 0, 0, 64, 17, 0)
        ip += source + destination
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        pseudo = source + destination + struct.pack("!BBH", 0, 17, length)
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp + payload) or 65535)
    return destination_mac + source_mac + struct.pack("!H", ethertype) + ip + udp + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--packets", type=int, default=2_000_000)
    parser.add_argument("--flows", type=int, default=10_000)
    args = parser.parse_args()
    if args.packets < 1 or not 1 <= args.flows <= 90_000:
        parser.error("requires positive packets and 1 to 90000 flows")
    frames = [[packet(flow, reverse) for flow in range(args.flows)] for reverse in (False, True)]
    with open(args.output, "wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index in range(args.packets):
            round_number, flow = divmod(index, args.flows)
            frame = frames[round_number % 2][flow]
            seconds, micros = divmod(index, 1_000_000)
            out.write(struct.pack("<4I", 1_700_000_000 + seconds, micros, len(frame), len(frame)))
            out.write(frame)


if __name__ == "__main__":
    main()
