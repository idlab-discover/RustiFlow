#!/usr/bin/env python3
"""Generate 1M UDP frames with 90% selecting IPv4 ingress ring 0 on x86-64."""

import argparse
from itertools import islice
import socket
import struct

from generate_pcap import packet


U32_MASK = (1 << 32) - 1
IPV4_ENDPOINTS = tuple(
    int.from_bytes(socket.inet_aton(f"198.18.241.{host}"), "little") for host in (1, 2)
)


def xor_multiply(value, shift, factor):
    return ((value ^ (value >> shift)) * factor) & U32_MASK


def mix_u32(value):
    value = xor_multiply(xor_multiply(value, 16, 0x7FEB352D), 15, 0x846CA68B)
    return value ^ (value >> 16)


def ipv4_queue(flow):
    """Match the canonical endpoints and queue hash in ebpf-ipv4."""
    ports = ((10000 + flow // 2) << 16) | (20000 + flow // 2)
    state = 0x811C9DC5
    for value in (*map(mix_u32, IPV4_ENDPOINTS), ports, 17):
        state ^= (value + 0x9E3779B9 + (state << 6) + (state >> 2)) & U32_MASK
    state = xor_multiply(xor_multiply(state, 16, 0x85EBCA6B), 13, 0xC2B2AE35)
    return (state ^ (state >> 16)) % 8


def hot_flows():
    # Interleave the two UDP payload sizes across 1,000 hot flows.
    groups = [
        islice((flow for flow in range(shape, 90_000, 4) if ipv4_queue(flow) == 0), 500)
        for shape in (0, 2)
    ]
    return [flow for group in zip(*groups, strict=True) for flow in group]


def background_flows():
    # Interleave both families and payload sizes. Skip ring 0 for IPv4.
    groups = [
        islice(
            (flow for flow in range(shape, 90_000, 4) if flow % 2 or ipv4_queue(flow) != 0),
            2_250,
        )
        for shape in range(4)
    ]
    return [flow for group in zip(*groups, strict=True) for flow in group]


def alternating_directions(flows):
    forward, reverse = ([packet(flow, reverse) for flow in flows] for reverse in (False, True))
    while True:
        yield from forward
        yield from reverse


def frames():
    hot = alternating_directions(hot_flows())
    background = alternating_directions(background_flows())
    for _ in range(100_000):
        yield from islice(hot, 9)
        yield next(background)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    with open(args.output, "wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames()):
            seconds, micros = divmod(index, 1_000_000)
            out.write(struct.pack("<4I", 1_700_000_000 + seconds, micros, len(frame), len(frame)))
            out.write(frame)


if __name__ == "__main__":
    main()
