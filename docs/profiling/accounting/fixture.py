"""Send numbered UDP_SEGMENT datagrams and census routed Ethernet frames on sink0."""

import argparse
import hashlib
import json
import socket
import struct
import time

SEGMENTS = 16
PAYLOAD = 512
FAMILIES = ((4, socket.AF_INET, "198.18.9.2", "198.18.10.2"),
            (6, socket.AF_INET6, "fd09:1::2", "fd09:2::2"))
MACS = bytes.fromhex("020000000002020000000001")


def payload(family, number):
    return struct.pack("!4sII", b"RF09", family, number).ljust(PAYLOAD, b"\x00")


def send(groups, rate, offset, background):
    streams = []
    digest = hashlib.sha256()
    for family, af, source, dest in FAMILIES:
        sock = socket.socket(af, socket.SOCK_DGRAM)
        sock.bind((source, 30000))
        sock.connect((dest, 31000))
        streams.append((sock, [b"".join(payload(family, (offset + g) * SEGMENTS + j)
                                        for j in range(SEGMENTS)) for g in range(groups)]))
    noise = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    noise.bind(("send0", 0))
    noise_frame = MACS + bytes.fromhex("88b5") + bytes(46)
    # Hash outside the timed window in transmission order.
    for group in range(groups):
        for _, bodies in streams:
            digest.update(bodies[group])
    if background:
        unrelated = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        unrelated.bind((FAMILIES[0][2], 30001))
    start = time.monotonic()
    for group in range(groups):
        if rate:
            delay = start + group * SEGMENTS * 2 / rate - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        for sock, bodies in streams:
            sent = sock.sendmsg([bodies[group]], [(17, 103, struct.pack("=H", PAYLOAD))])
            if sent != SEGMENTS * PAYLOAD:
                raise RuntimeError(f"short UDP send {sent}")
        if group % 64 == 0:
            noise.send(noise_frame)
            if background:
                unrelated.sendto(b"other UDP flow", (FAMILIES[0][3], 31001))
    return dict(start=start, seconds=time.monotonic() - start, packets_per_family=groups * SEGMENTS,
                other_frames=(groups + 63) // 64, other_udp=(groups + 63) // 64 if background else 0,
                payload_sha256=digest.hexdigest())


def receive(groups):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.bind(("sink0", 0))
    sock.settimeout(10)  # Includes sender setup for the stopped-reader control.
    seen = {4: set(), 6: set()}
    sizes = {4: 0, 6: 0}
    print("ready", flush=True)
    while True:
        try:
            frame = sock.recv(65535)
        except TimeoutError:
            break
        if not seen[4] and not seen[6]:
            sock.settimeout(2)
        typ = int.from_bytes(frame[12:14], "big")
        if typ not in (0x0800, 0x86dd):
            continue
        family, udp = (4, 34) if typ == 0x0800 else (6, 54)
        if frame[udp:udp+4] != struct.pack("!HH", 30000, 31000):
            continue
        ip_length = int.from_bytes(frame[16:18] if family == 4 else frame[18:20], "big")
        if family == 6:
            ip_length += 40
        expected_ip = (20 if family == 4 else 40) + 8 + PAYLOAD
        if (len(frame) != 14 + expected_ip or ip_length != expected_ip
                or int.from_bytes(frame[udp+4:udp+6], "big") != 8 + PAYLOAD):
            raise ValueError("reference leg did not deliver an individual Ethernet/UDP frame")
        body = frame[udp + 8:]
        magic, version, seq = struct.unpack_from("!4sII", body)
        if (magic != b"RF09" or version != family or seq >= groups * SEGMENTS
                or seq in seen[family] or body != payload(family, seq)):
            raise ValueError(f"invalid reference frame {family=} {seq=} {len(body)=}")
        seen[family].add(seq)
        sizes[family] += len(frame)
    packets, drops = struct.unpack("=II", sock.getsockopt(263, 6, 8))
    return dict(frames={k: len(v) for k, v in seen.items()}, bytes=sizes,
                socket_packets=packets, socket_drops=drops)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("send", "receive"))
    parser.add_argument("groups", type=int)
    parser.add_argument("--rate", type=int, default=32000)
    parser.add_argument("--offset", type=int, default=0, help="first group number in this send")
    parser.add_argument("--background", action="store_true", help="also send unrelated IPv4 UDP")
    args = parser.parse_args()
    if args.groups < 1 or args.rate < 0 or args.offset < 0:
        parser.error("expected positive groups and nonnegative rate and offset")
    result = send(args.groups, args.rate, args.offset, args.background) if args.mode == "send" else receive(args.groups)
    print(json.dumps(result))
