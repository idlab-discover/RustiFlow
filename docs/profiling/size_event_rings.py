#!/usr/bin/env python3
"""Calculate a RustiFlow ring byte override from a bounded reader stall."""

import argparse
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stall-ms", type=int, required=True)
    parser.add_argument(
        "--ipv4-hot-pps", type=int, required=True, help="peak pps in one IPv4 software ring"
    )
    parser.add_argument(
        "--ipv6-hot-pps", type=int, required=True, help="peak pps in one IPv6 software ring"
    )
    parser.add_argument("--cap-mib", type=int, required=True, help="total event-ring data budget")
    parser.add_argument("--ingress-only", action="store_true", help="budget one hook instead of two")
    args = parser.parse_args()
    if min(args.stall_ms, args.cap_mib) <= 0 or min(args.ipv4_hot_pps, args.ipv6_hot_pps) < 0:
        parser.error("stall and cap must be positive and rates must be nonnegative")
    cap = args.cap_mib * 2**20
    if cap >= 2**64:
        parser.error("total ring data cap exceeds u64")
    page = os.sysconf("SC_PAGE_SIZE")

    def ring_bytes(pps, record_bytes):
        records = (pps * args.stall_ms + 999) // 1000
        # The producer-consumer distance must be strictly below the data size.
        return max(page, 1 << (records * record_bytes).bit_length())

    v4 = ring_bytes(args.ipv4_hot_pps, 48)
    v6 = ring_bytes(args.ipv6_hot_pps, 80)
    total = (v4 + v6) * 8 * (1 if args.ingress_only else 2)
    if max(v4, v6) >= 2**32:
        parser.error("required ring exceeds the u32 map size")
    if total > cap:
        parser.error(f"requested stall needs {total} data bytes across the event maps")
    print(f"{v4},{v6},{cap}")


if __name__ == "__main__":
    main()
