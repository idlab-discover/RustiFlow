"""Print the per-direction offer sheet; measured columns are filled on the lab DUT."""
import csv
import sys

# Profile length is destination MAC through FCS, in bytes. Minimum IPv6 UDP
# requires 66 B; the minimum-size dual-family UDP cell alternates 64 and 66 B.
profiles = [
    ("min-ipv4", "IPv4 UDP", 64),
    ("min-ipv6", "IPv6 UDP", 66),
    ("min-mixed", "50:50 UDP", 65),
    ("min-tcp6", "IPv6 TCP", 78),
    *[(f"fixed-{size}", family, size) for size in (128, 512, 1518, 9018)
      for family in ("IPv4 UDP", "IPv6 UDP", "50:50 UDP")],
    ("trace", "native", 1884490735 / 2000000 + 4),
]
identity = ["profile", "family", "frame_bytes_with_fcs_mean", "mode", "direction",
            "configured_wire_gbps", "configured_mpps", "rep", "arm"]
measured = ["seconds", "tx_frames", "tx_bytes_incl_fcs", "actual_tx_mpps", "actual_tx_wire_gbps",
            "rx_frames", "rx_bytes_incl_fcs", "delivered_mpps", "delivered_wire_gbps",
            "sequence_missing", "duplicate", "corrupt", "rx_discard", "queue_drop",
            "submitted4", "dropped4", "submitted6", "dropped6", "decoded4", "decoded6",
            "closed_file_packets4", "closed_file_packets6", "close_ms", "status"]
writer = csv.writer(sys.stdout, lineterminator="\n")
writer.writerow(identity + measured)
for name, family, size in profiles:
    for mode, directions in [("A-to-B", ["A-to-B"]), ("B-to-A", ["B-to-A"]),
                             ("full-duplex", ["A-to-B", "B-to-A"])]:
        for gbps in (50, 100, 150, 180, 200):
            mpps = 1000 * gbps / (8 * (size + 20))
            for rep in range(6):  # rep 0 is an excluded warmup
                for arm in (("base", "sized") if rep % 2 else ("sized", "base")):
                    for direction in directions:
                        writer.writerow([name, family, size, mode, direction, gbps,
                                         f"{mpps:.6f}", rep, arm] + [""] * len(measured))
