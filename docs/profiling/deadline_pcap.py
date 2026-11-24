#!/usr/bin/env python3
"""Generate the expiry experiment's capture-clock workloads."""

import argparse
import struct

from generate_pcap import packet

FLOWS = 65_536
CHURN_COHORT = 4_096
ROUNDS = 64
EPOCH = 1_700_000_000


def fixture(output, mode):
    frames = [
        [packet(flow, reverse) for flow in range(FLOWS)]
        for reverse in (False, True)
    ]
    record = struct.Struct("<4I")
    with open(output, "wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for phase in range(ROUNDS):
            if mode == "mostly-live":
                period_us = 16_000_000
                phase_frames = frames[phase % 2]
            else:
                period_us = 3_000_000
                persistent = FLOWS // 2
                cohorts = (FLOWS - persistent) // CHURN_COHORT
                start = persistent + (phase % cohorts) * CHURN_COHORT
                stop = start + CHURN_COHORT
                phase_frames = (
                    frames[phase % 2][:persistent]
                    + frames[0][start:stop]
                    + frames[1][start:stop]
                )
            for index, frame in enumerate(phase_frames):
                timestamp = phase * period_us + index * period_us // len(phase_frames)
                seconds, micros = divmod(timestamp, 1_000_000)
                capture.write(record.pack(EPOCH + seconds, micros, len(frame), len(frame)))
                capture.write(frame)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("mostly-live", "mixed-churn"))
    parser.add_argument("output")
    args = parser.parse_args()
    fixture(args.output, args.mode)
