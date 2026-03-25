# Engineering Notes

This file keeps short-lived design choices and execution notes that would make
`AGENTS.md` too long.

## 2026-03-25

- Use branch `codex/ingestion-semantics-foundation` for the AGENTS-driven
  improvement track instead of landing exploratory changes directly on `main`.
- Prefer performance-aware correctness for ingestion work so foundational
  metadata changes do not need to be redone later.
- Realtime packet events now carry kernel monotonic timestamps and aligned
  packet/header/payload length semantics. Stabilize and measure before adding
  more event fields.
- Timing and IAT features now preserve sub-millisecond precision internally.
- Retransmission work should stay bounded: fix non-TCP false positives, move
  beyond exact duplicate sequence numbers, and leave richer TCP quality signals
  such as duplicate ACKs and handshake analysis for later checklist items.
- Retransmission stats now stay TCP-only and count overlap in TCP sequence
  space, including SYN and FIN sequence-number use, instead of only exact
  duplicate sequence numbers.
- Active/idle tracking now compares thresholds in microseconds before converting
  to exported millisecond values, and subflow counting now represents actual
  subflows instead of only counting gap boundaries after the first packet.
- ICMP stats now keep the original first seen type and code, but also track
  echo request and reply counts plus error and destination-unreachable counts
  across ICMPv4 and ICMPv6 traffic.
