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
- TCP lifecycle export now distinguishes observed handshake completion from
  resets seen before or after that observed handshake, so richer flow schemas
  do not have to infer lifecycle quality from flag totals alone.
- RustiFlow export now includes duplicate ACK counts, zero-window
  observations, and `tcp_close_style`. Duplicate ACKs currently mean repeated
  pure ACKs with the same ACK number and advertised window; zero-window events
  count TCP packets advertising a zero receive window; close style stays rooted
  in `BasicFlow` lifecycle state so timeout/reset/FIN semantics are not
  reimplemented in exporter code.
- Current test-hardening focus is to add adversarial deterministic cases before
  more feature work: false handshake completion, teardown edge cases, parser
  rejection behavior, and tiny fixture assertions that prove exported
  lifecycle semantics.
- Test hardening already exposed two parser quirks worth locking down: short
  unsupported offline frames must not panic the reader, and non-first IPv6
  fragments should be dropped instead of being treated like fresh transport
  headers.
- Test hardening also exposed a real `FlowTable` lifecycle bug: packet-driven
  termination export could overwrite `TcpReset` with `TcpTermination`, and a
  first-packet-terminated flow could be left behind for duplicate export.
- The next adversarial test layer should prefer integrated semantics over raw
  test count: simultaneous close teardown, contiguous-versus-overlapping TCP
  segments, and wrapper-level feature coordination in `RustiFlow`.
- That test layer exposed another real parser bug: offline IPv4 parsing was
  treating non-first IPv4 fragments as if they started with a fresh transport
  header. Non-first IPv4 fragments should now be dropped while first fragments
  still parse their transport header normally.
