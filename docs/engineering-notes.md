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
- `nf_flow` now exports `ip_version` without expanding the eBPF event payload.
  The value is derived from the normalized `IpAddr` already shared by offline
  and realtime ingestion, and fixture-backed tests lock down the IPv4 path
  while direct flow construction locks down the IPv6 path.
- Internal sharding and flow-table lookup now use typed `FlowKey` values
  instead of rebuilding formatted strings on the hot path. String flow ids are
  still created when a new flow is instantiated for export compatibility.
- `FeatureStats` now keeps running variance state (`m2`) and derives standard
  deviation on demand instead of updating `std` itself on every packet.
  Dedicated tests now lock down population-std semantics, order invariance, and
  merged directional variance behavior.
- Realtime packet-graph mode is now explicit and testable. When the graph is
  disabled, RustiFlow no longer constructs the packet-count watch channel or
  mutex-protected counter state, so high-throughput runs skip that observability
  plumbing entirely instead of merely branching around it in the loop body.
- RustiFlow now exports `ip_version`, `source_ip_scope`,
  `destination_ip_scope`, and `path_locality` derived from the normalized
  `IpAddr` endpoints already shared by offline and realtime ingestion. The
  adversarial test matrix covers private/shared/link-local/loopback/multicast
  cases across IPv4 and IPv6 so these coarse path signals do not depend on
  extra kernel event fields.
- `FlowTable` now keeps the ordinary existing-flow update path in place instead
  of removing and reinserting the map entry on every packet. Table-level tests
  now lock down two semantics that matter for that optimization: replacing an
  expired flow with a fresh flow on the same key, and early export that keeps
  the live flow resident for later final export.
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
