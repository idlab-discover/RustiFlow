# Handoff: adversarial synthetic-event tests (2026-10-20)

Status: findings and reproducers only; production behavior is unchanged. The
baseline test is active. Eight reproducers are ignored with finding-specific
reasons until fixes or semantic decisions are made. The performance probe is
manually run because its timing threshold is machine-dependent.

Production line numbers refer to `main` at `cf3e500`; test line numbers refer
to the original investigation before ignore attributes were added.

## Where the work is

- Test file:
  `rustiflow/src/tests/flows/realtime_adversarial_test.rs`, registered in
  `rustiflow/src/tests/flows/mod.rs`.
- Run with: `cargo test -p rustiflow realtime_adversarial -- --test-threads=1`
- Run all reproducers explicitly with:
  `cargo test -p rustiflow realtime_adversarial -- --include-ignored --test-threads=1`
- Original investigation result: 1 passed (baseline), 8 failed. IPv4 and IPv6 fail
  identically. Each test loops over `FAMILIES` (line 33) and stops at the
  first failing family. To see IPv6 on its own, temporarily set `FAMILIES` to
  `[Family::Ipv6]`.

### How the harness works

- `decode()` builds an `EbpfEventIpv4`/`EbpfEventIpv6` the way the eBPF
  programs do: addresses in wire order, everything else in host order. It then
  decodes the event with `PacketFeatures::from_ebpf_event_ipv4/6`, the same
  decoder the ring drain tasks use.
- `run()` (line 166) feeds the decoded packets to one
  `FlowTable<RustiFlow>`, in an explicit arrival order. That order models what
  a shard sees after events from different rings have been interleaved. It
  then calls `export_all_flows` at the latest timestamp and collects every
  exported flow.
- `clean_connection(client_isn, server_isn)` is a 9-segment TCP connection:
  SYN, SYN-ACK, ACK, request (100 B), response (200 B), then the close
  FIN|ACK, ACK, FIN|ACK, ACK, at t = 0..800 µs. The client sends 5 of the
  segments.
- `FlowSummary` is the whole value each test compares: source ip/port, packet
  count, forward packet count, duration, handshake flag, expire cause and
  close style.
- It does not go through `SourceBatcher`/`spawn_shard_workers`. It tests the
  flow-layer semantics under orderings that the pipeline can produce. It does
  not show the pipeline producing them.

## Root cause shared by findings 1–4

Live capture loads separate ingress and egress eBPF programs, and each has its
own 8 rings: `rustiflow/src/realtime.rs:396-402`. The eBPF queue hash
(`ebpf-ipv4/src/main.rs:137-151`, `ebpf-ipv6/src/main.rs:199-213`) is
canonical, so both directions of a biflow pick the same queue *index*. But
they land in different rings: `egress-ipv4-k` and `ingress-ipv4-k`. Each ring
is drained by its own task and dispatcher, so the two directions of one
connection reach the shard through independent queues. Their relative order
is not guaranteed. Under backlog it can be off by a lot.

The replay benchmark does not model this. `rustiflow/src/realtime/replay.rs:195`
says "All events of a flow go to the same source", and lines 258/270 route by
`flow % source_count`. So `replay_bench_test.rs` cannot catch any of this.

## Findings

### 1. SYN-ACK processed before SYN flips flow direction

- Test: `syn_ack_drained_before_syn_keeps_client_as_forward` (line 233). It
  swaps the first two segments, which are 100 µs apart.
- Observed: source = server:443, fwd_packets 4 instead of 5, duration 700
  instead of 800, `handshake_completed = false`.
- Cause: `rustiflow/src/flow_table.rs:131` fixes `forward_orientation` from
  whichever packet creates the flow. `BasicFlow::observe_tcp_handshake`
  (`rustiflow/src/flows/basic_flow.rs:92`) only accepts a forward SYN followed
  by a backward SYN-ACK. Every directional feature (fwd/bwd stats, IAT,
  windows) is mirrored for such flows.
- Fix ideas: if a flow's first packet is a SYN-ACK (SYN+ACK set) and the
  matching SYN arrives later, swap orientation once while the flow is young.
  Alternatively, give the source batcher a small reorder window keyed by
  timestamp. Decide whether the fix belongs in `FlowTable` (orientation) or in
  `BasicFlow` (handshake). AGENTS.md says `BasicFlow` owns lifecycle.

### 2. One direction lagging ≥1 s splits the flow

- Test: `one_direction_lagging_by_seconds_stays_one_flow` (line 279).
  Arrivals: client at t=0, client at t=2 s, then the server reply stamped
  t=0.5 s.
- Observed: two flows. The first is the client, 2 packets, exported as
  `IdleTimeout`. The second is a 1-packet flow sourced from the server.
- Cause: `rustiflow/src/flows/basic_flow.rs:361` and `:365` compute
  `((timestamp_us - first/last) / 1_000_000) as u64`. A negative difference of
  at least 1 s casts to roughly 1.8e19, which is greater than any timeout. The
  check comes from `rustiflow/src/flow_table.rs:79` (on every packet of an
  existing flow) and `:238` (periodic sweep). Integer division truncates
  toward zero, so lags under 1 s slip through (see 3).
- Fix: treat negative differences as 0, for example with
  `timestamp_us.saturating_sub(..).max(0)` before dividing. This is
  small and clear-cut. Add a direct `BasicFlow::is_expired` unit test as well.

### 3. Sub-second lag gives wrong duration and negative IAT

- Test: `sub_second_lag_never_yields_negative_duration_or_iat` (line 308).
  Arrivals: t=0, t=0.9 s (client), then t=0.4 s (server).
- Observed: duration 400 000 µs instead of 900 000, and `iat.get_min() < 0`.
- Cause: `rustiflow/src/flows/basic_flow.rs:288` overwrites
  `last_timestamp_us` with the older timestamp. Separately, `first_timestamp_us`
  is whichever packet arrived first, not the earliest. The features use raw
  differences:
  - `rustiflow/src/flows/features/iat_stats.rs:33` (negative IAT)
  - `rustiflow/src/flows/features/active_idle_stats.rs:29` (negative idle gap,
    which is harmless there because it is only used when > 5 s)
- Fix ideas: `last_timestamp_us = max(last, ts)`, and possibly
  `first_timestamp_us = min(first, ts)`. Decide whether IAT should clamp to 0
  or stay "arrival order" based. This is timing-sensitive: AGENTS.md asks for
  deliberate validation of offline/realtime alignment. Offline pcap order is
  monotonic, so a clamp should not change offline output. Verify that with the
  pcap fixture tests.

### 4. Peer ACK/FIN processed before own FIN: TCP close never detected

- Test: `peer_fin_drained_before_own_fin_still_terminates` (line 249). It
  rotates segments 5..8 so that the server's ACK and FIN arrive before the
  client FIN.
- Observed: expire cause `ExporterShutdown` instead of `TcpTermination`, and
  close style `BidirectionalFin`. The flow would sit until the idle timeout in
  real use.
- Cause: in `BasicFlow::is_tcp_finished`
  (`rustiflow/src/flows/basic_flow.rs:155-185`), an ACK only counts if it
  arrives after the FIN that sets the expected ACK (`expected_ack_seq_*` at
  :165/:173). The server's ACK of the client FIN was already processed and is
  never re-evaluated.
- Fix idea: track the highest ACK seen per direction, and when a FIN arrives,
  check it against that immediately. Use wrap-aware comparison (see 5).

### 5. Sequence-number overflow panics in debug builds

- Test: `sequence_numbers_crossing_the_wrap_close_cleanly` (line 265), with
  server ISN `u32::MAX` and client ISN `u32::MAX - 100`.
- Observed: panic "attempt to add with overflow" at
  `rustiflow/src/flows/basic_flow.rs:106` (`packet.sequence_number + 1`).
  The same pattern is at :165 and :173
  (`sequence_number + data_length as u32 + 1`).
- Impact: the default profile has overflow checks on, and `cargo xtask run`
  builds debug unless `--release` is given (`xtask/src/run.rs:27`). In that
  setup a shard task panics on any ISN near the wrap. That is reachable by
  random ISNs (about 1 in 2^32 per handshake, more for FINs after large
  transfers) and trivially by crafted packets. The shard's receiver then
  drops, and its flows are lost. Release builds wrap, which is already the
  correct TCP arithmetic.
- Fix: `wrapping_add` at all three sites. Also check
  `rustiflow/src/flows/features/retransmission_stats.rs:122`, which uses
  `saturating_add`. A segment ending at the wrap gets a truncated or empty
  range there, so retransmissions across the wrap are missed. The doc comment
  above that code already admits wraparound is unmodelled.

### 6. Straggler after teardown opens a ghost flow

- Test: `straggler_ack_after_teardown_does_not_open_a_new_flow` (line 330).
  After a clean close, the server retransmits its FIN|ACK (as it would if it
  missed the final ACK).
- Observed: a second, 1-packet flow sourced from the server, `HalfClose`,
  exported at shutdown.
- Cause: on termination, `rustiflow/src/flow_table.rs` removes the entry
  (the `FlowUpdate::Terminated` arm), so any later packet with the same key
  creates a fresh flow (`:107`).
- This is a semantics decision, not necessarily a bug. CICFlowMeter-style
  tools also produce these. Options:
  - a short TIME_WAIT-like tombstone per key that absorbs FIN/ACK/RST
    stragglers for N seconds;
  - or keep the current behaviour and document it.
- Interacts with 4: reordered teardown also produces stragglers.

### 7. FIN → FIN|ACK → ACK is labelled `SimultaneousFin`

- Test: `fin_ack_answer_to_a_fin_is_not_a_simultaneous_close` (line 353).
  This is the common three-segment close: the server's FIN carries the ACK of
  the client's FIN. It happens in order, with no reordering involved.
- Observed: `SimultaneousFin`.
- Cause: `rustiflow/src/flows/basic_flow.rs:158-169` sets
  `tcp_simultaneous_close` when a FIN arrives while the other side is still
  `FinSent`. The ACK carried in the same FIN|ACK is processed only after that
  check (:177-185).
- **Needs a decision**: the existing test
  `simultaneous_tcp_close_terminates_after_final_ack`
  (`rustiflow/src/tests/flows/basic_flow_test.rs:311`, assertion at :359)
  encodes this exact sequence as `SimultaneousFin`. In RFC 793 terms a FIN
  that acknowledges the peer's FIN is not simultaneous. The fix is to process
  the ACK part before the FIN part, or to require that the second FIN does
  *not* ack the first. Either way that existing test changes, and so does the
  `tcp_close_style` distribution in exported datasets. Document it in
  README/engineering notes if changed.

### 8. Retransmission range tracking is quadratic in gaps

- Test: `sparse_sequence_numbers_keep_per_packet_cost_flat` (line 372). It
  sends a single flow of 100-byte segments at stride 200, so every segment
  leaves a gap, and asserts the per-packet cost grows by less than 4x.
- Observed (debug build): 24 µs/pkt at 2k packets vs 184 µs/pkt at 40k
  packets (7.6x; 15.7x on another run).
- Cause: `rustiflow/src/flows/features/retransmission_stats.rs`. Every packet
  does a linear `any(..)` over all ranges (:57), then a linear scan plus
  `Vec::remove`/`insert` in `insert_sequence_range` (:126-145). Ranges are
  never pruned or capped, so memory per flow is unbounded too.
- Realistic triggers: realtime ring drops (`DROPPED_PACKETS`) punch holes in
  otherwise in-order streams. Crafted traffic can do it directly. One long
  flow can stall its shard.
- Fix ideas: binary search (ranges are kept sorted), plus a cap on tracked
  ranges or pruning of ranges far below the highest ACKed sequence. The timing
  assertion is machine-dependent. Before committing, prefer a deterministic
  assertion (for example on a tracked-range count, behind a test accessor)
  over wall-clock.

## eBPF parser gaps found by reading (not reachable via synthetic events)

These are offline/realtime divergences in the kernel side. Synthetic events
start *after* parsing, so they need pcap/veth validation instead.

- **IPv4 non-first fragments are not dropped.** `ebpf-ipv4/src/main.rs:77-89`
  never checks the fragment offset, so payload bytes of later fragments are
  parsed as TCP/UDP headers and create bogus flows. Offline drops them:
  `rustiflow/src/packet_features.rs:165`.
- **IPv6 non-first fragments are not dropped.** `ebpf-ipv6/src/main.rs:97-122`
  skips the Fragment header (8 bytes, which happens to be correct) but never
  reads its offset. Offline rejects them: `rustiflow/src/packet_features.rs:248`.
- **IPv6 AH length is wrong.** `ebpf-ipv6/src/main.rs:115` uses
  `(hdr_ext_len + 1) * 8` for every extension header. For AH (51) it should be
  `(payload_len + 2) * 4`, as offline does at
  `rustiflow/src/packet_features.rs:254`. Packets behind AH are parsed at the
  wrong offset.
- **IPv6 ESP is skipped instead of rejected.** `ebpf-ipv6/src/main.rs:87`
  lists ESP as an extension header, so the encrypted payload is read as a
  next-header and length. Offline returns `None`:
  `rustiflow/src/packet_features.rs:260`.

## Suggested order

1. Findings 5 and 2: `wrapping_add`, and non-negative time differences in
   `is_expired`. Small, local, clear-cut; one commit each.
2. Finding 3: monotonic `last_timestamp_us` (and decide on `first`/IAT). Run
   the pcap fixture and parity tests to confirm offline output is unchanged.
3. Findings 1 and 4: reorder tolerance for handshake orientation and FIN/ACK
   matching in `BasicFlow`.
4. Make the replay route ingress and egress of a flow through different
   sources (`rustiflow/src/realtime/replay.rs:250-275`), so that
   `replay_bench_test.rs` exercises cross-ring interleaving end to end.
5. Finding 7: decide on the close-style semantics, then update
   `basic_flow_test.rs:311` and the docs.
6. Finding 8: bounded and logarithmic range tracking.
7. Finding 6: decide on tombstones vs documenting.
8. The eBPF parser gaps, validated on the `rustiflow-t0` veth harness with
   fragmented, AH and ESP traffic.

Remove each finding-specific ignore attribute when its fix or agreed behavior
is covered. Replace the manual performance probe with deterministic coverage
before making it part of the default test suite.
