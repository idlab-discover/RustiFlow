# Adversarial realtime findings and resolutions

Investigated 2026-10-20; resolved in code on 2026-10-22. The original eight
scenarios now have active deterministic coverage. No adversarial tests remain
ignored. The original investigation is preserved in Git history.

## Resolutions

| Finding | Resolution |
| --- | --- |
| 1. SYN-ACK before SYN reverses the flow | A first SYN-ACK establishes its destination as the forward endpoint. Handshake observations are retained independently of cross-direction arrival order. |
| 2. Older timestamps expire flows | Expiration uses saturating, non-negative elapsed time before conversion to seconds. Existing strict timeout boundaries are preserved. |
| 3. Older timestamps corrupt duration and IAT | Flow and directional timestamps retain their minimum and maximum. IAT uses a nondecreasing reference and inserts zero intervals for late packets. Active/idle state does not move backwards; bulk durations retain the current bulk's timestamp bounds. |
| 4. ACK before FIN prevents termination | Each direction retains its highest observed ACK. Both FINs are checked against retained acknowledgments after every packet, using wrapping serial comparisons. Only packets with ACK set contribute acknowledgments. |
| 5. Sequence arithmetic overflows | SYN/FIN sequence arithmetic wraps explicitly. Retransmission ranges also unwrap sequence numbers across rollover. |
| 6. Late FIN creates another flow | The user chose to preserve late packets as a separate flow. The original suppression expectation was replaced with an assertion covering both exports and every packet. |
| 7. Three-segment close is called simultaneous | A FIN that acknowledges the peer's FIN is a normal close, exported under the existing `four_way_fin` label. `simultaneous_fin` requires both FINs to carry ACKs that do not cover the peer's FIN. The old test now uses valid sequence numbers and expects a normal close. |
| 8. Sparse ranges cause quadratic work and unbounded memory | An ordered map replaces linear range scans and vector shifts. Each direction retains at most 1,024 merged ranges and evicts the lowest sequence ranges first. The wall-clock assertion was replaced with deterministic cap, merge, gap, rollover, and recent-retransmission checks. |

Lifecycle changes remain in `BasicFlow`; `FlowTable` chooses initial orientation.
Reusable timing and retransmission changes remain in `flows/features/`.
CSV column names are unchanged, but corrected values can differ from older exports.

## Agreed semantics and limits

- Preserve observed packets after teardown, even when that produces a small
  additional flow. No tombstones or packet suppression were added.
- Use bounded streaming timing. Late packets do not trigger a reconstruction of
  chronological IATs, completed active/idle periods, or completed bulks. Offline
  and realtime ingestion apply the same policy.
- Bound retransmission history. Retransmissions overlapping only evicted ranges
  can be missed. TCP serial comparisons and sequence unwrapping assume observations
  less than half the 32-bit sequence space apart; very large capture gaps remain
  ambiguous. These features do not implement full TCP reassembly.
- A first SYN-ACK provides initiator evidence. Other first packets retain the
  first-observed-source convention. Arbitrarily reordered midstream capture
  cannot always identify the original initiator.
- Expired or exported flows are not reopened. These fixes do not recover packets
  lost by capture or reconstruct connections after delays exceeding expiration.

The normal/simultaneous close distinction and wrapping arithmetic follow
[RFC 9293, sections 3.4 and 3.6](https://www.rfc-editor.org/rfc/rfc9293.html).

## Parser findings

The additional parser discrepancies identified by source inspection were also
fixed:

- IPv4 eBPF skips non-initial fragments.
- IPv6 eBPF skips non-initial fragments, uses the fixed eight-byte Fragment
  header size, computes AH length as `(payload_len + 2) * 4`, and rejects ESP.
- Offline and eBPF parsing share `common::ipv6_extensions::Ipv6Extension`, so
  header classification, fragment offsets, and length units have one definition.
- eBPF checks availability of the full extension before advancing to the next
  header. Existing offline tests cover AH, fragments, ESP, and truncation.

Initial fragments remain eligible for extraction. Neither path reassembles
fragmented packets.

## Verification

The original ignored suite reproduced all eight findings before fixes. Additional
focused tests reproduced expiration subtraction overflow, incorrect directional
timestamp bounds, missed retransmissions across rollover, and unbounded retained
history before their fixes. The shared IPv6 helper test rejected the original
extension-parsing formula before correction.

The flow tests construct eBPF events for both address families and feed the real
decoders and `FlowTable<RustiFlow>`. They cover every interleaving preserving each
direction's order for the synthetic normal and simultaneous close sequences, with
normal-close cases also tested across sequence rollover. Other tests cover ACK
flags, retransmitted FINs, late timestamps, sparse ranges, and repeated sequence
epochs. An independent byte-coverage oracle checks range overlap decisions.

Commands:

```bash
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo xtask ebpf-ipv4
cargo xtask ebpf-ipv6
```

Live validation remains outstanding. In this session, `rustiflow-t0` was absent
and `sudo -n` required a password. Successful builds and shared-parser tests do
not establish kernel verifier acceptance or live capture correctness. A restored
local veth setup should exercise fragmented IPv4/IPv6, AH, ESP, ordinary TCP
teardown, and traffic in both directions.

The replay benchmark still routes each flow to one synthetic source. The new
interleaving tests validate flow-layer behavior directly; they do not demonstrate
that the ring-drain and dispatcher pipeline produces those orderings. Extending
the replay source topology remains separate validation work.
