# RustiFlow Agent Guide

This repository is a Rust workspace for a network flow extractor. The main crates are:

- `rustiflow`: user-space CLI, pcap reader, realtime capture, flow extraction, CSV/TUI output
- `common`: shared packet/event structs used by user space and eBPF programs
- `xtask`: helper commands for building and running the project
- `ebpf-ipv4` / `ebpf-ipv6`: Linux eBPF programs used for realtime capture

## Platform Notes

- Realtime eBPF support is Linux-specific.
- Linux is the source of truth for build, runtime, and performance validation.
- Do not assume that successful non-Linux builds imply realtime correctness.
- When touching `aya`/eBPF/realtime code, prefer validating on Linux.
- On the local Arch `rustiflow-t0` veth harness, legacy netlink tc attach is
  currently more reliable than `aya`'s automatic TCX attach path for realtime
  validation.

## Local Test Network

- The primary dedicated software-path test setup is local to `rgbcore`.
- A persistent veth pair is available for RustiFlow testing:
  - host namespace capture side: `rustiflow-t0`
  - peer namespace side: `rustiflow-p0`
  - peer namespace: `rustiflow-peer`
  - IPv4 addressing: `10.203.0.1/30` on `rustiflow-t0`, `10.203.0.2/30` on `rustiflow-p0`
  - IPv6 addressing: `fd42:203::1/64` on `rustiflow-t0`, `fd42:203::2/64` on `rustiflow-p0`
- This setup is intended to stress the RustiFlow software path without depending on the physical LAN.
- Treat it as a high-throughput local test harness, not as a substitute for true physical wire-rate validation.

## Remote Machine Guardrails

- Remote Linux machines reachable over SSH may be used only for this RustiFlow project.
- On those machines, run only RustiFlow-related commands, builds, checks, and tests.
- Do not use those machines for unrelated exploration, installs, experiments, or general development tasks.
- If remote work needs a dedicated workspace or directory, ask the user to create/provide it first.
- If any software or dependency needs to be installed on those machines, ask the user to do it.
- If there is any uncertainty about whether a command is appropriate to run on those machines, ask the user before running it.

## Non-Negotiables

- When writing or editing Rust in this repository, always apply the Rust guidance in this file first. Treat it as an active coding standard, not optional reading.
- Prefer changes that are small, local, and easy to review. Avoid broad opportunistic refactors unless the task specifically calls for them.
- Preserve the existing human-made structure of the codebase where possible. Fit new work into current boundaries before creating new ones.

## Commit Hygiene

- Keep commits clean, bounded, and purpose-specific.
- Prefer one logical change per commit. Do not mix unrelated fixes, refactors, docs updates, and test rewrites unless they are tightly coupled.
- When work spans multiple concerns, split it into a short chain of commits with readable messages.
- Before committing, check that the diff matches the stated purpose of the commit and does not include unrelated workspace noise.
- If a change is exploratory or lower confidence, prefer using a separate branch until it is trusted.

## Working Principles

- Prefer small, targeted changes over broad rewrites.
- Keep flow logic modular. Shared measurement logic belongs in `rustiflow/src/flows/features/`; exporter-specific schema logic belongs in the relevant flow type.
- Preserve output compatibility unless a schema change is intentional and documented.
- When changing CLI behavior, config structure, or CSV headers, update the README and any related examples.
- When using `format!`, inline variables into `{}` when possible.
- Prefer exhaustive `match` statements when practical; avoid wildcard arms that hide protocol or feature cases.
- Avoid bool-heavy APIs that create unclear call sites. Prefer enums or named methods when that improves clarity.
- Prefer comparing whole values in tests instead of asserting many individual fields when feasible.
- Do not add one-off helper functions that are only used once unless they make a complex block substantially clearer.

## Rust Style

- Follow `rustfmt` and Clippy guidance.
- Collapse nested `if` statements when it improves readability.
- Inline `format!` arguments when possible.
- Use method references instead of trivial closures when that is clearer.
- Keep modules from growing unnecessarily large. Prefer extracting a focused submodule instead of adding more unrelated logic to an already large file.

## RustiFlow-Specific Guidance

- Treat the offline pcap path and the realtime eBPF path as two distinct ingestion modes that should stay semantically aligned.
- Be careful with timing-related features. Realtime and offline timestamp sources differ, so changes to timing, IAT, active/idle, or expiration logic should be validated deliberately.
- Be careful with packet length semantics. Realtime and offline paths may observe slightly different length fields.
- `BasicFlow` owns flow lifecycle and termination behavior. Do not duplicate expiration or TCP teardown logic in higher-level flow types unless there is a strong reason.
- If you add a new feature family, first decide whether it belongs in:
  - a reusable `FlowFeature` implementation, or
  - one exporter only
- If you change contamination-free exports, keep in mind that these outputs intentionally avoid raw identifiers such as exact ports/IPs.

## Commands

Use the smallest command that gives confidence:

- Format:
  - `cargo fmt`
- Check the main crate:
  - `cargo check -p rustiflow`
- Run Rust tests for the main crate:
  - `cargo test -p rustiflow`
- Build eBPF programs:
  - `cargo xtask ebpf-ipv4`
  - `cargo xtask ebpf-ipv6`
- Run in dev mode:
  - `cargo xtask run -- [OPTIONS] <COMMAND>`

If a change touches shared code used by multiple crates, prefer checking the workspace as needed.

## Validation Expectations

- After Rust code changes, run `cargo fmt`.
- Run the narrowest relevant check/test command for the code you changed.
- If you change dependencies, run at least `cargo check` again after the dependency update.
- If you change CSV headers, config behavior, or user-facing commands, verify the corresponding documentation and examples.

## Notes On Existing Tests

- Treat the current test suite carefully: some tests may be stale or incomplete relative to the active code.
- When adding or repairing tests, prefer tests that reflect the current flow architecture and public behavior rather than resurrecting outdated internal field expectations.
- Before adding more feature work, prefer adversarial deterministic tests around TCP lifecycle, parser edge cases, and tiny offline fixtures that prove exported semantics.

## Engineering Checklist

Keep this section short and current. Completed work and decision history belong
in `docs/engineering-notes.md`.

### Current Focus

- [x] Measure how much of the remaining hot export path is snapshot ownership
  cost versus row serialization cost:
  isolate clone/copy work from string/CSV formatting work under the proven
  `10G` `--early-export 5` case.
- [x] Prototype a structural export path that writes CSV fields directly to the
  buffered writer instead of requiring one fully assembled row `String` per
  exported flow, then reprofile the same workload.
- [x] Evaluate whether a typed export snapshot or borrow-based export view can
  reduce per-export cloning/allocation without violating flow ownership,
  sharding, or semantic parity.
- [x] Identify the heaviest remaining field families inside `RustiFlow::dump`
  after the accepted top-level CSV cleanup, and only optimize subsystems that
  still show up materially in flamegraphs.
- [ ] Re-run the export-heavy comparison after each bounded structural change
  using at least:
  `basic --early-export 5`, `rustiflow --early-export 5`, and one no-early-
  export control, recording CPU, RSS, drop total, output size, and bitrate.
- [ ] Keep updating `docs/engineering-notes.md` after each bounded experiment
  with:
  workload, achieved bitrate, dropped-packet total, resource summary, and what
  the new bottleneck appears to be.

Primary files:

- `rustiflow/src/output.rs`
- `rustiflow/src/flows/basic_flow.rs`
- `rustiflow/src/flows/rusti_flow.rs`
- `rustiflow/src/flows/features/`
- `rustiflow/src/flow_table.rs`
- `rustiflow/src/realtime.rs`
- `docs/engineering-notes.md`

### Later Work

- [ ] Optional lightweight application-aware metadata: DNS, TLS, HTTP, QUIC.
- [ ] Better contamination-free abstractions than only coarse IANA port buckets.
- [ ] Fill remaining `nf_flow` gaps such as `vlan_id` and `tunnel_id` once
  packet metadata exists in both ingestion modes.

### Working rule

Before adding a new feature, ask:

- Is the underlying packet metadata trustworthy in both offline and realtime modes?
- Does this improve diagnostics more than refining an existing weak feature?
- Can it live in a reusable `FlowFeature`?
- Can it be tested with a tiny deterministic fixture?
