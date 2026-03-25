# RustiFlow Agent Guide

This repository is a Rust workspace for a network flow extractor. The main crates are:

- `rustiflow`: user-space CLI, pcap reader, realtime capture, flow extraction, CSV/TUI output
- `common`: shared packet/event structs used by user space and eBPF programs
- `xtask`: helper commands for building and running the project
- `ebpf-ipv4` / `ebpf-ipv6`: Linux eBPF programs used for realtime capture

## Remote Machine Guardrails

- Remote Linux machines reachable over SSH may be used only for this RustiFlow project.
- On those machines, run only RustiFlow-related commands, builds, checks, and tests.
- Do not use those machines for unrelated exploration, installs, experiments, or general development tasks.
- If remote work needs a dedicated workspace or directory, ask the user to create/provide it first.
- If any software or dependency needs to be installed on those machines, ask the user to do it.
- If there is any uncertainty about whether a command is appropriate to run on those machines, ask the user before running it.

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

## Platform Notes

- Realtime eBPF support is Linux-specific.
- macOS may be usable for some read-only work, formatting, and limited code inspection, but Linux is the source of truth for full build and runtime validation.
- Do not assume that successful macOS builds imply realtime correctness.
- When touching `aya`/eBPF/realtime code, prefer validating on Linux or in a Linux container/VM.

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
