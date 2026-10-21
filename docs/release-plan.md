# Next release plan

Publish a release of the current RustiFlow code and mark it as GitHub's Latest
release. Keep the WTMC release, its tag, and its assets as a historical artifact.
WTMC records the last fully handwritten version of the project.

The next release should cover the existing functionality. Defer new feature
families until after it ships. Choose the version and target date after the
readiness review identifies the remaining work.

## Current position

The maintainer reports that the latest GitHub build succeeded. The workflows at
commit `a939861` provide the following checks and outputs:

- [Rust CI](../.github/workflows/rust.yml) builds both eBPF programs and the
  userspace program, checks formatting, runs Clippy and tests, and builds docs.
- [Container CI](../.github/workflows/docker.yml) builds Linux amd64 images and
  publishes them to GHCR on eligible pushes. It also handles `v*` tags.
- These workflows do not attach standalone binaries to a GitHub release.

The [engineering notes](engineering-notes.md) still list live realtime validation
as outstanding after the byte-order and parser changes. A successful build does
not close that task.

## Release readiness

- [ ] Choose a release owner, version, target date, and candidate commit. Record
  them in this document. Limit subsequent candidate changes to release fixes.
- [ ] Review changes since the WTMC tag and write release notes. Cover CLI,
  configuration, CSV schemas, flow lifecycle, and offline/realtime semantics.
- [ ] Document the corrected realtime byte-order behavior and its implications
  for older datasets, using the engineering notes as the starting point.
- [ ] Confirm successful Linux CI for the exact candidate commit, including both
  eBPF builds, tests, formatting, and Clippy. Link the runs in the release record.
- [ ] Run a tiny deterministic offline fixture through the release binary and
  check the exported values and headers against expected results.
- [ ] Smoke-test IPv4 and IPv6 realtime capture on the local `rustiflow-t0` veth
  setup. Check addresses, ports, packet lengths, timing, and TCP termination.
  Compare offline and realtime exports for the same traffic where their timestamp
  and length sources permit it. Record the kernel, attach mode, commands, and
  results. Prefer legacy netlink tc attachment on the local Arch setup.
- [ ] Resolve release-blocking failures and document remaining limitations. Do
  not describe veth throughput as physical wire-rate validation.

## Packaging and documentation

- [ ] Decide which Linux architectures the release supports and which runtime
  dependencies each binary needs. The current container workflow covers amd64.
- [ ] Add a repeatable release packaging procedure or workflow. Build assets
  from the tagged commit, include checksums, and record the toolchain and build
  commands. Confirm that the package includes everything realtime capture needs.
- [ ] Test the packaged binary in a clean supported Linux environment. Verify
  installation, `--help`, offline extraction, and realtime capture requirements.
- [ ] Update the README installation instructions and examples for the selected
  assets. Reconcile the documented bpf-linker version with the tested build setup.
- [ ] Link the WTMC release from the new release notes and explain its historical
  role as the last fully handwritten version.

## Publication

- [ ] Tag the validated commit and publish the release notes, binaries, and
  checksums. Confirm that any versioned container images refer to that commit.
- [ ] Mark the new stable release as Latest on GitHub. Leave the WTMC tag and
  assets intact.
- [ ] Download the published assets and verify their checksums and a basic
  offline run. Check that the repository release link and README direct users
  to the new release, and that WTMC remains accessible.

The release is complete when users can download and run the validated assets
from GitHub's Latest release and still find the original WTMC artifact.
