# Real-Time Adaptive Feature Extraction for ML-Based Network Intrusion Detection

This is a feature extraction tool build in Rust using eBPF for network intrusion detection

## Install:

### Prerequisites

Make sure you have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Installing nightly:

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
```

Installing the bpf linker

```bash
sudo apt install llvm
cargo install --no-default-features bpf-linker
```

When you are running Ubuntu 20.04 LTS you need to run this command to avoid bugs:

```bash
sudo apt install linux-tools-5.8.0-63-generic
export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
```

### Building the project

To build the eBPF programs:

```bash
cargo xtask build-ebpf
```

To build the user space programs:

```bash
cargo build
```

To run the program:

```bash
RUST_LOG=info cargo xtask run -- realtime <interface>
```

To now the other possibilities, run this command:

```bash
RUST_LOG=info cargo xtask run -- help
```