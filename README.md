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
This is highly dependent on your operating system, just follow the error messages and install the requirements. For llvm you need version 18, make sure that Polly is installed with it.

```bash
sudo apt install llvm
sudo apt install llvm-dev
sudo apt install libzstd-dev
```

Make sure you are in the project root directory
```bash
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
cargo xtask ingress-ebpf
cargo xtask egress-ebpf
```

To build the user space programs:

```bash
cargo build
```

### Running the project

To run the program:

```bash
RUST_LOG=info cargo xtask run -- realtime <interface>
```

To now the other possibilities, run this command:

```bash
RUST_LOG=info cargo xtask run -- help
```
