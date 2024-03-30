# Network Intrusion Detection System Feature Extraction Tool

## Overview

This tool is designed for robust and efficient feature extraction in network intrusion detection systems. Leveraging Rust language and eBPF, it excels in processing high volumes of network traffic with remarkable speed and throughput.

![Badge displaying GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/matissecallewaert/nids-feature-extraction-tool/rust.yml?logo=github) ![Badge linking to the project documentation website](https://img.shields.io/website?url=https%3A%2F%2Fmatissecallewaert.github.io%2Fnids-feature-extraction-tool&label=Documentation) ![Ubuntu 22](https://img.shields.io/badge/Tested%20on%20ubuntu%2022-purple?logo=ubuntu) ![Ubuntu 20](https://img.shields.io/badge/Tested%20on%20ubuntu%2020-purple?logo=ubuntu)

![Animated image showing network flows](flows.gif)

## Key Features

- **High Throughput:** Utilizes Rust and the [Aya](https://aya-rs.dev/) library for eBPF program compilation and execution, ensuring exceptional performance and resource efficiency.
- **Versatile Feature Sets:** Offers a variety of pre-defined feature sets (flows) and the flexibility to create custom feature sets tailored to specific requirements.
- **Pcap File Support:** Facilitates packet analysis from pcap files, compatible with both Linux and Windows generated files.
- **Diverse Output Options:** Features can be outputted to the console, a CSV file, or other formats with minimal effort.

## Feature sets



## Installation Guide

### Prerequisites:
- **libpcap-dev**:
  ```sh
  sudo apt install libpcap-dev
  ```
- **Rust Installation**:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Nightly Rust Toolchain**:
  ```bash
  rustup install stable
  rustup toolchain install nightly --component rust-src
  ```

### bpf Linker Installation:
- **For Linux x86_64**:
  ```bash
  cargo install bpf-linker
  ```
- **For MacOS/Linux (Other Architectures)**:
  ```bash
  brew install llvm
  cargo install --no-default-features bpf-linker
  ```
- **Ubuntu 20.04 LTS Specific**:
  ```bash
  sudo apt install linux-tools-5.8.0-63-generic
  export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
  ```

## Building the Project

- **eBPF Programs**:
  ```bash
  cargo xtask ebpf-ipv4
  cargo xtask ebpf-ipv6
  ```
- **User Space Programs**:
  ```bash
  cargo build
  ```

## Usage Instructions

### Real-Time Traffic Capture:
- **To Run/Build**:
  ```bash
  RUST_LOG=info cargo xtask run -- realtime <interface> <flow_type> <flow_lifetime_sec> <output_method> [output_path] [dump_interval_sec]
  ```
- **Command Help**:
  ```bash
  RUST_LOG=info cargo xtask run -- realtime --help
  ```

### Reading from a Pcap File:
- **To Run/Build**:
  ```bash
  RUST_LOG=info cargo xtask run -- pcap <machine_type> <flow_type> <input_path> <output_method> [output_path]
  ```
- **Command Help**:
  ```bash
  RUST_LOG=info cargo xtask run -- pcap --help
  ```

**Note:** For specific logging levels, adjust `RUST_LOG` to `error` for error messages, and `debug` for debug messages.

---