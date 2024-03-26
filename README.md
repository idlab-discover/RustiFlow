# Real-Time Adaptive Feature Extraction for ML-Based Network Intrusion Detection

This is a feature extraction tool that is capable of exporting multiple kinds of feature and feature sets. The project is written in rust and uses eBPF code to collect the basic network traffic data from the incomming and outgoing packets. The project was made with following goals, it needed to be fast, adaptable and reliable.

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/matissecallewaert/nids-feature-extraction-tool/rust.yml?logo=github
) ![Website](https://img.shields.io/website?url=https%3A%2F%2Fmatissecallewaert.github.io%2Fnids-feature-extraction-tool&label=Documentation)

![flows](flows.gif)

## How to install:
### Installing libpcap-dev
#### Debian
```sh
sudo apt install libpcap-dev
```
#### Fedora
```sh
sudo dnf install libpcap-devel
```
### Installing rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Installing nightly

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
```

### Installing bpf linker

If you are running a Linux x86_64 system the installation is simple:

```bash
cargo install bpf-linker
```

If you are running MacOs or Linux on any other architecture, you need to install the newest stable version of LLVM first:

```bash
brew install llvm
```

Then install the linker with:

```bash
cargo install --no-default-features bpf-linker
```

When you are running Ubuntu 20.04 LTS you need to run this command to avoid bugs, because there is a bug in the default kernel of the distribution:

```bash
sudo apt install linux-tools-5.8.0-63-generic
export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
```

## Building the project:

To build the eBPF programs:

```bash
cargo xtask ingress-ebpf
cargo xtask egress-ebpf
```

To build the user space programs:

```bash
cargo build
```

## Running (and building) the project

To run (and build) the program, the dump interval argument is optional:

```bash
RUST_LOG=info cargo xtask run -- realtime <interface> <flow_lifetime_sec> <dump_interval>
```

To know the other possibilities, run this command:

```bash
RUST_LOG=info cargo xtask run -- help
```
## Explanation about the features

### cic_flow

**Terminology:**
- Ingress: The flow is going into the machine. Forward direction
- Egress: The flow is going out of the machine. Backward direction

These **features** are the same as in the **cic-ids** datasets. The features with their explanations are:
- **Flow Id:** Combination of source_ip, destination_ip, source_port, destination_port, protocol.
- **Source IP:** Source IP address (not the ip of the machine the program is running on).
- **Source Port:** Source port (not the port of the machine the program is running on).
- **Destination IP:** Destination IP address (the ip of the machine the program is running on).
- **Destination Port:** Destination port (the port of the machine the program is running on).
- **Protocol:** Transport layer protocol used in the flow.
- **Timestamp:** Timestamp of the start of the flow.
- **Flow Duration:** Time between the first packet and the last packet of the flow in microseconds.
- **Total Fwd Packets:** Total number of packets in the forward direction. (source to destination).
- **Total Backward Packets:** Total number of packets in the backward direction. (destination to source).
- **Total Length of Fwd Packets:** Total size of the payload in the packets in the forward direction.
- **Total Length of Bwd Packets:** Total size of the payload in the packets in the backward direction.
- **Fwd Packet Length Max:** Maximum payload size of the packets in the forward direction. 
- **Fwd Packet Length Min:** Minimum payload size of the packets in the forward direction. 
- **Fwd Packet Length Mean:** Mean payload size of the packets in the forward direction. 
- **Fwd Packet Length Std:** Standard deviation of the payload size of the packets in the forward direction.
- **Bwd Packet Length Max:** Maximum payload size of the packets in the backward direction.
- **Bwd Packet Length Min:** Minimum payload size of the packets in the backward direction.
- **Bwd Packet Length Mean:** Mean payload size of the packets in the backward direction. 
- **Bwd Packet Length Std:** Standard deviation of the payload size of the packets in the backward direction.
- **Flow Bytes/s:** payload transfer rate of the flow in bytes per second.
- **Flow Packets/s:** Packet transfer rate of the flow in packets per second.
- **Flow IAT Mean:** Mean time between two packets of the flow.
- **Flow IAT Std:** Standard deviation of the time between two packets of the flow.
- **Flow IAT Max:** Maximum time between two packets of the flow.
- **Flow IAT Min:** Minimum time between two packets of the flow.
- **Fwd IAT Total:** Total time between two packets in the forward direction.
- **Fwd IAT Mean:** Mean time between two packets in the forward direction.
- **Fwd IAT Std:** Standard deviation of the time between two packets in the forward direction.
- **Fwd IAT Max:** Maximum time between two packets in the forward direction.
- **Fwd IAT Min:** Minimum time between two packets in the forward direction.
- **Bwd IAT Total:** Total time between two packets in the backward direction.
- **Bwd IAT Mean:** Mean time between two packets in the backward direction.
- **Bwd IAT Std:** Standard deviation of the time between two packets in the backward direction.
- **Bwd IAT Max:** Maximum time between two packets in the backward direction.
- **Bwd IAT Min:** Minimum time between two packets in the backward direction.
- **Fwd PSH Flags:** Number of times the PSH flag was set in packets in the forward direction.
- **Bwd PSH Flags:** Number of times the PSH flag was set in packets in the backward direction.
- **Fwd URG Flags:** Number of times the URG flag was set in packets in the forward direction.
- **Bwd URG Flags:** Number of times the URG flag was set in packets in the backward direction.
- **Fwd Header Length:** Total size of the headers in the forward direction.
- **Bwd Header Length:** Total size of the headers in the backward direction.
- **Fwd Packets/s:** Packet transfer rate in the forward direction.
- **Bwd Packets/s:** Packet transfer rate in the backward direction.
- **Min Packet Length:** Minimum payload size of the packets in the flow.
- **Max Packet Length:** Maximum payload size of the packets in the flow.
- **Packet Length Mean:** Mean payload size of the packets in the flow.
- **Packet Length Std:** Standard deviation of the payload size of the packets in the flow.
- **Packet Length Variance:** Variance of the payload size of the packets in the flow.
- **FIN Flag Count:** Number of times the FIN flag was set in packets in the flow.
- **SYN Flag Count:** Number of times the SYN flag was set in packets in the flow.
- **RST Flag Count:** Number of times the RST flag was set in packets in the flow.
- **PSH Flag Count:** Number of times the PSH flag was set in packets in the flow.
- **ACK Flag Count:** Number of times the ACK flag was set in packets in the flow.
- **URG Flag Count:** Number of times the URG flag was set in packets in the flow.
- **CWE Flag Count:** Number of times the CWE flag was set in packets in the flow.
- **ECE Flag Count:** Number of times the ECE flag was set in packets in the flow.
- **Down/Up Ratio:** Ratio of the number of packets in the backwards direction to the number of packets in the forward direction. backwards/forwards
- **Average Packet Size:** Mean payload size of the packets in the flow.
- **Avg Fwd Segment Size:** Average payload size of the packets in the forward direction.
- **Avg Bwd Segment Size:** Average payload size of the packets in the backward direction.
- **Fwd Avg Bytes/Bulk:** Average size of the bulk of packets in the forward direction.
- **Fwd Avg Packets/Bulk:** Average number of packets in the bulk of packets in the forward direction.
- **Fwd Avg Bulk Rate:** Average rate of the bulk of packets in the forward direction.
- **Bwd Avg Bytes/Bulk:** Average size of the bulk of packets in the backward direction.
- **Bwd Avg Packets/Bulk:** Average number of packets in the bulk of packets in the backward direction.
- **Bwd Avg Bulk Rate:** Average rate of the bulk of packets in the backward direction.
- **Subflow Fwd Packets:** Number of packets in the forward direction of the subflow.
- **Subflow Fwd Bytes:** Number of bytes in the forward direction of the subflow.
- **Subflow Bwd Packets:** Number of packets in the backward direction of the subflow.
- **Subflow Bwd Bytes:** Number of bytes in the backward direction of the subflow.
- **Init_Win_bytes_forward:** Initial window size in the forward direction.
- **Init_Win_bytes_backward:** Initial window size in the backward direction.
- **act_data_pkt_fwd:** Number of packets with at least 1 byte of TCP data payload in the forward direction.
- **min_seg_size_forward:** Minimum header size of the packets in the forward direction.
- **Active Mean:** Mean active time a flow.
- **Active Std:** Standard deviation of the active time of a flow.
- **Active Max:** Maximum active time of a flow.
- **Active Min:** Minimum active time of a flow.
- **Idle Mean:** Mean idle time of a flow.
- **Idle Std:** Standard deviation of the idle time of a flow.
- **Idle Max:** Maximum idle time of a flow.
- **Idle Min:** Minimum idle time of a flow.
- **Label:** Label of the flow. 0 for benign, 1 for malicious.