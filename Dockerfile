FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Update the system and install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    build-essential \
    pkg-config \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
 && . $HOME/.cargo/env \
 && rustup install stable \
 && rustup toolchain install nightly --component rust-src \
 && cargo install bpf-linker

ENV PATH="/root/.cargo/bin:${PATH}"
ENV RUST_LOG=info

# Copy
WORKDIR /usr/src/app
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY .cargo ./.cargo
COPY common ./common
COPY rustiflow ./rustiflow
COPY xtask ./xtask
COPY rustfmt.toml .
COPY ebpf-ipv4 ./ebpf-ipv4
COPY ebpf-ipv6 ./ebpf-ipv6

# Build
RUN cargo xtask ebpf-ipv4 --release
RUN cargo xtask ebpf-ipv6 --release
RUN cargo build --release --locked

# Command
ENTRYPOINT ["/usr/src/app/target/release/rustiflow"]
