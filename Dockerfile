FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Update the system and install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    libpcap-dev \
    iproute2 \
    linux-tools-5.8.0-63-generic \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
 && . $HOME/.cargo/env \
 && rustup install stable \
 && rustup toolchain install nightly --component rust-src \
 && cargo install bpf-linker

ENV PATH="/root/.cargo/bin:${PATH}"
ENV PATH="/usr/lib/linux-tools/5.8.0-63-generic:$PATH"
ENV RUST_LOG=info

# Copy
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY common ./common
COPY feature-extraction-tool ./feature-extraction-tool
COPY xtask ./xtask
COPY rustfmt.toml .
COPY ebpf-ipv4 ./ebpf-ipv4
COPY ebpf-ipv6 ./ebpf-ipv6

# Build
RUN cargo xtask ebpf-ipv4 --release
RUN cargo xtask ebpf-ipv6 --release
RUN cargo build --release

# Command
ENTRYPOINT ["./target/release/rustiflow"]