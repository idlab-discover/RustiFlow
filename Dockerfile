# syntax=docker/dockerfile:1
#
# Both images install the same release bundle (`cargo xtask dist`):
#
#   docker build -t rustiflow .                     # default, Ubuntu 24.04 runtime
#   docker build --target slim -t rustiflow:slim .  # Debian bookworm-slim runtime
#
# By default the bundle is built from source in the `dist` stage. To install an
# existing bundle instead, point the `bundle` stage at a directory holding its
# tarball:  docker build --build-context bundle=target/dist .
# Export a freshly built bundle with:
#   docker build --target bundle --output type=local,dest=target/dist .

ARG BPF_LINKER_VERSION=0.12.0

# Bookworm's glibc is the oldest the release supports, so the binary also runs
# on the newer Ubuntu runtime and on hosts at least as new as bookworm.
FROM rust:1.99.0-bookworm AS dist
ARG BPF_LINKER_VERSION
# Recorded in the bundle MANIFEST; .git is not part of the build context.
ARG RUSTIFLOW_COMMIT=
ARG SOURCE_DATE_EPOCH=

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    zstd \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fL --retry 3 "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst" -o /tmp/bpf-linker.tar.zst \
    && tar --zstd -xf /tmp/bpf-linker.tar.zst -C "$CARGO_HOME/bin" \
    && rm /tmp/bpf-linker.tar.zst \
    && bpf-linker --version

WORKDIR /usr/src/app
COPY rust-toolchain.toml ./
COPY ebpf-ipv4/rust-toolchain.toml ./ebpf-ipv4/
COPY ebpf-ipv6/rust-toolchain.toml ./ebpf-ipv6/
RUN rustup toolchain install \
    && (cd ebpf-ipv4 && rustup toolchain install) \
    && (cd ebpf-ipv6 && rustup toolchain install)

COPY Cargo.toml Cargo.lock rustfmt.toml config.toml LICENSE README.md ./
COPY .cargo ./.cargo
COPY common ./common
COPY rustiflow ./rustiflow
COPY xtask ./xtask
COPY ebpf-ipv4 ./ebpf-ipv4
COPY ebpf-ipv6 ./ebpf-ipv6
COPY packaging ./packaging
RUN cargo xtask dist --out-dir /out

FROM scratch AS bundle
COPY --from=dist /out/ /

FROM debian:bookworm-slim AS slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpcap0.8 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=bind,from=bundle,target=/bundle \
    tar -xzf /bundle/rustiflow-*-x86_64-linux.tar.gz -C /tmp \
    && /tmp/rustiflow-*-x86_64-linux/install.sh --prefix /usr/local \
    && rm -rf /tmp/rustiflow-*-x86_64-linux
ENV RUST_LOG=info
WORKDIR /usr/src/app
ENTRYPOINT ["rustiflow"]

FROM ubuntu:24.04 AS default
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpcap0.8t64 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=bind,from=bundle,target=/bundle \
    tar -xzf /bundle/rustiflow-*-x86_64-linux.tar.gz -C /tmp \
    && /tmp/rustiflow-*-x86_64-linux/install.sh --prefix /usr/local \
    && rm -rf /tmp/rustiflow-*-x86_64-linux
ENV RUST_LOG=info
WORKDIR /usr/src/app
ENTRYPOINT ["rustiflow"]
