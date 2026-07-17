# syntax=docker/dockerfile:1
# Multi-stage build for pqfs.
FROM rust:1.86-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libfuse3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pqfs
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libfuse3-3 \
    fuse3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /mnt/pqfs

COPY --from=builder /usr/src/pqfs/target/release/pqfs /usr/local/bin/pqfs

# Keep the container alive so you can exec in and mount pqfs manually.
CMD ["sleep", "infinity"]
