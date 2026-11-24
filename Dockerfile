# syntax=docker/dockerfile:1
# Multi-stage build for pqfs.
FROM rust:1.99-bookworm AS builder

WORKDIR /usr/src/pqfs
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /mnt/pqfs

COPY --from=builder /usr/src/pqfs/target/release/pqfs /usr/local/bin/pqfs

# Keep the container alive so you can exec in and mount pqfs manually.
CMD ["sleep", "infinity"]
