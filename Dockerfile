# syntax=docker/dockerfile:1

# ==============================================================================
# STAGE 1: Builder (Alpine Linux targeting x86_64-unknown-linux-musl)
# ==============================================================================
FROM rust:alpine AS builder

# Install build dependencies required for native C/C++ compilation (ring, aws-lc-sys, openssl)
RUN apk add --no-cache \
    musl-dev \
    gcc \
    g++ \
    make \
    cmake \
    perl \
    pkgconfig \
    openssl-dev \
    openssl-libs-static

WORKDIR /app

# Enable SQLx offline mode and static OpenSSL linking for musl
ENV SQLX_OFFLINE=true \
    OPENSSL_STATIC=true

# Copy manifest and offline SQLx query cache
COPY Cargo.toml Cargo.lock ./
COPY .sqlx/ ./.sqlx/
COPY config/ ./config/
COPY migrations/ ./migrations/
COPY src/ ./src/

# Compile static release binary targeting x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl

# ==============================================================================
# STAGE 2: Distroless Minimal Static Runtime
# ==============================================================================
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy statically linked binary from builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/korgan /usr/local/bin/korgan

# Run as nonroot user (UID 65532, GID 65532)
USER 65532:65532

# Expose HTTP port
EXPOSE 8080

# Run service
ENTRYPOINT ["/usr/local/bin/korgan"]
