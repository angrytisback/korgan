# syntax=docker/dockerfile:1

# ==============================================================================
# STAGE 1: Builder (Alpine Linux, static musl target matching TARGETARCH)
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

# Compile a static release binary for the architecture being built
# (amd64 -> x86_64-unknown-linux-musl, arm64 -> aarch64-unknown-linux-musl).
# The classic builder does not set TARGETARCH; it defaults to amd64 below.
# The binary stays at target/<triple>/release/korgan (the release workflow
# copies it from there) and is also copied to /app/korgan for the next stage.
ARG TARGETARCH
RUN case "${TARGETARCH:-amd64}" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && cargo build --release --target "${RUST_TARGET}" \
 && cp "target/${RUST_TARGET}/release/korgan" /app/korgan

# ==============================================================================
# STAGE 2: Distroless Minimal Static Runtime
# ==============================================================================
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy statically linked binary from builder stage
COPY --from=builder /app/korgan /usr/local/bin/korgan

# Run as nonroot user (UID 65532, GID 65532)
USER 65532:65532

# Expose HTTP port
EXPOSE 8080

# Run service
ENTRYPOINT ["/usr/local/bin/korgan"]
