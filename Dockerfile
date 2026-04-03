# Dockerfile.scratch
# Minimal scratch image with static binary

# Build stage using official musl builder
FROM rust:1.94-alpine AS builder

# Install musl build tools
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Fully static executable (no musl ld.so + libc.so at runtime — OK for scratch)
ENV RUSTFLAGS="-C target-feature=+crt-static"

# Build the application
RUN cargo build --release --target x86_64-unknown-linux-musl

# Verify no shared-library dependencies (glibc ldd says "statically linked"; musl ldd often does not)
RUN if readelf -d ./target/x86_64-unknown-linux-musl/release/dnsntp 2>/dev/null | grep -q NEEDED; then \
      echo "binary is not fully static"; exit 1; fi

# Runtime stage - completely empty base
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/dnsntp /dnsntp

# Expose port
EXPOSE 53535/udp

# Run the binary
ENTRYPOINT ["/dnsntp"]