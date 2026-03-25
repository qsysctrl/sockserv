# Build stage
FROM rust:1.85-slim AS builder

WORKDIR /app

# Copy dependency definitions
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install ca-certificates for HTTPS (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/sockserv .

# Expose SOCKS5 port
EXPOSE 1080

# Set environment variables
ENV RUST_LOG=info

# Run the server
CMD ["./sockserv"]
