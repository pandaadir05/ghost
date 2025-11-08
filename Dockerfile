# Use multi-stage build for smaller final image
FROM rust:1.75-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY ghost-core/Cargo.toml ghost-core/
COPY ghost-cli/Cargo.toml ghost-cli/

# Create dummy source files to build dependencies
RUN mkdir ghost-core/src ghost-cli/src && \
    echo "fn main() {}" > ghost-cli/src/main.rs && \
    echo "" > ghost-core/src/lib.rs

# Build dependencies
RUN cargo build --release && \
    rm -rf ghost-core/src ghost-cli/src target/release/deps/ghost*

# Copy source code
COPY ghost-core/src ghost-core/src/
COPY ghost-cli/src ghost-cli/src/

# Build application
RUN cargo build --release --bin ghost-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ghost

# Copy binary
COPY --from=builder /app/target/release/ghost-cli /usr/local/bin/ghost

# Set ownership and permissions
RUN chown root:root /usr/local/bin/ghost && \
    chmod 755 /usr/local/bin/ghost

USER ghost

ENTRYPOINT ["/usr/local/bin/ghost"]