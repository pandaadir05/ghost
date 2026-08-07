# Use multi-stage build for smaller final image
FROM rust:1.75-slim as builder

WORKDIR /app

# Install system dependencies. libyara-dev + libclang-dev are needed to
# build with the yara-scanning feature (libclang for yara-sys's bindgen).
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libyara-dev \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests for every workspace member - Cargo resolves the whole
# workspace even when only building one package, so all of them must be
# present, not just the two this image actually ships.
COPY Cargo.toml Cargo.lock ./
COPY ghost-core/Cargo.toml ghost-core/
COPY ghost-cli/Cargo.toml ghost-cli/
COPY ghost-tui/Cargo.toml ghost-tui/
COPY benches/Cargo.toml benches/

# Create dummy source files to build dependencies
RUN mkdir ghost-core/src ghost-cli/src ghost-tui/src benches/benches && \
    echo "fn main() {}" > ghost-cli/src/main.rs && \
    echo "fn main() {}" > ghost-tui/src/main.rs && \
    echo "fn main() {}" > benches/benches/detection_performance.rs && \
    echo "" > ghost-core/src/lib.rs

# Build dependencies. ghost-cli does not itself declare a yara-scanning
# feature, so it must be enabled via the qualified `pkg/feature` form.
RUN cargo build --release --features ghost-core/yara-scanning && \
    rm -rf ghost-core/src ghost-cli/src target/release/deps/ghost*

# Copy source code
COPY ghost-core/src ghost-core/src/
COPY ghost-cli/src ghost-cli/src/

# Build application
RUN cargo build --release --bin ghost-cli --features ghost-core/yara-scanning

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies. libyara-dev (not just the bare runtime
# library) to reliably pull in whatever shared-object package it depends on.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ghost

# Copy binary
COPY --from=builder /app/target/release/ghost-cli /usr/local/bin/ghost
# Detection rules must ship with the binary; without them the YARA engine
# has nothing to load. GHOST_RULES_DIR points the engine at them.
COPY rules /usr/local/share/ghost/rules
ENV GHOST_RULES_DIR=/usr/local/share/ghost/rules

# Set ownership and permissions
RUN chown root:root /usr/local/bin/ghost && \
    chmod 755 /usr/local/bin/ghost

USER ghost

ENTRYPOINT ["/usr/local/bin/ghost"]