# =============================================================================
# FlashAudit - Multi-stage Docker build
# =============================================================================

# Stage 1: Build the binary using Rust
FROM rust:alpine AS builder

# Install build dependencies for static linking
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copy actual source and rebuild
COPY src ./src
COPY rules.yaml ./

# Touch main.rs to trigger rebuild with actual code
RUN touch src/main.rs && cargo build --release

# =============================================================================
# Stage 2: Create minimal runtime image
# =============================================================================
FROM alpine:3.19

LABEL org.opencontainers.image.title="FlashAudit"
LABEL org.opencontainers.image.description="High-performance secrets scanner"
LABEL org.opencontainers.image.source="https://github.com/Ruddxxy/Flash-Audit"
LABEL org.opencontainers.image.licenses="MIT"

# Install git (required for --staged and --git-diff functionality)
RUN apk add --no-cache git ca-certificates

# Create non-root user for security
RUN adduser -D -u 1000 flashaudit

# Copy binary from builder
COPY --from=builder /app/target/release/flash_audit /usr/local/bin/flash_audit

# Copy default rules
COPY --from=builder /app/rules.yaml /etc/flashaudit/rules.yaml

# Make binary executable
RUN chmod +x /usr/local/bin/flash_audit

# Set git safe directory (required for scanning mounted repos)
RUN git config --global --add safe.directory '*'

USER flashaudit
WORKDIR /repo

ENTRYPOINT ["flash_audit"]
CMD ["--help"]
