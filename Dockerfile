# Multi-stage build for minimal image
FROM rust:1.75-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    build-base \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    git

# Copy source
COPY . .

# Build release binary
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl

# Create non-root user
RUN addgroup -g 1000 proxy && \
    adduser -D -s /bin/sh -u 1000 -G proxy proxy

# Copy binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/proxy-server /usr/local/bin/
COPY --from=builder /app/config.toml /etc/proxy/

# Set permissions
RUN chmod +x /usr/local/bin/proxy-server && \
    chown -R proxy:proxy /etc/proxy

USER proxy

EXPOSE 28265
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:28265/health || exit 1

CMD ["proxy-server", "--config", "/etc/proxy/config.toml"]
