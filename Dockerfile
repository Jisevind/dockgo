# Build Stage
FROM golang:1.25-alpine AS builder
WORKDIR /build

# Copy source
COPY dockgo .

# DEBUG: Check what was copied
RUN ls -lR /build

# Build
RUN go mod download
RUN go build -o dockgo ./cmd/dockgo

# Final Stage
FROM alpine:latest

WORKDIR /app

# Install Docker CLI, Compose, and su-exec (for permission handling)
RUN apk add --no-cache docker-cli docker-cli-compose su-exec dos2unix

# Create non-root user (but don't switch to it yet)
RUN adduser -D dockgo

# Copy binary
COPY --from=builder /build/dockgo ./dockgo
COPY entrypoint.sh ./entrypoint.sh
RUN dos2unix ./entrypoint.sh && chmod +x ./entrypoint.sh

# Environment defaults
ENV PORT=3131
ENV DOCKCHECK_BIN=./dockgo

EXPOSE 3131

ENTRYPOINT ["./entrypoint.sh"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget -q --spider http://localhost:3131/api/health || exit 1

CMD ["./dockgo", "serve"]
