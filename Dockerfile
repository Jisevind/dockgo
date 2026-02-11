# Build Stage
FROM golang:1.25-alpine AS builder
WORKDIR /build

# Copy source
COPY dockcheck-go .

# Build
RUN go mod download
RUN go build -o dockgo ./cmd/dockgo

# Final Stage
FROM alpine:latest

WORKDIR /app

# Install Docker CLI and Compose (Required for engine interactions)
RUN apk add --no-cache docker-cli docker-cli-compose

# Copy binary from builder
COPY --from=builder /build/dockgo ./dockgo

# Environment defaults
ENV PORT=3131
ENV DOCKCHECK_BIN=./dockgo

EXPOSE 3131

CMD ["./dockgo", "serve"]
