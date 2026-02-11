# Build Stage
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY dockcheck-go .
RUN go mod download
RUN go build -o dockgo ./cmd/dockgo

# Final Stage
FROM node:18-alpine

WORKDIR /app

# Copy package files first for caching
COPY package*.json ./
RUN npm install --production

# Install Docker CLI and Compose for "docker compose" support
RUN apk add --no-cache docker-cli docker-cli-compose

# Copy app source
COPY . .

# Copy binary from builder
COPY --from=builder /build/dockgo ./dockgo

# Environment defaults
ENV NODE_ENV=production
ENV DOCKCHECK_BIN=./dockgo

EXPOSE 3131

CMD ["npm", "start"]
