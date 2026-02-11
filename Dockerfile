# Build Stage
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY dockcheck-go .
RUN go mod download
RUN go build -o dockcheck ./cmd/dockcheck

# Final Stage
FROM node:18-alpine

WORKDIR /app

# Copy package files first for caching
COPY package*.json ./
RUN npm install --production

# Copy app source
COPY . .

# Copy binary from builder
COPY --from=builder /build/dockcheck ./dockcheck

# Environment defaults
ENV NODE_ENV=production
ENV DOCKCHECK_BIN=./dockcheck

EXPOSE 3131

CMD ["npm", "start"]
