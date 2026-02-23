# Multi-stage build for Go auth-service production optimization
FROM golang:1.26-alpine AS base

# Install build dependencies without pinned versions
# Alpine 3.22 packages are updated frequently
# hadolint ignore=DL3018
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
FROM base AS deps
RUN go mod download && go mod verify

# Build stage
FROM base AS build
COPY --from=deps /go/pkg /go/pkg
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o auth-service \
    ./cmd/server

# Production stage
FROM alpine:3.23 AS production

# Install runtime dependencies without pinned versions
# Alpine 3.22 packages are updated frequently
# hadolint ignore=DL3018
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl && \
    update-ca-certificates

# Create app directory with proper permissions
WORKDIR /app

# Create non-root user for security
RUN addgroup -g 10001 -S authservice && \
    adduser -S authservice -u 10001 -G authservice

# Copy the binary from build stage
COPY --from=build --chown=authservice:authservice /app/auth-service /app/auth-service

# Copy configuration files
COPY --from=build --chown=authservice:authservice /app/configs /app/configs

# Create logs directory
RUN mkdir -p /app/logs && \
    chown authservice:authservice /app/logs

# Switch to non-root user
USER authservice

# Expose port
EXPOSE 8080

# Health check using the service's health endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/auth/health/live || exit 1

# Start the application
CMD ["./auth-service"]
