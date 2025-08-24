# Multi-stage Docker build for OAuth2 Authentication Service
#
# Stage 1: Build stage
FROM golang:1.25-alpine AS builder

# Add stage label for build output
LABEL stage=builder

# Install build dependencies
RUN apk add --no-cache git=2.45.2-r0 ca-certificates=20240705-r0 tzdata=2024a-r1

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download and verify dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o auth-service \
    ./cmd/server

# Stage 2: Final stage
FROM scratch AS production

# Add stage label for build output
LABEL stage=production

# Copy timezone data from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /build/auth-service /auth-service

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /auth-service --health-check

# Create non-root user (even though scratch doesn't have user management,
# this sets the user ID for the process)
USER 1000:1000

# Run the application
ENTRYPOINT ["/auth-service"]
