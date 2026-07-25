# ==========================================
# STAGE 1: Build static binary Go
# ==========================================
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy dependency manifests first to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically-linked binary with debug symbol stripping (-s -w)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /app/trimly-api ./cmd/api

# ==========================================
# STAGE 2: Minimalist production runtime image
# ==========================================
FROM alpine:3.21

# Install CA certificates and timezone data
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/trimly-api /app/trimly-api

# Change ownership to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Environment variables default
ENV PORT=8080

# Command to run binary
ENTRYPOINT ["/app/trimly-api"]
