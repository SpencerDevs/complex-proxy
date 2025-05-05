FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install required dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy Go module files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY src ./src

# Build the application
RUN CGO_ENABLED=1 go build -o i6shark src/main.go

# Create a minimal runtime image
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy the built binary from the builder stage
COPY --from=builder /app/i6shark .

# Copy .env file
COPY .env .

# Expose the service port
EXPOSE 80

# Run the application
CMD ["./i6shark"] 