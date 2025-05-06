FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

# Just tidy and build, skip the init since go.mod already exists
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o proxy src/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/proxy .

# The container needs to run with network capabilities
# Use --cap-add=NET_ADMIN when running
EXPOSE 80

CMD ["./proxy"] 