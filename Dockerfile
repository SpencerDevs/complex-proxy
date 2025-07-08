FROM golang:1.21-alpine AS builder

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

WORKDIR /app

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./src ./
RUN go build -o i6shark main.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/i6shark .

EXPOSE 80

CMD ["./i6shark"]
