# Multi-stage build for mailscript
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /build/bin/mailscript ./cmd/mailscript

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata netcat-openbsd

RUN addgroup -g 1000 mailscript && \
    adduser -D -u 1000 -G mailscript mailscript

WORKDIR /opt/mailscript

COPY --from=builder /build/bin/mailscript /usr/local/bin/

RUN mkdir -p /opt/mailscript/policies && \
    chown -R mailscript:mailscript /opt/mailscript

USER mailscript

EXPOSE 3025 3587 50051

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z 127.0.0.1 3025 || exit 1

ENTRYPOINT ["/usr/local/bin/mailscript"]
CMD ["proxy", "--help"]
