# Build context: repository root (see docker-compose.yml).
FROM docker.io/golang:1.27-bookworm AS builder
ENV CGO_ENABLED=0
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -o /out/relay-admind ./cmd/relay-admind

FROM docker.io/debian:bookworm-slim
# openssh-client is needed by the probe to read the backend's auth methods
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/relay-admind /usr/local/bin/relay-admind
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/relay-admind"]
