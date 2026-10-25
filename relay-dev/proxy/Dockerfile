# Build context: repository root (see docker-compose.yml).
FROM docker.io/golang:1.27-bookworm AS builder
ENV CGO_ENABLED=0
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    mkdir -p /out/plugins \
 && (cd cmd/sshpiperd && go build -o /out/sshpiperd .) \
 && go build -tags full -o /out/plugins ./plugin/... ./relay-dev/spikes/... \
 && go build -o /out/registryctl ./cmd/registryctl

FROM docker.io/debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iptables openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/ /sshpiperd/
COPY relay-dev/proxy/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh && mkdir -p /var/lib/sshpiperd /audit && chmod 0700 /var/lib/sshpiperd /audit

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
