# Build context: repository root (see docker-compose.yml).
FROM docker.io/golang:1.27-bookworm AS tools
ENV CGO_ENABLED=0
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -o /out/registryctl ./cmd/registryctl

FROM docker.io/debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-client sshpass nmap tcpdump python3 python3-venv jq expect \
      iproute2 iputils-ping netcat-openbsd ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Debian refuses system-wide pip installs (PEP 668): use a venv.
RUN python3 -m venv /opt/ssh-audit \
 && /opt/ssh-audit/bin/pip install --no-cache-dir ssh-audit \
 && ln -s /opt/ssh-audit/bin/ssh-audit /usr/local/bin/ssh-audit

# Static OpenSSH clients with distinct HASSH, as in the upstream testrunner.
COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/local/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/local/bin/ssh-8.0p1

# Registry client, to run verify-front from an allowed source address.
COPY --from=tools /out/registryctl /usr/local/bin/registryctl
COPY relay-dev/spikes/kexinit.py /usr/local/bin/kexinit.py

CMD ["sleep", "infinity"]
