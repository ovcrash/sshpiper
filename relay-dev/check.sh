#!/usr/bin/env bash
# Upstream quality gates in golang:1.27-bookworm: gofumpt, go vet, unit
# tests with -race (both modules) and, unless --no-lint, golangci-lint.
# The repository is copied inside the container so that the CRLF working
# tree of a Windows checkout does not leak into the checks.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

lint=1
if [ "${1:-}" = "--no-lint" ]; then
	lint=0
fi

docker run --rm \
	-e LINT="$lint" \
	-v "$(docker_repo_path):/src:ro" \
	-v relay-dev-gomod:/go/pkg/mod \
	-v relay-dev-gocache:/root/.cache/go-build \
	-v relay-dev-gobin:/go/bin \
	-v relay-dev-gocache-runner:/usercache \
	docker.io/golang:1.27-bookworm bash -euo pipefail -c '
		mkdir /work
		tar -C /src --exclude=./relay-dev/audit --exclude=./relay-dev/secrets -cf - . | tar -C /work -xf -
		cd /work
		git config --global --add safe.directory /work
		# undo core.autocrlf: convert files git stores with LF but the
		# checkout has with CRLF
		git ls-files --eol | awk "\$1==\"i/lf\" && \$2==\"w/crlf\" {print \$NF}" | xargs -r sed -i "s/\r\$//"

		[ -x /go/bin/gofumpt ] || go install mvdan.cc/gofumpt@v0.8.0
		echo "== gofumpt -l ."
		out="$(gofumpt -l .)"
		if [ -n "$out" ]; then echo "$out"; exit 1; fi
		echo "(empty)"

		echo "== go vet (root, -tags full)"
		go vet -tags full ./...
		echo "== go vet (cmd/sshpiperd)"
		(cd cmd/sshpiperd && go vet ./...)

		# Tests run as an unprivileged user, like upstream CI: some of them
		# (e.g. an unreadable key file) cannot fail as root.
		useradd -u 1000 -m runner
		chown -R runner /work /usercache
		as_runner() {
			setpriv --reuid=1000 --regid=1000 --init-groups \
				env HOME=/home/runner GOCACHE=/usercache PATH="$PATH" "$@"
		}
		echo "== go test -race -cover -tags full ./... (root module)"
		as_runner go test -race -cover -tags full ./...
		echo "== go test -race -cover ./... (cmd/sshpiperd)"
		(cd cmd/sshpiperd && as_runner go test -race -cover ./...)

		if [ "$LINT" = 1 ]; then
			[ -x /go/bin/golangci-lint ] || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
			golangci-lint version
			echo "== golangci-lint (root)"
			GOGC=10 golangci-lint run --timeout=60m --build-tags full -D errcheck
			echo "== golangci-lint (cmd/sshpiperd)"
			(cd cmd/sshpiperd && GOGC=10 golangci-lint run --timeout=60m -D errcheck)
		fi
		echo "== all gates passed"
	'
