#!/usr/bin/env bash
# Build the relay binaries into a destination directory (default /usr/local/bin).
# Pure Go, no CGO, Go 1.27. Run from a clone of the repository.
#
#   sudo ./deploy/build.sh              # installs into /usr/local/bin
#   ./deploy/build.sh ./out             # installs into ./out
set -euo pipefail

dest="${1:-/usr/local/bin}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$dest"
export CGO_ENABLED=0

echo "building sshpiperd (daemon)…"
(cd "$repo/cmd/sshpiperd" && go build -o "$dest/sshpiperd" .)

echo "building the relay plugin…"
(cd "$repo" && go build -tags full -o "$dest/relay" ./plugin/relay)

echo "building registryctl (CLI)…"
(cd "$repo" && go build -o "$dest/registryctl" ./cmd/registryctl)

# The console UI bundle (cmd/relay-admind/web/dist) is committed, so relay-admind
# builds without Node. Regenerate it only if a toolchain is present and you
# changed the frontend sources.
if command -v npm >/dev/null 2>&1; then
	echo "rebuilding the console bundle (npm found)…"
	(cd "$repo/cmd/relay-admind/web" && npm ci --silent && npm run build)
else
	echo "npm not found; using the committed console bundle"
fi

echo "building relay-admind (registration API + console)…"
(cd "$repo" && go build -o "$dest/relay-admind" ./cmd/relay-admind)

echo "done. binaries in $dest:"
ls -1 "$dest"/sshpiperd "$dest"/relay "$dest"/registryctl "$dest"/relay-admind
