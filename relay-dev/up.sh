#!/usr/bin/env bash
# Build and start the dev bench (one command). Extra arguments are passed to
# "docker compose up", e.g. ./up.sh --force-recreate
set -euo pipefail
. "$(dirname "$0")/lib.sh"

mkdir -p "$RELAY_DEV_DIR/secrets" "$RELAY_DEV_DIR/audit"
chmod 0700 "$RELAY_DEV_DIR/secrets" 2>/dev/null || true

for n in 1 2 3; do
	f="$RELAY_DEV_DIR/secrets/backend$n.env"
	if [ ! -f "$f" ]; then
		umask 077
		printf 'SSH_USER=user%s\nSSH_PASSWORD=%s\n' "$n" "$(random_password)" >"$f"
		echo "created $f"
	fi
done

compose up --build --detach --wait "$@"
"$(dirname "$0")/seed.sh"
compose ps
