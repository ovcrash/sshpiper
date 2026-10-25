#!/usr/bin/env bash
# Stop the dev bench. Pass -v to also delete the host key volumes.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

compose down --remove-orphans "$@"
