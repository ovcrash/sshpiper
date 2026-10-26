#!/usr/bin/env bash
# Register one entry with registryctl and walk it to "exposed". The backend VM
# must already exist. After generating the persona this prints the host keys to
# install on the VM, then waits for you to confirm before probing and exposing.
#
#   sudo RELAY_ENV=/etc/relay/relay.env ./deploy/register-entry.sh \
#       --ip 203.0.113.10 --user alice --backend 10.0.0.21 --password-file pw.txt
#
# Any extra add flags (--public-key/--private-key instead of --password) are
# passed through to "registryctl add".
set -euo pipefail

env_file="${RELAY_ENV:-/etc/relay/relay.env}"
[ -f "$env_file" ] && { set -a; . "$env_file"; set +a; }
: "${SSHPIPERD_REGISTRY:?set SSHPIPERD_REGISTRY (in $env_file or the environment)}"
ctl="${RELAY_BIN_DIR:-/usr/local/bin}/registryctl"
export SSHPIPERD_REGISTRY

ip=""
for ((i = 1; i <= $#; i++)); do
	if [ "${!i}" = "--ip" ]; then
		j=$((i + 1))
		ip="${!j}"
	fi
done
[ -n "$ip" ] || {
	echo "a --ip is required" >&2
	exit 1
}

"$ctl" add "$@"
"$ctl" persona gen --ip "$ip"

keydir="$(mktemp -d)"
"$ctl" persona export-keys --ip "$ip" --dir "$keydir"
echo
echo "Host keys written to $keydir — install them on the VM as /etc/ssh/ssh_host_*"
echo "and restart its sshd. Then press Enter to probe and expose (Ctrl-C to stop)."
read -r _

"$ctl" probe --ip "$ip"
"$ctl" expose --ip "$ip"
"$ctl" show --ip "$ip"
echo "entry $ip is exposed."
