#!/usr/bin/env bash
# Launch the relay proxy. Reads /etc/relay/relay.env (or $RELAY_ENV) for the
# SSHPIPERD_* / RELAY_* variables (see relay.env.example), adds the external
# IPs to the interface, then runs sshpiperd with the relay plugin.
#
# Used directly or by relay-proxy.service. Needs CAP_NET_ADMIN (or root) to
# add the addresses, and CAP_NET_BIND_SERVICE (or root) to bind port 22.
set -euo pipefail

env_file="${RELAY_ENV:-/etc/relay/relay.env}"
if [ -f "$env_file" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$env_file"
	set +a
fi

bindir="${RELAY_BIN_DIR:-/usr/local/bin}"
iface="${RELAY_EXTERNAL_IFACE:-eth0}"

# add each external IP to the interface if missing (one per entry)
for ip in $(printf '%s' "${RELAY_EXTERNAL_IPS:-}" | tr ', ' '  '); do
	[ -n "$ip" ] || continue
	if ! ip -4 addr show dev "$iface" 2>/dev/null | grep -q "inet $ip/"; then
		echo "adding external address $ip to $iface"
		ip addr add "$ip/32" dev "$iface"
	fi
done

: "${SSHPIPERD_REGISTRY:?set SSHPIPERD_REGISTRY in $env_file}"
mkdir -p "$(dirname "$SSHPIPERD_REGISTRY")"
[ -z "${SSHPIPERD_AUDIT_DIR:-}" ] || mkdir -p "$SSHPIPERD_AUDIT_DIR"

# SSHPIPERD_PORT, SSHPIPERD_REGISTRY, SSHPIPERD_AUDIT_DIR, SSHPIPERD_SENSOR_NAME,
# SSHPIPERD_PRESERVE_SOURCE_PORT and SSHPIPERD_COPY_CLIENT_VERSION are read by
# sshpiperd from the environment, so they need not be repeated on the command
# line. The plugin takes the registry path explicitly.
exec "$bindir/sshpiperd" "$bindir/relay" --registry "$SSHPIPERD_REGISTRY"
