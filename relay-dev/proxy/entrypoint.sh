#!/bin/sh
# Proxy entrypoint: add the test "external" addresses, make sure the registry
# exists, then run sshpiperd.
#   EXTERNAL_IPS        comma-separated IPv4 addresses to add (/32)
#   EXTERNAL_IFACE      interface to add them to (default eth0)
#   SSHPIPERD_REGISTRY  registry path; created when missing
# Remaining arguments are passed to sshpiperd unchanged.
set -eu

iface="${EXTERNAL_IFACE:-eth0}"
for ip in $(printf '%s' "${EXTERNAL_IPS:-}" | tr ',' ' '); do
	if ! ip -4 addr show dev "$iface" | grep -q "inet $ip/"; then
		ip addr add "$ip/32" dev "$iface"
	fi
done
ip -4 -brief addr show dev "$iface"

if [ -n "${SSHPIPERD_REGISTRY:-}" ]; then
	/sshpiperd/registryctl init
fi

exec /sshpiperd/sshpiperd "$@"
