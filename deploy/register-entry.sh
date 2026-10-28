#!/usr/bin/env bash
# Register one account with registryctl and walk it to "exposed". The backend
# VM (the ssh target) must already exist. In the multi-user model the proxy
# presents a generated site persona per IP and the probe captures the backend's
# own host keys, so nothing is installed on the VM. An IP can carry several
# accounts (one per username); the site persona is shared and generated once.
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

ip="" user=""
for ((i = 1; i <= $#; i++)); do
	case "${!i}" in
	--ip) j=$((i + 1)); ip="${!j}" ;;
	--user) j=$((i + 1)); user="${!j}" ;;
	esac
done
[ -n "$ip" ] && [ -n "$user" ] || {
	echo "both --ip and --user are required" >&2
	exit 1
}

"$ctl" add "$@"

# The site persona (host keys presented on this IP) is shared by every account.
# Generate it once; keep it if the site already has one (another account added it).
"$ctl" persona gen --ip "$ip" || echo "(site $ip already has host keys — keeping them)"

# The probe captures the backend's real host keys (the connection pin) and
# checks this account's credential — no key install on the VM.
"$ctl" probe --ip "$ip" --user "$user"
"$ctl" expose --ip "$ip" --user "$user"
"$ctl" show --ip "$ip" --user "$user"
echo "account $user@$ip is exposed."
