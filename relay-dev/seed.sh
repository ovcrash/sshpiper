#!/usr/bin/env bash
# Create the two test accounts, give each site its generated host keys, probe
# the backends (which captures their real keys for the pin) and expose. In the
# multi-user model the backend keeps its own host keys; the proxy presents the
# generated site persona, so there is no key install on the backend anymore.
# Idempotent: accounts that already exist are left alone.
#   10.99.0.11 -> backend1 (user1)
#   10.99.0.12 -> backend2 (user2)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ctl() { compose exec -T proxy /sshpiperd/registryctl "$@"; }

for n in 1 2; do
	ip="10.99.0.1$n"
	load_backend_env "$n"

	if ctl list | awk 'NR>1 {print $2}' | grep -qx "$ip"; then
		echo "== account for $ip already exists, skipping"
		continue
	fi

	echo "== account $n: $ip ($SSH_USER) -> backend$n"
	compose exec -T -e RELAY_PW="$SSH_PASSWORD" proxy sh -c \
		"umask 077; printf %s \"\$RELAY_PW\" > /tmp/pw; /sshpiperd/registryctl add --ip $ip --user $SSH_USER --backend backend$n --password-file /tmp/pw; rm -f /tmp/pw"

	id="$(ctl list | awk -v ip="$ip" '$2 == ip {print $1}')"
	ctl persona gen --ip "$ip"   # the presented site identity (generated)
	ctl probe --id "$id"          # captures backend$n's real keys for the pin
done

for n in 1 2; do
	ip="10.99.0.1$n"
	id="$(ctl list | awk -v ip="$ip" '$2 == ip {print $1}')"

	echo "== verify-front $ip (from the tester; differences are listed, not fatal)"
	compose exec -T tester registryctl verify-front --ip "$ip" --proxy "$ip" || true

	state="$(ctl list | awk -v ip="$ip" '$2 == ip {print $6}')"
	if [ "$state" = "ready" ]; then
		ctl expose --id "$id"
	fi
done

ctl list
