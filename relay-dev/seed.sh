#!/usr/bin/env bash
# Create the two test entries, give each its host keys, probe the backends and
# expose the entries. Idempotent: entries that already exist are left alone.
#   10.99.0.11 -> backend1 (user1)
#   10.99.0.12 -> backend2 (user2)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ctl() { compose exec -T proxy /sshpiperd/registryctl "$@"; }

wait_ssh() { # wait_ssh HOST
	compose exec -T tester sh -c "until nc -z $1 22; do sleep 0.5; done"
}

for n in 1 2; do
	ip="10.99.0.1$n"
	load_backend_env "$n"

	if ctl list | awk 'NR>1 {print $2}' | grep -qx "$ip"; then
		echo "== entry for $ip already exists, skipping"
		continue
	fi

	echo "== entry $n: $ip -> backend$n ($SSH_USER)"
	# the password goes through the environment, never on a command line
	compose exec -T -e RELAY_PW="$SSH_PASSWORD" proxy sh -c \
		"umask 077; printf %s \"\$RELAY_PW\" > /tmp/pw; /sshpiperd/registryctl add --ip $ip --user $SSH_USER --backend backend$n --password-file /tmp/pw; rm -f /tmp/pw"

	id="$(ctl list | awk -v ip="$ip" '$2 == ip {print $1}')"
	ctl persona gen --id "$id"

	# host keys go to the backend: replace the ones it generated itself
	compose exec -T proxy sh -c "rm -f /keys/backend$n/ssh_host_*"
	ctl persona export-keys --id "$id" --dir "/keys/backend$n"
	compose restart "backend$n" >/dev/null
	compose up -d --wait "backend$n" >/dev/null
	wait_ssh "backend$n"

	ctl probe --id "$id"
done

for n in 1 2; do
	ip="10.99.0.1$n"
	id="$(ctl list | awk -v ip="$ip" '$2 == ip {print $1}')"

	echo "== verify-front $ip (from the tester; differences are listed, not fatal)"
	compose exec -T tester registryctl verify-front --id "$id" --proxy "$ip" || true

	state="$(ctl list | awk -v ip="$ip" '$2 == ip {print $6}')"
	if [ "$state" = "ready" ]; then
		ctl expose --id "$id"
	fi
done

ctl list
