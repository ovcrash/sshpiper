#!/usr/bin/env bash
# M0 smoke test, run against a bench started with up.sh. Every connection
# starts from the tester container.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
failures=0

pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

# tester_ssh PASSWORD ARGS...: ssh from the tester, password through SSHPASS
# so that it never shows up in a process list.
tester_ssh() {
	local password="$1"
	shift
	compose exec -T -e SSHPASS="$password" tester sshpass -e ssh "${SSH_OPTS[@]}" "$@"
}

load_backend_env 1
u1="$SSH_USER" p1="$SSH_PASSWORD"
load_backend_env 2
u2="$SSH_USER" p2="$SSH_PASSWORD"

echo "== backend1: effective sshd settings (sshd -T)"
compose exec -T backend1 sh -c 'grep -n "^Include" /etc/ssh/sshd_config; sshd -T | grep -E "^(kexalgorithms|ciphers|macs|compression|passwordauthentication) "'

for spec in "10.99.0.11 $u1 $p1 backend1" "10.99.0.12 $u2 $p2 backend2"; do
	set -- $spec
	echo "== password login through the proxy ($2@$1)"
	out="$(tester_ssh "$3" -tt "$2@$1" 'echo "host=$(hostname) user=$(id -un)"' | tr -d '\r')"
	echo "$out"
	if grep -q "host=$4 user=$2" <<<"$out"; then
		pass "login via $1 lands on $4"
	else
		fail "login via $1 did not land on $4"
	fi
done

echo "== wrong password is refused"
if tester_ssh "wrong-$p1" -o NumberOfPasswordPrompts=1 "$u1@10.99.0.11" true 2>&1; then
	fail "wrong password accepted"
else
	pass "wrong password refused"
fi

echo "== asciicast recordings in /audit"
casts="$(compose exec -T proxy find /audit -name '*.cast')"
if [ -n "$casts" ]; then
	echo "$casts"
	first="$(head -n1 <<<"$casts" | tr -d '\r')"
	compose exec -T proxy head -n 3 "$first"
	pass ".cast file recorded"
else
	fail "no .cast file in /audit"
fi

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all checks passed"
