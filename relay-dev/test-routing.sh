#!/usr/bin/env bash
# M3 checks, run against a bench started with up.sh (which seeds entries 1 and 2).
# Every connection starts from the tester container.
#   PASS/FAIL  hard criteria
#   KNOWN      differences that the SSH library cannot remove today (see
#              docs/relay/SPIKES.md); reported, not counted as failures
set -uo pipefail
. "$(dirname "$0")/lib.sh"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
failures=0

pass() { echo "PASS: $*"; }
known() { echo "KNOWN: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

ctl() { compose exec -T proxy /sshpiperd/registryctl "$@"; }
tester() { compose exec -T tester "$@"; }

# login PASSWORD HOST USER CMD: password login from the tester
login() {
	local pw="$1" host="$2" user="$3"
	shift 3
	compose exec -T -e SSHPASS="$pw" tester sshpass -e ssh "${SSH_OPTS[@]}" -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "$user@$host" "$@"
}

fingerprints() { # fingerprints HOST: "type fingerprint" lines
	tester sh -c "ssh-keyscan -t ed25519,ecdsa,rsa $1 2>/dev/null | ssh-keygen -lf - | awk '{print \$4, \$2}' | sort"
}

echo "== 1. host keys: each address presents its own site persona, decoupled from the backend"
for pair in "10.99.0.11 10.99.0.21" "10.99.0.12 10.99.0.22"; do
	set -- $pair
	front="$(fingerprints "$1")"
	back="$(fingerprints "$2")"
	if [ -n "$front" ] && [ "$front" != "$back" ]; then
		pass "$1 presents its own site host keys, distinct from backend $2"
	else
		fail "$1 should present the generated site persona, not the backend's keys"
		echo "$front" && echo "$back"
	fi
done
if [ "$(fingerprints 10.99.0.11 | sort -u | md5sum)" != "$(fingerprints 10.99.0.12 | sort -u | md5sum)" ]; then
	pass "the two addresses present different keys"
else
	fail "both addresses present the same keys"
fi

echo "== 2. version and algorithm lists, compared with the backend"
for pair in "10.99.0.11 10.99.0.21" "10.99.0.12 10.99.0.22"; do
	set -- $pair
	front="$(tester python3 /usr/local/bin/kexinit.py "$1" | tr -d '\r')"
	back="$(tester python3 /usr/local/bin/kexinit.py "$2" | tr -d '\r')"
	for field in version encryption_algorithms_server_to_client mac_algorithms_server_to_client compression_algorithms_server_to_client; do
		if [ "$(grep "^$field:" <<<"$front")" = "$(grep "^$field:" <<<"$back")" ]; then
			pass "$1 $field identical to $2"
		else
			fail "$1 $field differs from $2"
		fi
	done
	for field in kex_algorithms server_host_key_algorithms hasshServer; do
		if [ "$(grep "^$field:" <<<"$front")" = "$(grep "^$field:" <<<"$back")" ]; then
			pass "$1 $field identical to $2"
		else
			known "$1 $field differs from $2"
		fi
	done
done
echo "-- ssh-audit view of 10.99.0.11 (algorithm sections)"
tester ssh-audit -n 10.99.0.11 2>/dev/null | grep -E "^\(gen\)|^\(kex\)|^\(key\)|^\(enc\)|^\(mac\)" | head -20

echo "== 3. authentication"
. "$(dirname "$0")/secrets/backend1.env"
u1="$SSH_USER" p1="$SSH_PASSWORD"
. "$(dirname "$0")/secrets/backend2.env"
u2="$SSH_USER" p2="$SSH_PASSWORD"

out="$(login "$p1" 10.99.0.11 "$u1" hostname | tr -d '\r')"
[ "$out" = "backend1" ] && pass "correct password on 10.99.0.11 opens backend1" || fail "10.99.0.11 gave '$out'"
out="$(login "$p2" 10.99.0.12 "$u2" hostname | tr -d '\r')"
[ "$out" = "backend2" ] && pass "correct password on 10.99.0.12 opens backend2" || fail "10.99.0.12 gave '$out'"

via="$(login "wrong-$p1" 10.99.0.11 "$u1" true 2>&1 | tr -d '\r')"
direct="$(login "wrong-$p1" 10.99.0.21 "$u1" true 2>&1 | tr -d '\r')"
if grep -q "Permission denied" <<<"$via"; then pass "wrong password refused through the proxy"; else fail "wrong password: $via"; fi
echo "   via proxy: ${via##*: }   direct: ${direct##*: }"

via="$(login "$p1" 10.99.0.11 nosuchuser true 2>&1 | tr -d '\r')"
direct="$(login "$p1" 10.99.0.21 nosuchuser true 2>&1 | tr -d '\r')"
if grep -q "Permission denied" <<<"$via"; then pass "unknown user refused through the proxy"; else fail "unknown user: $via"; fi
echo "   via proxy: ${via##*: }   direct: ${direct##*: }"

# the credential of one address must not open the other one
out="$(login "$p1" 10.99.0.12 "$u1" true 2>&1 | tr -d '\r')"
grep -q "Permission denied" <<<"$out" && pass "credential of backend1 refused on 10.99.0.12" || fail "cross-credential: $out"

echo "== 4. key entry, added while the proxy runs"
started_before="$(docker inspect -f '{{.State.StartedAt}}' "$(compose ps -q proxy)")"

# a third address and a third backend (user3, key-only)
compose exec -T proxy sh -c 'ip addr show dev eth0 | grep -q "inet 10.99.0.13/" || ip addr add 10.99.0.13/32 dev eth0'
. "$(dirname "$0")/secrets/backend3.env"
u3="$SSH_USER"
ctl list | awk 'NR>1 {print $2}' | grep -qx 10.99.0.13 && { ctl retire --ip 10.99.0.13 >/dev/null 2>&1; echo "(an earlier run left 10.99.0.13 behind: recreate the bench with ./down.sh -v && ./up.sh)"; exit 1; }

compose exec -T proxy sh -c 'rm -f /tmp/k /tmp/k.pub /tmp/other /tmp/other.pub; ssh-keygen -q -t ed25519 -N "" -f /tmp/k; ssh-keygen -q -t ed25519 -N "" -f /tmp/other'
compose exec -T proxy cat /tmp/k.pub | compose exec -T backend3 sh -c "install -d -m 700 -o $u3 -g $u3 /home/$u3/.ssh && cat > /home/$u3/.ssh/authorized_keys && chown $u3:$u3 /home/$u3/.ssh/authorized_keys && chmod 600 /home/$u3/.ssh/authorized_keys"
ctl add --ip 10.99.0.13 --user "$u3" --backend backend3 --public-key /tmp/k.pub --private-key /tmp/k >/dev/null
ctl persona gen --ip 10.99.0.13 >/dev/null
compose exec -T proxy sh -c 'rm -f /keys/backend3/ssh_host_*'
ctl persona export-keys --ip 10.99.0.13 --dir /keys/backend3 >/dev/null
compose restart backend3 >/dev/null && compose up -d --wait backend3 >/dev/null
tester sh -c 'until nc -z backend3 22; do sleep 0.5; done'
# the key must be installed again: the container filesystem survives a restart, but check
ctl probe --ip 10.99.0.13 | tail -1

# before expose: not served to attackers, served to the tester (verification source)
ctl expose --ip 10.99.0.13 >/dev/null && pass "entry 10.99.0.13 exposed"

# the tester uses the private key of the entry as the "attacker"
compose exec -T proxy cat /tmp/k | compose exec -T tester sh -c 'cat > /tmp/k && chmod 600 /tmp/k'
compose exec -T proxy cat /tmp/other | compose exec -T tester sh -c 'cat > /tmp/other && chmod 600 /tmp/other'
out="$(tester ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i /tmp/k "$u3@10.99.0.13" hostname 2>&1 | tr -d '\r')"
[ "$out" = "backend3" ] && pass "the key of the entry opens backend3 through 10.99.0.13" || fail "key login: $out"
out="$(tester ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i /tmp/other "$u3@10.99.0.13" hostname 2>&1 | tr -d '\r')"
grep -q "Permission denied" <<<"$out" && pass "another key is refused" || fail "other key: $out"
n="$(compose exec -T backend3 sh -c "grep -c . /home/$u3/.ssh/authorized_keys" | tr -d '\r')"
[ "$n" = "1" ] && pass "authorized_keys of the backend holds exactly one key (the entry's)" || fail "authorized_keys has $n lines"

started_after="$(docker inspect -f '{{.State.StartedAt}}' "$(compose ps -q proxy)")"
[ "$started_before" = "$started_after" ] && pass "entry added and served without restarting the proxy" || fail "the proxy was restarted"

echo "== 5. retire without restart"
ctl retire --ip 10.99.0.13 >/dev/null
out="$(tester ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i /tmp/k "$u3@10.99.0.13" hostname 2>&1 | tr -d '\r')"
if grep -qiE "closed|reset|refused|kex_exchange" <<<"$out"; then pass "retired address closes the connection: $out"; else fail "retired address answered: $out"; fi
started_after="$(docker inspect -f '{{.State.StartedAt}}' "$(compose ps -q proxy)")"
[ "$started_before" = "$started_after" ] && pass "retired without restarting the proxy" || fail "the proxy was restarted"

echo "== 6. address not in the registry"
compose exec -T proxy sh -c 'ip addr show dev eth0 | grep -q "inet 10.99.0.14/" || ip addr add 10.99.0.14/32 dev eth0'
out="$(tester ssh "${SSH_OPTS[@]}" -o BatchMode=yes "x@10.99.0.14" true 2>&1 | tr -d '\r')"
if grep -qiE "closed|reset|refused|kex_exchange" <<<"$out"; then pass "unknown address closes without an answer: $out"; else fail "unknown address answered: $out"; fi

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all hard checks passed"
