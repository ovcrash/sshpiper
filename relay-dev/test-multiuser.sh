#!/usr/bin/env bash
# Multi-user check: one external IP serves several users, each with its own
# credential, routing to possibly different backends, while presenting one
# shared site persona (host key). Run against a bench started with up.sh (the
# seed exposes 10.99.0.11 -> backend1 as user1).
set -uo pipefail
. "$(dirname "$0")/lib.sh"

TOKEN="${RELAY_ADMIN_TOKEN:-bench-token}"
API="http://10.99.0.3:8090"
IP="10.99.0.11"
failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

api() {
	local m="$1" p="$2" b="${3:-}"
	compose exec -T tester sh -c "curl -s -o /tmp/body -w '%{http_code}' -X $m \
		-H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \
		${b:+--data '$b'} $API$p; echo; cat /tmp/body"
}

load_backend_env 2
u2="$SSH_USER" p2="$SSH_PASSWORD"
load_backend_env 1
u1="$SSH_USER" p1="$SSH_PASSWORD"

echo "== add a second user on $IP that routes to a different backend (backend2)"
out="$(api POST /v1/accounts "{\"external_ip\":\"$IP\",\"username\":\"$u2\",\"backend_host\":\"10.99.0.22\",\"password\":\"$p2\"}")"
code="$(head -1 <<<"$out")"
body="$(tail -n +2 <<<"$out")"
[ "$code" = "201" ] && pass "second account created" || fail "create: $code $body"
id2="$(sed -n 's/.*"id":\([0-9]*\).*/\1/p' <<<"$body")"

echo "== probe and expose the second account (site persona already set by the seed)"
api POST "/v1/accounts/$id2/probe" >/dev/null
out="$(api POST "/v1/accounts/$id2/expose")"
[ "$(head -1 <<<"$out")" = "200" ] && pass "second account exposed" || fail "expose: $out"

OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10"

echo "== each user lands on its own backend through the same IP"
h1="$(compose exec -T -e SSHPASS="$p1" tester sshpass -e ssh $OPTS "$u1@$IP" hostname | tr -d '\r')"
[ "$h1" = "backend1" ] && pass "$u1@$IP -> backend1" || fail "$u1@$IP -> '$h1'"
h2="$(compose exec -T -e SSHPASS="$p2" tester sshpass -e ssh $OPTS "$u2@$IP" hostname | tr -d '\r')"
[ "$h2" = "backend2" ] && pass "$u2@$IP -> backend2" || fail "$u2@$IP -> '$h2'"

echo "== the IP presents one host key (the site persona), distinct from other IPs"
k11="$(compose exec -T tester ssh-keyscan -t ed25519 "$IP" 2>/dev/null | awk '{print $3}' | head -1)"
k12="$(compose exec -T tester ssh-keyscan -t ed25519 10.99.0.12 2>/dev/null | awk '{print $3}' | head -1)"
[ -n "$k11" ] && pass "site key present on $IP" || fail "no site key on $IP"
[ -n "$k11" ] && [ "$k11" != "$k12" ] && pass "different IPs present different site keys" || fail "sites share a host key"

echo "== an unknown user on the IP is refused (no account enumeration)"
out="$(compose exec -T -e SSHPASS=whatever tester sshpass -e ssh $OPTS -o NumberOfPasswordPrompts=1 "nosuchuser@$IP" true 2>&1 | tr -d '\r')"
grep -qiE "permission denied|authentication failed" <<<"$out" && pass "unknown user refused: $out" || fail "unknown user not refused: $out"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all multi-user checks passed"
