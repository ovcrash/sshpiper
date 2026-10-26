#!/usr/bin/env bash
# M8 checks: register an entry entirely through the relay-admind REST API
# (as an external automation would, after creating the VM), then the proxy
# serves it without a restart. Run against a bench started with up.sh.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

TOKEN="${RELAY_ADMIN_TOKEN:-bench-token}"
API="http://10.99.0.3:8090"
IP="10.99.0.13"       # a spare external address, served by backend3
failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

# api METHOD PATH [BODY] : curl from the tester, prints "HTTPCODE\n BODY"
api() {
	local method="$1" path="$2" body="${3:-}"
	compose exec -T tester sh -c "curl -s -o /tmp/body -w '%{http_code}' -X $method \
		-H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \
		${body:+--data '$body'} $API$path; echo; cat /tmp/body"
}

load_backend_env 3
u3="$SSH_USER" p3="$SSH_PASSWORD"

# make sure a previous run left nothing behind
if compose exec -T proxy /sshpiperd/registryctl list | awk 'NR>1{print $2}' | grep -qx "$IP"; then
	echo "entry $IP already exists; recreate the bench (./down.sh -v && ./up.sh)"
	exit 1
fi

echo "== healthz (no token) and auth"
code="$(compose exec -T tester sh -c "curl -s -o /dev/null -w '%{http_code}' $API/v1/healthz")"
[ "$code" = "200" ] && pass "healthz 200" || fail "healthz $code"
code="$(compose exec -T tester sh -c "curl -s -o /dev/null -w '%{http_code}' $API/v1/entries")"
[ "$code" = "401" ] && pass "no token -> 401" || fail "no token -> $code"

echo "== register the entry via the API"
out="$(api POST /v1/entries "{\"external_ip\":\"$IP\",\"username\":\"$u3\",\"backend_host\":\"10.99.0.23\",\"password\":\"$p3\"}")"
code="$(head -1 <<<"$out")"
body="$(tail -n +2 <<<"$out")"
[ "$code" = "201" ] && pass "create -> 201" || fail "create -> $code: $body"
grep -q "$p3" <<<"$body" && fail "create response leaks the password" || pass "no password in the create response"

echo "== generate the persona, fetch the host keys (as the VM builder would)"
code="$(head -1 <<<"$(api POST /v1/entries/$IP/persona/generate)")"
[ "$code" = "200" ] && pass "persona generate -> 200" || fail "persona generate -> $code"
keys="$(tail -n +2 <<<"$(api GET /v1/entries/$IP/persona/keys)")"
echo "$keys" | compose exec -T tester sh -c 'cat > /tmp/keys.json'
# install the keys on backend3 and restart it (the external VM provisioning step)
for t in ed25519 ecdsa rsa; do
	compose exec -T tester sh -c "jq -r .$t /tmp/keys.json" | compose exec -T backend3 sh -c "cat > /hostkeys/ssh_host_${t}_key; chmod 600 /hostkeys/ssh_host_${t}_key"
done
compose restart backend3 >/dev/null 2>&1
compose up -d --wait backend3 >/dev/null 2>&1

echo "== probe and expose via the API"
out="$(api POST /v1/entries/$IP/probe)"
pbody="$(tail -n +2 <<<"$out")"
if [ "$(head -1 <<<"$out")" = "200" ] && grep -q '"Problems":null' <<<"$pbody"; then
	pass "probe -> ready (no problems)"
else
	fail "probe: $(head -1 <<<"$out") $pbody"
fi
out="$(api POST /v1/entries/$IP/expose)"
[ "$(head -1 <<<"$out")" = "200" ] && pass "expose -> 200" || fail "expose -> $(head -1 <<<"$out"): $(tail -n +2 <<<"$out")"

# the external address must exist on the proxy for the tester to reach it
compose exec -T proxy sh -c "ip addr show dev eth0 | grep -q 'inet $IP/' || ip addr add $IP/32 dev eth0"

echo "== the proxy serves the API-registered address without a restart"
started_before="$(docker inspect -f '{{.State.StartedAt}}' "$(compose ps -q proxy)")"
host="$(compose exec -T -e SSHPASS="$p3" tester sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no "$u3@$IP" hostname | tr -d '\r')"
[ "$host" = "backend3" ] && pass "login on $IP lands on backend3" || fail "login gave '$host'"
started_after="$(docker inspect -f '{{.State.StartedAt}}' "$(compose ps -q proxy)")"
[ "$started_before" = "$started_after" ] && pass "proxy not restarted" || fail "proxy restarted"

echo "== retire via the API closes the address"
code="$(head -1 <<<"$(api POST /v1/entries/$IP/retire '{}')")"
[ "$code" = "200" ] && pass "retire -> 200" || fail "retire -> $code"
out="$(compose exec -T tester ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes "x@$IP" true 2>&1 | tr -d '\r')"
grep -qiE "closed|reset|refused|kex_exchange" <<<"$out" && pass "retired address closes: $out" || fail "retired address answered: $out"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all admin API checks passed"
