#!/usr/bin/env bash
# Console checks: relay-admind serves the operator console UI without a token,
# gates every /v1 call behind the token, and the read-only audit API lists a
# recorded session, returns its detail and serves its asciicast. Run against a
# bench started with up.sh.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

TOKEN="${RELAY_ADMIN_TOKEN:-bench-token}"
API="http://10.99.0.3:8090"
failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

# curl helpers run from the tester container. code_* print the HTTP status.
code_noauth() { compose exec -T tester sh -c "curl -s -o /dev/null -w '%{http_code}' '$API$1'"; }
code_auth() { compose exec -T tester sh -c "curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer $TOKEN' '$API$1'"; }
body_auth() { compose exec -T tester sh -c "curl -s -H 'Authorization: Bearer $TOKEN' '$API$1'"; }
body_noauth() { compose exec -T tester sh -c "curl -s '$API$1'"; }

echo "== the console UI is served without a token"
c="$(code_noauth /)"
[ "$c" = "200" ] && pass "GET / -> 200" || fail "GET / -> $c"
body_noauth / | grep -qi "relay console" && pass "index.html is the console" || fail "index.html unexpected"
c="$(code_noauth /dist/app.js)"
[ "$c" = "200" ] && pass "GET /dist/app.js -> 200" || fail "app.js -> $c"
c="$(code_noauth /dist/app.css)"
[ "$c" = "200" ] && pass "GET /dist/app.css -> 200" || fail "app.css -> $c"

echo "== /v1 is gated by the token"
c="$(code_noauth /v1/audit/sessions)"
[ "$c" = "401" ] && pass "audit sessions without token -> 401" || fail "no token -> $c"
c="$(code_auth /v1/audit/sessions)"
[ "$c" = "200" ] && pass "audit sessions with token -> 200" || fail "with token -> $c"

echo "== generate one audited session"
load_backend_env 1
OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o PreferredAuthentications=password -o PubkeyAuthentication=no"
compose exec -T -e SSHPASS="$SSH_PASSWORD" tester sshpass -e ssh $OPTS "$SSH_USER@10.99.0.11" 'uname -a; exit 0' >/dev/null 2>&1 || true
sleep 1

echo "== the audit API lists the session, returns its detail and its cast"
sessions="$(body_auth /v1/audit/sessions)"
n="$(echo "$sessions" | jq 'length' 2>/dev/null || echo 0)"
if [ "${n:-0}" -ge 1 ]; then
	pass "audit lists $n session(s)"
else
	fail "audit lists no sessions: $sessions"
fi
day="$(echo "$sessions" | jq -r '.[0].day' 2>/dev/null)"
id="$(echo "$sessions" | jq -r '.[0].id' 2>/dev/null)"
if [ -n "$day" ] && [ "$day" != "null" ]; then
	c="$(code_auth "/v1/audit/sessions/$day/$id")"
	[ "$c" = "200" ] && pass "session detail -> 200" || fail "session detail -> $c"
	detail="$(body_auth "/v1/audit/sessions/$day/$id")"
	echo "$detail" | jq -e '.events | length > 0' >/dev/null 2>&1 && pass "detail has an event timeline" || fail "detail has no events"
	cast="$(echo "$detail" | jq -r '.casts[0].channel // empty' 2>/dev/null)"
	if [ -n "$cast" ]; then
		c="$(code_auth "/v1/audit/sessions/$day/$id/cast/$cast")"
		[ "$c" = "200" ] && pass "cast $cast -> 200" || fail "cast -> $c"
	else
		echo "note: no cast in the first session (ok)"
	fi
else
	fail "could not read a session id from the list"
fi

echo "== path traversal is refused"
c="$(code_auth "/v1/audit/sessions/2026-13-99/nope")"
[ "$c" = "404" ] && pass "bad day -> 404" || fail "bad day -> $c"
c="$(code_auth "/v1/audit/sessions/$day/$id/cast/..%2f..%2fevents.jsonl")"
[ "$c" = "404" ] || [ "$c" = "400" ] && pass "cast traversal refused ($c)" || fail "cast traversal -> $c"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all console checks passed"
