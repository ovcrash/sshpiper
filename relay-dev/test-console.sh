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

echo "== the audit API lists sessions (capped and paginated)"
# Snapshot the list once inside the tester (the bench adds health-check
# sessions continuously, so two separate requests see different newest rows).
# All jq runs against that one snapshot.
compose exec -T tester sh -c "curl -s -H 'Authorization: Bearer $TOKEN' '$API/v1/audit/sessions?limit=500' > /tmp/sess.json"
tjq() { compose exec -T tester sh -c "jq -r '$1' /tmp/sess.json" | tr -d '\r'; }
n="$(tjq 'length')"
if [ "${n:-0}" -ge 1 ]; then pass "audit lists $n session(s)"; else fail "audit lists no sessions (n=$n)"; fi
if [ "${n:-0}" -le 1000 ]; then pass "list is capped ($n <= 1000)"; else fail "list not capped: $n"; fi

# pagination: page 2 must not repeat page 1's first id
id0="$(tjq '.[0].id')"
pg2id="$(compose exec -T tester sh -c "curl -s -H 'Authorization: Bearer $TOKEN' '$API/v1/audit/sessions?limit=2&offset=2' | jq -r '.[0].id'" | tr -d '\r')"
pg1id="$(compose exec -T tester sh -c "curl -s -H 'Authorization: Bearer $TOKEN' '$API/v1/audit/sessions?limit=2&offset=0' | jq -r '.[0].id'" | tr -d '\r')"
[ -n "$pg2id" ] && [ "$pg1id" != "$pg2id" ] && pass "pagination returns distinct pages" || fail "pagination page1=$pg1id page2=$pg2id"

echo "== detail + cast of a complete session (one with a recording)"
# pick, from the snapshot, a session that has a cast (so detail + cast are
# meaningful and already flushed), else fall back to the first row.
# extract day/id from the selected object inside the container to avoid quoting issues
compose exec -T tester sh -c "jq -c '(map(select(.channels>0))[0]) // .[0]' /tmp/sess.json > /tmp/sel.json"
day="$(compose exec -T tester sh -c "jq -r '.day' /tmp/sel.json" | tr -d '\r')"
id="$(compose exec -T tester sh -c "jq -r '.id' /tmp/sel.json" | tr -d '\r')"
if [ -n "$day" ] && [ "$day" != "null" ]; then
	compose exec -T tester sh -c "curl -s -H 'Authorization: Bearer $TOKEN' '$API/v1/audit/sessions/$day/$id' > /tmp/detail.json"
	c="$(code_auth "/v1/audit/sessions/$day/$id")"
	[ "$c" = "200" ] && pass "session detail -> 200" || fail "session detail -> $c"
	compose exec -T tester sh -c "jq -e '.events | length > 0' /tmp/detail.json" >/dev/null 2>&1 && pass "detail has an event timeline" || fail "detail has no events"
	cast="$(compose exec -T tester sh -c "jq -r '.casts[0].channel // empty' /tmp/detail.json" | tr -d '\r')"
	if [ -n "$cast" ]; then
		c="$(code_auth "/v1/audit/sessions/$day/$id/cast/$cast")"
		[ "$c" = "200" ] && pass "cast $cast -> 200" || fail "cast -> $c"
	else
		echo "note: selected session has no cast (ok)"
	fi
else
	fail "could not read a session id from the list"
fi

echo "== path traversal is refused"
c="$(code_auth "/v1/audit/sessions/2026-13-99/nope")"
[ "$c" = "404" ] && pass "bad day -> 404" || fail "bad day -> $c"
c="$(code_auth "/v1/audit/sessions/$day/$id/cast/..%2f..%2fevents.jsonl")"
{ [ "$c" = "404" ] || [ "$c" = "400" ]; } && pass "cast traversal refused ($c)" || fail "cast traversal -> $c"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all console checks passed"
