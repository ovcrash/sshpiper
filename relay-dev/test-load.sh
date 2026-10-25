#!/usr/bin/env bash
# M7 load test: N concurrent sessions, each with output, all audited without
# loss; then a SIGTERM must flush the audit queue (graceful shutdown).
# Run against a bench started with up.sh.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

N="${1:-10}"
failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

load_backend_env 1
common="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no"
RUN="run$RANDOM"

echo "== $N concurrent sessions (run $RUN)"
# Fan out inside the tester (one docker exec): N parallel ssh, each printing a
# run-unique marker and some output. Collecting inside the container avoids
# losing stdout of many parallel "docker exec" on the host.
got="$(compose exec -T -e SSHPASS="$SSH_PASSWORD" -e N="$N" -e U="$SSH_USER" -e RUN="$RUN" -e COMMON="$common" tester sh -c '
	rm -rf /tmp/load; mkdir -p /tmp/load
	i=1
	while [ "$i" -le "$N" ]; do
		sshpass -e ssh $COMMON "$U@10.99.0.11" \
			"echo MARK-$RUN-$i-\$(hostname); for n in 1 2 3; do echo line-\$n; done" \
			> /tmp/load/$i 2>/dev/null &
		i=$((i + 1))
	done
	wait
	grep -h -c "MARK-$RUN-.*-backend1" /tmp/load/* | awk "{s+=\$1} END {print s}"
' | tr -d '\r')"
[ "$got" = "$N" ] && pass "$N/$N sessions reached backend1" || fail "$got/$N markers from backend1"

echo "== every session of this run fully audited"
sleep 1
audited="$(compose exec -T proxy sh -c "grep -l MARK-$RUN- /audit/*/*/events.jsonl 2>/dev/null | wc -l" | tr -d '\r')"
[ "$audited" = "$N" ] && pass "$N/$N sessions have their command recorded" || fail "$audited/$N sessions audited"

complete="$(compose exec -T proxy sh -c '
	n=0
	for f in $(grep -l MARK-'"$RUN"'- /audit/*/*/events.jsonl 2>/dev/null); do
		grep -q login.success "$f" && grep -q session.closed "$f" && n=$((n + 1))
	done
	echo $n' | tr -d '\r')"
[ "$complete" = "$N" ] && pass "$N/$N have login.success and session.closed" || fail "$complete/$N complete"

echo "== no audit records dropped under load"
dropped="$(compose exec -T proxy sh -c 'cat /audit/all-*.jsonl 2>/dev/null' | grep -c '"eventid":"piper.audit.dropped"' || true)"
[ "$dropped" = "0" ] && pass "no piper.audit.dropped events" || fail "$dropped drop events under load"

echo "== graceful shutdown flushes the audit (SIGTERM)"
marker="SHUTDOWN-$RANDOM"
compose exec -T -e SSHPASS="$SSH_PASSWORD" tester \
	sshpass -e ssh $common "$SSH_USER@10.99.0.11" "echo $marker" >/dev/null 2>&1
compose kill -s SIGTERM proxy >/dev/null 2>&1
for _ in $(seq 1 20); do
	compose ps proxy 2>/dev/null | grep -q "Up" || break
	sleep 0.5
done
found="$(compose run --rm --no-deps -v relay-dev_proxy-audit:/audit --entrypoint sh proxy -c "cat /audit/all-*.jsonl 2>/dev/null | grep -c $marker" 2>/dev/null | tr -d '\r')"
[ "${found:-0}" != "0" ] && pass "the session before SIGTERM was flushed to disk" || fail "session before SIGTERM not on disk"

compose up -d --wait proxy >/dev/null 2>&1

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all load/shutdown checks passed"
