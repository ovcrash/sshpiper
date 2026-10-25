#!/usr/bin/env bash
# M4 checks: the audit records a full session, recon leaves a trace, the HASSH
# matches the reference, no password appears in the diagnostic logs, and the
# files have the right permissions. Run against a bench started with up.sh.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

load_backend_env 1
T="$(compose ps -q tester)"
OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

# copy via stdin: docker cp with a POSIX path misbehaves under MSYS_NO_PATHCONV
compose exec -T tester sh -c 'cat > /tmp/session.exp' <"$RELAY_DEV_DIR/spikes/session.exp"

echo "== generate traffic: interactive shell, exec, wrong password, recon banner grab"
compose exec -T tester expect -f /tmp/session.exp 10.99.0.11 "$SSH_USER" "$SSH_PASSWORD" >/dev/null 2>&1 || true
compose exec -T -e SSHPASS="$SSH_PASSWORD" tester sshpass -e ssh $OPTS -o PreferredAuthentications=password -o PubkeyAuthentication=no "$SSH_USER@10.99.0.11" 'id; exit 3' >/dev/null 2>&1 || true
compose exec -T -e SSHPASS=wrong tester sshpass -e ssh $OPTS -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 "$SSH_USER@10.99.0.11" true >/dev/null 2>&1 || true
compose exec -T tester sh -c 'ssh-9.8p1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=none -o BatchMode=yes 10.99.0.11 true 2>/dev/null; exit 0'
sleep 1

alljson() { compose exec -T proxy sh -c 'cat /audit/all-*.jsonl'; }
all="$(alljson)"

echo "== every expected event type is present"
for ev in piper.session.connect piper.client.version piper.client.kex piper.login.success piper.login.failed \
	piper.command.input piper.channel.input piper.channel.output piper.channel.request piper.channel.exit \
	piper.client.size piper.session.closed; do
	if grep -q "\"eventid\":\"$ev\"" <<<"$all"; then pass "event $ev present"; else fail "event $ev missing"; fi
done

echo "== exec session: command and exit status"
sess="$(compose exec -T proxy sh -c 'grep -l "\"input\":\"id; exit 3\"" /audit/*/*/events.jsonl | head -1' | tr -d '\r')"
if [ -n "$sess" ] && compose exec -T proxy cat "$sess" | grep -q '"exit_status":3'; then
	pass "exec command recorded with exit status 3"
else
	fail "exec command/exit not recorded"
fi

echo "== recon (no auth) recorded version + reference HASSH"
ref="$(awk '/^hassh:/{print $2}' "$RELAY_DEV_DIR/../sshkex/testdata/ssh-98p1.ref")"
if grep -q "\"hassh\":\"$ref\"" <<<"$all"; then
	pass "banner grab recorded with reference HASSH $ref"
else
	fail "recon HASSH $ref not recorded"
fi

echo "== asciicast replays with input and output"
cast="$(compose exec -T proxy sh -c 'ls /audit/*/*/channel-*.cast 2>/dev/null | head -1' | tr -d '\r')"
if [ -n "$cast" ]; then
	body="$(compose exec -T proxy cat "$cast")"
	if head -1 <<<"$body" | grep -q '"version": *2' && grep -q ',"o",' <<<"$body" && grep -q ',"i",' <<<"$body"; then
		pass "asciicast has a v2 header with i and o events"
	else
		fail "asciicast incomplete"
	fi
else
	fail "no asciicast file"
fi

echo "== no password in the diagnostic logs"
if compose logs --no-log-prefix proxy 2>&1 | grep -q "$SSH_PASSWORD"; then
	fail "the password appears in the diagnostic logs"
else
	pass "no password in the diagnostic logs"
fi

echo "== file permissions (0700 session dir, 0600 files)"
dmode="$(compose exec -T proxy sh -c 'stat -c %a "$(ls -d /audit/*/*/ | head -1)"' | tr -d '\r')"
fmode="$(compose exec -T proxy sh -c 'stat -c %a "$(ls /audit/*/*/events.jsonl | head -1)"' | tr -d '\r')"
[ "$dmode" = "700" ] && pass "session dir is 0700" || fail "session dir mode $dmode"
[ "$fmode" = "600" ] && pass "events.jsonl is 0600" || fail "events.jsonl mode $fmode"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all audit checks passed"
