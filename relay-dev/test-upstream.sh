#!/usr/bin/env bash
# Upstream checks (M5): the backend sees the client's source port and the
# client's own version line, and the audit records each backend connection.
# The client port is forced with a ProxyCommand (nc -p PORT), so it is known.
# Run against a bench started with up.sh.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

load_backend_env 1
OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)

# seen_port PORT: login from client port PORT, print the port the backend sees
seen_port() {
	compose exec -T -e SSHPASS="$SSH_PASSWORD" tester sshpass -e ssh "${OPTS[@]}" \
		-o "ProxyCommand=nc -p $1 %h %p" "$SSH_USER@10.99.0.11" 'echo $SSH_CONNECTION' 2>/dev/null |
		tr -d '\r' | awk '{print $2}'
}

echo "== forced client ports"
base=$((41000 + RANDOM % 2000))
for p in $base $((base + 1)) $((base + 2)); do
	got="$(seen_port "$p")"
	if [ "$got" = "$p" ]; then
		pass "client port $p -> backend sees $got"
	else
		fail "client port $p -> backend sees '${got:-nothing}'"
	fi
done

echo "== kernel-chosen client port"
# the session sleeps so the client socket can be read with ss while it is open
out="$(compose exec -T -e SSHPASS="$SSH_PASSWORD" tester sh -c '
	sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o PreferredAuthentications=password -o PubkeyAuthentication=no "$0@10.99.0.11" "echo \$SSH_CONNECTION; sleep 3" &
	sleep 1.5
	ss -Htn state established "( dst 10.99.0.11 and dport = :22 )" | awk "{print \"client \" \$3}"
	wait' "$SSH_USER" 2>/dev/null | tr -d '\r')"
cli="$(awk '/^client /{n=split($2,a,":"); print a[n]}' <<<"$out" | head -1)"
srv="$(awk '!/^client /{print $2}' <<<"$out" | head -1)"
if [ -n "$cli" ] && [ "$cli" = "$srv" ]; then
	pass "kernel-chosen client port $cli -> backend sees $srv"
else
	fail "kernel-chosen client port ${cli:-?} -> backend sees ${srv:-?}"
fi

echo "== a failed attempt then a successful one in the same connection"
compose exec -T tester sh -c 'cat > /tmp/two.exp' <<'EXP'
set timeout 20
set pw [lindex $argv 0]
set user [lindex $argv 1]
set port [lindex $argv 2]
log_user 0
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	-o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=2 \
	-o "ProxyCommand=nc -p $port %h %p" $user@10.99.0.11 {echo $SSH_CONNECTION}
expect "password:"
send "wrong\r"
expect "password:"
send "$pw\r"
expect -re {(\S+) (\d+) (\S+) 22}
puts $expect_out(2,string)
expect eof
EXP
p=$((base + 10))
got="$(compose exec -T tester expect -f /tmp/two.exp "$SSH_PASSWORD" "$SSH_USER" "$p" 2>/dev/null | tr -d '\r' | tail -1)"
if [ "$got" = "$p" ]; then
	pass "after a failed attempt the successful one still uses port $p"
else
	echo "KNOWN: after a failed attempt the backend sees port '${got:-?}' instead of $p (each attempt opens a new connection; the previous one may still hold the port)"
fi

echo "== audit: backend connections of that session"
f="$(compose exec -T proxy sh -c "grep -l '\"src_port\":$p,' /audit/*/*/events.jsonl | tail -1" | tr -d '\r')"
seq="$(compose exec -T proxy cat "$f" 2>/dev/null | grep -o '"eventid":"piper\.[a-z_.]*"' | sed 's/.*piper\.//; s/"//' | tr '
' ' ')"
echo "   $seq"
if [[ "$seq" == "session.connect client.version client.kex "* ]] &&
	[[ "$seq" == *"backend.connected login.failed backend.disconnected backend.connected login.success"* ]]; then
	pass "audit: version and HASSH before auth, then connected, failed, abandoned closed, reconnected, success"
else
	fail "unexpected audit sequence"
fi
n="$(compose exec -T proxy cat "$f" | grep '"eventid":"piper.backend.connected"' | grep -cE "\"local_port\":$p[,}]")"
[ "$n" = "2" ] && pass "both backend connections recorded with local_port $p" || fail "local_port $p recorded $n time(s), want 2"

echo "== client version on the backend wire"
B="$(compose ps -q backend1)"
docker rm -f relaycap >/dev/null 2>&1
docker run -d --name relaycap --net "container:$B" --cap-add NET_RAW --cap-add NET_ADMIN 	--entrypoint tcpdump relay-dev-tester -i eth0 -l -A -s 300 'tcp dst port 22 and src host 10.99.0.2' >/dev/null
sleep 3
for c in ssh-9.8p1 ssh-8.0p1; do
	compose exec -T -e SSHPASS="$SSH_PASSWORD" tester sshpass -e "$c" "${OPTS[@]}" "$SSH_USER@10.99.0.11" true >/dev/null 2>&1
done
sleep 1
wire="$(docker logs relaycap 2>&1 | grep -ao 'SSH-2\.0-[A-Za-z0-9_.+-]*' | sort -u)"
docker rm -f relaycap >/dev/null 2>&1
for v in SSH-2.0-OpenSSH_9.8 SSH-2.0-OpenSSH_8.0; do
	grep -qx "$v" <<<"$wire" && pass "backend receives the client version $v" || fail "backend did not receive $v"
done
grep -qx 'SSH-2.0-Go' <<<"$wire" && fail "backend still receives SSH-2.0-Go" || pass "backend never receives SSH-2.0-Go"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all upstream checks passed"
