#!/usr/bin/env bash
# M6 checks: scp and sftp transfers in both directions are logged and copied on
# the proxy, with the same SHA-256 as the file on the backend and on the client.
# The transfer itself must reach the backend unchanged. Run after up.sh.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

failures=0
pass() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

load_backend_env 1
sshenv="SSHPASS=$SSH_PASSWORD"
common="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no"

# tester runs a command, sshpass feeds the password
t() { compose exec -T -e "$sshenv" tester sh -c "$1"; }

echo "== prepare files on the tester and the backend"
t "head -c 200000 /dev/urandom > /tmp/up.bin; sha256sum /tmp/up.bin | cut -d' ' -f1 > /tmp/up.sha"
up_sha="$(t 'cat /tmp/up.sha' | tr -d '\r')"
# a file on the backend to download (via a shell exec through the proxy)
t "sshpass -e ssh $common $SSH_USER@10.99.0.11 'head -c 150000 /dev/urandom > /tmp/down.bin; sha256sum /tmp/down.bin | cut -d\" \" -f1' > /tmp/down.sha"
down_sha="$(t 'cat /tmp/down.sha' | tr -d '\r')"

run_case() { # run_case TRANSFER DIR CMD  (CMD already includes sshpass)
	echo "== $1 $2"
	t "$3" >/dev/null 2>&1 || true
	sleep 1
}

# scp upload (OpenSSH 9.x defaults to sftp; force the legacy protocol with -O)
run_case scp upload "sshpass -e scp -O $common /tmp/up.bin $SSH_USER@10.99.0.11:/tmp/up-scp.bin"
# scp download
run_case scp download "sshpass -e scp -O $common $SSH_USER@10.99.0.11:/tmp/down.bin /tmp/down-scp.bin"
# modern scp (no -O) runs over the sftp subsystem, so it exercises the SFTP
# parser end to end and still works with a password (unlike "sftp -b")
run_case sftp upload "sshpass -e scp $common /tmp/up.bin $SSH_USER@10.99.0.11:/tmp/up-sftp.bin"
run_case sftp download "sshpass -e scp $common $SSH_USER@10.99.0.11:/tmp/down.bin /tmp/down-sftp.bin"

echo "== the files really reached the backend (unchanged)"
for f in /tmp/up-scp.bin /tmp/up-sftp.bin; do
	got="$(t "sshpass -e ssh $common $SSH_USER@10.99.0.11 'sha256sum $f 2>/dev/null | cut -d\" \" -f1'" | tr -d '\r')"
	[ "$got" = "$up_sha" ] && pass "backend has $f with the original hash" || fail "backend $f hash=$got want=$up_sha"
done

echo "== the proxy logged and stored each transfer"
all="$(compose exec -T proxy sh -c 'cat /audit/all-*.jsonl')"
check_stored() { # check_stored EVENTID SHA LABEL
	local line
	line="$(grep "\"eventid\":\"$1\"" <<<"$all" | grep "\"shasum\":\"$2\"" | head -1)"
	if [ -z "$line" ]; then
		fail "$3: no $1 event with sha $2"
		return
	fi
	pass "$3: event logged with the right sha"
	if compose exec -T proxy test -f "/audit/files/$2"; then
		local ps
		ps="$(compose exec -T proxy sha256sum "/audit/files/$2" | cut -d' ' -f1 | tr -d '\r')"
		[ "$ps" = "$2" ] && pass "$3: proxy copy present, hash matches" || fail "$3: proxy copy hash $ps"
	else
		fail "$3: no proxy copy files/$2"
	fi
}
check_stored piper.file.upload   "$up_sha"   "scp/sftp upload"
check_stored piper.file.download "$down_sha" "scp/sftp download"

echo "== both uploads of this run logged (legacy scp + sftp, same content)"
n="$(grep "\"eventid\":\"piper.file.upload\"" <<<"$all" | grep -c "\"shasum\":\"$up_sha\"")"
[ "$n" = "2" ] && pass "two upload events for this content (scp and sftp)" || fail "upload events for this run = $n (want 2)"

echo "== both transfer kinds recognised"
kinds="$(grep "\"shasum\":\"$up_sha\"" <<<"$all" | grep -o '"transfer":"[a-z]*"' | sort -u | tr '\n' ' ')"
echo "   $kinds"
if grep -q '"transfer":"scp"' <<<"$kinds" && grep -q '"transfer":"sftp"' <<<"$kinds"; then
	pass "scp and sftp both recognised"
else
	fail "missing scp or sftp transfer kind"
fi

echo "== identical content stored once (deduplicated)"
compose exec -T proxy test -f "/audit/files/$up_sha" && pass "single copy files/$up_sha" || fail "no copy for $up_sha"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all file transfer checks passed"
