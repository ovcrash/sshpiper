#!/bin/sh
# Backend entrypoint: create the test user, install host keys, run sshd.
#   SSH_USER / SSH_PASSWORD  account to create (from secrets/backendN.env)
#   /hostkeys                persistent volume holding the host keys
set -eu

: "${SSH_USER:?SSH_USER is required}"
: "${SSH_PASSWORD:?SSH_PASSWORD is required}"

if ! id "$SSH_USER" >/dev/null 2>&1; then
	useradd --create-home --shell /bin/bash "$SSH_USER"
fi
printf '%s:%s\n' "$SSH_USER" "$SSH_PASSWORD" | chpasswd

# Reuse host keys from the volume when present, otherwise generate them
# (ssh-keygen -A: Ubuntu defaults, ed25519 + ecdsa P-256 + rsa 3072) and
# save them to the volume.
if ls /hostkeys/ssh_host_*_key >/dev/null 2>&1; then
	cp /hostkeys/ssh_host_* /etc/ssh/
else
	ssh-keygen -A
	cp /etc/ssh/ssh_host_* /hostkeys/
fi
chmod 0600 /etc/ssh/ssh_host_*_key
chmod 0644 /etc/ssh/ssh_host_*_key.pub

/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
