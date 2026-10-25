# Shared helpers for the relay-dev scripts (sourced, not executed).

# Git Bash on Windows rewrites arguments that look like POSIX paths
# (/audit -> C:/Program Files/Git/audit); docker needs them untouched.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

RELAY_DEV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$RELAY_DEV_DIR/.." && pwd)"

compose() {
	(cd "$RELAY_DEV_DIR" && docker compose "$@")
}

# Path of the repository as the Docker daemon sees it (Windows path under
# Git Bash, /mnt/c/... under WSL, plain path on Linux).
docker_repo_path() {
	if pwd -W >/dev/null 2>&1; then
		(cd "$REPO_DIR" && pwd -W)
	else
		printf '%s\n' "$REPO_DIR"
	fi
}

random_password() {
	LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
}

# load_backend_env N: export SSH_USER and SSH_PASSWORD of backend N.
load_backend_env() {
	# shellcheck disable=SC1090
	. "$RELAY_DEV_DIR/secrets/backend$1.env"
	export SSH_USER SSH_PASSWORD
}
