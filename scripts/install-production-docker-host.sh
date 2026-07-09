#!/usr/bin/env bash
set -euo pipefail

log_max_size="${DEEP_DOCKER_LOG_MAX_SIZE:-50m}"
log_max_file="${DEEP_DOCKER_LOG_MAX_FILE:-5}"
install_docker=true
prune_docker=false

usage() {
  cat <<'EOF'
Usage: install-production-docker-host.sh [options]

Installs Docker Engine on Ubuntu/Debian hosts when needed and applies the
production Docker host baseline used by XPoint services.

Options:
  --skip-docker-install       Do not install Docker packages; only configure the host.
  --prune                    Remove stopped containers, unused images, and build cache.
                             Volumes are never pruned. Existing rollback image
                             cache can be removed.
  --log-max-size VALUE       Docker json-file max-size. Default: 50m.
  --log-max-file VALUE       Docker json-file max-file. Default: 5.
  -h, --help                 Show this help.

Environment:
  DEEP_DOCKER_LOG_MAX_SIZE   Default value for --log-max-size.
  DEEP_DOCKER_LOG_MAX_FILE   Default value for --log-max-file.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-docker-install)
      install_docker=false
      ;;
    --prune)
      prune_docker=true
      ;;
    --log-max-size)
      if [ "$#" -lt 2 ]; then
        echo "--log-max-size requires a value" >&2
        exit 2
      fi
      log_max_size="$2"
      shift
      ;;
    --log-max-file)
      if [ "$#" -lt 2 ]; then
        echo "--log-max-file requires a value" >&2
        exit 2
      fi
      log_max_file="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    echo "This command needs root privileges. Re-run as root or install sudo." >&2
    exit 1
  fi

  sudo "$@"
}

docker_compose_available() {
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1
}

ensure_apt_host_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Package installation is enabled, but this installer only supports apt-based hosts." >&2
    exit 1
  fi

  echo "Installing baseline host packages..."
  run_root apt-get update
  run_root apt-get install -y ca-certificates curl gnupg openssl python3 nodejs npm
}

install_docker_packages() {
  ensure_apt_host_packages

  if docker_compose_available; then
    echo "Docker Engine and Compose plugin are already available."
    return
  fi

  echo "Installing Docker Engine and Compose plugin..."

  run_root install -m 0755 -d /etc/apt/keyrings
  tmp_key="$(mktemp)"
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID:-}"
  case "$os_id" in
    ubuntu|debian)
      ;;
    *)
      echo "Unsupported apt distribution for Docker repository: ${os_id:-unknown}" >&2
      rm -f "$tmp_key"
      exit 1
      ;;
  esac

  curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o "$tmp_key"
  run_root rm -f /etc/apt/keyrings/docker.gpg
  run_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg "$tmp_key"
  rm -f "$tmp_key"
  run_root chmod a+r /etc/apt/keyrings/docker.gpg

  codename="${VERSION_CODENAME:-}"
  if [ -z "$codename" ]; then
    echo "Cannot detect OS VERSION_CODENAME for Docker apt repository." >&2
    exit 1
  fi

  arch="$(dpkg --print-architecture)"
  echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${os_id} ${codename} stable" \
    | run_root tee /etc/apt/sources.list.d/docker.list >/dev/null

  run_root apt-get update
  run_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

configure_docker_logging() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to merge /etc/docker/daemon.json safely." >&2
    exit 1
  fi

  echo "Configuring Docker json-file log rotation: max-size=${log_max_size}, max-file=${log_max_file}"
  run_root mkdir -p /etc/docker
  run_root python3 - "$log_max_size" "$log_max_file" <<'PY'
import json
import os
import shutil
import sys
import time

log_max_size = sys.argv[1]
log_max_file = sys.argv[2]
path = "/etc/docker/daemon.json"
data = {}

if os.path.exists(path) and os.path.getsize(path) > 0:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        backup = f"{path}.bak-invalid-{int(time.time())}"
        shutil.copy2(path, backup)
        print(f"Existing daemon.json was invalid JSON; backed up to {backup}", file=sys.stderr)
        data = {}

data["log-driver"] = "json-file"
log_opts = data.get("log-opts")
if not isinstance(log_opts, dict):
    log_opts = {}
log_opts["max-size"] = log_max_size
log_opts["max-file"] = log_max_file
data["log-opts"] = log_opts

tmp = f"{path}.tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp, path)
PY
}

reload_or_start_docker() {
  run_root systemctl enable --now docker

  if run_root systemctl reload docker >/dev/null 2>&1; then
    echo "Docker daemon reloaded."
    return
  fi

  if run_root systemctl kill -s HUP docker >/dev/null 2>&1; then
    echo "Docker daemon received SIGHUP."
    return
  fi

  echo "Warning: Docker daemon is running, but reload/SIGHUP failed. New log settings may require a service restart." >&2
}

prune_unused_docker_artifacts() {
  echo "Pruning stopped containers, unused images, and build cache. Docker volumes are not pruned."
  run_root docker container prune -f
  run_root docker image prune -af
  run_root docker builder prune -af
}

if [ "$install_docker" = true ]; then
  install_docker_packages
fi

configure_docker_logging
reload_or_start_docker

if [ "$prune_docker" = true ]; then
  prune_unused_docker_artifacts
fi

run_root docker version
run_root docker compose version
run_root docker system df

echo "Production Docker host baseline is ready."
