#!/bin/sh
set -eu

source_config="${DEEP_TURN_CONFIG_SOURCE:-/etc/coturn/turnserver.conf}"
runtime_config="${DEEP_TURN_RUNTIME_CONFIG:-/run/coturn-runtime/turnserver.conf}"
secret_file="${DEEP_TURN_SHARED_SECRET_FILE:-/run/secrets/turn-shared-secret}"
public_host="${DEEP_TURN_PUBLIC_HOST:-}"
external_ip="${DEEP_TURN_EXTERNAL_IP:-}"
certificate_file="${DEEP_TURN_CERT_FILE:-}"
private_key_file="${DEEP_TURN_PKEY_FILE:-}"

case "$public_host" in
  ''|*[!A-Za-z0-9.-]*) echo 'DEEP_TURN_PUBLIC_HOST is invalid.' >&2; exit 64 ;;
esac
case "$external_ip" in
  auto) external_ip="$(detect-external-ip)" ;;
  ''|*[!0-9A-Fa-f:.]*) echo 'DEEP_TURN_EXTERNAL_IP is invalid.' >&2; exit 64 ;;
esac

for required_file in "$source_config" "$secret_file" "$certificate_file" "$private_key_file"; do
  if [ -z "$required_file" ] || [ ! -f "$required_file" ] || [ -L "$required_file" ]; then
    echo 'A required coturn input is unavailable or unsafe.' >&2
    exit 66
  fi
done

secret="$(tr -d '\r\n' < "$secret_file")"
case "$secret" in
  ''|*[!A-Za-z0-9+/=_-]*) echo 'The coturn shared secret has an invalid format.' >&2; exit 65 ;;
esac

runtime_directory="$(dirname "$runtime_config")"
mkdir -p "$runtime_directory"
umask 077
temporary_config="$runtime_config.tmp"
trap 'rm -f "$temporary_config"' EXIT HUP INT TERM
{
  cat "$source_config"
  printf '%s\n' \
    "realm=$public_host" \
    "server-name=$public_host" \
    "external-ip=$external_ip" \
    "cert=$certificate_file" \
    "pkey=$private_key_file" \
    "static-auth-secret=$secret"
} > "$temporary_config"
mv "$temporary_config" "$runtime_config"
unset secret
trap - EXIT HUP INT TERM

exec turnserver -c "$runtime_config"
