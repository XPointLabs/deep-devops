#!/bin/sh
set -eu

case "${DEEP_INGRESS_CERTIFICATE_PROFILE:-}" in
  pinned-self-issued|deep-managed|operator-managed) ;;
  *) echo "Invalid DEEP_INGRESS_CERTIFICATE_PROFILE." >&2; exit 64 ;;
esac

case "${DEEP_INGRESS_HOST:-}" in
  ''|*[!A-Za-z0-9.-]*|.*|*.) echo "Invalid DEEP_INGRESS_HOST." >&2; exit 64 ;;
esac
case "${DEEP_NODE_REALITY_SERVER_NAME:-}" in
  ''|*[!A-Za-z0-9.-]*|.*|*.) echo "Invalid DEEP_NODE_REALITY_SERVER_NAME." >&2; exit 64 ;;
esac
if [ "${DEEP_INGRESS_HOST}" = "${DEEP_NODE_REALITY_SERVER_NAME}" ]; then
  echo "HTTPS and Reality SNI values must be distinct." >&2
  exit 64
fi
case "${DEEP_INGRESS_MAX_BODY_BYTES:-}" in
  ''|*[!0-9]*) echo "Invalid DEEP_INGRESS_MAX_BODY_BYTES." >&2; exit 64 ;;
esac
if [ "${DEEP_INGRESS_MAX_BODY_BYTES}" -lt 1024 ] || [ "${DEEP_INGRESS_MAX_BODY_BYTES}" -gt 8388608 ]; then
  echo "DEEP_INGRESS_MAX_BODY_BYTES is outside the approved range." >&2
  exit 64
fi
for timeout in "${DEEP_INGRESS_CLIENT_TIMEOUT_SECONDS:-}" "${DEEP_INGRESS_SERVER_TIMEOUT_SECONDS:-}"; do
  case "$timeout" in ''|*[!0-9]*) echo "Invalid ingress timeout." >&2; exit 64 ;; esac
  if [ "$timeout" -lt 5 ] || [ "$timeout" -gt 120 ]; then
    echo "Ingress timeout is outside the approved range." >&2
    exit 64
  fi
done

for required in \
  /run/secrets/ingress-current.crt \
  /run/secrets/ingress-current.key \
  /run/secrets/ingress-current.spki-sha256 \
  /run/ingress-attestation/preflight.v1; do
  if [ ! -f "$required" ] || [ -L "$required" ] || [ ! -s "$required" ]; then
    echo "A required ingress artifact is unavailable." >&2
    exit 78
  fi
done

attestation=/run/ingress-attestation/preflight.v1
cert_hash="$(sha256sum /run/secrets/ingress-current.crt | cut -d ' ' -f 1)"
key_hash="$(sha256sum /run/secrets/ingress-current.key | cut -d ' ' -f 1)"
pin_hash="$(sha256sum /run/secrets/ingress-current.spki-sha256 | cut -d ' ' -f 1)"
grep -Fqx 'deep-production-ingress-attestation.v1' "$attestation" &&
grep -Fqx "profile=${DEEP_INGRESS_CERTIFICATE_PROFILE}" "$attestation" &&
grep -Fqx "host=${DEEP_INGRESS_HOST}" "$attestation" &&
grep -Fqx "currentCertificateFileSha256=${cert_hash}" "$attestation" &&
grep -Fqx "currentPrivateKeyFileSha256=${key_hash}" "$attestation" &&
grep -Fqx "currentPinFileSha256=${pin_hash}" "$attestation" || {
  echo "Ingress preflight attestation is stale or invalid." >&2
  exit 78
}
grep -Fqx "clientTimeoutSeconds=${DEEP_INGRESS_CLIENT_TIMEOUT_SECONDS}" "$attestation" &&
grep -Fqx "serverTimeoutSeconds=${DEEP_INGRESS_SERVER_TIMEOUT_SECONDS}" "$attestation" &&
grep -Fqx "quorumCoordinatorCidr=${DEEP_QUORUM_COORDINATOR_CIDR}" "$attestation" || {
  echo "Ingress policy attestation is stale or invalid." >&2
  exit 78
}

cat /run/secrets/ingress-current.crt /run/secrets/ingress-current.key > /var/lib/haproxy/ingress-current.pem
chmod 0400 /var/lib/haproxy/ingress-current.pem

sed \
  -e "s|\${DEEP_INGRESS_HOST}|${DEEP_INGRESS_HOST}|g" \
  -e "s|\${DEEP_NODE_REALITY_SERVER_NAME}|${DEEP_NODE_REALITY_SERVER_NAME}|g" \
  -e "s|\${DEEP_INGRESS_MAX_BODY_BYTES}|${DEEP_INGRESS_MAX_BODY_BYTES}|g" \
  -e "s|\${DEEP_INGRESS_CLIENT_TIMEOUT_SECONDS}|${DEEP_INGRESS_CLIENT_TIMEOUT_SECONDS}|g" \
  -e "s|\${DEEP_INGRESS_SERVER_TIMEOUT_SECONDS}|${DEEP_INGRESS_SERVER_TIMEOUT_SECONDS}|g" \
  -e "s|\${DEEP_QUORUM_COORDINATOR_CIDR}|${DEEP_QUORUM_COORDINATOR_CIDR}|g" \
  /usr/local/etc/haproxy/haproxy.cfg.template > /var/lib/haproxy/haproxy.cfg

haproxy -c -f /var/lib/haproxy/haproxy.cfg
exec haproxy -W -db -f /var/lib/haproxy/haproxy.cfg
