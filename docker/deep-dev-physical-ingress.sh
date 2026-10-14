#!/bin/sh
set -eu
umask 077
test "${DEEP_DEV_PROJECT:-}" = deep-dev-current || { echo 'Physical ingress rejected: project scope.' >&2; exit 64; }
case "${1:-}" in ''|--check) ;; *) echo 'Physical ingress rejected: command scope.' >&2; exit 64 ;; esac
test "$#" -le 1 || { echo 'Physical ingress rejected: argument count.' >&2; exit 64; }
for node in 1 2 3; do
  for kind in crt key; do
    file="/run/node-${node}/server.${kind}"
    test -f "$file" && test ! -L "$file" && test -s "$file" || { echo 'Physical ingress rejected: retained leaf input.' >&2; exit 78; }
  done
  # Only the original TLS leaf pair is available here. No node identity/BLS,
  # CA private key, application state, operator journal or floor is mounted.
  { cat "/run/node-${node}/server.crt"; printf '\n'; cat "/run/node-${node}/server.key"; printf '\n'; } > "/var/lib/haproxy/node-${node}.pem"
  chmod 0400 "/var/lib/haproxy/node-${node}.pem"
done
# HAProxy's CRL loader expects PEM. Wrap the exact signed public DER bytes;
# this does not author, extend, replace or disable the existing revocation list.
test -f /run/public/dev-ca.crl && test ! -L /run/public/dev-ca.crl || exit 78
test "$(wc -c < /run/public/dev-ca.crl)" -le 65536 || exit 78
{ printf '%s\n' '-----BEGIN X509 CRL-----'; base64 -w 64 /run/public/dev-ca.crl; printf '%s\n' '-----END X509 CRL-----'; } > /var/lib/haproxy/dev-ca.crl.pem
haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
if [ "${1:-}" = --check ]; then exit 0; fi
printf 'ready\n' > /var/lib/haproxy/ready
exec haproxy -W -db -f /usr/local/etc/haproxy/haproxy.cfg
