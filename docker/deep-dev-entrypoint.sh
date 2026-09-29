#!/bin/sh
set -eu
# Explicit development CA, ordinary platform chain/hostname validation remains on.
install -m 0644 /run/deep-public/dev-ca.crt /usr/local/share/ca-certificates/deep-dev.crt
update-ca-certificates >/dev/null 2>&1
exec dotnet "$@"
