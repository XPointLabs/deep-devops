#!/bin/sh
set -eu

# /workspace/cache is a fresh bounded tmpfs in every chain role. Seed it from
# the build-time compiler output so runtime commands never need compiler access.
cp -R /opt/hardhat-cache/. /workspace/cache/
exec "$@"
