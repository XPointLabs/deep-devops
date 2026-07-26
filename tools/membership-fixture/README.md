# Local-only membership fixture generator

This source is a Docker-dev one-shot only. Its deterministic DEV-LOCAL-ONLY
seed material is used only while creating signatures and is never published,
mounted into runtime services, written to the named artifact volume, or logged.
It intentionally uses deterministic development signers with the native Sodium
Ed25519 verification contract and makes no production signer, authority, or
client-activation claim.

The generator requires `--advertised-host` with one canonical loopback,
RFC1918, or IPv4 link-local address. It rejects hostnames, wildcard/public
addresses, and signs the six device-reachable endpoints
`http://HOST:41801/` through `http://HOST:41806/`.
