# Local-only membership fixture generator

This source is a Docker-dev one-shot only. Its deterministic DEV-LOCAL-ONLY
seed material is used only while creating signatures and is never published,
mounted into runtime services, written to the named artifact volume, or logged.
It intentionally uses the contract test-style deterministic verifier and makes
no production signer, authority, or client-activation claim.
