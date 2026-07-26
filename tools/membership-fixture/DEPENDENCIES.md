# Pinned local inputs

The supported launcher copies only these public packages into the Docker build
context and verifies their SHA-256 before the one-shot image is built:

- `Deep.Protocol 0.3.0-p04.b887fa0` — `8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442`
- `Deep.Protocol.MembershipRoutes 0.1.0-p15.local` — `fe7b5e638c1ab5e7505f45bb7d5804048d2a4ad273c88dd75d7d46ae80db641a`

They are the local package outputs aligned to the requested protocol `f224a96`,
shared `1900d0f`, XNode `a315285`, and Registry `893a174` contract handoff.
No package source is contacted by the generator image.
