# NTS observation adapter

This interim provider runs outside the exact-three .NET Protocol graph. It uses
the pinned `beevik/nts` 0.3.3 and `beevik/ntp` 1.6.0 modules with `go.sum`, not
custom AES-SIV or a compiled C++ library. A native managed .NET/NuGet provider
may replace this process boundary without changing DTT1 or trusted floor semantics.

The process accepts a bounded, closed line-delimited JSON request on stdin.
The first signed-policy source list is fixed for its lifetime. Registry obtains
host, port, SPKI pin, source ID and radius only from an independently verified
XNA1/DTS1 chain. TLS 1.3, normal CA/hostname validation and that exact SPKI pin
are all required. Host wall time is used by standard certificate validation only;
an incorrect host clock may prevent acquisition, never authorize time.

The provider retains NTS session cookies in memory, applies KE backoff and
checks nonce/UID/AEAD framing before provider parsing. `Response.Validate()`
must confirm NTS authentication and synchronized NTPv4 before output. Only
authenticated **server transmit time**, full monotonic query duration, signed
dispersion/delay and precision determine its interval. `ClockOffset`, HTTP Date
and plain NTP are not authority. No cookie, exporter key, packet or diagnostics
is printed. Failed sources are absent from the bounded response.

Registry additionally rejects unknown/duplicate IDs, binds the current exact
signed policy, enforces two signed failure families, bounds age/radius and
intersects intervals. It persists a HMAC-authenticated greatest lower bound
before use. Upper bounds are instance-local and must be re-attested after every
Registry restart. Deleting/restoring its custody volume is not ordinary recovery;
the HMAC file is integrity protection, not an independent hardware rollback counter.

Build/test uses the official Go toolchain; generated executables are ignored.
The initial observed Go builder digest is
`golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c`.
The release gate must also audit this process artifact and dependencies; success
of a probe alone is not witness independence, node recovery or device evidence.
