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
is printed. Failed sources are absent from the bounded response. Stderr contains
only fixed failure categories (key exchange timeout/rejection, query timeout/
rejection, validation, interval or provider failure), with no source identifiers
or provider error text. Backoff-only polls are silent. Diagnostics are not
observations and do not alter the closed stdout response or any trust check.

After the existing two bounded UDP attempts time out, the peer retains its
negotiated session rather than treating packet loss as evidence that its keys
are invalid. The same exponential retry backoff still applies, including the
minimum10 seconds, factor1.5 and maximum5 days; no observation is emitted while
waiting. Non-timeout authentication/framing/provider failures still discard the
session. Only a successfully authenticated and policy-bounded NTP response resets
backoff. TLS, source pins, nonce/AEAD validation, per-query timeouts and signed
Registry interval/freshness checks are unchanged. The default dev Docker build
now executes the checked-in Go tests before compiling the helper.

`artifacts/s05-current-publication-20261015/nts-query-timeout-red-01/` reproduced
the timeout/session-discard regression. `nts-query-timeout-02/` passed the
unfiltered Go package tests and built the Linux ARM64 helper with native0.
Docker progress/test output is in `native.log.stderr`, not the empty stdout log.
These are source/helper receipts, not sustained NTS, mailbox or physical evidence;
the existing Windows operator helper has not been replaced by these builds.
Final `nts-query-timeout-03/` executed all seven tests with0fail/skip, native0,
and built/exported the helper SDK test image; gofmt inspection found no
unformatted files. DevOps release contracts passed51 commands; the actual
production readiness status remains blocked by10 missing release evidence
items. Synthetic contract device-acceptance results are not physical devices.

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
