# First-release local Registry and XNode stack

This lane is the small, clean local topology for the first messenger release:
one Registry and exactly three XNodes with real Xray/Reality processes. It is
independent from `deep-survival-dev`; project, network, volumes and the default
`429xx/430xx` ports do not overlap the survival lane.

The default developer path has no HAProxy. Registry and XNode diagnostic APIs
bind directly to loopback by default, while each XNode publishes its own
VLESS/Reality listener. The optional `tls` overlay puts the Registry and XNode
application APIs behind HAProxy and leaves VLESS directly published because
HAProxy is not the masked transport.

## Inputs

For a new local topology, use the guarded bootstrap. It refuses to overwrite an
existing identity directory, writes through a protected staging directory, and
never emits private values:

```powershell
.\scripts\first-release-local-bootstrap.ps1
```

It creates three new, independent identities under
`C:\Work\DeepSession\secrets\first-release-local`, writes the ignored
`first-release.env`, provisions one distinct raw 32-byte ONION state-protection
key per node plus independent Registry ContactResolve integrity/witness custody,
then runs `Config`. Ed25519 generation
uses the platform Node cryptography provider; Reality public/private pairs use
the already-built local XNode image's Xray implementation with networking
disabled. BLS public keys and proofs use the XNode
`Bls12381RegistrationProofService` against a temporary, volume-free Prague EVM
for the EIP-2537 map operation. The local proof domain is chain `31337` and
address `0x000000000000000000000000000000000000f001`.

The bootstrap does not read retired UAT/survival identities, stop survival
services, rotate existing identities, or delete Docker volumes. To expose the
direct lane to a trusted LAN on first creation, provide the exact address to
both parameters:

```powershell
.\scripts\first-release-local-bootstrap.ps1 -Start `
  -BindHost 192.168.1.44 -PublicHost 192.168.1.44
```

The optional TLS profile and its PEM remain a separate operator action. `-Start`
also requires explicit `-TrustedObservedUnixTime`, `-TrustedTimeValidUntilUnix`,
and `-TrustedTimeUncertaintySeconds`; bootstrap never substitutes the host clock
for an operator-observed trusted-time anchor.

For an identity directory created before ONION runtime closure landed, augment
it without rotating any identity:

```powershell
.\scripts\first-release-local-runtime-provision.ps1
```

The command is idempotent only for the complete three-key set. A partial set,
wrong-length key, duplicate key, reparse path, or mismatched environment binding
fails closed. It never prints key bytes. For the pre-file-secret environment
format, the same command performs a one-time migration of all three VLESS UUIDs
and REALITY private keys into protected per-node files, removes their inline
environment bindings, and writes only exact `_FILE` paths. Mixed or partial
legacy/file state is rejected rather than repaired heuristically.

The XNode production ONION host is now implemented. Each instance uses bounded
state below `/state/privacy-routing`: `replay.state`, `entropy.state`, and the
`key-vault` directory. Roles are exact and non-interchangeable in this topology:
node 1 is `Ingress`, node 2 is `Core`, and node 3 is `Exit`. The verified XND1
view must grant the matching role to each router owner.

### Current production-authority blocker

`Production authority` means a named operational custody role and its rotation,
recovery and signing procedure; the mere presence of a private-key file does
not assign that authority. Until Mr. X explicitly changes the assignment, Mr. X
is the sole pre-production owner of every authority role below. Distinct roles
still use distinct keys. The current protected secret inventory is only a
partial implementation:

| Authority role | Temporary owner | Current local material | Still required |
|---|---|---|---|
| offline XNA1/DTS1 root | Mr. X | none bound | production custody signer and recovery procedure |
| Registry DTT1 threshold | Mr. X | three witness seeds; custody plan bound for pre-production | assign exact independent failure domains before GA |
| MSG authenticated evidence | Mr. X | none bound | signer custody and authoring service |
| Contact/XPK | Mr. X | local transport/integrity state only | verified service authority, signer custody and publication inputs |
| Group GSR1/DCR1 | Mr. X | none bound | verified artifact source and signer custody |
| Android release | Mr. X | Play upload key copied to `secrets/prod/android` | Play app-signing certificate lineage |
| Windows release | Mr. X | none bound | package-signing certificate/HSM |

The XNode BLS/Ed25519/X25519/ONION files are node identity and runtime custody,
not substitutes for any missing root, MSG, Contact, Group or release-signing
authority. This sole-owner assignment is valid only before users/GA. Public GA
still requires the XPoint 2-of-3 offline-root custody split and a documented
authority transition; no script infers an owner from a directory name.

The Registry production composition is now wired: protected monotonic time,
the one-use request ledger, three file-backed DTT1 witness keys, the read-only
canonical artifact source, and the `contact-resolve-authority provision-time`
and `author-package` operator actions all use dedicated first-release custody
and state paths. The Registry image builds with the local Protocol source so
those production-only APIs are present; no DEV authority is enabled.

`Up`, `Verify`, and both operator actions nevertheless stop before image build
or any Docker mutation. There is no production implementation of
`IXPointNetworkBootstrapRootSigner` for `XNA1/DTS1` root custody, and there is no
production genesis author entry point for
`ADH1/ADC1/XVP1/XNV1/XNH1/XND1/PMT2`. Existing production authors cover genesis
`XNA1/DTS1` only when a real root signer is supplied, plus nonce-bound
`DTT1/ADP1` issuance from an already verified closure. Arbitrary bytes, test
fixtures, DEV trust, an OS-clock witness, and synthetic signers remain
forbidden. The earliest missing signing authority is the offline
`IXPointNetworkBootstrapRootSigner` custody implementation; the remaining
listed genesis publishers/authors are also required before this lane can start.
`Config` is independently usable and currently passes with the protected local
environment; it does not waive this authority preflight or mutate Docker state.

The XNode health contract also marks both Contact and GroupControl terminals as
required. They are deliberately not activated from partial inputs: Contact
still lacks an exact trusted HTTPS Registry origin together with the verified
XPoint genesis pin and directory leaf key, while GroupControl lacks the
per-node verified GSR1/DCR1 artifact source. Until those production inputs and
their runtime compositions exist, `/health/ready` reports each missing required
terminal as `required-unavailable`; XNode health and `topology-ready` cannot go
green. Internal HTTP, raw artifacts, and synthetic authority values are not
fallbacks.

Copy `.env.first-release.local.example` to an ignored, operator-controlled
path and replace every `__REQUIRED_*__` marker. Do not commit that file or paste
rendered Compose configuration into logs. VLESS client IDs and Reality private
keys remain only in the protected files referenced by that environment file.

Manual preparation is still supported when bootstrap is intentionally not
used. After bootstrap, the generated environment file can be reused with the
launcher without regenerating identities:

```powershell
.\scripts\first-release-local.ps1 -Action Verify `
  -EnvFile C:\Work\DeepSession\secrets\first-release-local\first-release.env
```

The Compose file accepts paths to the six protected Ed25519/X25519 files, the
three raw ONION state-protection files, six independent Registry authority
custody files, and the protected artifact/operator directories;
it does not generate, inspect or copy them. Router IDs must match their Ed25519
seeds, X25519 scalars must be independent, and the BLS public proof fields must
come from the selected local registration domain. The lane deliberately does
not use retired UAT identities or survival secrets.

The XNode image is restored from the exact local protocol-cutover package set
under `../xnode/artifacts/local-protocol-cutover`. Compose pins its version and
both package SHA-256 values, the Dockerfile copies the matching lock files, and
restore runs in locked mode against a dedicated feed with no fallback for
`Deep.Protocol*`. If the XNode/protocol cutover is regenerated, update the
three public package pins together after reviewing `source-manifest.json`.
This build input is local/UAT evidence only; it is not a substitute for signed
release packages.

For host-only development keep:

```text
FIRST_RELEASE_BIND_HOST=127.0.0.1
FIRST_RELEASE_PUBLIC_HOST=127.0.0.1
```

For a trusted-LAN device run, set both to the exact LAN IPv4 address. Do not use
`0.0.0.0` as a published identity. Host firewall rules remain an operator
responsibility.

## Validate and run

The launcher always executes the static topology contract and `docker compose
config --quiet` before changing Docker state. It also rejects a reparse-linked
or oversized environment file and any remaining `__REQUIRED_*__` marker without
printing the file's values. VLESS client IDs and Reality private keys are
protected file inputs mounted read-only rather than environment values. After
the runtime and authority preflights succeed,
it builds the shared XNode image once and starts all three instances without
duplicating the build:

```powershell
.\scripts\first-release-local.ps1 -Action Config -EnvFile C:\protected\first-release.env
.\scripts\first-release-local.ps1 -Action Up -EnvFile C:\protected\first-release.env
.\scripts\first-release-local.ps1 -Action Verify -EnvFile C:\protected\first-release.env
```

Once the missing production authors exist and have published the complete
canonical closure, provision trusted time using explicit operator-observed
values. Mutable trusted-time, replay-ledger and artifact-LKG state stays in the
dedicated Registry named volume, while keys remain Docker secrets:

```powershell
.\scripts\first-release-local.ps1 -Action ProvisionTime `
  -EnvFile C:\protected\first-release.env `
  -ObservedUnixTime <operator-observed-unix-seconds> `
  -TrustedTimeValidUntilUnix <reviewed-expiry-unix-seconds> `
  -TrustedTimeUncertaintySeconds <1-through-30>
```

For an offline request/response exchange, place the canonical request directly
in the protected operator directory and select a new output name there:

```powershell
.\scripts\first-release-local.ps1 -Action AuthorPackage `
  -EnvFile C:\protected\first-release.env `
  -RequestFile C:\protected\operator\request.cdr1 `
  -OutputFile C:\protected\operator\response.cdr1
```

The wrapper suppresses operator-command output so custody values and private
paths cannot enter logs. Rotation additionally requires the exact current
trusted-time state SHA-256 through `-ExpectedTrustedTimeStateSha256`.

Startup is fail-closed and ordered:

1. `state-init` grants the unprivileged runtime UID access only to the four
   dedicated named volumes and exits.
2. Registry starts and must pass both `/health/live` and `/health/ready`.
3. All three XNodes start only after Registry is healthy. Their health checks
   require `/health/ready` plus Xray `running=true`, `mocked=false`, and
   `degraded=false`, and require both Contact and GroupControl terminal status
   to be `ready`.
4. `topology-ready` retries for at most 90 seconds and succeeds only when
   Registry contains exactly the three configured router IDs and all three
   heartbeat transport statuses are running, non-mocked and non-degraded.

Default direct endpoints are:

| Surface | Endpoint |
| --- | --- |
| Registry API | `http://127.0.0.1:42910` |
| XNode APIs | `http://127.0.0.1:42901` through `:42903` |
| XNode VLESS/Reality | `127.0.0.1:42941` through `:42943` |

Stop without deleting state:

```powershell
.\scripts\first-release-local.ps1 -Action Down -EnvFile C:\protected\first-release.env
```

There is intentionally no reset action. Delete the four explicitly named
`deep-first-release-local-*` volumes only during a separately approved local
data reset.

## Optional TLS UAT profile

Supply `FIRST_RELEASE_TLS_PEM_FILE` as an absolute protected combined
certificate/private-key PEM path and use `-Tls` consistently:

```powershell
.\scripts\first-release-local.ps1 -Action Up -Tls -EnvFile C:\protected\first-release.env
.\scripts\first-release-local.ps1 -Action Verify -Tls -EnvFile C:\protected\first-release.env
```

In this profile direct cleartext Registry/XNode API publications are removed.
HAProxy publishes TLS XNode application endpoints on `43001-43003` and Registry
on `43010`; VLESS/Reality remains direct on `42941-42943`. HAProxy exposes only
the bounded client routes, strips spoofable forwarding headers, hides health
routes, and re-resolves every backend through Docker DNS after replacement.

This is a local/UAT topology, not production deployment evidence. The current
three-node profile may reuse nodes between routes and does not claim six-node
route disjointness, production PKI, mTLS, chaos coverage, or production-ready
membership/directory artifacts.
