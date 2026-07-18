# Infrastructure metadata privacy

Accountable human owner: Mr. X.

The default Compose profile remains unchanged for compatibility. It does not carry a metadata
privacy release claim. The opt-in `metadata-safe-v1` profile is the only profile accepted by the
strict infrastructure metadata gate:

```powershell
$env:DEEP_INFRA_PRIVACY_PROFILE = 'metadata-safe-v1'
docker compose `
  -f docker-compose.uat-private.yml `
  -f docker-compose.metadata-safe.yml `
  config
node scripts/metadata-privacy-gate.mjs `
  --artifacts <explicit-sanitized-artifact-path> `
  --metrics <explicit-metrics-export-path> `
  --expected-artifact-files <exact-positive-count> `
  --expected-metric-files <exact-positive-count> `
  --xnode-dir <clean-pinned-xnode-checkout> `
  --client-expectations <P01-metadata-expectations.v1.json> `
  --summary <isolated-summary-path>
```

The gate accepts explicit UTF-8 text inputs only. Each selected root must contain at least one file,
and the aggregate artifact and metric counts must equal the separately declared positive counts.
Empty/zero-match selections, unsupported or binary content, malformed selected JSON/JSONL, wrong
profile, symlinks, oversized inputs, dirty or unpinned XNode source, mismatched P01 fixture, invalid
Compose configuration, and scanner findings fail closed. A metadata finding exits `1`; an incomplete
selection, parse error or harness/contract failure exits `2`.

## Data inventory and retention

| Component | Retained data in metadata-safe profile | Limit | Verification |
|---|---|---:|---|
| Xray access | Disabled; generated config has no access sink | 0 hours | Pinned generator-source contract |
| Xray error | Warning/error class; operational process failures | 24-hour target | Exact local wall-clock archive observation |
| XNode | Warning/error categories and aggregate health | 24-hour target | Exact local wall-clock archive observation and scanner |
| Storage/file/push/calls | Startup, health and operational failures; no request-body/path capture | 24-hour target | Exact local wall-clock archive observation and scanner |
| Metrics | Aggregate service/operation/status/error/route-index labels | 7 days | Allowlist metric-label lint |
| Sanitized evidence | Rule IDs, counts, generic input ordinals and policy state | 30 days | Metadata and secret scanners |
| Push provider | Provider-controlled delivery/device metadata | Unknown locally | Provider contract and Mr. X deletion request evidence |

The machine-readable source of truth is
`config/metadata-safe/retention-policy.v1.json`. Docker `local` logging is bounded to two compressed
1 MiB segments per service. This is only a size bound and never proof of a 24-hour deletion SLA.
The 24-hour value is a target until an operator validates a
`deep-local-log-retention-observation.v1` receipt against the exact local archive directory. The
validator binds the complete current archive set by generic ordinals, byte sizes and observed
filesystem modification times, and rejects any archive older than 24 hours. This proves a
local point-in-time observation only. Validation requires the observation clock to be within five
minutes of the verifier and rejects archive mtimes ahead of that clock. It does not prove prior
deletion, continuous enforcement, remote replicas or provider deletion.

The checked-in local-retention example represents an empty synthetic directory. A real receipt
must be generated from and immediately revalidated against the deployment host's exact archive
directory; copying the example is not operational evidence. The repository gate deliberately does
not expose a free-form `--local-retention-root` option and never sets a local-retention verified
claim: a deployment-specific trusted inventory must bind the real container/archive root before
this standalone verifier can be used as operational evidence.

## Exact Compose topology

The gate validates the fully merged Compose render, not just the privacy overlay. It accepts exactly
seven services, one internal bridge network, seven named state volumes, three node secrets and the
reviewed loopback-only host ports. It rejects host network/PID/IPC sharing, public or additional
ports, Docker socket and bind mounts, devices, privileged mode, added capabilities, weakened
`cap_drop`/`security_opt`, host-gateway mappings, extra services/networks/listeners and unexpected
service/build keys.

The metadata-safe overlay moves the container-internal VLESS listener from privileged port `443` to
`8443`, removes `NET_BIND_SERVICE`, and does not publish that listener to the host. This opt-in UAT
topology is not a policy for a future public relay; such a relay requires a separately versioned and
reviewed topology contract.

## Proxy and Xray

The pinned XNode source in the local `2.0.1-i01b` manifest generates Xray logging at `warning` and
does not configure an `access` destination. The metadata-safe Compose overlay additionally raises
ASP.NET/XNode categories to `Warning`; errors, degraded state and supervisor restarts remain visible.
The gate rejects an Xray generator that introduces an access sink or debug/info logging.

This is static source plus Compose-config evidence. No live Xray/REALITY traffic or runtime log
capture was performed in P01B.

## Metrics and evidence

Allowed labels are low-cardinality operational fields only: service, operation, status code, error
class, route index, transport and result. Session IDs, sender/recipient/public keys, mailbox IDs,
push/device tokens, capabilities, source/client IPs, paths, URLs and stable correlation IDs are
blocked.

JSON and JSONL inputs are parsed structurally and inspected recursively; text formats receive the
same fallback regex scan. IPv4, IPv6, request targets, Session IDs, mailbox/push capabilities and
stable correlation fields are rejected in nested objects, arrays, quoted fields and free-form text.

Findings contain only rule ID, a generic input ordinal, optional line and a separate finding
fingerprint. Logical paths, filenames and raw matched values are never copied into
summaries or console output. Tests use documentation-only synthetic values.

## Break-glass and key separation

Mr. X authorizes a maximum 60-minute access window. A valid closure receipt must prove:

- status is closed;
- access was revoked;
- raw exports were deleted;
- deletion was verified;
- the receipt contains no raw identifiers;
- operational-log and sanitized-evidence key references are distinct.

The checked-in example contains public secret references, not keys. Actual key material belongs in
the approved secret manager and must never be placed in Compose output, evidence or Git.

## Provider boundary

Deep can minimize its local logs and evidence. It cannot prove FCM/APNs/Huawei or hosting-provider
retention/deletion from this repository. `providerDeletionGuaranteed` therefore remains `false`.
Production readiness requires reviewed provider contracts and Mr. X-approved external deletion
evidence.
