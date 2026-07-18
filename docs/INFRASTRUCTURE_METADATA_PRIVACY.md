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
  --xnode-dir <clean-pinned-xnode-checkout> `
  --client-expectations <P01-metadata-expectations.v1.json> `
  --summary <isolated-summary-path>
```

The gate accepts explicit text inputs only. Empty selections, wrong profile, symlinks, unexpected
file formats, oversized inputs, dirty or unpinned XNode source, mismatched P01 fixture, invalid
Compose configuration, and scanner findings fail closed.

## Data inventory and retention

| Component | Retained data in metadata-safe profile | Limit | Verification |
|---|---|---:|---|
| Xray access | Disabled; generated config has no access sink | 0 hours | Pinned generator-source contract |
| Xray error | Warning/error class; operational process failures | 24 hours | Bounded Docker local logs |
| XNode | Warning/error categories and aggregate health | 24 hours | Bounded Docker local logs and scanner |
| Storage/file/push/calls | Startup, health and operational failures; no request-body/path capture | 24 hours | Bounded Docker local logs and scanner |
| Metrics | Aggregate service/operation/status/error/route-index labels | 7 days | Allowlist metric-label lint |
| Sanitized evidence | Rule IDs, counts, relative paths and policy state | 30 days | Metadata and secret scanners |
| Push provider | Provider-controlled delivery/device metadata | Unknown locally | Provider contract and Mr. X deletion request evidence |

The machine-readable source of truth is
`config/metadata-safe/retention-policy.v1.json`. Docker `local` logging is bounded to two compressed
1 MiB segments per service. This is a size bound, not proof of a 24-hour deletion SLA; operators
must run the documented lifecycle and produce a closed break-glass/deletion receipt.

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

Findings contain rule ID, relative path, line and a fingerprint of rule/path/line only. Raw matched
values are never copied into summaries. Tests use documentation-only synthetic values.

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
