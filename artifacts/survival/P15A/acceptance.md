# P15A compatibility lab acceptance

Decision owner: **Mr. X**.

Accepted status:

`P15A-COMPATIBILITY-LAB-GO / WINDOWS-ARM64-DOCKER-GO /`
`PRODUCT-RUNTIME-NO-GO / REPLICA-CHAOS-NO-GO /`
`BRIDGE-IMPAIRMENT-NO-GO`

This carrier records sanitized evidence for source commit
`f605351dc34621b130690ed3f3fb7ef42d35c57b`, tree
`9b136e0ed09c379b3eec4a5878d5f2ed435a4c7c`, with RED parent
`779cce43ea7ede84417f1ad082cf10a43392e8c2`.

## Review decisions

- `dependency_audit_retry`: GO; P0/P1/P2/P3 = 0/0/0/0.
- `p14c1_carrier_final_review`: GO; P0/P1/P2/P3 = 0/0/0/0.
  Disclosure: the reviewer participated in the preceding C2 work but did not
  implement C3.

## Executed evidence

- The mandatory verifier passed: 26 Node tests, the PowerShell lifecycle
  contract, failure-independent cleanup tests, and the native ARM64
  semantic-label cleanup integration.
- Two ordinary parallel native ARM64 runs passed and produced byte-identical
  sanitized evidence with SHA-256
  `b2995a9ae3f47404fa735b0e2be5d6dfca61d66a0a477e70f8a8585dc8c9a5cf`.
- The independently recomputed build-context identity matched both evidence
  files:
  `sha256:8a5a6bde35c72679b4a810acb7018ddd1d065b41d1b2741091390acf4207c4ae`.
- Each successful run recorded four services, four probes, four restarts, one
  bounded network fault, zero residual resources, and zero residual images.
- Both parallel projects ended with zero containers, networks, volumes,
  images, and run tags.
- Pre-semantic-validation, post-build, post-up, and semantic-label-drift
  failure paths each ended with zero containers, networks, volumes, images,
  run tags, and evidence files.
- An unrelated sentinel container retained its exact identity, image, state,
  restart count, project, and service labels across a complete successful run.

## Corrective machine-readable receipts

The C4 corrective reran the four failure scenarios and one successful sentinel
scenario from a separately materialized clean worktree of the same exact
source commit and tree. Its raw-byte build-context identity is
`sha256:e2efbcf3696acb20cdfb1de7c6141e13de73fb4e6be4c849bfc8e363ced55ee9`;
it is recorded separately and does not replace or conflate the earlier
two-parallel-run context identity.

| Receipt | SHA-256 | Coverage |
|---|---|---|
| [`failure-path-receipt.json`](failure-path-receipt.json) | `d8dcd6e4fb339e70edb644ddbb08083e20ed6629f6526dbc9b861ab8a30ad545` | Four fail-closed process exits and per-scenario zero container/network/volume/image/tag/evidence inventory |
| [`sentinel-receipt.json`](sentinel-receipt.json) | `6d9e264355e2cc008c8801c4b9941ddcb0eb4b9ecf20cb01ffc9f1101a616190` | Successful run evidence hash, zero residual Docker inventory, and equal SHA-256 digests of the canonical sentinel field set before and after |

[`receipt-validation.json`](receipt-validation.json) binds both required
receipt paths and hashes to the exact source commit/tree and records
`validationStatus=PASSED`; its SHA-256 is
`9738cdf52afaf2d71b973b3beee75583464558406e0ea8c4e6307b107667620a`.
That validation hash is bound into [`work-package-report.json`](work-package-report.json),
whose SHA-256 is
`908f510f0d489980a49061bb2f1e758946d2af0dca46fc6116c884285ce7f9e2`.
This provides the immutable receipt-to-validation-to-report-to-acceptance
chain. The sentinel receipt contains only digests and the canonical field
names; it contains no raw sentinel identity, image, status, project, service,
or container name.

The evidence contains no project names, ownership nonces, container IDs,
endpoints, ports, credentials, tokens, keys, payloads, raw responses, or
machine paths. No Git push was performed.

## External blockers

`DEEP_W1W2_PRODUCER_SOURCE_MAP` remains an inherited external prerequisite for
the repository-wide W1/W2 producer gate. Production deployment evidence,
physical-device acceptance, and accountable signoff evidence also remain
external and incomplete. These blockers do not change the accepted P15A
compatibility-lab and Windows ARM64 Docker results, and they must not be
represented as lab failures or as completed production evidence.
