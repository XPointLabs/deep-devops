# W0 immutable integration manifest

Accountable human: Mr. X.

The corrected local-only W0 compatibility set is pinned by:

- `release/manifests/survival-v2.0.2-w0.detached.local.json`;
- `release/contracts/survival-compatibility-v2.0.2-w0.json`;
- `release/evidence/w0-final-manifest.json`.

The manifest pins exact accepted commits for the W0 clients, DevOps and XNode.
`deep-protocol` deliberately remains at
`8484b130a274ca7d8de574e563c83198180d7808`; the P03 protocol change belongs
to W1. All other repository pins are unchanged from the accepted I01B matrix.

This is an immutable local integration boundary, not a production-readiness
claim. Package restore remains offline/local-only, external publication is
forbidden, and no network checkout is required for manifest validation.

P01, P01B, P02, P02B and P02C have accepted `GO` review status. The strict P01
metadata product gate intentionally remains `EXPECTED-RED` with eight
unresolved consumer checks. P03A/P03B are the W1 consumers that close those
checks; the W0 manifest must not rewrite that expected state as green.

## Detached carrier semantics

The manifest JSON is a detached, content-addressed artifact. Its raw SHA-256 is
the distribution identity; it does not claim that the manifest file itself is
already present inside every commit that it lists.

The pinned `deep-devops` commit
`7e4e392b72bddf24b262609f8a2994549a08ce20` is the contract carrier. Validation
loads the exact contract bytes with Git object lookup from that commit and
checks their SHA-256 and schema. The working-tree copy is never the authority.
The contract records DevOps runtime base
`67cb8113e94708a4597bb98a88e00ad9ba632415`; the validator additionally requires
that runtime base to be the carrier's exact first parent. Therefore a pin to
the pre-contract runtime commit cannot pass, while the detached manifest avoids
an impossible self-reference.

The earlier `survival-v2.0.2-w0.local.json` remains as immutable historical
evidence of the rejected construction and is not the corrected integration
entry point.
