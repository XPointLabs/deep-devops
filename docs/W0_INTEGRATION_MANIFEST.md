# W0 immutable integration manifest

Accountable human: Mr. X.

The local-only W0 compatibility set is pinned by:

- `release/manifests/survival-v2.0.2-w0.local.json`;
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
