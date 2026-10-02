# Existing DID2 Registry automatic-time transition

Normative owner: [DR-0068](../../docs/survival-program/decisions/DR-0068-manual-to-nts-protected-floor-upgrade.md).
Registry commands and report semantics: [candidate operator guide](../../deep-registry-api/docs/DID2_DIRECTORY_CANDIDATE.md).

`scripts/upgrade-did2-registry-time.cjs` is a narrow Linux Docker operator:
it runs only `provision-nts-floor`, `observe-trusted-time` or `refresh-current-head` in a disposable
candidate container. It does not promote/restart Registry, alter ingress,
reset state or floor, rotate keys, or touch other Docker services. Preserve the
new floor and its fence with the retained custody backups.

Require explicit deployment authorization, a retained protected manual-anchor
backup authenticated with its independent integrity key, its exact SHA-256,
the running source container's exact image ID, and the locally verified candidate
image ID/revision. Load that image using a verified archive before invoking:

```text
node scripts/upgrade-did2-registry-time.cjs --mode provision --container <exact-running-container> --source-image sha256:<source-id> --image sha256:<candidate-id> --revision <40-hex-commit> --manual-sha256 <retained-64-hex-hash>
```

Repeat with `--mode observe` to acquire real NTS under the exact signed policy.
After retaining a current ADA2/floor backup, `--mode renew` acquires NTS, proposes
a bounded head window, then invokes `refresh-current-head` under a second fresh
acquisition. Registry verifies the complete journal and independent PostgreSQL
floor, preserves content and atomically advances that floor before ADA2. This
mode does mutate the current signed head; it never resets account content,
genesis, registered keys or any rollback floor. It is not application promotion.
The script preserves the exact source environment except the three automatic
time settings, all bind mounts and their read/write flags. Provisioning has no
network; observation has the retained Docker network but no published ports.
Neither command grants application readiness or reusable freshness evidence.

For the DR-0069 DID2-only source image, use `--mode observe-did2` or
`--mode renew-did2`. These explicit modes omit only the three retired directory
configuration sections, and only when each present section is explicitly
disabled. Active or ambiguous old authority configuration rejects. No legacy
value is translated, no retained file is deleted, and every current DID2
credential, independent floor, ledger, mount and network setting is preserved.
The ordinary modes remain unchanged for the preceding diagnostic image.
This prepares a disposable operator only; it still does not promote Registry.

The floor uses the existing explicit path, or a new separate sibling of ADA2
named `nts-lower-floor.state` for a manual-only composition. Scope, duplicate
keys, mount aliases, source-image CAS and candidate revision are checked before
the owned command runs. Registry independently verifies cryptography and custody.
The temporary environment is mode 0600, outside repository artifacts; no values
or Docker stderr are printed. Disposable cleanup never removes mounted state.
An interrupted/pending transition must be resumed using the exact retained
manual hash, never repaired by deleting its fence or re-provisioning ADA2.

Verify script changes with `node --test scripts/upgrade-did2-registry-time.test.cjs`.
Synthetic script tests do not prove NTS, production activation or physical E2E.

## Existing-state readiness canary

`scripts/start-did2-registry-canary.cjs` supports `preflight` and `start`:

```text
node scripts/start-did2-registry-canary.cjs --mode preflight --container <exact-running-container> --source-image sha256:<source-id> --image sha256:<candidate-id> --revision <40-hex-commit> --canary deep-did2-registry-canary-<unique-suffix>
```

After preflight succeeds, repeat with `start`. This diagnostic retains the
same custody, independent PostgreSQL floor, mounts and Docker network. It
enables NTS but explicitly disables head renewal; NTS may advance its protected
time floor. It rejects an already active renewal worker and host networking.
It does not publish ports, attach ingress aliases, stop the source container,
provision state or disable catalog writes to hide incomplete DID2 inputs.
Only disabled retired configuration is omitted. A failed or colliding canary
is never removed automatically. The private mode-0600 environment is removed;
the diagnostic container and mounted state remain for scoped inspection.

Verify with `node --test scripts/start-did2-registry-canary.test.cjs`.
This canary is not deployment, current proof evidence or device E2E. Before
enabling any head-renewal worker separately, retain a fresh ADA2 backup and
independently observed floor, as required above.

When the retained source view has expired, append `--view-file <absolute-public-XNV1>`
and `--view-sha256 <independent-file-digest>` for a distinctly named diagnostic
canary. The file must come from the validated native operational-successor
export. Only that canary's current-view input changes through one read-only
mount; Registry still verifies its signed authority and issuance interval.
This is not network-bundle publication or node/TLS-key activation. Do not
route clients to a proof-only canary while nodes retain an older closure.

For the companion node rollout, regenerate the current canonical node compose
and use the installer runtime stager. Retired `ContactAuthority` and
`GroupControlAuthority` sections must be absent, not set to false: the DID2-only
node rejects both. The diagnostic preparation helper also omits these sections;
it does not import state or grant application readiness by preparing files.

## Existing-state worker canary

After retaining the current ADA2 and independently observed PostgreSQL floor,
select `worker-preflight` followed by `worker-start` with the same arguments as
the current-view canary plus `--bundle-file <native-exported-public-NCP2>`,
`--bundle-sha256 <independent-bundle-digest>` and
`--retained-ada2-sha256 <fresh-protected-backup-digest>`. The state digest must
still match immediately before create. The worker enables bounded native head
renewal and retains the exact existing floor, keys and account content. It may
advance the signed head and independent floor, never reset them.

This mode also selects the current full public bundle through a read-only
mount, without modifying the retained old bundle. It requires already enabled,
network-scoped distribution and valid renewal lead/interval/window options.
No public ports, ingress aliases, source stop or production promotion occur.
Verify actual proof readiness and byte-identical distribution, then perform a
separately scoped matched Registry/node promotion. Enabling the worker is not
proof of a completed renewal/recovery cycle or physical delivery.

`scripts/promote-did2-registry-canary.cjs` is the separately authorized promotion
step. Use `preflight` then `promote`, supplying the exact source image/revision,
worker, unique `deep-did2-registry-canary-promoted-<suffix>` replacement, retained
loopback port and the same independently hashed view/bundle/ADA2 inputs. It
requires an exact worker environment/mount match and both actual health checks.
It creates the replacement before stopping either process, stops the diagnostic
worker to retain a single renewal owner, and reuses only the existing loopback
listener with the original restart policy. The public reverse proxy, other
services, keys, account content and protected floors are not rewritten.

Coordinate this transition with the already staged three-node runtime. Validate
the public HTTPS closure bytes and current proof readiness after activation;
internal health is not device evidence. If activation fails after either stop,
inspect the retained containers and bounded private diagnostics before recovery.
Never restore an earlier ADA2 file over an advanced independent floor. Verify
the promotion helper with `node --test scripts/promote-did2-registry-canary.test.cjs`.

The public DID2 route set must include `/api/v2/account-directory/history`
alongside admissions, proofs and network closure. A client or node recovering a
protected earlier head needs this endpoint; successful readiness cannot prove
that proxy route exists. `scripts/add-did2-registry-history-route.cjs` supports
`preflight`/`apply` for the exact retained four-route snippet, its independent
SHA-256, retained loopback port and an exclusive private backup file. It adds
only history with the same upstream/security include, tests nginx before and
after replacement, then reloads nginx. An ambiguous snippet or changed input
rejects. Certbot, TLS policy and unrelated virtual hosts are not rewritten.
Verify with `node --test scripts/add-did2-registry-history-route.test.cjs`;
actual HTTPS/history recovery and device delivery remain separate gates.

After independent provisioning of the permanent DID2 route/publication journals
and the DR48 existing-node access list, use
`scripts/add-did2-registry-contact-routes.cjs` with the same `preflight`/`apply`
argument set. Its source is exactly the five-route snippet after history was
added. It adds only the two V2 coordination paths, preserving the listener,
security include and other virtual hosts; already-updated, partial or foreign
snippets reject. Run both route test files together. An unauthenticated empty
401 proves access gating only, not witness issuance or device contact delivery.
Runtime dependencies and database provisioning belong to the
[Registry runbook](../../deep-registry-api/docs/DID2_DIRECTORY_CANDIDATE.md#private-did2-contact-coordination-deployment),
not a second DevOps protocol specification.
