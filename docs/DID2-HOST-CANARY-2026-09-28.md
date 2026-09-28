# DID2 host startup on production infrastructure — 2026-09-28

This is a partial operator observation, not a release/device-E2E gate.
The hosts are production Registry and seed1–seed3. There is no separate remote
UAT fleet; `UAT` is only the isolated diagnostic software profile. Mr. X permits
production testing until he explicitly reports users exist.

## Verified inputs and operator actions

- Owner CI [36394029688](https://github.com/XPointLabs/deep-devops/actions/runs/36394029688)
  published the multi-architecture XNode candidate from source
  `3c1b85eb86fb681691723e7a74c981668ded39b2` without `latest` or GitHub Release.
  Exact image: `ghcr.io/xpointlabs/xnode@sha256:d5ebd8b3faf831b4b1785044a32cddd7ca00026a1db7fcd8da85db0410172a56`.
- Owner CI [36397951769](https://github.com/XPointLabs/deep-devops/actions/runs/36397951769)
  published Registry source `989eddba24fe5273ad956380fc33c8801de3d6d7`.
  Pulled OCI revision matched. Exact operator image:
  `ghcr.io/xpointlabs/deep-registry-api@sha256:2b0a9078f8a3794e5e5551cb3358108505f50552ae22f9c23733e4b56dc65714`.
- The initial nonce-proof refusal was diagnosed as operator time uncertainty
  30 seconds exceeding the signed policy's maximum 10 seconds. The verifier
  was not relaxed. Independent UTC observation, synchronized NTP and host boot
  preceding the operator-created anchor were checked before explicit protected
  CAS refinement to uncertainty 8 seconds. The new interval remained wholly
  inside the advanced previous interval. The existing API was not replaced.
- The external floor was read from the exact configured PostgreSQL namespace,
  not the unrelated default-schema row. Generation/tree: `14/6`; core hash:
  `1C8ED552A2B676AEF6F85E3EA627753D940CB60DE857D1695DAE3C5FB6DFE47E`.
  The existing operator authenticated the ADA2 journal and exported the matching
  head and 14 covered signed heads. No floor/genesis/account history was reset.

Time semantics belong to
[Account Directory Transparency](../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md).
Network restart semantics belong to
[DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md).

## Observed host result

All three separate loopback-only diagnostic hosts started on the same immutable
XNode image and returned readiness HTTP 200. With privacy routing enabled,
their actual startup call path obtains a nonce-fresh Registry proof, verifies
signed network history and the installed local onion public key, and durably
commits the directory/network floors before releasing receive capability.

Each host then passed a same-image process restart without deleting state.
Each retained 12 state files; the retained Data Protection key-ring content
digest was unchanged across its restart. This checks successful authenticated
restart, not a tamper/rollback fault-injection drill.

The existing root checkpoint plus authenticated successor tail was sufficient
for these live proofs. A separately authored initial checkpoint targeting head
14 was **not activated**: an already accepted checkpoint lineage must not be
replaced by a different generation-zero checkpoint. Offline root material never
left local custody; only its public signed candidate was copied to Registry.

Existing registered Ed25519 identities and original node/ingress/storage
containers were preserved. The original seed containers remained healthy.
Certificate renewal and staking configuration were not changed.

## Local gates and remaining work

- Registry full source-cutover suite: 440 passed, zero failed/skipped;
  focused production-authority suite: 24 passed.
- Preparation helper: 3 Node tests passed; offline bootstrap operator fixture
  passed its four top-level checks. These synthetic fixtures are not physical
  delivery evidence.
- Android remained authorized through ADB; one Windows client process was
  present. Presence is not an account/contact/message assertion.

The diagnostic hosts intentionally have no carrier activation and no public
peer TLS listener. Public signed-origin TLS, two-replica pre-key publication,
claim/DPH2, Windows↔Android text delivery, files/images and groups remain
unverified. Next rollout must use the supported installer with reviewed DID2
wiring; these isolated compose services do not replace its production topology.
