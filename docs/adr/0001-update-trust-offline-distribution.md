# ADR 0001: Update trust and offline distribution

- Status: prototype accepted for contract testing; production rollout requires independent review
- Date: 2026-07-18
- Decision owner: Mr. X
- Scope: release evidence and offline verification only

## Context

Deep must remain able to authenticate update artifacts when an app store, the
Deep domains, DNS, or an ordinary repository mirror is unavailable. TLS and a
download hash copied from the same compromised CI job do not establish this
trust. A compromised mirror must be able to deny service, but it must not be
able to select an older release, combine metadata from different releases, or
substitute a package signed by another Android certificate.

This decision follows the four top-level roles and client update order in
[The Update Framework specification 1.0.35](https://theupdateframework.github.io/specification/latest/):
root, targets, snapshot, then timestamp. In particular, root trust ships with
the client, snapshot metadata binds one coherent set of target metadata,
timestamp metadata limits freeze, and root rotation advances one version at a
time under both the old and new root thresholds.

The checked-in implementation is intentionally a TUF-like prototype and POUF,
not a claim of interoperability or full TUF conformance. It does not download
or install anything and is not linked into application runtime.

## Decision

### Trust roles and production ceremony

| Role | Production threshold | Key location | Maximum expiry | Purpose |
|---|---:|---|---:|---|
| root | 2 of 3 | three offline hardware devices in separate physical locations | 365 days | delegates every top-level role and rotates/revokes keys |
| targets | 2 of 3 | offline release-signing devices, separate from root | 90 days | delegates platform-specific release paths |
| `android-release` | 2 of 3 | isolated platform release-signing devices | 30 days | signs APK, SBOM and reproducibility target descriptions |
| snapshot | 1 of 2 | protected release service plus sealed recovery device | 14 days | binds exact versions, lengths and SHA-256 values of all target metadata |
| timestamp | 1 of 2 | protected short-lived signing service plus sealed recovery device | 7 days | binds the current snapshot and bounds the freeze window |

All human custody and approval steps are performed by Mr. X. The 2-of-3 layout
still uses separate devices and locations, so compromise or loss of one device
does not meet a threshold. It does not protect against compromise or coercion
of the sole human custodian; adding independent human custodians remains a
production governance improvement.

Root and targets private keys must never be present in an ordinary CI runner,
repository, artifact, container image, environment variable, or general-purpose
secret store. Snapshot and timestamp keys are separate from one another and
from targets. The CI prototype derives deliberately insecure test keys from
public labels; those keys are reproducible, have no production authority, and
their private representation is never written to evidence.

### Metadata profile

The prototype profile has these rules:

- every metadata file is exactly the UTF-8 canonical encoding: recursive
  lexicographic object-key ordering, no BOM, no leading/trailing whitespace,
  and one canonical integer representation;
- parsing retains both the raw downloaded bytes and the parsed envelope;
- parent metadata length and SHA-256 fields bind the exact raw child file, not a
  parsed/re-serialized approximation;
- only safe integer JSON numbers are accepted by the canonicalizer;
- Ed25519 public keys and signatures use lowercase hexadecimal encodings;
- key IDs are SHA-256 of the canonical public-key object;
- `spec_version` is exactly `1.0.35`;
- consistent snapshots are mandatory;
- each metadata envelope is limited to 1 MiB;
- duplicate or unrecognized signer IDs fail closed;
- expiry is evaluated against one fixed UTC update-start time;
- timestamp version must advance; snapshot and target versions cannot decrease;
- snapshot and timestamp parent descriptions require exact version, byte length,
  and SHA-256;
- delegated target paths must match the terminating `android-release`
  delegation;
- root versions advance exactly by one and each new root meets both the old and
  new root threshold independently over the same exact candidate document;
- persisted trust state binds the exact trusted-root version and SHA-256 of its
  raw canonical bytes, plus the last trusted version of every online/targets
  role.

Unknown JSON properties are retained by canonicalization. The production
implementation must either reuse a reviewed TUF implementation with a published
POUF or independently validate this profile before interoperability is claimed.

### Offline repository bundle

An offline bundle contains public files only:

```text
metadata/
  1.root.json
  N.root.json
  timestamp.json
  snapshot.json
  targets.json
  android-release.json
targets/
  android/<release>.apk
  sbom/<release>.cdx.json
  provenance/<release>.repro.json
```

Root metadata already trusted by the client or verifier is not replaced merely
because removable media contains another `root.json`. Every intervening
numbered root is verified sequentially. At startup, the supplied trusted-root
file must exactly match both the root version and raw-file SHA-256 in persisted
state. A same-version root with a different keyset is rejected even if it is
self-consistent.

After a candidate root meets the old and new thresholds, its version/raw
SHA-256 binding is atomically persisted before online roles are processed. A
later timestamp failure therefore cannot roll trust back to the earlier root.
The final role versions are atomically persisted only after the complete update
cycle succeeds. Metadata and targets can be copied by
USB, local Wi-Fi, Bluetooth, a P2P transport, or an untrusted public mirror;
the carrier receives no trust.

The verifier must have a credible clock. If the timestamp expires, it fails
closed. An offline carrier cannot extend expiry. During an outage longer than
seven days, Mr. X must run the isolated timestamp/snapshot recovery ceremony
and distribute newly signed public metadata. Increasing expiry to hide an
operational failure is prohibited.

### Android package contract

`android-release.json` binds the APK byte length and SHA-256 plus:

- package ID `network.xpoint.deep`;
- version code and version name;
- expected package-signing certificate SHA-256;
- source commit and resilient-program revision SHA-256;
- signed CycloneDX SBOM target and SHA-256;
- signed reproducibility provenance target;
- build-definition SHA-256 and `SOURCE_DATE_EPOCH`;
- at least two distinct builder IDs that independently produced the same APK
  SHA-256.

Offline verification first authenticates the metadata chain, then reads the
source APK once with its signed length as a bound and authenticates that exact
byte snapshot together with the SBOM and provenance. It writes those bytes with
exclusive creation into a fresh, canonical, non-link private local directory
and invokes a directly addressed Java runtime as:

`java -cp <apksigner.jar> com.android.apksigner.ApkSignerTool verify --verbose
--print-certs <private-snapshot.apk>`.

The canonical runtime root has a protected exact-tree manifest containing its
entrypoint and every regular file's canonical relative path, byte length, and
SHA-256. The manifest itself, the Java entrypoint, and `apksigner.jar` have
protected policy SHA-256 values. Before and after the process the verifier
rejects any missing, additional, linked, relocated, or changed runtime-tree
entry and rechecks the manifest, Java entrypoint, JAR, and snapshot. Neither
`ComSpec`, `PATH`, a batch/shell launcher, nor caller-supplied arguments are
used; the class and complete argument vector are built inside the verifier.
The child receives a minimal environment whose temporary-directory variables
point at the private snapshot directory. It must report exactly one unique
signer certificate digest, which is compared with signed target metadata.
Changing or swapping the carrier's source path after the snapshot is created
cannot change the verified bytes. A hash copied from distribution media is not
a trusted tool policy.

The executable/JAR policy location and verification temp root must be on a
locally administered protected volume. The prototype rejects link paths and
uses exclusive create plus restrictive POSIX modes, but it does not claim that
these operations alone establish a reviewed Windows ACL/reparse-point boundary.
Production Windows packaging must provision and verify that boundary.
The host kernel, process loader, and operating-system libraries remain the
trusted computing base; the JRE manifest closes the application runtime tree,
not a compromised host OS.

The package hash authenticates the exact manifest/package/version bytes; the
package-signing check independently proves the Android signing identity. The
prototype does not install the APK and does not bypass Android signature
lineage or downgrade checks. The synthetic CI signer output and synthetic APK
bytes are contract fixtures only and are explicitly not release evidence.

Example for a real, already-built offline bundle:

```powershell
node .\scripts\update-trust.mjs verify-android `
  --trusted-root D:\trusted\root.json `
  --state D:\trusted\update-trust-state.json `
  --candidate-root D:\bundle\metadata\2.root.json `
  --metadata-dir D:\bundle\metadata `
  --artifact-root D:\bundle\targets `
  --target android/network.xpoint.deep-2.0.1.apk `
  --java-runtime D:\trusted-tools\jre\bin\java.exe `
  --java-runtime-sha256 <JAVA-EXE-SHA-256-from-protected-offline-tool-policy> `
  --java-runtime-root D:\trusted-tools\jre `
  --java-runtime-manifest D:\trusted-policy\java-runtime-tree.json `
  --java-runtime-manifest-sha256 <MANIFEST-SHA-256-from-protected-offline-tool-policy> `
  --apk-signer-jar D:\trusted-tools\android\apksigner.jar `
  --apk-signer-jar-sha256 <JAR-SHA-256-from-protected-offline-tool-policy> `
  --verification-temp-root D:\trusted-temp `
  --now 2030-01-01T00:00:00Z `
  --summary .\artifacts\survival\P02\offline-android-real-summary.json
```

The state file must already contain the provisioned trusted root's exact
version/raw SHA-256 binding. `--now` is supplied explicitly so evidence records
the fixed update-start time;
production wrappers must obtain it from a trusted system clock, not from the
bundle.

### SBOM and reproducible-build contract

The SBOM is a separately hashed and signed CycloneDX target. The reproducibility
record is another signed target with exact source commit, program revision,
build definition, source epoch, SBOM hash, and builder results. At least two
different builders must report the same final APK SHA-256.

This contract detects mismatched evidence; it does not make two builder IDs
independent by assertion. Production evidence must bind each builder identity
to retained, independently controlled build attestations. A matching
reproducible build also does not replace source review, dependency audit,
package signing, or device acceptance.

### Exact iOS residual limits

This metadata can authenticate an IPA as a file, but it cannot authorize iOS to
install or launch it:

- App Store distribution and TestFlight remain Apple-mediated; Apple documents
  that a TestFlight build is available for at most 90 days.
- Ad Hoc distribution requires a distribution certificate, a provisioning
  profile, and devices registered in that profile.
- Apple Developer Enterprise distribution is only for proprietary internal-use
  apps. Apple documents 12-month distribution-profile expiry, after which the
  app will not launch; manual and MDM trust behavior still applies.
- EU alternative marketplaces and Web Distribution require Apple authorization
  and iOS/iPadOS notarization and remain region, entitlement, account, and
  platform-policy constrained.
- TUF metadata cannot override Apple code signing, entitlements, provisioning,
  notarization, revocation, device eligibility, or OS policy. It therefore
  cannot provide a general anonymous iOS sideload channel.

Primary Apple references:

- [TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/)
- [Create an Ad Hoc provisioning profile](https://developer.apple.com/help/account/provisioning-profiles/create-an-ad-hoc-provisioning-profile/)
- [Distribute proprietary in-house apps](https://support.apple.com/guide/deployment/depce7cefc4d/web)
- [Alternative distribution and notarization in the EU](https://developer.apple.com/support/dma-and-apps-in-the-eu)

## Rejected alternatives

- **TLS or domain pinning alone:** does not protect against compromised CI,
  rollback, freeze, or coherent-metadata substitution.
- **One long-lived signing key:** has no role separation, threshold recovery, or
  bounded online-key impact.
- **Very long timestamp expiry:** improves availability by silently accepting a
  long freeze window.
- **Hash posted beside the APK:** a compromised publisher can replace both.
- **Android package signature alone:** authenticates a signer but does not
  provide metadata freshness, delegated release authority, SBOM, or rollback
  state.
- **Treating iOS like Android:** ignores mandatory Apple distribution controls.

## Consequences and remaining work

The repository now has executable negative fixtures and public evidence, but
production remains blocked until:

1. an independently reviewed TUF implementation/POUF is selected;
2. Mr. X provisions production hardware keys outside CI and records public key
   ceremonies;
3. clients persist the trusted-root raw hash/version and every metadata version
   with a reviewed same-directory atomic state implementation (including
   platform-specific power-loss durability);
4. the production Java runtime exact-tree manifest and `apksigner.jar` policy,
   real release APK, SBOM, provenance, and two-builder evidence are exercised
   together;
5. trusted-clock behavior and recovery media are tested on target devices;
6. platform specialists review the private snapshot directory's Windows
   ACL/reparse protections and Unix ownership/mode assumptions;
7. an independent security reviewer approves the design.
