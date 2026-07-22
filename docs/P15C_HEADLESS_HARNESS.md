# P15C isolated headless harness

Decision owner: **Mr. X**.

P15C proves an isolated, source-pinned Linux/ARM64 lifecycle for the accepted
P14C2 XNode, local contracts, registry, staking backend and the four
compatibility runtimes. It is deliberately classified as a headless harness,
not as a product runtime or device test.

## Safety boundary

The driver creates a random `p15c-` project and a protected run directory
outside every source repository. It fails before build or startup if the exact
namespace collides. Existing Docker resources are listed only for a bounded
before/after inventory; the driver never reads their environment, reuses their
images by tag, or calls another Compose project's lifecycle.

The only chain is an ephemeral Hardhat chain `31337`. Deployment uses its
standard local accounts. The normalized manifest contains only four public
contract addresses and their deployment blocks, and each address must have
bytecode. No external RPC or funded account is accepted.

Three fresh Ed25519 seeds are held as protected files. Each XNode receives its
seed and generated public configuration through Compose secrets. Sensitive
identity material is absent from environment variables, command arguments,
logs, evidence and retained ownership receipts.

VLESS is explicitly disabled. Registry heartbeat, DPF1 activation, client
registration and device execution are outside this package.

## Runtime topology

All eleven services use a single internal bridge and `linux/arm64`. Only local
operator APIs bind to `127.0.0.1`; compatibility storage, file, push and calls
routes remain container-internal. Every long-running service has a healthcheck;
`test-client` is a one-shot exact-source E2E runner.

Base images must already exist under the exact RepoDigests recorded in
`release/contracts/p15c-headless-v1.json`. Runtime and build policy is no-pull,
the XNode build requires SDK `10.0.301`, and the ASP.NET runtime is a distinct
runtime-only image.

## Verification

Run the focused, non-runtime checks first:

```powershell
node --test scripts/p15c-headless-contracts.test.mjs
node --test scripts/p15c-headless-source-preflight.test.mjs
node --test scripts/p15c-local-contract-manifest.test.mjs
node --test scripts/p15c-evidence-sanitizer.test.mjs
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/p15c-ephemeral-secrets.test.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/p15c-headless-lab.test.ps1
```

Acceptance additionally requires `P15C_REAL_INTEGRATION=1` and the environment
inputs documented by `scripts/p15c-headless-lab.integration.test.ps1`. The
integration lane runs both lifecycle shapes:

1. normal `Run`, including exact cleanup;
2. `Run -KeepRunning`, followed by `Verify` and exact `Down`.

`Verify` and `Down` first validate the receipt, current Compose hash, exact
six-source pins, exact run/secret markers, protected secret contents and the
strict local-contract manifest before the first Docker query. They then
revalidate the owned image IDs and labels. `Verify` proves every long-running
service, including calls, is healthy. `Down` removes only the validated project
resources and exact owned image IDs, requires zero owned resources and a
byte-for-byte unchanged foreign inventory, and only then removes retained state.

## Evidence limits

The final evidence is aggregate and bounded. It contains no paths, endpoints,
Docker IDs, environment dumps, keys, raw responses, logs or payload identifiers.
Runtime logs and raw local deployment output exist only inside the protected
owned run directory and are destroyed by normal cleanup or exact retained
`Down`.

`Run -KeepRunning` writes only the ownership receipt. It never writes final
PASS evidence. Exact `Down` requires a new canonical `EvidencePath` outside all
source repositories and the owned run tree; the final evidence is published
only after scoped cleanup and foreign-inventory validation succeed. If resource
cleanup is incomplete, the run directory, logs, secrets and receipt are retained
for diagnosis and no final evidence is emitted.

Passing P15C means only:

`P15C1-HEADLESS-HARNESS-GO / P14C2-LINUX-ARM64-EXECUTION-GO /
LOCAL-EPHEMERAL-CONTRACT-DEPLOY-GO / SCOPED-LIFECYCLE-GO /
P14-PROFILE-ACTIVATION-NOT-TESTED / VLESS-NO-GO / DEVICE-E2E-NO-GO /
PRODUCT-RUNTIME-NO-GO`.
