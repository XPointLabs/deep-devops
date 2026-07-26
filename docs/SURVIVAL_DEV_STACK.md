# Persistent survival development stack

`docker-compose.survival.dev.yml` is the ordinary long-running developer stack.
It uses the fixed `deep-survival-dev` project, a private bridge network,
persistent named volumes, and filtered exports of local source trees. It
contains no remote chain, release evidence, retained receipt, or one-shot
cleanup workflow. The formal P15C release gate remains separate in
`docker-compose.p15c-headless.yml`.

From the `deep-devops` repository, start the loopback-only messenger stack:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Up
```

The launcher writes ignored, non-secret handoff files to
`artifacts/survival-dev/client.android.env` and `client.windows.env`. Android
and Windows receive `127.0.0.1` by default; each XNode URL is pinned inline to its exact
development router ID. Debug HTTP does not use TLS pins. Use `adb reverse` for a
physical Android Debug build without exposing the unauthenticated services:

```powershell
41801, 41802, 41803, 41804, 41805, 41806, 41810, 41821, 41822, 41823 | ForEach-Object { adb reverse "tcp:$_" "tcp:$_" }
```

If the incomplete chain profile is being inspected, also reverse its optional
ports:

```powershell
41545, 41811 | ForEach-Object { adb reverse "tcp:$_" "tcp:$_" }
```

When reverse forwarding is unavailable, explicitly add
`-LanHost <workstation-ip>`. Only that opt-in binds client ports to the exact
supplied IPv4 interface and places the same address in both client artifacts. It
never binds `0.0.0.0`.

Raw `docker compose ... up` is not supported. The launcher creates filtered,
fail-closed source contexts, exchanges signed relay contacts, restarts the
XNodes, probes host HTTP endpoints, verifies all six contacts, and writes the
client handoff files; a raw Compose invocation does not perform those steps.

Regular builds reuse BuildKit and package layers. Rebuild only edited services
when convenient:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Build -Service xnode-1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Restart -Service xnode-1
```

The launcher also exchanges the six fresh signed relay contacts through the
local bootstrap sidecar and restarts the XNodes. Routed storage still requires
exactly three signed, distinct hops. The other three pinned nodes provide one
strictly disjoint fallback route for a classified pre-durable transport failure;
this is a fixed development trust set, not dynamic discovery.

Run the bounded chaos evidence lane after the shared transport tests have been
built. It executes instrumented transport contract tests for: pre-dispatch
ingress fallback, one retrieve fallback, and the fail-closed outcome-unknown
behavior for ambiguous stores. It then stops and restores each local XNode and
verifies the exact six-contact topology again:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev-chaos.ps1
```

The resulting `artifacts/survival-dev/six-node-chaos.json` is machine-readable,
development-only evidence. It explicitly does not claim dynamic membership,
production anonymity, replicated storage, cross-node deduplication, persisted
contacts without bootstrap, or write continuity through an arbitrary failed
intermediate relay. The retrieve fallback is marked privacy-degraded because
the current development protocol sends the first route's router identifiers as
exclusions to the fallback ingress. Do not use it as a production anonymity
claim.

Hardhat and staking are optional because messenger development does not require
a chain. The chain profile is currently unsupported and incomplete: `-Chain`
can start its containers for implementation work, but contract deployment and
generated backend configuration are not automated yet. Do not treat it as a
working chain environment until the next iteration completes that automation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Up -Chain
```

Status and logs:

```powershell
docker compose -f docker-compose.survival.dev.yml ps
docker compose -f docker-compose.survival.dev.yml logs -f --tail=200
docker compose -f docker-compose.survival.dev.yml logs -f --tail=200 contracts-devnet
```

Stop containers while preserving development data:

```powershell
docker compose -f docker-compose.survival.dev.yml down
```

An intentional full reset also deletes the named volumes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Down -Reset
```

Default messenger host ports are XNodes `41801-41806`, registry `41810`,
storage `41820`, file `41821`, push `41822`, and calls `41823`. The unsupported
chain profile additionally uses Hardhat `41545` and staking `41811`. All traffic
is Debug HTTP intended only for loopback or the exact trusted developer IPv4
interface selected with `-LanHost`.
