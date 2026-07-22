# Persistent survival development stack

`docker-compose.survival.dev.yml` is the ordinary long-running developer stack.
It uses the fixed `deep-survival-dev` project, one internal network, persistent
named volumes, local source trees, and a local Hardhat chain. It contains no
remote chain, release evidence, retained receipt, or one-shot cleanup workflow.
The formal P15C release gate remains separate in `docker-compose.p15c-headless.yml`.

From the `deep-devops` repository, start the loopback-only messenger stack:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Up
```

The launcher writes ignored, non-secret handoff files to
`artifacts/survival-dev/client.android.env` and `client.windows.env`. Android
and Windows receive `127.0.0.1`; each XNode URL is pinned inline to its exact
development router ID. Debug HTTP does not use TLS pins. Use `adb reverse` for a
physical Android Debug build without exposing the unauthenticated services:

```powershell
41801..41803 + 41821..41823 | ForEach-Object { adb reverse "tcp:$_" "tcp:$_" }
```

When reverse forwarding is unavailable, explicitly add `-LanHost <workstation-ip>`.
Only that opt-in binds client ports on all interfaces and places the supplied LAN
address in the Android artifact.

The equivalent loopback-only Docker command is useful when no Android device is
involved:

```powershell
docker compose -f docker-compose.survival.dev.yml up -d --build --wait
```

Regular builds reuse BuildKit and package layers. Rebuild only edited services
when convenient:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Build -Service xnode-1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Restart -Service xnode-1
```

The launcher also exchanges the three fresh signed relay contacts through the
local bootstrap sidecar and restarts the XNodes so routed storage can select hop
indices `0`, `1`, and `2`.

Hardhat and staking are optional because messenger development does not require a
chain. Start them with `-Chain`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Up -Chain
```

Status and logs:

```powershell
docker compose -f docker-compose.survival.dev.yml ps
docker compose -f docker-compose.survival.dev.yml logs -f --tail=200
docker compose -f docker-compose.survival.dev.yml logs -f --tail=200 contracts-devnet
```

Deploy the local contracts after Hardhat is healthy when contract state is
needed:

```powershell
docker compose -f docker-compose.survival.dev.yml exec contracts-devnet pnpm exec hardhat run scripts/deploy-local-devnet.js --network localhost
```

Stop containers while preserving development data:

```powershell
docker compose -f docker-compose.survival.dev.yml down
```

An intentional full reset also deletes the named volumes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Down -Reset
```

Default host ports are Hardhat `41545`, XNodes `41801`–`41803`, registry
`41810`, staking `41811`, storage `41820`, file `41821`, push `41822`, and calls
`41823`. All traffic is Debug HTTP intended only for a trusted developer LAN.
