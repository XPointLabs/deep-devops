import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const compose = readFileSync(path.join(root, 'docker-compose.staking.prod.local.yml'), 'utf8');
const provision = readFileSync(
  path.join(root, 'scripts', 'Prepare-ProductionRegistryCandidate.ps1'), 'utf8');

const registryStart = compose.indexOf('\n  registry:\n');
const portalStart = compose.indexOf('\n  staking-portal:\n');
assert.ok(registryStart >= 0 && portalStart > registryStart, 'registry service block is missing');
const registry = compose.slice(registryStart, portalStart);

assert.match(registry,
  /^    image: \$\{DEEP_REGISTRY_IMAGE:\?set an immutable deep-registry-api image digest\}$/m);
assert.doesNotMatch(registry, /^    build:/m,
  'production Registry must consume an immutable image and never build on the host');
assert.match(registry, /^      ContactResolveProductionAuthority__Enabled: "true"$/m);
assert.match(registry, /^      DirectoryPublication__NetworkIdHex: \$\{DEEP_XPOINT_NETWORK_ID_HEX:\?set DEEP_XPOINT_NETWORK_ID_HEX\}$/m);
assert.match(registry, /^      ContactResolveDirectoryArtifacts__GenesisAuthorityCoreHashHex: \$\{DEEP_XPOINT_GENESIS_PIN_HEX:\?set DEEP_XPOINT_GENESIS_PIN_HEX\}$/m);
assert.match(registry, /^        read_only: true$/m);
assert.equal((registry.match(/ContactResolveProductionAuthority__Witnesses__\d+__Ed25519SeedPath:/g) ?? []).length, 3);
assert.equal((registry.match(/source: contact-resolve-witness-\d+-ed25519/g) ?? []).length, 3);
assert.doesNotMatch(registry, /offline-root|msg-authenticated-evidence|group-gsr1-dcr1|contact-xpk/,
  'unrelated or offline authority seeds must not enter the Registry container');

assert.match(provision,
  /ghcr\.io\/xpointlabs\/deep-registry-api@sha256:[0-9a-f]{64}/);
assert.match(provision, /authorityOwner -cne 'Mr\. X'/);
assert.match(provision, /deployment-candidate-v1/);
assert.match(provision, /already exists; review it before retrying/);
assert.match(provision, /registry-dtt-signer-1\.ed25519\.seed/);
assert.match(provision, /registry-dtt-signer-2\.ed25519\.seed/);
assert.match(provision, /registry-dtt-signer-3\.ed25519\.seed/);
assert.doesNotMatch(provision, /offline-root-1\.ed25519\.seed/,
  'offline root seed must never be copied into a deployment candidate');

process.stdout.write(`${JSON.stringify({
  schema: 'deep-production-registry-contracts.v1',
  status: 'ok',
  checked: 16,
}, null, 2)}\n`);
