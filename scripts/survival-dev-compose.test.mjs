import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const compose = readFileSync(new URL('../docker-compose.survival.dev.yml', import.meta.url), 'utf8');
const docs = readFileSync(new URL('../docs/SURVIVAL_DEV_STACK.md', import.meta.url), 'utf8');
const launcher = readFileSync(new URL('./survival-dev.ps1', import.meta.url), 'utf8');
const seed = readFileSync(new URL('./survival-dev-seed.mjs', import.meta.url), 'utf8');
const verify = readFileSync(new URL('./survival-dev-verify.mjs', import.meta.url), 'utf8');
const contextExport = readFileSync(new URL('./survival-dev-context-export.mjs', import.meta.url), 'utf8');
const bootstrap = readFileSync(new URL('../tools/relay-bootstrap/relay-bootstrap.mjs', import.meta.url), 'utf8');

function serviceBlock(name) {
  const match = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-z][a-z0-9-]*:\\r?$|^networks:|^volumes:)`, 'm'));
  assert.ok(match, `missing service ${name}`);
  return match[1];
}

test('daily stack has a fixed isolated project and exact persistent service set', () => {
  assert.match(compose, /^name: deep-survival-dev$/m);
  assert.doesNotMatch(compose, /P15C_|ownership-nonce|evidence|\buat\b|sepolia/i);
  const servicesSection = compose.match(/^services:\r?\n([\s\S]*?)(?=^networks:)/m)?.[1] ?? '';
  const services = [...servicesSection.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map(match => match[1]).sort();
  assert.deepEqual(services, [
    'calls', 'contracts-devnet', 'file', 'push', 'registry', 'relay-bootstrap', 'staking-backend',
    'storage', 'xnode-1', 'xnode-2', 'xnode-3'
  ]);
  assert.match(compose, /^networks:\r?\n  runtime:\r?\n    driver: bridge$/m);
});

test('shared images have one incremental build producer and persistent consumers', () => {
  assert.match(serviceBlock('xnode-1'), /\n    build:/);
  assert.doesNotMatch(serviceBlock('xnode-2'), /\n    build:/);
  assert.doesNotMatch(serviceBlock('xnode-3'), /\n    build:/);
  assert.match(serviceBlock('storage'), /\n    build:/);
  for (const role of ['file', 'push', 'calls']) assert.doesNotMatch(serviceBlock(role), /\n    build:/);
  assert.match(compose, /^x-xnode: &xnode[\s\S]*?^  image: deep-survival\/xnode:dev$/m);
  for (const role of ['xnode-1', 'xnode-2', 'xnode-3']) assert.match(serviceBlock(role), /<<: \*xnode/);
  for (const role of ['storage', 'file', 'push', 'calls']) assert.match(serviceBlock(role), /image: deep-survival\/compat:dev/);
  assert.doesNotMatch(compose, /--no-cache/);
});

test('only local Hardhat and loopback host ports are configured', () => {
  const contracts = serviceBlock('contracts-devnet');
  assert.match(contracts, /command: \[pnpm, exec, hardhat, node, --hostname, 0\.0\.0\.0\]/);
  assert.match(contracts, /eth_chainId/);
  assert.doesNotMatch(compose, /https?:\/\/(?!127\.0\.0\.1|0\.0\.0\.0|[a-z][a-z0-9-]*:)/i);
  const bindings = [...compose.matchAll(/"\$\{SURVIVAL_BIND_HOST:-127\.0\.0\.1\}:(\d+):(\d+)"/g)];
  assert.equal(bindings.length, 10);
  assert.equal(new Set(bindings.map(match => match[1])).size, bindings.length);
});

test('LAN opt-in binds only the supplied IPv4 address and documents exact device forwarding', () => {
  assert.match(launcher, /\$env:SURVIVAL_BIND_HOST = \$advertisedHost/);
  assert.doesNotMatch(launcher, /SURVIVAL_BIND_HOST\s*=.*0\.0\.0\.0/);
  assert.match(launcher, /Name = 'client\.windows\.env'; Host = \$HostName/);
  assert.match(launcher, /survival-dev-seed\.mjs'\) '--host' \$advertisedHost/);
  assert.match(launcher, /survival-dev-verify\.mjs'\) '--host' \$advertisedHost/);
  assert.match(seed, /isIP\(host\) !== 4/);
  assert.match(verify, /isIP\(host\) !== 4/);
  assert.match(docs, /41801, 41802, 41803, 41810, 41821, 41822, 41823/);
  assert.match(docs, /41545, 41811/);
});

test('every stateful service uses a named volume and operator commands are documented', () => {
  for (const volume of [
    'contracts-deployments', 'xnode-1-state', 'xnode-2-state', 'xnode-3-state',
    'registry-state', 'staking-state', 'storage-state', 'file-state', 'push-state', 'calls-state'
  ]) assert.match(compose, new RegExp(`^  ${volume}:$`, 'm'));
  assert.match(docs, /survival-dev\.ps1 -Action Up/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml ps/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml logs -f --tail=200/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml down/);
  assert.match(docs, /formal P15C release gate/i);
  assert.match(docs, /raw `docker compose .*up.*` is not supported/i);
  assert.match(docs, /chain.*unsupported|unsupported.*chain/i);
  assert.doesNotMatch(docs, /вЂ|Ã|â|�/);
  assert.doesNotMatch(docs, /--no-cache/);
});

test('daily launcher always uses the fixed project without release-gate ceremony', () => {
  assert.match(launcher, /'deep-survival-dev'/);
  assert.match(launcher, /ValidateSet\('Up','Down','Status','Logs','Build','Restart'\)/);
  assert.match(launcher, /'compose', '-p', \$Project, '-f', \$ComposePath/);
  assert.match(launcher, /\[string\]\$LanHost/);
  assert.match(launcher, /SURVIVAL_BIND_HOST/);
  assert.match(launcher, /client\.android\.env/);
  assert.match(launcher, /client\.windows\.env/);
  assert.doesNotMatch(launcher, /DEEP_STAKING_URL/);
  assert.match(launcher, /DEEP_STAKING_BACKEND_URL/);
  for (const routerId of [
    '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
    '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
    'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b'
  ]) assert.match(launcher, new RegExp(routerId));
  assert.match(launcher, /survival-dev-seed\.mjs/);
  assert.match(launcher, /survival-dev-context-export\.mjs/);
  assert.doesNotMatch(launcher, /Up requires -LanHost/);
  assert.match(seed, /api\/network\/contact/);
  assert.match(seed, /relay-bootstrap/);
  assert.match(verify, /JSON\.stringify\(\{ id: `survival-\$\{method\}`, method, payload: \{\} \}\)/);
  assert.doesNotMatch(verify, /params:/);
  assert.match(bootstrap, /api\/relay-contacts/);
  assert.match(bootstrap, /\/seed/);
  assert.match(serviceBlock('contracts-devnet'), /profiles: \[chain\]/);
  assert.match(serviceBlock('staking-backend'), /profiles: \[chain\]/);
  assert.match(compose, /Runtime__BootstrapFromStorage: "true"/);
  assert.match(compose, /RegistryBootstrap__BaseUrl: http:\/\/relay-bootstrap:8080/);
  assert.doesNotMatch(launcher, /nonce|evidence|receipt|P15C_/i);
  assert.match(contextExport, /git.*ls-files/si);
  assert.match(contextExport, /prohibited source entries/i);
});

test('development identities remain exact strings and Up proves host HTTP reachability', () => {
  for (const suffix of ['1', '2', '3']) {
    assert.match(compose, new RegExp(`Node__Ed25519PrivateKey: "[0]{63}${suffix}"`));
  }
  assert.match(compose, /SURVIVAL_XNODE_BUILD_CONTEXT/);
  assert.match(compose, /SURVIVAL_REGISTRY_BUILD_CONTEXT/);
  assert.match(compose, /SURVIVAL_STAKING_BUILD_CONTEXT/);
  assert.match(compose, /SURVIVAL_CONTRACTS_BUILD_CONTEXT/);
  assert.doesNotMatch(compose, /additional_contexts:[\s\S]*?SURVIVAL_(?:XNODE|REGISTRY|STAKING|CONTRACTS)_PATH/);
  assert.match(compose, /health\/live/);
  assert.match(compose, /^x-xnode:[\s\S]*?GET \/health\/live HTTP\/1\.1[\s\S]*?^x-compat-build:/m);
  assert.match(serviceBlock('registry'), /GET \/health\/live HTTP\/1\.1/);
  assert.doesNotMatch(serviceBlock('xnode-1'), /test -r \/proc\/1\/status/);
  assert.doesNotMatch(serviceBlock('registry'), /test -r \/proc\/1\/status/);
  assert.match(launcher, /--force-recreate/);
  assert.match(launcher, /Assert-SurvivalHostEndpoints/);
  for (const port of [41801, 41802, 41803, 41810, 41820, 41821, 41822, 41823, 41999]) {
    assert.match(launcher, new RegExp(String(port)));
  }
});
