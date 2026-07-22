import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const compose = readFileSync(new URL('../docker-compose.survival.dev.yml', import.meta.url), 'utf8');
const docs = readFileSync(new URL('../docs/SURVIVAL_DEV_STACK.md', import.meta.url), 'utf8');
const launcher = readFileSync(new URL('./survival-dev.ps1', import.meta.url), 'utf8');
const seed = readFileSync(new URL('./survival-dev-seed.mjs', import.meta.url), 'utf8');
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
  assert.match(compose, /^networks:\r?\n  runtime:\r?\n    internal: true$/m);
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

test('every stateful service uses a named volume and operator commands are documented', () => {
  for (const volume of [
    'contracts-deployments', 'xnode-1-state', 'xnode-2-state', 'xnode-3-state',
    'registry-state', 'staking-state', 'storage-state', 'file-state', 'push-state', 'calls-state'
  ]) assert.match(compose, new RegExp(`^  ${volume}:$`, 'm'));
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml up -d --build --wait/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml ps/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml logs -f --tail=200/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml down/);
  assert.match(docs, /formal P15C release gate/i);
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
  for (const routerId of [
    '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
    '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
    'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b'
  ]) assert.match(launcher, new RegExp(routerId));
  assert.match(launcher, /survival-dev-seed\.mjs/);
  assert.doesNotMatch(launcher, /Up requires -LanHost/);
  assert.match(seed, /api\/network\/contact/);
  assert.match(seed, /relay-bootstrap/);
  assert.match(bootstrap, /api\/relay-contacts/);
  assert.match(bootstrap, /\/seed/);
  assert.match(serviceBlock('contracts-devnet'), /profiles: \[chain\]/);
  assert.match(serviceBlock('staking-backend'), /profiles: \[chain\]/);
  assert.match(compose, /Runtime__BootstrapFromStorage: "true"/);
  assert.match(compose, /RegistryBootstrap__BaseUrl: http:\/\/relay-bootstrap:8080/);
  assert.doesNotMatch(launcher, /nonce|evidence|receipt|P15C_/i);
});
