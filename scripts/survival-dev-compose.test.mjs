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

test('daily stack has a fixed isolated project, persistent services, and one chain volume initializer', () => {
  assert.match(compose, /^name: deep-survival-dev$/m);
  assert.doesNotMatch(compose, /P15C_|ownership-nonce|evidence|\buat\b|sepolia/i);
  const servicesSection = compose.match(/^services:\r?\n([\s\S]*?)(?=^networks:)/m)?.[1] ?? '';
  const services = [...servicesSection.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map(match => match[1]).sort();
  assert.deepEqual(services, [
    'calls', 'contracts-deploy', 'contracts-deployments-init', 'contracts-devnet', 'contracts-smoke', 'file', 'push', 'registry', 'relay-bootstrap', 'staking-backend',
    'storage', 'xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6'
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
  for (const role of ['xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6']) assert.match(serviceBlock(role), /<<: \*xnode/);
  for (const role of ['storage', 'file', 'push', 'calls']) assert.match(serviceBlock(role), /image: deep-survival\/compat:dev/);
  assert.doesNotMatch(compose, /--no-cache/);
});

test('only local Hardhat and loopback host ports are configured', () => {
  const deploymentsInit = serviceBlock('contracts-deployments-init');
  const contracts = serviceBlock('contracts-devnet');
  const deploy = serviceBlock('contracts-deploy');
  const smoke = serviceBlock('contracts-smoke');
  const staking = serviceBlock('staking-backend');
  assert.match(deploymentsInit, /profiles: \[chain\]/);
  assert.match(deploymentsInit, /user: "0:0"/);
  assert.match(deploymentsInit, /restart: "no"/);
  assert.match(deploymentsInit, /cap_drop: \[ALL\]/);
  assert.match(deploymentsInit, /cap_add: \[CHOWN\]/);
  assert.match(deploymentsInit, /no-new-privileges:true/);
  assert.match(deploymentsInit, /network_mode: none/);
  assert.match(deploymentsInit, /contracts-deployments:\/workspace\/deployments/);
  assert.match(deploymentsInit, /chown -R 1000:1000 \/workspace\/deployments/);
  assert.doesNotMatch(deploymentsInit, /build:/);
  assert.match(contracts, /command: \[pnpm, exec, hardhat, node, --hostname, 0\.0\.0\.0\]/);
  assert.match(contracts, /USER node/);
  assert.match(contracts, /restart: "no"/);
  assert.match(contracts, /contracts-deployments-init: \{ condition: service_completed_successfully \}/);
  assert.match(deploy, /profiles: \[chain\]/);
  assert.match(deploy, /restart: "no"/);
  assert.match(deploy, /network_mode: service:contracts-devnet/);
  assert.doesNotMatch(deploy, /<<: \*service|networks:/);
  assert.match(deploy, /cap_drop: \[ALL\]/);
  assert.match(deploy, /no-new-privileges:true/);
  assert.match(deploy, /contracts-deployments:\/workspace\/deployments/);
  assert.match(deploy, /contracts-devnet: \{ condition: service_healthy \}/);
  assert.match(deploy, /rm -f \/workspace\/deployments\/localhost\.latest\.json/);
  assert.match(deploy, /scripts\/deploy-local-devnet\.js --network localhost/);
  assert.match(smoke, /profiles: \[chain\]/);
  assert.match(smoke, /restart: "no"/);
  assert.match(smoke, /network_mode: service:contracts-devnet/);
  assert.doesNotMatch(smoke, /<<: \*service|networks:/);
  assert.match(smoke, /cap_drop: \[ALL\]/);
  assert.match(smoke, /no-new-privileges:true/);
  assert.match(smoke, /contracts-deployments:\/workspace\/deployments:ro/);
  assert.match(smoke, /contracts-deploy: \{ condition: service_completed_successfully \}/);
  assert.match(smoke, /scripts\/local-devnet-smoke\.js/);
  assert.match(staking, /contracts-smoke: \{ condition: service_completed_successfully \}/);
  assert.doesNotMatch(staking, /contracts-devnet: \{ condition: service_healthy \}/);
  assert.match(contracts, /eth_chainId/);
  assert.doesNotMatch(compose, /https?:\/\/(?!127\.0\.0\.1|0\.0\.0\.0|[a-z][a-z0-9-]*:)/i);
  const bindings = [...compose.matchAll(/"\$\{SURVIVAL_BIND_HOST:-127\.0\.0\.1\}:(\d+):(\d+)"/g)];
  assert.equal(bindings.length, 13);
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
  assert.match(docs, /41801, 41802, 41803, 41804, 41805, 41806, 41810, 41821, 41822, 41823/);
  assert.match(docs, /41545, 41811/);
});

test('every stateful service uses a named volume and operator commands are documented', () => {
  for (const volume of [
    'contracts-deployments', 'xnode-1-state', 'xnode-2-state', 'xnode-3-state',
    'xnode-4-state', 'xnode-5-state', 'xnode-6-state',
    'registry-state', 'staking-state', 'storage-state', 'file-state', 'push-state', 'calls-state'
  ]) assert.match(compose, new RegExp(`^  ${volume}:$`, 'm'));
  assert.match(docs, /survival-dev\.ps1 -Action Up/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml ps/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml logs -f --tail=200/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml down/);
  assert.match(docs, /formal P15C release gate/i);
  assert.match(docs, /raw `docker compose .*up.*` is not supported/i);
  assert.doesNotMatch(docs, /The chain profile is currently unsupported/i);
  assert.match(docs, /Direct `docker compose` chain\s+restarts are unsupported/i);
  assert.match(docs, /contracts-deployments-init/);
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
    'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b',
    'fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b',
    'fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def',
    'b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075'
  ]) assert.match(launcher, new RegExp(routerId));
  assert.match(launcher, /survival-dev-seed\.mjs/);
  assert.match(launcher, /survival-dev-context-export\.mjs/);
  assert.match(launcher, /function Reset-SurvivalChainLifecycle/);
  assert.match(launcher, /'contracts-deploy', 'contracts-smoke', 'staking-backend'/);
  assert.match(launcher, /if \(\$Chain\) \{ Reset-SurvivalChainLifecycle \}/);
  assert.match(launcher, /Restarting contracts-devnet invalidates its in-memory chain/);
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
  assert.match(compose, /Runtime__AllowPrivatePeerEndpoints: "true"/);
  assert.match(compose, /RegistryBootstrap__BaseUrl: http:\/\/relay-bootstrap:8080/);
  assert.doesNotMatch(launcher, /nonce|evidence|receipt|P15C_/i);
  assert.match(contextExport, /git.*ls-files/si);
  assert.match(contextExport, /prohibited source entries/i);
});

test('development identities remain exact strings and Up proves host HTTP reachability', () => {
  for (const suffix of ['1', '2', '3', '4', '5', '6']) {
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
  assert.doesNotMatch(launcher, /--force-recreate/);
  assert.match(launcher, /Assert-SurvivalHostEndpoints/);
  for (const port of [41801, 41802, 41803, 41804, 41805, 41806, 41810, 41820, 41821, 41822, 41823, 41999]) {
    assert.match(launcher, new RegExp(String(port)));
  }
});
