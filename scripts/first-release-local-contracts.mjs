import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
export const baseComposePath = path.join(repositoryRoot, 'docker-compose.first-release.local.yml');
export const tlsComposePath = path.join(repositoryRoot, 'docker-compose.first-release.tls.yml');
export const haproxyPath = path.join(repositoryRoot, 'config', 'first-release-local', 'haproxy.cfg');
export const xnodeDockerfilePath = path.join(repositoryRoot, 'docker', 'first-release-xnode.Dockerfile');
export const registryDockerfilePath = path.join(repositoryRoot, 'docker', 'first-release-registry.Dockerfile');
export const localNugetConfigPath = path.join(repositoryRoot, 'docker', 'first-release-local.NuGet.Config');
const routers = Object.freeze(['xnode-1', 'xnode-2', 'xnode-3']);
const routerIds = Object.freeze(['a1'.repeat(32), 'b2'.repeat(32), 'c3'.repeat(32)]);

function syntheticEnvironment(includeTls = false, overrides = {}) {
  const environment = {
    ...process.env,
    COMPOSE_DISABLE_ENV_FILE: '1',
    FIRST_RELEASE_BIND_HOST: '127.0.0.1',
    FIRST_RELEASE_PUBLIC_HOST: '127.0.0.1',
    FIRST_RELEASE_MASK_DOMAIN: 'www.example.com',
    FIRST_RELEASE_CONTACT_RESOLVE_NETWORK_ID: 'ab'.repeat(16),
    FIRST_RELEASE_CONTACT_RESOLVE_GENESIS_AUTHORITY_CORE_HASH: 'cd'.repeat(32),
    FIRST_RELEASE_CONTACT_RESOLVE_ARTIFACT_ROOT: path.join(repositoryRoot, 'synthetic-contact-artifacts'),
    FIRST_RELEASE_CONTACT_RESOLVE_OPERATOR_ROOT: path.join(repositoryRoot, 'synthetic-contact-operator')
  };
  for (let index = 1; index <= 3; index += 1) {
    Object.assign(environment, {
      [`FIRST_RELEASE_XNODE_${index}_ROUTER_ID`]: routerIds[index - 1],
      [`FIRST_RELEASE_XNODE_${index}_ED25519_FILE`]: path.join(repositoryRoot, `synthetic-node-${index}-ed25519`),
      [`FIRST_RELEASE_XNODE_${index}_X25519_FILE`]: path.join(repositoryRoot, `synthetic-node-${index}-x25519`),
      [`FIRST_RELEASE_XNODE_${index}_ONION_STATE_PROTECTION_FILE`]: path.join(repositoryRoot, `synthetic-node-${index}-onion-state`),
      [`FIRST_RELEASE_XNODE_${index}_BLS_PUBLIC_KEY`]: `${index}`.repeat(256),
      [`FIRST_RELEASE_XNODE_${index}_BLS_SIGNATURE`]: `${index + 3}`.repeat(512),
      [`FIRST_RELEASE_XNODE_${index}_VLESS_CLIENT_ID_FILE`]: path.join(repositoryRoot, `synthetic-node-${index}-vless-client-id`),
      [`FIRST_RELEASE_XNODE_${index}_REALITY_PUBLIC_KEY`]: `synthetic-public-${index}`,
      [`FIRST_RELEASE_XNODE_${index}_REALITY_PRIVATE_KEY_FILE`]: path.join(repositoryRoot, `synthetic-node-${index}-reality-private`),
      [`FIRST_RELEASE_XNODE_${index}_REALITY_SHORT_ID`]: `${index}`.repeat(16)
    });
  }
  for (let index = 1; index <= 3; index += 1) {
    Object.assign(environment, {
      [`FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_${index}_ID`]: `${index + 3}`.repeat(64),
      [`FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_${index}_SEED_FILE`]: path.join(repositoryRoot, `synthetic-witness-${index}.seed`)
    });
  }
  Object.assign(environment, {
    FIRST_RELEASE_CONTACT_RESOLVE_TRUSTED_TIME_KEY_FILE: path.join(repositoryRoot, 'synthetic-trusted-time.key'),
    FIRST_RELEASE_CONTACT_RESOLVE_REQUEST_LEDGER_KEY_FILE: path.join(repositoryRoot, 'synthetic-request-ledger.key'),
    FIRST_RELEASE_CONTACT_RESOLVE_ARTIFACT_STATE_KEY_FILE: path.join(repositoryRoot, 'synthetic-artifact-state.key')
  });
  if (includeTls) {
    environment.FIRST_RELEASE_TLS_PEM_FILE = path.join(repositoryRoot, 'synthetic-server.pem');
  }
  Object.assign(environment, overrides);
  return environment;
}

function render(files, includeTls = false, overrides = {}) {
  const args = ['compose'];
  for (const file of files) args.push('-f', path.basename(file));
  if (includeTls) args.push('--profile', 'tls');
  args.push('config', '--format', 'json');
  const result = spawnSync('docker', args, {
    cwd: repositoryRoot,
    env: syntheticEnvironment(includeTls, overrides),
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.error) throw new Error(`docker compose config could not run: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`docker compose config failed closed: ${result.stderr.trim()}`);
  return JSON.parse(result.stdout);
}

export function validateMissingEnvironmentFailsClosed() {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('FIRST_RELEASE_'))
  );
  environment.COMPOSE_DISABLE_ENV_FILE = '1';
  const result = spawnSync(
    'docker',
    ['compose', '-f', path.basename(baseComposePath), 'config', '--quiet'],
    { cwd: repositoryRoot, env: environment, encoding: 'utf8', windowsHide: true }
  );
  if (result.error) throw new Error(`docker compose config could not run: ${result.error.message}`);
  assert.notEqual(result.status, 0, 'base compose must reject absent required identity inputs');
  assert.match(result.stderr, /FIRST_RELEASE_/);
  return true;
}

export function renderBase(overrides = {}) {
  return render([baseComposePath], false, overrides);
}

export function renderTls(overrides = {}) {
  return render([baseComposePath, tlsComposePath], true, overrides);
}

function assertHardened(service, name) {
  assert.notEqual(service.privileged, true, `${name} must not be privileged`);
  assert.equal(service.network_mode === 'host', false, `${name} must not use host networking`);
  assert.equal(JSON.stringify(service).toLowerCase().includes('docker.sock'), false, `${name} must not mount docker.sock`);
  assert.deepEqual(service.cap_drop, ['ALL'], `${name} must drop every capability`);
  assert.deepEqual(service.security_opt, ['no-new-privileges:true'], `${name} must forbid privilege escalation`);
}

function publishedPorts(service) {
  return (service.ports ?? []).map(port => Number(port.published)).sort((left, right) => left - right);
}

function validateCommonTopology(topology, expectedServices) {
  assert.equal(topology.name, 'deep-first-release-local');
  assert.deepEqual(
    Object.keys(topology.services).sort(),
    expectedServices.slice().sort(),
    'lane must contain only the expected Registry, XNode, init/readiness and optional ingress services'
  );
  assert.equal(JSON.stringify(topology).toLowerCase().includes('survival'), false, 'lane must not reuse survival resources');
  assert.deepEqual(Object.keys(topology.volumes).sort(), [
    'registry-state', 'xnode-1-state', 'xnode-2-state', 'xnode-3-state'
  ]);
  assert.deepEqual(Object.keys(topology.secrets).sort(), [
    'contact-resolve-artifact-state-integrity', 'contact-resolve-request-ledger-integrity',
    'contact-resolve-trusted-time-integrity', 'contact-resolve-witness-1-ed25519',
    'contact-resolve-witness-2-ed25519', 'contact-resolve-witness-3-ed25519',
    'xnode-1-ed25519', 'xnode-1-onion-state-protection', 'xnode-1-reality-private',
    'xnode-1-vless-client-id', 'xnode-1-x25519',
    'xnode-2-ed25519', 'xnode-2-onion-state-protection', 'xnode-2-reality-private',
    'xnode-2-vless-client-id', 'xnode-2-x25519',
    'xnode-3-ed25519', 'xnode-3-onion-state-protection', 'xnode-3-reality-private',
    'xnode-3-vless-client-id', 'xnode-3-x25519'
  ]);
  assert.deepEqual(Object.keys(topology.networks), ['first-release']);
  assert.equal(topology.networks['first-release'].name, 'deep-first-release-local-network');
  assertHardened(topology.services.registry, 'registry');
  assert.match(topology.services.registry.build.dockerfile.replaceAll('\\', '/'), /deep-devops\/docker\/first-release-registry\.Dockerfile$/);
  assert.match(topology.services.registry.build.additional_contexts.protocol_source.replaceAll('\\', '/'), /deep-protocol$/);
  assert.equal(topology.services.registry.environment.ContactResolveProductionAuthority__Enabled, 'false');
  assert.equal(topology.services.registry.environment.ContactResolveDirectoryArtifacts__GenesisAuthorityCoreHashHex, 'cd'.repeat(32));
  assert.equal(topology.services.registry.volumes.some(volume =>
    volume.type === 'bind' && volume.target === '/contact-resolve/artifacts' && volume.read_only === true), true);
  assert.equal(topology.services.registry.secrets.length, 6);
  assert.match(topology.services.registry.healthcheck.test.join(' '), /health\/live/);
  assert.match(topology.services.registry.healthcheck.test.join(' '), /health\/ready/);
  assert.deepEqual(
    topology.services.registry.depends_on,
    { 'state-init': { condition: 'service_completed_successfully', required: true } }
  );

  routers.forEach((name, index) => {
    const service = topology.services[name];
    assertHardened(service, name);
    assert.equal(service.environment.Node__PublicHost, '127.0.0.1');
    assert.equal(service.environment.RegistryHeartbeat__Enabled, 'true');
    assert.equal(service.environment.RegistryHeartbeat__Endpoint, 'http://registry:8080/api/nodes/register');
    assert.equal(service.environment.RegistryRegistration__ChainId, '31337');
    assert.equal(
      service.environment.RegistryRegistration__ServiceNodeRewardsAddress,
      '0x000000000000000000000000000000000000f001'
    );
    assert.equal(service.environment.Vless__MockProcess, 'false');
    assert.equal(service.environment.RequiredTerminals__Contact, 'true');
    assert.equal(service.environment.RequiredTerminals__GroupControl, 'true');
    assert.equal(service.environment.Vless__TransportMode, 'Reality');
    assert.equal(service.environment.Vless__ClientIdFile, '/run/secrets/vless-client-id');
    assert.equal(service.environment.Vless__Reality__PrivateKeyFile, '/run/secrets/reality-private.key');
    assert.equal(Object.hasOwn(service.environment, 'Vless__ClientId'), false);
    assert.equal(Object.hasOwn(service.environment, 'Vless__Reality__PrivateKey'), false);
    assert.equal(service.environment.Node__RouterId, routerIds[index]);
    assert.match(service.build.dockerfile.replaceAll('\\', '/'), /deep-devops\/docker\/first-release-xnode\.Dockerfile$/);
    assert.equal(service.build.args.DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION, '0.6.0-local.2ee5f72df11c');
    assert.match(service.build.additional_contexts.protocol_cutover.replaceAll('\\', '/'), /xnode\/artifacts\/local-protocol-cutover$/);
    assert.match(service.build.additional_contexts.devops_context.replaceAll('\\', '/'), /deep-devops\/docker$/);
    assert.match(service.healthcheck.test.join(' '), /health\/ready/);
    assert.match(service.healthcheck.test.join(' '), /"running":true/);
    assert.match(service.healthcheck.test.join(' '), /"mocked":false/);
    assert.match(service.healthcheck.test.join(' '), /"degraded":false/);
    assert.match(service.healthcheck.test.join(' '), /"contact":"ready"/);
    assert.match(service.healthcheck.test.join(' '), /"groupControl":"ready"/);
    assert.equal(service.depends_on.registry.condition, 'service_healthy');
    assert.equal(service.depends_on['state-init'].condition, 'service_completed_successfully');
    const peers = Object.keys(service.environment).filter(key => /^PrivacyRouting__Peers__\d+__RouterId$/.test(key));
    assert.equal(peers.length, 2, `${name} must pin the other two routers`);
    assert.equal(service.environment.PrivacyRouting__StateProtectionKeyPath, '/run/secrets/onion-state-protection.key');
    assert.equal(service.environment.PrivacyRouting__ReplayStateRelativePath, 'privacy-routing/replay.state');
    assert.equal(service.environment.PrivacyRouting__EntropyStateRelativePath, 'privacy-routing/entropy.state');
    assert.equal(service.environment.PrivacyRouting__KeyVaultDirectoryRelativePath, 'privacy-routing/key-vault');
    assert.equal(service.environment.PrivacyRouting__ReceivePosition, ['Ingress', 'Core', 'Exit'][index]);
    assert.ok(service.secrets.some(secret =>
      secret.source === `xnode-${index + 1}-onion-state-protection` &&
      secret.target === 'onion-state-protection.key'));
    assert.ok(service.secrets.some(secret =>
      secret.source === `xnode-${index + 1}-vless-client-id` &&
      secret.target === 'vless-client-id'));
    assert.ok(service.secrets.some(secret =>
      secret.source === `xnode-${index + 1}-reality-private` &&
      secret.target === 'reality-private.key'));
  });

  const readiness = topology.services['topology-ready'];
  assertHardened(readiness, 'topology-ready');
  assert.equal(readiness.user, '65532:65532');
  for (const name of ['registry', ...routers]) {
    assert.equal(readiness.depends_on[name].condition, 'service_healthy', `readiness must wait for ${name}`);
  }
  assert.match(readiness.command.join(' '), /totalNodes === 3/);
  assert.match(readiness.command.join(' '), /transportStatus\?\.running === true/);
  assert.match(readiness.command.join(' '), /attempt < 45/);
}

export function validateBase(topology) {
  validateCommonTopology(
    topology,
    ['registry', 'state-init', 'topology-ready', ...routers]
  );
  assert.equal(JSON.stringify(topology).toLowerCase().includes('haproxy'), false, 'HAProxy is forbidden in base dev');
  assert.deepEqual(publishedPorts(topology.services.registry), [42910]);
  assert.equal(topology.services.registry.ports[0].host_ip, '127.0.0.1');
  routers.forEach((name, index) => {
    const service = topology.services[name];
    assert.deepEqual(publishedPorts(service), [42901 + index, 42941 + index]);
    assert.equal(service.ports.every(port => port.host_ip === '127.0.0.1'), true);
  });
  return { serviceCount: 6, routerCount: 3, haproxyInBase: false };
}

export function validateTls(topology, haproxy) {
  validateCommonTopology(
    topology,
    ['registry', 'state-init', 'tls-ingress', 'topology-ready', ...routers]
  );
  const ingress = topology.services['tls-ingress'];
  assert.ok(ingress, 'TLS overlay must add HAProxy ingress');
  assert.deepEqual(ingress.profiles, ['tls']);
  assertHardened(ingress, 'tls-ingress');
  assert.deepEqual(publishedPorts(ingress), [43001, 43002, 43003, 43010]);
  assert.deepEqual(publishedPorts(topology.services.registry), []);
  routers.forEach((name, index) => {
    assert.deepEqual(publishedPorts(topology.services[name]), [42941 + index], `${name} must expose only VLESS directly in TLS mode`);
    assert.match(topology.services[name].environment.PrivacyRouting__PublicPeerBaseUrl, /^https:\/\//);
  });
  assert.match(haproxy, /resolvers docker[\s\S]*nameserver docker_dns 127\.0\.0\.11:53/);
  assert.equal((haproxy.match(/resolvers docker resolve-prefer ipv4 init-addr libc,none/g) ?? []).length, 10);
  assert.match(haproxy, /http-request deny deny_status 404/);
  assert.doesNotMatch(haproxy, /health\/(?:live|ready)/, 'health endpoints must not be public through HAProxy');
  return { tlsProfile: true, directApiPorts: 0, directVlessPorts: 3 };
}

export async function validateSourceContracts() {
  const [baseSource, tlsSource, envExample, haproxy, xnodeDockerfile, registryDockerfile, localNugetConfig] = await Promise.all([
    readFile(baseComposePath, 'utf8'),
    readFile(tlsComposePath, 'utf8'),
    readFile(path.join(repositoryRoot, '.env.first-release.local.example'), 'utf8'),
    readFile(haproxyPath, 'utf8'),
    readFile(xnodeDockerfilePath, 'utf8'),
    readFile(registryDockerfilePath, 'utf8'),
    readFile(localNugetConfigPath, 'utf8')
  ]);
  assert.doesNotMatch(baseSource, /haproxy/i, 'base compose source must not mention HAProxy');
  assert.match(tlsSource, /profiles: \[tls\]/);
  assert.doesNotMatch(
    envExample,
    /(?:REALITY_PRIVATE_KEY|ED25519_FILE|X25519_FILE|ONION_STATE_PROTECTION_FILE)=[0-9a-f]{64}$/m,
    'example must not contain private material'
  );
  assert.equal((baseSource.match(/RegistryHeartbeat__Enabled: "true"/g) ?? []).length, 1, 'heartbeat must be enabled by the shared XNode environment only');
  assert.match(xnodeDockerfile, /dotnet restore "\$PROJECT" --locked-mode/);
  assert.match(xnodeDockerfile, /-p:DeepProtocolLocalCutover=true/g);
  assert.match(xnodeDockerfile, /sha256sum -c -/);
  assert.match(registryDockerfile, /-p:DeepProtocolLocalCutover=true/g);
  assert.match(registryDockerfile, /ENTRYPOINT \["dotnet", "Deep\.Registry\.Api\.dll"\]/);
  assert.match(baseSource, /ContactResolveProductionAuthority__Enabled: "false"/);
  assert.match(baseSource, /ContactResolveDirectoryArtifacts__ReadOnlyRoot/);
  assert.match(baseSource, /RequiredTerminals__Contact: "true"/);
  assert.match(baseSource, /RequiredTerminals__GroupControl: "true"/);
  assert.match(baseSource, /'"contact":"ready"'/);
  assert.match(baseSource, /'"groupControl":"ready"'/);
  assert.doesNotMatch(baseSource, /ContactService__RuntimeActivation: "true"/);
  assert.doesNotMatch(baseSource, /GroupControlService__RuntimeActivation: "true"/);
  assert.doesNotMatch(baseSource, /DevelopmentOnly|DEV[_-]?TRUST/i);
  assert.doesNotMatch(baseSource, /Vless__ClientId:/);
  assert.doesNotMatch(baseSource, /Vless__Reality__PrivateKey:/);
  assert.doesNotMatch(baseSource, /FIRST_RELEASE_XNODE_[123]_VLESS_CLIENT_ID(?!_FILE)/);
  assert.doesNotMatch(baseSource, /FIRST_RELEASE_XNODE_[123]_REALITY_PRIVATE_KEY(?!_FILE)/);
  assert.match(localNugetConfig, /first-release-local-protocol/);
  assert.doesNotMatch(localNugetConfig, /production-successor-protocol/);
  return { haproxy };
}

export async function main() {
  const { haproxy } = await validateSourceContracts();
  const result = {
    schemaVersion: '1.0.0',
    status: 'first-release-local-compose-contract-accepted',
    base: validateBase(renderBase()),
    tls: validateTls(renderTls(), haproxy),
    missingEnvironmentRejected: validateMissingEnvironmentFailsClosed(),
    survivalStackTouched: false,
    productionReady: false
  };
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`First-release local compose validation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
