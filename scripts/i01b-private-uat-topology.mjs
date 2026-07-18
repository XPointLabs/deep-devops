import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
export const composePath = path.join(repositoryRoot, 'docker-compose.uat-private.yml');
export const syntheticRouterIds = Object.freeze(['a1'.repeat(32), 'b2'.repeat(32), 'c3'.repeat(32)]);

const routers = Object.freeze(['xnode-1', 'xnode-2', 'xnode-3']);
const services = Object.freeze(['calls', 'file', 'push', 'storage', ...routers]);
const ips = Object.freeze(['172.30.81.11', '172.30.81.12', '172.30.81.13']);
const networkName = 'i01b-private-uat';
const ancillaryPorts = Object.freeze({ file: '29101', push: '29102', calls: '29103' });
const stateTargets = Object.freeze({
  calls: '/var/lib/deep/i01b-private-uat/calls',
  file: '/var/lib/deep/i01b-private-uat/file',
  push: '/var/lib/deep/i01b-private-uat/push',
  storage: '/var/lib/deep/i01b-private-uat/storage',
  'xnode-1': '/var/lib/deep/i01b-private-uat/xnode-1',
  'xnode-2': '/var/lib/deep/i01b-private-uat/xnode-2',
  'xnode-3': '/var/lib/deep/i01b-private-uat/xnode-3'
});
const routerServiceKeys = Object.freeze([
  'build', 'cap_add', 'cap_drop', 'command', 'depends_on', 'entrypoint', 'environment',
  'healthcheck', 'labels', 'networks', 'ports', 'secrets', 'security_opt', 'volumes'
]);
const ancillaryServiceKeys = Object.freeze([
  'build', 'cap_drop', 'command', 'entrypoint', 'environment', 'healthcheck', 'networks',
  'labels', 'security_opt', 'volumes'
]);

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value ?? {}).sort(), [...expected].sort(), `${label} must have exact keys`);
}

function exactValue(actual, expected, label) {
  assert.deepEqual(actual, expected, `${label} must be exact`);
}

function validateGlobalEscapeHatches(topology) {
  for (const [name, service] of Object.entries(topology.services)) {
    assert.ok(service.privileged === undefined || service.privileged === false, `${name} privileged is forbidden`);
    assert.equal(service.pid, undefined, `${name} pid namespace is forbidden`);
    assert.equal(service.ipc, undefined, `${name} ipc namespace is forbidden`);
    assert.equal(service.devices, undefined, `${name} devices are forbidden`);
    assert.equal(service.network_mode, undefined, `${name} network_mode is forbidden`);
    assert.equal(service.extra_hosts, undefined, `${name} extra_hosts and host-gateway are forbidden`);
    assert.notEqual(service.build?.network, 'host', `${name} build network host is forbidden`);
    assert.ok(
      !JSON.stringify(service).toLowerCase().includes('docker.sock'),
      `${name} docker.sock is forbidden`
    );
    for (const mount of service.volumes ?? []) {
      assert.equal(mount.type, 'volume', `${name} bind mounts are forbidden`);
    }
  }
}

function validateBuild(service, name, inputs) {
  exactKeys(service.build, ['args', 'context', 'dockerfile'], `${name} build`);
  assert.equal(service.build.context, inputs.syntheticXnodeContext, `${name} build context mismatch`);
  assert.equal(service.build.dockerfile, inputs.syntheticXnodeDockerfile, `${name} Dockerfile mismatch`);
  exactValue(service.build.args, {
    APP_DLL: 'XNode.dll',
    PROJECT: 'src/XNode/XNode.csproj',
    RUNTIME_IMAGE: `mcr.microsoft.com/dotnet/aspnet:10.0@${inputs.syntheticRuntimeDigest}`,
    SDK_IMAGE: `mcr.microsoft.com/dotnet/sdk:10.0@${inputs.syntheticSdkDigest}`,
    XRAY_SHA256: inputs.syntheticXraySha256,
    XRAY_VERSION: inputs.syntheticXrayVersion
  }, `${name} build args`);
  assert.match(service.build.args.SDK_IMAGE, /@sha256:[0-9a-f]{64}$/, `${name} SDK image must be digest pinned`);
  assert.match(service.build.args.RUNTIME_IMAGE, /@sha256:[0-9a-f]{64}$/, `${name} runtime image must be digest pinned`);
  assert.match(service.build.args.XRAY_SHA256, /^[0-9a-f]{64}$/, `${name} Xray SHA256 must be exact`);
}

function getAllowlist(environment, name) {
  const prefix = 'Runtime__PrivatePeerEndpointAllowlist__';
  const keys = Object.keys(environment).filter(key => key.startsWith(prefix));
  assert.equal(keys.length, 12, `${name} must render exactly three complete allowlist tuples`);
  return [0, 1, 2].map(index => Object.fromEntries(
    ['RouterId', 'IpAddress', 'Port', 'Path'].map(field => {
      const key = `${prefix}${index}__${field}`;
      assert.ok(Object.hasOwn(environment, key), `${name} is missing ${key}`);
      return [field, environment[key]];
    })
  ));
}

function validateRouter(topology, name, index, inputs) {
  const service = topology.services[name];
  exactKeys(service, routerServiceKeys, `${name} service`);
  validateBuild(service, name, inputs);
  exactValue(service.cap_add, ['NET_BIND_SERVICE'], `${name} cap_add`);
  exactValue(service.cap_drop, ['ALL'], `${name} cap_drop`);
  exactValue(service.security_opt, ['no-new-privileges:true'], `${name} security_opt`);
  assert.equal(service.command, null, `${name} command override is forbidden`);
  assert.equal(service.entrypoint, null, `${name} entrypoint override is forbidden`);
  exactValue(service.depends_on, { storage: { condition: 'service_healthy', required: true } }, `${name} depends_on`);
  exactKeys(service.networks, [networkName], `${name} networks`);
  assert.equal(service.networks[networkName].ipv4_address, ips[index], `${name} private IP mismatch`);

  const environment = service.environment;
  const expectedExact = {
    ASPNETCORE_ENVIRONMENT: 'UAT',
    ASPNETCORE_URLS: 'http://0.0.0.0:8080;http://0.0.0.0:8081',
    DOTNET_ENVIRONMENT: 'UAT',
    Node__ApiListenUrl: 'http://0.0.0.0:8080',
    Node__DataDirectory: stateTargets[name],
    Node__Ed25519PrivateKeyPath: '/run/secrets/i01b-private-uat-node-ed25519',
    Node__Network: 'uat',
    Node__PeerRpcListenUrl: 'http://0.0.0.0:8081',
    Node__PublicHost: ips[index],
    Node__PublicIp: ips[index],
    Node__PublicPeerRpcEndpoint: `http://${ips[index]}:8081/api/peer/onion`,
    Node__PublicPeerRpcPort: '8081',
    Node__PublicPort: '443',
    RegistryBootstrap__BaseUrl: '',
    RegistryHeartbeat__Enabled: 'false',
    Runtime__AllowPublicPeerEndpoints: 'false',
    Runtime__BootstrapFromStorage: 'false',
    Runtime__EnablePrivateAllowlistMembership: 'true',
    Runtime__EnablePrivatePeerEndpoints: 'true',
    Runtime__PrivatePeerNetworkIdentity: 'uat',
    Runtime__RequireSignedRelayContacts: 'true',
    StorageRpc__BaseUrl: 'http://storage:8080',
    Vless__Enabled: 'true',
    Vless__GeneratedConfigPath: '/tmp/deep/xray.generated.json',
    Vless__InboundListenHost: '0.0.0.0',
    Vless__InboundListenPort: '443',
    Vless__MockProcess: 'false',
    Vless__PublicHost: ips[index],
    Vless__PublicPort: '443',
    Vless__TransportMode: 'Tcp',
    Vless__WorkingDirectory: '/tmp/deep/xray',
    Vless__XrayExecutablePath: '/usr/local/bin/xray'
  };
  for (const [key, expected] of Object.entries(expectedExact)) {
    assert.equal(environment[key], expected, `${name} ${key} must be exact`);
  }
  assert.equal(environment.Node__RouterId, syntheticRouterIds[index], `${name} RouterId mismatch`);
  assert.equal(
    Object.keys(environment).length,
    Object.keys(expectedExact).length + 1 + 12,
    `${name} environment has unexpected keys`
  );
  exactValue(
    getAllowlist(environment, name),
    ips.map((ip, peerIndex) => ({
      RouterId: syntheticRouterIds[peerIndex],
      IpAddress: ip,
      Port: '8081',
      Path: '/api/peer/onion'
    })),
    `${name} allowlist`
  );

  exactValue(service.labels, {
    'io.deep.i01b.public-peer-authorization': 'DenyAll',
    'io.deep.i01b.readiness-before-bootstrap': '503',
    'io.deep.i01b.supply-chain-preflight-required': 'true',
    'io.deep.i01b.xnode-dockerfile-sha256': inputs.syntheticDockerfileSha256,
    'io.deep.i01b.xnode-source-commit': inputs.syntheticXnodeCommit
  }, `${name} labels`);
  exactValue(service.ports, [{
    mode: 'ingress', host_ip: '127.0.0.1', target: 8080,
    published: String(29311 + index), protocol: 'tcp'
  }], `${name} API publication`);
  exactValue(service.secrets, [{
    source: `i01b-private-uat-node-${index + 1}-ed25519`,
    target: 'i01b-private-uat-node-ed25519',
    mode: '0400'
  }], `${name} secret mount`);
  exactValue(service.volumes, [{
    type: 'volume',
    source: `i01b-private-uat-${name}-state`,
    target: stateTargets[name],
    volume: {}
  }], `${name} volume`);
}

function validateAncillary(service, name, inputs) {
  const expectedKeys = name === 'storage' ? ancillaryServiceKeys : [...ancillaryServiceKeys, 'ports'];
  exactKeys(service, expectedKeys, `${name} service`);
  exactKeys(service.build, ['args', 'context', 'dockerfile'], `${name} build`);
  assert.equal(service.build.context, repositoryRoot, `${name} build context mismatch`);
  assert.equal(service.build.dockerfile, `docker/${name}-service.Dockerfile`, `${name} Dockerfile mismatch`);
  exactValue(service.build.args, {
    NODE_IMAGE: `node:24-bookworm-slim@${inputs.syntheticNodeDigest}`
  }, `${name} build args`);
  assert.match(
    service.build.args.NODE_IMAGE,
    /^node:24-bookworm-slim@sha256:[0-9a-f]{64}$/,
    `${name} Node image must be digest pinned`
  );
  exactValue(service.labels, {
    'io.deep.i01b.compat-content-sha256': inputs.syntheticCompatContentSha256,
    'io.deep.i01b.devops-source-commit': inputs.syntheticDevopsCommit,
    'io.deep.i01b.supply-chain-preflight-required': 'true'
  }, `${name} labels`);
  exactValue(service.cap_drop, ['ALL'], `${name} cap_drop`);
  assert.equal(service.cap_add, undefined, `${name} cap_add is forbidden`);
  exactValue(service.security_opt, ['no-new-privileges:true'], `${name} security_opt`);
  assert.equal(service.command, null, `${name} command override is forbidden`);
  assert.equal(service.entrypoint, null, `${name} entrypoint override is forbidden`);
  exactValue(service.networks, { [networkName]: null }, `${name} networks`);
  exactValue(service.volumes, [{
    type: 'volume',
    source: `i01b-private-uat-${name}-state`,
    target: stateTargets[name],
    volume: {}
  }], `${name} volume`);
  if (name === 'storage') {
    assert.equal(service.ports, undefined, 'storage must remain unpublished');
  } else {
    exactValue(service.ports, [{
      mode: 'ingress', host_ip: '127.0.0.1', target: 8080,
      published: ancillaryPorts[name], protocol: 'tcp'
    }], `${name} loopback publication`);
  }
}

function validateSourcePlaceholders(inputs) {
  const requiredExampleVariables = [
    'I01B_PRIVATE_UAT_XNODE_DIR',
    'I01B_PRIVATE_UAT_XNODE_DOCKERFILE',
    'I01B_PRIVATE_UAT_EXPECTED_XNODE_COMMIT',
    'I01B_PRIVATE_UAT_EXPECTED_XNODE_DOCKERFILE_SHA256',
    'I01B_PRIVATE_UAT_DOTNET_SDK_DIGEST',
    'I01B_PRIVATE_UAT_DOTNET_RUNTIME_DIGEST',
    'I01B_PRIVATE_UAT_XRAY_VERSION',
    'I01B_PRIVATE_UAT_XRAY_SHA256',
    'I01B_PRIVATE_UAT_NODE_IMAGE_DIGEST',
    'I01B_PRIVATE_UAT_EXPECTED_DEVOPS_COMMIT',
    'I01B_PRIVATE_UAT_EXPECTED_COMPAT_CONTENT_SHA256',
    ...[1, 2, 3].map(index => `I01B_PRIVATE_UAT_NODE_${index}_ROUTER_ID`)
  ];
  for (const variable of [
    ...requiredExampleVariables,
    ...[1, 2, 3].map(index => `I01B_PRIVATE_UAT_NODE_${index}_ED25519_SECRET_FILE`)
  ]) {
    assert.match(inputs.source, new RegExp(`\\$\\{${variable}:\\?REQUIRED`), `${variable} must be REQUIRED`);
  }
  for (const variable of requiredExampleVariables) {
    assert.match(
      inputs.example,
      new RegExp(`^${variable}=(?:sha256:)?__REQUIRED`, 'm'),
      `${variable} example must be REQUIRED`
    );
  }
  for (const index of [1, 2, 3]) {
    assert.match(
      inputs.example,
      new RegExp(`^I01B_PRIVATE_UAT_NODE_${index}_ED25519_SECRET_FILE=\\./secret-templates/uat-private-i01b/node-${index}-ed25519\\.seed\\.example$`, 'm'),
      `node ${index} example secret path must point only at its placeholder template`
    );
  }
  for (const [index, template] of inputs.secretTemplates.entries()) {
    assert.match(
      template,
      new RegExp(`^__REQUIRED_FRESH_I01B_PRIVATE_UAT_NODE_${index + 1}_ED25519_SEED_NOT_COMMITTED__\\s*$`),
      `node ${index + 1} secret template must remain a placeholder`
    );
  }
  const newText = [inputs.source, inputs.example, ...inputs.secretTemplates].join('\n').toLowerCase();
  for (const retired of [
    ...(inputs.retired.retiredRouterPublicIds ?? []),
    ...(inputs.retired.retiredOperatorAddresses ?? [])
  ]) {
    assert.ok(!newText.includes(String(retired).toLowerCase()), `retired identity ${retired} is forbidden`);
  }
  assert.doesNotMatch(newText, /host\.docker\.internal|host-gateway|docker\.sock/i, 'host escape hatch is forbidden');
  assert.doesNotMatch(newText, /contractnodeid|contract_node_id/i, 'chain node IDs are forbidden');
  assert.match(inputs.reviewedDockerfile, /^ARG SDK_IMAGE\s*$/m, 'Dockerfile SDK image must have no default');
  assert.match(inputs.reviewedDockerfile, /^ARG RUNTIME_IMAGE\s*$/m, 'Dockerfile runtime image must have no default');
  assert.match(inputs.reviewedDockerfile, /^ARG XRAY_VERSION\s*$/m, 'Dockerfile Xray version must have no default');
  assert.match(inputs.reviewedDockerfile, /^ARG XRAY_SHA256\s*$/m, 'Dockerfile Xray SHA256 must be required');
  assert.doesNotMatch(inputs.reviewedDockerfile, /^ARG XRAY_DOWNLOAD_URL/m, 'ambient Xray URL override is forbidden');
  assert.match(
    inputs.reviewedDockerfile,
    /test "\$\{#XRAY_SHA256\}" -eq 64/,
    'Dockerfile must require an exact-length Xray SHA256'
  );
  assert.match(
    inputs.reviewedDockerfile,
    /sha256sum -c -/,
    'Dockerfile must verify the Xray archive unconditionally'
  );
  assert.doesNotMatch(
    inputs.reviewedDockerfile,
    /if \[ -n "\$\{XRAY_SHA256/,
    'optional Xray archive verification is forbidden'
  );
  for (const [name, dockerfile] of Object.entries(inputs.reviewedAncillaryDockerfiles)) {
    assert.match(dockerfile, /^ARG NODE_IMAGE\s*$/m, `${name} Node image must have no default`);
    assert.match(dockerfile, /^FROM \$\{NODE_IMAGE\}\s*$/m, `${name} must consume only the required Node image`);
    assert.doesNotMatch(dockerfile, /^FROM\s+node:/m, `${name} unpinned Node base is forbidden`);
  }
}

export function validateTopology(topology, inputs) {
  assert.equal(topology.name, 'deep-i01b-private-uat', 'compose project name mismatch');
  exactKeys(topology.services, services, 'service set');
  exactKeys(topology.networks, [networkName], 'compose networks');
  exactValue(topology.networks[networkName], {
    name: 'deep-i01b-private-uat-isolated',
    driver: 'bridge',
    ipam: { config: [{ subnet: '172.30.81.0/24' }] },
    internal: true
  }, 'private network');
  const expectedVolumeNames = services.map(name => `i01b-private-uat-${name}-state`).sort();
  exactKeys(topology.volumes, expectedVolumeNames, 'compose volumes');
  for (const name of expectedVolumeNames) {
    exactValue(topology.volumes[name], { name: `deep-${name}` }, `${name} resource`);
  }
  const secretNames = [1, 2, 3].map(index => `i01b-private-uat-node-${index}-ed25519`);
  exactKeys(topology.secrets, secretNames, 'compose secrets');
  for (const [index, name] of secretNames.entries()) {
    exactValue(topology.secrets[name], {
      name: `deep-${name}`,
      file: path.resolve(repositoryRoot, `secret-templates/uat-private-i01b/node-${index + 1}-ed25519.seed.example`)
    }, `${name} resource`);
  }

  validateGlobalEscapeHatches(topology);
  routers.forEach((name, index) => validateRouter(topology, name, index, inputs));
  ['storage', 'file', 'push', 'calls'].forEach(name =>
    validateAncillary(topology.services[name], name, inputs));
  validateSourcePlaceholders(inputs);

  return {
    schemaVersion: '2.0.0',
    status: 'static-private-topology-contract-accepted',
    serviceCount: 7,
    routerCount: 3,
    allowlistMappingCount: 9,
    readinessBeforeBootstrap: 503,
    sourcePreflightRequired: true,
    identityPreflightRequired: true,
    bootstrapCeremonyRequired: true,
    publicPeerAuthorizationExpected: 'DenyAll',
    vless443Published: false,
    realityVlessEndToEndProven: false,
    uatRestartAuthorized: false,
    productionReady: false
  };
}

export function renderTopology() {
  const syntheticXnodeContext = path.resolve(repositoryRoot, '..', 'synthetic-reviewed-xnode');
  const syntheticXnodeDockerfile = path.resolve(repositoryRoot, 'docker', 'xnode-xray.Dockerfile');
  const syntheticXnodeCommit = 'd4'.repeat(20);
  const syntheticDockerfileSha256 = 'e5'.repeat(32);
  const syntheticSdkDigest = `sha256:${'11'.repeat(32)}`;
  const syntheticRuntimeDigest = `sha256:${'22'.repeat(32)}`;
  const syntheticXrayVersion = 'v0.0.0-synthetic';
  const syntheticXraySha256 = '33'.repeat(32);
  const syntheticNodeDigest = `sha256:${'44'.repeat(32)}`;
  const syntheticDevopsCommit = 'f6'.repeat(20);
  const syntheticCompatContentSha256 = '55'.repeat(32);
  const environment = {
    ...process.env,
    COMPOSE_DISABLE_ENV_FILE: '1',
    I01B_PRIVATE_UAT_XNODE_DIR: syntheticXnodeContext,
    I01B_PRIVATE_UAT_XNODE_DOCKERFILE: syntheticXnodeDockerfile,
    I01B_PRIVATE_UAT_EXPECTED_XNODE_COMMIT: syntheticXnodeCommit,
    I01B_PRIVATE_UAT_EXPECTED_XNODE_DOCKERFILE_SHA256: syntheticDockerfileSha256,
    I01B_PRIVATE_UAT_DOTNET_SDK_DIGEST: syntheticSdkDigest,
    I01B_PRIVATE_UAT_DOTNET_RUNTIME_DIGEST: syntheticRuntimeDigest,
    I01B_PRIVATE_UAT_XRAY_VERSION: syntheticXrayVersion,
    I01B_PRIVATE_UAT_XRAY_SHA256: syntheticXraySha256,
    I01B_PRIVATE_UAT_NODE_IMAGE_DIGEST: syntheticNodeDigest,
    I01B_PRIVATE_UAT_EXPECTED_DEVOPS_COMMIT: syntheticDevopsCommit,
    I01B_PRIVATE_UAT_EXPECTED_COMPAT_CONTENT_SHA256: syntheticCompatContentSha256,
    ...Object.fromEntries([1, 2, 3].flatMap(index => [
      [`I01B_PRIVATE_UAT_NODE_${index}_ROUTER_ID`, syntheticRouterIds[index - 1]],
      [`I01B_PRIVATE_UAT_NODE_${index}_ED25519_SECRET_FILE`,
        `./secret-templates/uat-private-i01b/node-${index}-ed25519.seed.example`]
    ]))
  };
  const result = spawnSync(
    'docker',
    ['compose', '-f', path.basename(composePath), 'config', '--format', 'json'],
    { cwd: repositoryRoot, env: environment, encoding: 'utf8', windowsHide: true }
  );
  if (result.error) throw new Error(`docker compose config could not run: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`docker compose config failed closed: ${result.stderr.trim()}`);
  return {
    topology: JSON.parse(result.stdout),
    syntheticXnodeContext,
    syntheticXnodeDockerfile,
    syntheticXnodeCommit,
    syntheticDockerfileSha256,
    syntheticSdkDigest,
    syntheticRuntimeDigest,
    syntheticXrayVersion,
    syntheticXraySha256,
    syntheticNodeDigest,
    syntheticDevopsCommit,
    syntheticCompatContentSha256
  };
}

export async function loadContractInputs(rendered = renderTopology()) {
  const [source, example, reviewedDockerfile, retired, ...remaining] = await Promise.all([
    readFile(composePath, 'utf8'),
    readFile(path.join(repositoryRoot, '.env.uat-private.example'), 'utf8'),
    readFile(path.join(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'), 'utf8'),
    readFile(path.join(repositoryRoot, 'config', 'retired-uat-public-identities.json'), 'utf8').then(JSON.parse),
    ...['storage', 'file', 'push', 'calls'].map(name => readFile(
      path.join(repositoryRoot, 'docker', `${name}-service.Dockerfile`),
      'utf8'
    )),
    ...[1, 2, 3].map(index => readFile(
      path.join(repositoryRoot, 'secret-templates', 'uat-private-i01b', `node-${index}-ed25519.seed.example`),
      'utf8'
    ))
  ]);
  const reviewedAncillaryDockerfiles = Object.fromEntries(
    ['storage', 'file', 'push', 'calls'].map((name, index) => [name, remaining[index]])
  );
  const secretTemplates = remaining.slice(4);
  return {
    ...rendered,
    source,
    example,
    reviewedDockerfile,
    reviewedAncillaryDockerfiles,
    retired,
    secretTemplates
  };
}

export async function main() {
  const rendered = renderTopology();
  const result = validateTopology(rendered.topology, await loadContractInputs(rendered));
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01B private UAT topology validation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
