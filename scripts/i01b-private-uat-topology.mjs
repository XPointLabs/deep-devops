import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
export const composePath = path.join(repositoryRoot, 'docker-compose.uat-private.yml');

export const syntheticRouterIds = Object.freeze([
  'a1'.repeat(32),
  'b2'.repeat(32),
  'c3'.repeat(32)
]);

const expectedServices = Object.freeze([
  'calls',
  'file',
  'push',
  'storage',
  'xnode-1',
  'xnode-2',
  'xnode-3'
]);
const expectedRouters = Object.freeze(['xnode-1', 'xnode-2', 'xnode-3']);
const expectedIps = Object.freeze(['172.30.81.11', '172.30.81.12', '172.30.81.13']);
const ancillaryLoopbackPorts = Object.freeze({
  file: '29101',
  push: '29102',
  calls: '29103'
});
const networkName = 'i01b-private-uat';
const resourcePrefix = 'deep-i01b-private-uat-';

function exactKeys(actual, expected, label) {
  assert.deepEqual(Object.keys(actual ?? {}).sort(), [...expected].sort(), `${label} must have exact keys`);
}

function assertExactString(environment, key, expected, routerName) {
  assert.equal(environment[key], expected, `${routerName} must set ${key}=${expected}`);
}

function getAllowlist(environment, routerName) {
  const prefix = 'Runtime__PrivatePeerEndpointAllowlist__';
  const allowlistKeys = Object.keys(environment).filter(key => key.startsWith(prefix));
  assert.equal(allowlistKeys.length, 12, `${routerName} must render exactly three complete allowlist tuples`);

  return [0, 1, 2].map(index => {
    const item = {};
    for (const field of ['RouterId', 'IpAddress', 'Port', 'Path']) {
      const key = `${prefix}${index}__${field}`;
      assert.ok(Object.hasOwn(environment, key), `${routerName} is missing ${key}`);
      item[field] = environment[key];
    }
    return item;
  });
}

function validateNoChainConfiguration(topology) {
  const forbiddenKey = /(^Contracts__|^RegistryRegistration__|Ethereum|Arbitrum|ChainId|RpcUrl|FallbackRpc)/i;
  const forbiddenValue = /(arbitrum|sepolia|ethereum|eth_chainId|:8545\b|\/rpc\b)/i;
  for (const [serviceName, service] of Object.entries(topology.services)) {
    for (const [key, value] of Object.entries(service.environment ?? {})) {
      assert.doesNotMatch(key, forbiddenKey, `${serviceName} contains chain/RPC variable ${key}`);
      assert.doesNotMatch(String(value), forbiddenValue, `${serviceName}.${key} contains a chain/RPC value`);
    }
  }
}

function validateFreshIdentityContract(topology, retired) {
  const retiredRouterIds = new Set(
    (retired.retiredRouterPublicIds ?? []).map(value => String(value).toLowerCase())
  );
  const renderedRouterIds = expectedRouters.map(name =>
    String(topology.services[name].environment.Node__RouterId).toLowerCase()
  );
  assert.equal(new Set(renderedRouterIds).size, 3, 'router identities must be unique');
  for (const routerId of renderedRouterIds) {
    assert.match(routerId, /^[0-9a-f]{64}$/, 'router identity must be exactly 64 hexadecimal characters');
    assert.ok(!retiredRouterIds.has(routerId), 'retired public router identity is forbidden');
  }
}

function validatePlaceholderContract(source, example, secretTemplates, retired) {
  assert.doesNotMatch(source, /(?:^|[/\\])\.?env\.uat(?:$|[/\\\s])/im, 'old .env.uat path is forbidden');
  assert.doesNotMatch(source, /secret-templates[/\\]uat[/\\]/i, 'old UAT secret template path is forbidden');
  for (const variable of [
    'I01B_PRIVATE_UAT_NODE_1_ROUTER_ID',
    'I01B_PRIVATE_UAT_NODE_2_ROUTER_ID',
    'I01B_PRIVATE_UAT_NODE_3_ROUTER_ID',
    'I01B_PRIVATE_UAT_NODE_1_ED25519_SECRET_FILE',
    'I01B_PRIVATE_UAT_NODE_2_ED25519_SECRET_FILE',
    'I01B_PRIVATE_UAT_NODE_3_ED25519_SECRET_FILE'
  ]) {
    assert.match(
      source,
      new RegExp(`\\$\\{${variable}:\\?REQUIRED`),
      `${variable} must be a REQUIRED compose placeholder`
    );
  }
  for (const index of [1, 2, 3]) {
    assert.match(
      example,
      new RegExp(`I01B_PRIVATE_UAT_NODE_${index}_ROUTER_ID=__REQUIRED_FRESH_`),
      `node ${index} public identity example must remain a fresh placeholder`
    );
    assert.match(
      secretTemplates[index - 1],
      new RegExp(`^__REQUIRED_FRESH_I01B_PRIVATE_UAT_NODE_${index}_ED25519_SEED_NOT_COMMITTED__\\s*$`),
      `node ${index} secret template must contain only its required placeholder`
    );
  }

  const retiredStrings = [
    ...(retired.retiredOperatorAddresses ?? []),
    ...(retired.retiredRouterPublicIds ?? [])
  ];
  const newConfigurationText = [source, example, ...secretTemplates].join('\n').toLowerCase();
  for (const retiredValue of retiredStrings) {
    assert.ok(
      !newConfigurationText.includes(String(retiredValue).toLowerCase()),
      `retired identity ${retiredValue} must not appear in the private UAT configuration`
    );
  }
  assert.doesNotMatch(
    newConfigurationText,
    /contractnodeid|contract_node_id/,
    'chain contract node IDs are forbidden in the chain-free private topology'
  );
}

export function validateTopology(topology, inputs) {
  assert.equal(topology.name, 'deep-i01b-private-uat', 'compose project name must be standalone');
  assert.deepEqual(Object.keys(topology.services).sort(), [...expectedServices], 'service set must be exact');

  exactKeys(topology.networks, [networkName], 'compose networks');
  const network = topology.networks[networkName];
  assert.equal(network.name, 'deep-i01b-private-uat-isolated', 'network resource name must be standalone');
  assert.equal(network.internal, true, 'private UAT network must be internal');
  assert.equal(network.driver, 'bridge', 'private UAT network must use the bridge driver');
  assert.deepEqual(
    network.ipam?.config?.map(item => item.subnet),
    ['172.30.81.0/24'],
    'private UAT network must have one exact subnet'
  );

  exactKeys(topology.secrets, [
    'i01b-private-uat-node-1-ed25519',
    'i01b-private-uat-node-2-ed25519',
    'i01b-private-uat-node-3-ed25519'
  ], 'compose secrets');
  exactKeys(topology.volumes, [
    'i01b-private-uat-calls-state',
    'i01b-private-uat-file-state',
    'i01b-private-uat-push-state',
    'i01b-private-uat-storage-state',
    'i01b-private-uat-xnode-1-state',
    'i01b-private-uat-xnode-2-state',
    'i01b-private-uat-xnode-3-state'
  ], 'compose volumes');
  for (const resource of [...Object.values(topology.secrets), ...Object.values(topology.volumes)]) {
    assert.ok(resource.name.startsWith(resourcePrefix), 'secret/volume resource name must be I01B-private');
  }

  let allowlistMappingCount = 0;
  let publishedPortCount = 0;
  for (const [serviceName, service] of Object.entries(topology.services)) {
    assert.ok(!service.network_mode, `${serviceName} must not use host network mode`);
    exactKeys(service.networks, [networkName], `${serviceName} networks`);
    assert.ok(
      !(service.extra_hosts ?? []).some(value => JSON.stringify(value).includes('host.docker.internal')),
      `${serviceName} must not use host.docker.internal`
    );

    const ports = service.ports ?? [];
    publishedPortCount += ports.length;
    if (!expectedRouters.includes(serviceName)) {
      if (serviceName === 'storage') {
        assert.equal(ports.length, 0, 'storage must remain internal and publish no ports');
      } else {
        assert.equal(ports.length, 1, `${serviceName} must publish one exact loopback E2E endpoint`);
        assert.equal(ports[0].host_ip, '127.0.0.1', `${serviceName} E2E endpoint must bind loopback`);
        assert.equal(ports[0].target, 8080, `${serviceName} E2E endpoint must target port 8080`);
        assert.equal(
          ports[0].published,
          ancillaryLoopbackPorts[serviceName],
          `${serviceName} E2E endpoint uses the wrong fixed host port`
        );
      }
      assert.equal(service.secrets?.length ?? 0, 0, `${serviceName} must not consume router secrets`);
      continue;
    }

    const routerIndex = expectedRouters.indexOf(serviceName);
    const expectedIp = expectedIps[routerIndex];
    const environment = service.environment ?? {};
    assert.equal(service.networks[networkName]?.ipv4_address, expectedIp, `${serviceName} static IP mismatch`);
    assertExactString(environment, 'DOTNET_ENVIRONMENT', 'UAT', serviceName);
    assertExactString(environment, 'ASPNETCORE_ENVIRONMENT', 'UAT', serviceName);
    assertExactString(environment, 'Node__Network', 'uat', serviceName);
    assertExactString(environment, 'Runtime__EnablePrivatePeerEndpoints', 'true', serviceName);
    assertExactString(environment, 'Runtime__PrivatePeerNetworkIdentity', 'uat', serviceName);
    assertExactString(environment, 'Runtime__AllowPublicPeerEndpoints', 'false', serviceName);
    assertExactString(environment, 'Runtime__RequireSignedRelayContacts', 'true', serviceName);
    assertExactString(environment, 'Runtime__BootstrapFromStorage', 'false', serviceName);
    assertExactString(environment, 'RegistryHeartbeat__Enabled', 'false', serviceName);
    assertExactString(environment, 'RegistryBootstrap__BaseUrl', '', serviceName);
    assertExactString(
      environment,
      'Node__PublicPeerRpcEndpoint',
      `http://${expectedIp}:8081/api/peer/onion`,
      serviceName
    );
    assertExactString(environment, 'Node__PublicPeerRpcPort', '8081', serviceName);
    assert.equal(
      service.labels?.['io.deep.i01b.public-peer-authorization'],
      'DenyAll',
      `${serviceName} must declare the fail-closed DenyAll expectation`
    );

    assert.equal(ports.length, 1, `${serviceName} may publish only its router API`);
    assert.equal(ports[0].host_ip, '127.0.0.1', `${serviceName} API must bind only to loopback`);
    assert.equal(ports[0].target, 8080, `${serviceName} may publish only target 8080`);
    assert.notEqual(ports[0].target, 8081, `${serviceName} peer RPC must not be published`);
    assert.notEqual(ports[0].target, 443, `${serviceName} VLESS must not be published`);

    assert.equal(service.secrets?.length, 1, `${serviceName} must consume one Ed25519 seed secret`);
    assert.equal(
      service.secrets[0].source,
      `i01b-private-uat-node-${routerIndex + 1}-ed25519`,
      `${serviceName} must consume only its own fresh identity secret`
    );
    assert.equal(
      environment.Node__Ed25519PrivateKeyPath,
      '/run/secrets/i01b-private-uat-node-ed25519',
      `${serviceName} must sign relay contacts from its mounted secret`
    );
    exactKeys(service.depends_on, ['storage'], `${serviceName} dependencies`);

    const allowlist = getAllowlist(environment, serviceName);
    allowlistMappingCount += allowlist.length;
    assert.deepEqual(
      allowlist,
      expectedIps.map((ipAddress, index) => ({
        RouterId: topology.services[expectedRouters[index]].environment.Node__RouterId,
        IpAddress: ipAddress,
        Port: '8081',
        Path: '/api/peer/onion'
      })),
      `${serviceName} allowlist must equal all three advertised tuples, including self`
    );
    assert.deepEqual(
      allowlist[routerIndex],
      {
        RouterId: environment.Node__RouterId,
        IpAddress: expectedIp,
        Port: '8081',
        Path: '/api/peer/onion'
      },
      `${serviceName} self tuple must equal its signed advertised identity`
    );
  }

  assert.equal(allowlistMappingCount, 9, 'topology must render exactly nine allowlist mappings');
  assert.equal(
    publishedPortCount,
    6,
    'topology must publish exactly three router APIs and three ancillary E2E endpoints'
  );
  assert.doesNotMatch(inputs.source, /host\.docker\.internal/i, 'host.docker.internal is forbidden');
  assert.doesNotMatch(inputs.source, /\bnetwork_mode\s*:\s*host\b/i, 'host network mode is forbidden');
  validateNoChainConfiguration(topology);
  validateFreshIdentityContract(topology, inputs.retired);
  validatePlaceholderContract(
    inputs.source,
    inputs.example,
    inputs.secretTemplates,
    inputs.retired
  );

  return {
    schemaVersion: '1.0.0',
    status: 'static-private-topology-contract-accepted',
    composeProject: topology.name,
    serviceCount: Object.keys(topology.services).length,
    routerCount: expectedRouters.length,
    compatibilityServiceCount: 4,
    allowlistMappingCount,
    publishedLoopbackRouterApiCount: expectedRouters.length,
    publishedLoopbackAncillaryCount: Object.keys(ancillaryLoopbackPorts).length,
    networkCount: Object.keys(topology.networks).length,
    volumeCount: Object.keys(topology.volumes).length,
    secretCount: Object.keys(topology.secrets).length,
    publicPeerAuthorizationExpected: 'DenyAll',
    uatRestartAuthorized: false,
    productionReady: false
  };
}

export function renderTopology() {
  const environment = {
    ...process.env,
    COMPOSE_DISABLE_ENV_FILE: '1',
    I01B_PRIVATE_UAT_NODE_1_ROUTER_ID: syntheticRouterIds[0],
    I01B_PRIVATE_UAT_NODE_2_ROUTER_ID: syntheticRouterIds[1],
    I01B_PRIVATE_UAT_NODE_3_ROUTER_ID: syntheticRouterIds[2],
    I01B_PRIVATE_UAT_NODE_1_ED25519_SECRET_FILE:
      './secret-templates/uat-private-i01b/node-1-ed25519.seed.example',
    I01B_PRIVATE_UAT_NODE_2_ED25519_SECRET_FILE:
      './secret-templates/uat-private-i01b/node-2-ed25519.seed.example',
    I01B_PRIVATE_UAT_NODE_3_ED25519_SECRET_FILE:
      './secret-templates/uat-private-i01b/node-3-ed25519.seed.example'
  };
  const result = spawnSync(
    'docker',
    ['compose', '-f', path.basename(composePath), 'config', '--format', 'json'],
    {
      cwd: repositoryRoot,
      env: environment,
      encoding: 'utf8',
      windowsHide: true
    }
  );
  if (result.error) throw new Error(`docker compose config could not run: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`docker compose config failed closed: ${result.stderr.trim()}`);
  }
  return JSON.parse(result.stdout);
}

export async function loadContractInputs() {
  const secretTemplateDirectory = path.join(repositoryRoot, 'secret-templates', 'uat-private-i01b');
  const [source, example, retired, ...secretTemplates] = await Promise.all([
    readFile(composePath, 'utf8'),
    readFile(path.join(repositoryRoot, '.env.uat-private.example'), 'utf8'),
    readFile(path.join(repositoryRoot, 'config', 'retired-uat-public-identities.json'), 'utf8')
      .then(JSON.parse),
    ...[1, 2, 3].map(index =>
      readFile(path.join(secretTemplateDirectory, `node-${index}-ed25519.seed.example`), 'utf8')
    )
  ]);
  return { source, example, retired, secretTemplates };
}

export async function main() {
  const result = validateTopology(renderTopology(), await loadContractInputs());
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01B private UAT topology validation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
