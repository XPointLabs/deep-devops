import assert from 'node:assert/strict';
import test from 'node:test';
import {
  loadContractInputs,
  renderTopology,
  validateTopology
} from './i01b-private-uat-topology.mjs';

const topology = renderTopology();
const inputs = await loadContractInputs();

function clone(value) {
  return structuredClone(value);
}

test('compose config renders and satisfies the complete I01B private UAT contract', () => {
  const result = validateTopology(topology, inputs);
  assert.deepEqual(
    {
      services: result.serviceCount,
      routers: result.routerCount,
      mappings: result.allowlistMappingCount,
      networks: result.networkCount,
      publicAuthorization: result.publicPeerAuthorizationExpected,
      restart: result.uatRestartAuthorized,
      production: result.productionReady
    },
    {
      services: 7,
      routers: 3,
      mappings: 9,
      networks: 1,
      publicAuthorization: 'DenyAll',
      restart: false,
      production: false
    }
  );
});

test('fails closed if any UAT/private environment switch changes', () => {
  const mutated = clone(topology);
  mutated.services['xnode-1'].environment.ASPNETCORE_ENVIRONMENT = 'Production';
  assert.throws(() => validateTopology(mutated, inputs), /ASPNETCORE_ENVIRONMENT=UAT/);
});

test('fails closed if public peer authorization is enabled', () => {
  const mutated = clone(topology);
  mutated.services['xnode-1'].environment.Runtime__AllowPublicPeerEndpoints = 'true';
  assert.throws(() => validateTopology(mutated, inputs), /AllowPublicPeerEndpoints=false/);
});

test('fails closed if one of the nine allowlist mappings is missing', () => {
  const mutated = clone(topology);
  delete mutated.services['xnode-2'].environment
    .Runtime__PrivatePeerEndpointAllowlist__2__Path;
  assert.throws(() => validateTopology(mutated, inputs), /exactly three complete allowlist tuples/);
});

test('fails closed if an advertised peer endpoint differs from its exact tuple', () => {
  const mutated = clone(topology);
  mutated.services['xnode-3'].environment.Node__PublicPeerRpcEndpoint =
    'http://172.30.81.12:8081/api/peer/onion';
  assert.throws(() => validateTopology(mutated, inputs), /PublicPeerRpcEndpoint/);
});

test('fails closed if storage, peer RPC, or VLESS becomes published', () => {
  const mutated = clone(topology);
  mutated.services.storage.ports = [{
    mode: 'ingress',
    host_ip: '0.0.0.0',
    target: 8080,
    published: '38100',
    protocol: 'tcp'
  }];
  assert.throws(() => validateTopology(mutated, inputs), /storage must remain internal/);
});

test('fails closed if an ancillary E2E endpoint is not an exact loopback binding', () => {
  const mutated = clone(topology);
  mutated.services.push.ports[0].host_ip = '0.0.0.0';
  assert.throws(() => validateTopology(mutated, inputs), /push E2E endpoint must bind loopback/);
});

test('fails closed on an extra network or host network mode', () => {
  const extraNetwork = clone(topology);
  extraNetwork.networks.default = { name: 'unexpected' };
  assert.throws(() => validateTopology(extraNetwork, inputs), /compose networks must have exact keys/);

  const hostMode = clone(topology);
  hostMode.services.calls.network_mode = 'host';
  assert.throws(() => validateTopology(hostMode, inputs), /must not use host network mode/);
});

test('fails closed on host.docker.internal', () => {
  const mutated = clone(topology);
  mutated.services.push.extra_hosts = ['host.docker.internal:host-gateway'];
  assert.throws(() => validateTopology(mutated, inputs), /must not use host\.docker\.internal/);
});

test('fails closed on any chain service or chain RPC variable', () => {
  const chainService = clone(topology);
  chainService.services['staking-indexer'] = clone(chainService.services.calls);
  assert.throws(() => validateTopology(chainService, inputs), /service set must be exact/);

  const chainVariable = clone(topology);
  chainVariable.services['xnode-1'].environment.Contracts__EthereumRpcUrl =
    'https://example.invalid/rpc';
  assert.throws(() => validateTopology(chainVariable, inputs), /chain\/RPC variable/);
});

test('fails closed on a retired public identity', () => {
  const mutated = clone(topology);
  const retiredId = inputs.retired.retiredRouterPublicIds[0];
  mutated.services['xnode-1'].environment.Node__RouterId = retiredId;
  for (const router of ['xnode-1', 'xnode-2', 'xnode-3']) {
    mutated.services[router].environment
      .Runtime__PrivatePeerEndpointAllowlist__0__RouterId = retiredId;
  }
  assert.throws(() => validateTopology(mutated, inputs), /retired public router identity is forbidden/);
});

test('fails closed if registry bootstrap or heartbeat is enabled', () => {
  const bootstrap = clone(topology);
  bootstrap.services['xnode-1'].environment.RegistryBootstrap__BaseUrl =
    'http://registry:8080';
  assert.throws(() => validateTopology(bootstrap, inputs), /RegistryBootstrap__BaseUrl=/);

  const heartbeat = clone(topology);
  heartbeat.services['xnode-1'].environment.RegistryHeartbeat__Enabled = 'true';
  assert.throws(() => validateTopology(heartbeat, inputs), /RegistryHeartbeat__Enabled=false/);
});
