import assert from 'node:assert/strict';
import test from 'node:test';
import { loadContractInputs, renderTopology, validateTopology } from './i01b-private-uat-topology.mjs';

const rendered = renderTopology();
const topology = rendered.topology;
const inputs = await loadContractInputs(rendered);
const clone = value => structuredClone(value);

test('compose config satisfies the complete static private topology contract', () => {
  const result = validateTopology(topology, inputs);
  assert.deepEqual({
    services: result.serviceCount,
    routers: result.routerCount,
    mappings: result.allowlistMappingCount,
    readiness: result.readinessBeforeBootstrap,
    vlessPublished: result.vless443Published,
    restart: result.uatRestartAuthorized,
    production: result.productionReady
  }, {
    services: 7,
    routers: 3,
    mappings: 9,
    readiness: 503,
    vlessPublished: false,
    restart: false,
    production: false
  });
});

const mutations = [
  ['privileged', value => { value.services.calls.privileged = true; }, /privileged is forbidden/],
  ['host pid', value => { value.services.push.pid = 'host'; }, /pid namespace is forbidden/],
  ['host ipc', value => { value.services.file.ipc = 'host'; }, /ipc namespace is forbidden/],
  ['device', value => { value.services.storage.devices = ['/dev/kvm:/dev/kvm']; }, /devices are forbidden/],
  ['docker socket', value => {
    value.services.calls.volumes = [{
      type: 'bind', source: '/var/run/docker.sock', target: '/var/run/docker.sock'
    }];
  }, /docker\.sock is forbidden/],
  ['arbitrary bind', value => {
    value.services.push.volumes = [{ type: 'bind', source: '/tmp', target: '/host' }];
  }, /bind mounts are forbidden/],
  ['extra_hosts', value => { value.services.file.extra_hosts = ['example:127.0.0.1']; }, /extra_hosts/],
  ['host-gateway', value => {
    value.services.storage.extra_hosts = ['host.docker.internal:host-gateway'];
  }, /extra_hosts/],
  ['host network mode', value => { value.services.calls.network_mode = 'host'; }, /network_mode is forbidden/],
  ['host build network', value => { value.services.calls.build.network = 'host'; }, /build network host/],
  ['unexpected service key', value => { value.services.calls.user = 'root'; }, /service must have exact keys/],
  ['extra network', value => { value.networks.default = { name: 'unexpected' }; }, /compose networks/],
  ['extra service network', value => { value.services.calls.networks.default = null; }, /calls networks/],
  ['router cap add', value => { value.services['xnode-1'].cap_add = ['NET_ADMIN']; }, /cap_add/],
  ['ancillary cap add', value => { value.services.calls.cap_add = ['NET_BIND_SERVICE']; }, /service must have exact keys/],
  ['cap drop', value => { value.services.push.cap_drop = []; }, /cap_drop/],
  ['security option', value => { value.services.file.security_opt = []; }, /security_opt/],
  ['API listener', value => {
    value.services['xnode-1'].environment.Node__ApiListenUrl = 'http://0.0.0.0:9999';
  }, /Node__ApiListenUrl/],
  ['ASP.NET listeners', value => {
    value.services['xnode-1'].environment.ASPNETCORE_URLS = 'http://0.0.0.0:8080';
  }, /ASPNETCORE_URLS/],
  ['peer listener', value => {
    value.services['xnode-2'].environment.Node__PeerRpcListenUrl = 'http://0.0.0.0:443';
  }, /Node__PeerRpcListenUrl/],
  ['storage RPC URL', value => {
    value.services['xnode-1'].environment.StorageRpc__BaseUrl = 'http://host.docker.internal:8080';
  }, /StorageRpc__BaseUrl/],
  ['VLESS argument', value => {
    value.services['xnode-3'].environment.Vless__TransportMode = 'Reality';
  }, /Vless__TransportMode/],
  ['membership flag', value => {
    value.services['xnode-1'].environment.Runtime__EnablePrivateAllowlistMembership = 'false';
  }, /EnablePrivateAllowlistMembership/],
  ['storage bootstrap', value => {
    value.services['xnode-1'].environment.Runtime__BootstrapFromStorage = 'true';
  }, /BootstrapFromStorage/],
  ['public peer authorization', value => {
    value.services['xnode-2'].environment.Runtime__AllowPublicPeerEndpoints = 'true';
  }, /AllowPublicPeerEndpoints/],
  ['allowlist tuple', value => {
    value.services['xnode-3'].environment.Runtime__PrivatePeerEndpointAllowlist__1__Port = '8082';
  }, /allowlist/],
  ['volume source', value => {
    value.services.calls.volumes[0].source = 'foreign-volume';
  }, /calls volume/],
  ['volume target', value => {
    value.services.file.volumes[0].target = '/tmp/file';
  }, /file volume/],
  ['secret source', value => {
    value.services['xnode-1'].secrets[0].source = 'i01b-private-uat-node-2-ed25519';
  }, /secret mount/],
  ['secret mode', value => {
    value.services['xnode-2'].secrets[0].mode = '0444';
  }, /secret mount/],
  ['build context', value => {
    value.services['xnode-1'].build.context = 'C:\\ambient';
  }, /build context/],
  ['Dockerfile path', value => {
    value.services['xnode-2'].build.dockerfile = 'Dockerfile';
  }, /Dockerfile mismatch/],
  ['SDK digest removal', value => {
    value.services['xnode-3'].build.args.SDK_IMAGE = 'mcr.microsoft.com/dotnet/sdk:10.0';
  }, /build args/],
  ['Xray hash removal', value => {
    value.services['xnode-1'].build.args.XRAY_SHA256 = '';
  }, /build args/],
  ['Xray version change', value => {
    value.services['xnode-1'].build.args.XRAY_VERSION = 'latest';
  }, /build args/],
  ['public VLESS port', value => {
    value.services['xnode-1'].ports.push({
      mode: 'ingress', host_ip: '0.0.0.0', target: 443, published: '443', protocol: 'tcp'
    });
  }, /API publication/],
  ['public storage port', value => {
    value.services.storage.ports = [{
      mode: 'ingress', host_ip: '127.0.0.1', target: 8080, published: '38100', protocol: 'tcp'
    }];
  }, /service must have exact keys/]
];

for (const [name, mutate, pattern] of mutations) {
  test(`fails closed on ${name}`, () => {
    const value = clone(topology);
    mutate(value);
    assert.throws(() => validateTopology(value, inputs), pattern);
  });
}

test('fails closed on a retired router identity', () => {
  const value = clone(topology);
  const retired = inputs.retired.retiredRouterPublicIds[0];
  value.services['xnode-1'].environment.Node__RouterId = retired;
  assert.throws(() => validateTopology(value, inputs), /RouterId mismatch/);
});

test('fails closed if the reviewed Dockerfile restores image defaults or optional Xray verification', () => {
  const imageDefault = {
    ...inputs,
    reviewedDockerfile: inputs.reviewedDockerfile.replace(
      'ARG SDK_IMAGE',
      'ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0'
    )
  };
  assert.throws(() => validateTopology(topology, imageDefault), /SDK image must have no default/);

  const optionalHash = {
    ...inputs,
    reviewedDockerfile: inputs.reviewedDockerfile.replace(
      'echo "$XRAY_SHA256  /tmp/xray-download/xray.zip" | sha256sum -c -',
      'if [ -n "${XRAY_SHA256:-}" ]; then echo "$XRAY_SHA256  /tmp/xray-download/xray.zip" | sha256sum -c -; fi'
    )
  };
  assert.throws(() => validateTopology(topology, optionalHash), /optional Xray archive verification/);
});
