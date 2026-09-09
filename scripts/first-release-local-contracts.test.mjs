import test from 'node:test';
import assert from 'node:assert/strict';
import {
  renderBase,
  renderTls,
  validateBase,
  validateTls,
  validateSourceContracts,
  validateMissingEnvironmentFailsClosed
} from './first-release-local-contracts.mjs';

test('base compose fails closed when required identity inputs are absent', () => {
  assert.equal(validateMissingEnvironmentFailsClosed(), true);
});

test('base topology is direct Registry plus exactly three XNodes without HAProxy', () => {
  const topology = renderBase();
  assert.doesNotThrow(() => validateBase(topology));
});

test('base publication can be moved from loopback to an explicit LAN address', () => {
  const host = '192.0.2.25';
  const topology = renderBase({ FIRST_RELEASE_BIND_HOST: host, FIRST_RELEASE_PUBLIC_HOST: host });
  assert.equal(topology.services.registry.ports[0].host_ip, host);
  for (const name of ['xnode-1', 'xnode-2', 'xnode-3']) {
    assert.equal(topology.services[name].ports.every(port => port.host_ip === host), true);
    assert.equal(topology.services[name].environment.Node__PublicHost, host);
  }
});

test('base validation rejects a weakened XNode dependency', () => {
  const topology = structuredClone(renderBase());
  topology.services['xnode-1'].depends_on.registry.condition = 'service_started';
  assert.throws(() => validateBase(topology), /service_healthy/);
});

test('base validation rejects a mocked Xray transport', () => {
  const topology = structuredClone(renderBase());
  topology.services['xnode-2'].environment.Vless__MockProcess = 'true';
  assert.throws(() => validateBase(topology));
});

test('base validation rejects a swapped ONION receive position', () => {
  const topology = structuredClone(renderBase());
  topology.services['xnode-1'].environment.PrivacyRouting__ReceivePosition = 'Exit';
  assert.throws(() => validateBase(topology), /Ingress/);
});

test('TLS overlay hides direct APIs and keeps only direct VLESS publication', async () => {
  const topology = renderTls();
  const { haproxy } = await validateSourceContracts();
  assert.doesNotThrow(() => validateTls(topology, haproxy));
});

test('TLS validation rejects a re-exposed Registry cleartext port', async () => {
  const topology = structuredClone(renderTls());
  topology.services.registry.ports = [{ target: 8080, published: '42910', protocol: 'tcp', mode: 'ingress' }];
  const { haproxy } = await validateSourceContracts();
  assert.throws(() => validateTls(topology, haproxy));
});

test('TLS validation rejects a weakened common XNode dependency', async () => {
  const topology = structuredClone(renderTls());
  topology.services['xnode-1'].depends_on.registry.condition = 'service_started';
  const { haproxy } = await validateSourceContracts();
  assert.throws(() => validateTls(topology, haproxy), /service_healthy/);
});
