import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertNoForbiddenText,
  assertOwnedResources,
  assertSafeCleanupCommand,
  validateCleanupInventory,
  validateComposeModel,
  validateImageMetadata,
  validateKeepRunningGate,
  validateOwnershipReceipt,
  validateProjectName
} from './p15c-headless-contracts.mjs';

const sha = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const digest = `sha256:${'c'.repeat(64)}`;
const nonce = 'd'.repeat(32);
const project = 'p15c-0123456789abcdef';

test('project namespace is exact and bounded', () => {
  assert.equal(validateProjectName(project), true);
  for (const invalid of ['p15c-ABCDEF0123456789', 'p15-0123456789abcdef', 'p15c-short', `${project}0`]) {
    assert.throws(() => validateProjectName(invalid));
  }
});

test('cleanup is exact-project compose down only', () => {
  assert.equal(assertSafeCleanupCommand(`docker compose -p ${project} -f docker-compose.p15c-headless.yml down --volumes --remove-orphans`, project), true);
  for (const command of [
    'docker system prune -af',
    'docker container prune',
    'docker rm -f $(docker ps -aq)',
    'docker compose down --volumes',
    `docker compose -p p15c-fedcba9876543210 down --volumes --remove-orphans`
  ]) assert.throws(() => assertSafeCleanupCommand(command, project));
});

test('foreign resources are rejected before mutation', () => {
  assert.equal(assertOwnedResources(project, [{ project, kind: 'container' }]), true);
  assert.throws(() => assertOwnedResources(project, [{ project: 'foreign', kind: 'network' }]));
});

test('forbidden authority, transport and host-integration text is rejected', () => {
  assert.equal(assertNoForbiddenText('Vless__Enabled=false\nproductRuntime=false'), true);
  for (const value of ['mnemonic', 'arbitrum sepolia', 'host-gateway', '/var/run/docker.sock', 'privileged: true', 'profile signer']) {
    assert.throws(() => assertNoForbiddenText(value));
  }
});

test('compose model is isolated Linux ARM64 headless topology', () => {
  const roles = ['contracts-devnet', 'xnode-1', 'xnode-2', 'xnode-3', 'registry', 'staking-backend', 'storage', 'file', 'push', 'calls', 'test-client'];
  const services = Object.fromEntries(roles.map(role => [role, {
    platform: 'linux/arm64',
    networks: ['runtime'],
    image: role.startsWith('xnode-') ? `p15c-node:${sha}` : `p15c-${role}:${sha}`,
    pull_policy: 'never',
    read_only: true,
    cap_drop: ['ALL'],
    security_opt: ['no-new-privileges:true'],
    healthcheck: role === 'test-client' ? undefined : { test: ['CMD', 'true'] },
    labels: {
      'org.opencontainers.image.revision': sha,
      'org.opencontainers.image.source-tree': tree,
      'com.xpoint.p15c.role': role,
      'com.xpoint.evidence-class': 'headless-harness',
      'com.xpoint.product-runtime': 'false'
    },
    environment: role.startsWith('xnode-') ? { Vless__Enabled: 'false' } : {},
    ports: ['127.0.0.1:39001:8080']
  }]));
  services['test-client'].restart = 'no';
  delete services['test-client'].ports;
  delete services.storage.ports;
  delete services.file.ports;
  delete services.push.ports;
  delete services.calls.ports;
  const model = { name: project, services, networks: { runtime: { internal: true } }, volumes: {} };
  assert.equal(validateComposeModel(model, { sha, tree }), true);
  model.networks.runtime.internal = false;
  assert.throws(() => validateComposeModel(model, { sha, tree }));
});

test('built image metadata is exact and non-product', () => {
  const labels = {
    'org.opencontainers.image.revision': sha,
    'org.opencontainers.image.source-tree': tree,
    'org.opencontainers.image.source': 'xnode',
    'com.xpoint.p15c.role': 'xnode',
    'com.xpoint.evidence-class': 'headless-harness',
    'com.xpoint.product-runtime': 'false',
    'com.xpoint.p15c.ownership-nonce': nonce
  };
  assert.equal(validateImageMetadata({ id: digest, os: 'linux', architecture: 'arm64', labels }, { sha, tree, role: 'xnode', nonce }), true);
  labels['com.xpoint.product-runtime'] = 'true';
  assert.throws(() => validateImageMetadata({ id: digest, os: 'linux', architecture: 'arm64', labels }, { sha, tree, role: 'xnode', nonce }));
});

test('KeepRunning and receipt validation fail closed', () => {
  assert.equal(validateKeepRunningGate({ allGatesPassed: true, requested: true }), true);
  assert.throws(() => validateKeepRunningGate({ allGatesPassed: false, requested: true }));
  const receipt = { schema: 'deep-p15c-ownership.v1', project, nonce, composeSha256: digest.slice(7), sources: { devops: { sha, tree } }, images: [{ role: 'xnode', id: digest }] };
  assert.equal(validateOwnershipReceipt(receipt, { project, nonce, composeSha256: digest.slice(7), sources: receipt.sources }), true);
  assert.throws(() => validateOwnershipReceipt({ ...receipt, nonce: 'e'.repeat(32) }, { project, nonce, composeSha256: digest.slice(7), sources: receipt.sources }));
});

test('cleanup inventory must be empty', () => {
  assert.equal(validateCleanupInventory({ containers: 0, networks: 0, volumes: 0, images: 0 }), true);
  assert.throws(() => validateCleanupInventory({ containers: 0, networks: 1, volumes: 0, images: 0 }));
});
