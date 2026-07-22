import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const exactRoles = Object.freeze([
  'contracts-devnet', 'xnode-1', 'xnode-2', 'xnode-3', 'registry',
  'staking-backend', 'storage', 'file', 'push', 'calls', 'test-client'
]);
const longRunningRoles = new Set(exactRoles.filter(role => role !== 'test-client'));
const forbiddenText = /(?:\buat\b|\bmnemonic\b|sepolia|deep[-_](?:uat|dev|integration)|deep-staking-prod-local|old\s+identity|legacy\s+compose|host-gateway|\/var\/run\/docker\.sock|\bprivileged\s*:\s*true\b|\bcap_add\b|\bdevices\s*:|\bextra_hosts\b|\bnetwork_mode\s*:\s*host\b|profile\s*(?:signer|activation)|client\s+verifier|runtime\s+registration|mock\s*xray|product[- ]?runtime\s*:\s*true)/i;

function fail(message) { throw new Error(`P15C contract failure: ${message}`); }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function same(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
function exactKeys(value, expected) {
  return object(value) && same(Object.keys(value).sort(), [...expected].sort());
}

function parseJsonNoDuplicateKeys(text) {
  let index = 0;
  const whitespace = () => { while (/\s/.test(text[index] ?? '')) index += 1; };
  const string = () => {
    const start = index;
    if (text[index++] !== '"') fail('JSON string is invalid');
    while (index < text.length) {
      if (text[index] === '\\') { index += 2; continue; }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
    }
    fail('JSON string is unterminated');
  };
  const value = () => {
    whitespace();
    if (text[index] === '{') return jsonObject();
    if (text[index] === '[') return array();
    if (text[index] === '"') { string(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(index));
    if (!match) fail('JSON value is invalid');
    index += match[0].length;
  };
  const jsonObject = () => {
    index += 1; whitespace(); const keys = new Set();
    if (text[index] === '}') { index += 1; return; }
    while (index < text.length) {
      whitespace(); const key = string();
      if (keys.has(key)) fail(`duplicate JSON key: ${key}`);
      keys.add(key); whitespace();
      if (text[index++] !== ':') fail('JSON object separator is invalid');
      value(); whitespace();
      if (text[index] === '}') { index += 1; return; }
      if (text[index++] !== ',') fail('JSON object delimiter is invalid');
    }
    fail('JSON object is unterminated');
  };
  const array = () => {
    index += 1; whitespace();
    if (text[index] === ']') { index += 1; return; }
    while (index < text.length) {
      value(); whitespace();
      if (text[index] === ']') { index += 1; return; }
      if (text[index++] !== ',') fail('JSON array delimiter is invalid');
    }
    fail('JSON array is unterminated');
  };
  value(); whitespace();
  if (index !== text.length) fail('JSON has trailing content');
  return JSON.parse(text);
}

export function validateProjectName(value) {
  if (typeof value !== 'string' || !/^p15c-[0-9a-f]{16}$/.test(value)) fail('project name must be p15c- plus 16 lowercase hex characters');
  return true;
}

export function assertSafeCleanupCommand(command, project) {
  validateProjectName(project);
  const normalized = String(command).trim().replace(/\s+/g, ' ');
  if (/\b(?:system|container|network|volume|image)\s+prune\b/i.test(normalized) || /\bdocker\s+(?:rm|rmi)\b/i.test(normalized)) {
    fail('broad Docker cleanup is prohibited');
  }
  fail('cleanup must use individually captured and revalidated resource identities');
}

export function assertOwnedResources(project, resources) {
  validateProjectName(project);
  for (const resource of resources ?? []) {
    if (!object(resource) || resource.project !== project) fail(`foreign ${resource?.kind ?? 'Docker'} resource must not be touched`);
  }
  return true;
}

export function assertNoForbiddenText(value) {
  if (forbiddenText.test(String(value))) fail('forbidden authority, legacy, host-integration or activation text is present');
  return true;
}

function networksOf(service) {
  return Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});
}

function validatePorts(role, ports) {
  for (const value of ports ?? []) {
    const text = typeof value === 'string' ? value : `${value.host_ip ?? ''}:${value.published ?? ''}:${value.target ?? ''}`;
    if (!/^127\.0\.0\.1:\d{2,5}:\d{2,5}(?:\/(?:tcp|udp))?$/.test(text)) fail(`host port for ${role} must bind only 127.0.0.1`);
  }
  if (['storage', 'file', 'push', 'calls', 'test-client'].includes(role) && (ports?.length ?? 0) !== 0) {
    fail(`${role} must remain internal-only`);
  }
}

export function validateComposeModel(model, expected) {
  if (!object(model)) fail('Compose model is missing');
  validateProjectName(model.name);
  const roles = Object.keys(model.services ?? {}).sort();
  if (!same(roles, [...exactRoles].sort())) fail('Compose service set is not the exact P15C headless topology');
  const networks = Object.keys(model.networks ?? {});
  if (!same(networks, ['runtime']) || model.networks.runtime?.internal !== true) fail('exact internal runtime bridge is required');
  if (Object.keys(model.volumes ?? {}).length !== 0) fail('P15C named volumes are prohibited');

  const xnodeImages = new Set();
  const xnodeImageBuilders = [];
  for (const role of exactRoles) {
    const service = model.services[role];
    if (!object(service) || service.platform !== 'linux/arm64' || service.pull_policy !== 'never') fail(`${role} is not locked to local Linux ARM64/no-pull`);
    if (!same(networksOf(service), ['runtime'])) fail(`${role} must use only runtime bridge`);
    if (service.network_mode || service.pid || service.ipc || service.privileged === true || service.devices || service.extra_hosts || service.cap_add) fail(`unsafe host integration exists for ${role}`);
    if (service.read_only !== true || !Array.isArray(service.cap_drop) || !service.cap_drop.includes('ALL') || !Array.isArray(service.security_opt) || !service.security_opt.includes('no-new-privileges:true')) fail(`${role} hardening is incomplete`);
    if (longRunningRoles.has(role) && (!object(service.healthcheck) || service.healthcheck.disable === true || !Array.isArray(service.healthcheck.test))) fail(`${role} healthcheck is missing`);
    validatePorts(role, service.ports);

    const labels = service.labels ?? {};
    if (labels['org.opencontainers.image.revision'] !== expected.sha || labels['org.opencontainers.image.source-tree'] !== expected.tree || labels['com.xpoint.p15c.role'] !== role || labels['com.xpoint.evidence-class'] !== 'headless-harness' || String(labels['com.xpoint.product-runtime']) !== 'false') fail(`${role} service labels are invalid`);
    if (role.startsWith('xnode-')) {
      xnodeImages.add(service.image);
      if (object(service.build)) xnodeImageBuilders.push(role);
      const env = service.environment ?? {};
      if (String(env.Vless__Enabled).toLowerCase() !== 'false') fail(`${role} must explicitly disable VLESS`);
      if (typeof env.Node__Ed25519PrivateKeyPath !== 'string' || !env.Node__Ed25519PrivateKeyPath.startsWith('/run/secrets/') || Object.hasOwn(env, 'Node__Ed25519PrivateKey')) fail(`${role} identity must use only a Compose secret file path`);
      if (!Array.isArray(service.secrets) || service.secrets.length !== 2) fail(`${role} must receive only its generated seed and generated configuration secrets`);
    }
    if ((service.volumes?.length ?? 0) !== 0) fail(`${role} has a prohibited volume mount`);
  }
  if (xnodeImages.size !== 1) fail('all three XNodes must consume one exact image');
  if (!same(xnodeImageBuilders, ['xnode-1'])) fail('the shared XNode image must have exactly one producer');
  return true;
}

export function validateImageMetadata(image, expected) {
  if (!/^sha256:[0-9a-f]{64}$/.test(String(image?.id ?? ''))) fail('built image id is missing');
  if (image.os !== 'linux' || image.architecture !== 'arm64') fail('built image is not Linux ARM64');
  const labels = image.labels ?? {};
  const values = {
    'org.opencontainers.image.revision': expected.sha,
    'org.opencontainers.image.source-tree': expected.tree,
    'com.xpoint.p15c.role': expected.role,
    'com.xpoint.evidence-class': 'headless-harness',
    'com.xpoint.product-runtime': 'false',
    'com.xpoint.p15c.ownership-nonce': expected.nonce
  };
  for (const [key, value] of Object.entries(values)) if (String(labels[key] ?? '') !== value) fail(`image label ${key} is invalid`);
  if (!String(labels['org.opencontainers.image.source'] ?? '').trim()) fail('image source label is missing');
  return true;
}

export function validateKeepRunningGate({ allGatesPassed, requested }) {
  if (requested === true && allGatesPassed !== true) fail('KeepRunning is legal only after all gates pass');
  return true;
}

export function validateOwnershipReceipt(receipt, expected) {
  if (!exactKeys(receipt, ['schema', 'project', 'nonce', 'composeSha256', 'manifestSha256', 'foreignSnapshotSha256', 'sources', 'images']) || receipt.schema !== 'deep-p15c-ownership.v1') fail('ownership receipt schema is invalid');
  validateProjectName(receipt.project);
  if ((expected.project && receipt.project !== expected.project) || (expected.nonce && receipt.nonce !== expected.nonce) || !/^[0-9a-f]{32}$/.test(receipt.nonce ?? '') || (expected.composeSha256 && receipt.composeSha256 !== expected.composeSha256) || (expected.manifestSha256 && receipt.manifestSha256 !== expected.manifestSha256) || (expected.foreignSnapshotSha256 && receipt.foreignSnapshotSha256 !== expected.foreignSnapshotSha256) || ![receipt.composeSha256, receipt.manifestSha256, receipt.foreignSnapshotSha256].every(value => /^[0-9a-f]{64}$/.test(value ?? ''))) fail('ownership receipt binding is invalid');
  if (JSON.stringify(receipt.sources) !== JSON.stringify(expected.sources)) fail('ownership receipt source pins are invalid');
  if (!Array.isArray(receipt.images) || receipt.images.length < 1 || receipt.images.some(image => !exactKeys(image, ['role', 'source', 'sha', 'tree', 'id']) || !/^sha256:[0-9a-f]{64}$/.test(image.id ?? '') || !/^[a-z0-9-]+$/.test(image.role ?? '') || !/^[A-Za-z][A-Za-z0-9]*$/.test(image.source ?? '') || !/^[0-9a-f]{40}$/.test(image.sha ?? '') || !/^[0-9a-f]{40}$/.test(image.tree ?? ''))) fail('ownership receipt image inventory is invalid');
  const roles = receipt.images.map(image => image.role);
  const ids = receipt.images.map(image => image.id);
  if (new Set(roles).size !== roles.length || new Set(ids).size !== ids.length || (expected.roles && !same([...roles].sort(), [...expected.roles].sort()))) fail('ownership receipt image roles or ids are duplicated or unexpected');
  for (const image of receipt.images) {
    const source = receipt.sources[image.source];
    if (!source || source.sha !== image.sha || source.tree !== image.tree) fail('ownership receipt image source binding is invalid');
  }
  return true;
}

export function validateCleanupInventory(value) {
  for (const key of ['containers', 'networks', 'volumes', 'images']) if (value?.[key] !== 0) fail('owned resources remain after cleanup');
  return true;
}

export function validateCollisionInventory(project, inventory) {
  validateProjectName(project);
  for (const kind of ['containers', 'networks', 'volumes', 'images']) {
    if (!Array.isArray(inventory?.[kind])) fail('collision inventory is incomplete');
    if (inventory[kind].some(resource => resource?.project === project || String(resource?.name ?? '').startsWith(`${project}-`) || String(resource?.name ?? '').startsWith(`${project}_`))) fail(`project ${kind} collision exists`);
  }
  return true;
}

export function validateForeignInventoryInvariant(before, after) {
  if (typeof before !== 'string' || before !== after) fail('foreign Docker inventory changed');
  return true;
}

export function stableForeignInventory(inventory) {
  const containers = (inventory?.containers ?? []).map(value => ({
    id: value.id,
    name: value.name,
    image: value.image,
    project: value.project ?? ''
  }));
  const images = (inventory?.images ?? []).map(value => ({
    id: value.id,
    repository: value.repository,
    tag: value.tag,
    digest: value.digest
  }));
  const networks = (inventory?.networks ?? []).map(value => ({
    id: value.id,
    name: value.name,
    driver: value.driver,
    scope: value.scope,
    project: value.project ?? ''
  }));
  const volumes = (inventory?.volumes ?? []).map(value => ({
    name: value.name,
    driver: value.driver,
    project: value.project ?? ''
  }));
  const ordered = value => value
    .map(record => JSON.stringify(record))
    .sort()
    .map(record => JSON.parse(record));
  return JSON.stringify({
    containers: ordered(containers),
    images: ordered(images),
    networks: ordered(networks),
    volumes: ordered(volumes)
  });
}

function validateCleanupResource(resource, project, nonce) {
  if (!object(resource) || !['container', 'network', 'image'].includes(resource.kind)) {
    fail('captured cleanup resource is invalid');
  }
  if (resource.project !== project || resource.nonce !== nonce
    || resource.labels?.['com.xpoint.p15c.ownership-nonce'] !== nonce) {
    fail('captured cleanup resource ownership is invalid');
  }
  if (resource.kind === 'image' && !/^sha256:[0-9a-f]{64}$/.test(resource.id ?? '')) {
    fail('captured image identity is invalid');
  }
  if (['container', 'network'].includes(resource.kind) && !/^[0-9a-f]{12,64}$/.test(resource.id ?? '')) {
    fail(`captured ${resource.kind} identity is invalid`);
  }
}

function resourceKey(resource) {
  return `${resource.kind}:${resource.id}`;
}

function exactRemovalCommand(resource) {
  if (resource.kind === 'container') return ['container', 'rm', '--force', resource.id];
  if (resource.kind === 'network') return ['network', 'rm', resource.id];
  return ['image', 'rm', resource.id];
}

export async function executeExactResourceCleanup({ project, nonce, captured, list, inspect, remove }) {
  validateProjectName(project);
  if (!/^[0-9a-f]{32}$/.test(nonce ?? '') || !Array.isArray(captured) || captured.length === 0) {
    fail('cleanup authority must contain owned resource evidence');
  }
  for (const resource of captured) validateCleanupResource(resource, project, nonce);
  const keys = captured.map(resourceKey);
  if (new Set(keys).size !== keys.length) fail('cleanup authority contains duplicate resource identities');
  const rank = { container: 0, network: 1, image: 2 };
  const remaining = new Map(captured.map(resource => [resourceKey(resource), structuredClone(resource)]));
  const ordered = [...captured].sort((left, right) => rank[left.kind] - rank[right.kind] || resourceKey(left).localeCompare(resourceKey(right)));
  for (const resource of ordered) {
    const currentInventory = await list();
    const scoped = (currentInventory ?? []).filter(value => value?.project === project || value?.nonce === nonce);
    if (scoped.length !== remaining.size || scoped.some(value => !remaining.has(resourceKey(value)))) {
      fail('same-project or same-nonce cleanup membership changed after capture');
    }
    const current = await inspect(resource);
    validateCleanupResource(current, project, nonce);
    if (JSON.stringify(current) !== JSON.stringify(remaining.get(resourceKey(resource)))) {
      fail('cleanup resource identity or ownership changed before removal');
    }
    await remove(resource, exactRemovalCommand(resource));
    remaining.delete(resourceKey(resource));
  }
  const finalInventory = await list();
  if ((finalInventory ?? []).some(value => value?.project === project || value?.nonce === nonce)) {
    fail('owned or injected resources remain after exact cleanup');
  }
  return true;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export async function loadValidatedReceiptOnce({ read, validate }) {
  const bytes = await read();
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) fail('receipt reader must return canonical bytes');
  return deepFreeze(await validate(bytes));
}

function normalizedPath(value) {
  return String(value ?? '').replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
}

export async function publishOwnedOutput({ staged, destination, ownedRoot, destinationExists, validateParents, moveNoReplace }) {
  const stagedPath = normalizedPath(staged);
  const root = `${normalizedPath(ownedRoot)}\\`;
  if (!stagedPath.startsWith(root) || stagedPath === normalizedPath(destination)) fail('staged output is outside the owned run tree');
  for (let pass = 0; pass < 2; pass += 1) {
    if (await validateParents(destination) !== true) fail('output parent validation failed closed');
    if (await destinationExists(destination)) fail('output destination already exists');
  }
  await moveNoReplace(staged, destination);
  return true;
}

export function validateReceiptResources(resources, expected) {
  assertOwnedResources(expected.project, resources);
  for (const resource of resources ?? []) {
    if (!['container', 'network', 'image'].includes(resource.kind) || resource.nonce !== expected.nonce || resource.labels?.['com.xpoint.p15c.ownership-nonce'] !== expected.nonce) fail('owned runtime resource binding is invalid');
    if (resource.kind === 'image') {
      validateImageMetadata({ id: resource.id, os: resource.os, architecture: resource.architecture, labels: resource.labels }, { sha: expected.sources.devops.sha, tree: expected.sources.devops.tree, role: resource.role, nonce: expected.nonce });
    }
  }
  return true;
}

export async function executeWithGuaranteedCleanup(operation, cleanup) {
  let result;
  let operationError;
  let cleanupError;
  try { result = await operation(); } catch (error) { operationError = error; }
  try { await cleanup(); } catch (error) { cleanupError = error; }
  if (operationError && cleanupError) throw new AggregateError([operationError, cleanupError], 'P15C operation and cleanup both failed');
  if (operationError) throw operationError;
  if (cleanupError) throw cleanupError;
  return result;
}

export function validateLifecycleOperationOrder(operations) {
  const required = ['source-preflight', 'collision-check', 'foreign-snapshot', 'image-preflight', 'generate-secrets', 'source-export', 'compose-config', 'build', 'up-contracts', 'deploy-contracts', 'up-runtime', 'probe', 'e2e', 'labels', 'cleanup', 'evidence'];
  if (!Array.isArray(operations) || operations.length !== required.length || !same(operations, required)) fail('lifecycle operation order is invalid');
  return true;
}

export function validateLifecycleOperationPrefix(operations, { retained }) {
  const common = ['source-preflight', 'collision-check', 'foreign-snapshot', 'image-preflight', 'generate-secrets', 'source-export', 'compose-config', 'build', 'up-contracts', 'deploy-contracts', 'up-runtime', 'probe', 'e2e', 'labels'];
  const expected = retained ? [...common, 'receipt-retained'] : [...common, 'cleanup', 'evidence'];
  if (!Array.isArray(operations) || !same(operations, expected)) fail('observed lifecycle does not match its exact normal/retained plan');
  return true;
}

export function validateFinalEvidenceEligibility({ retained, zeroOwned, foreignUnchanged }) {
  if (retained === true || zeroOwned !== true || foreignUnchanged !== true) fail('final PASS evidence requires completed cleanup and unchanged foreign inventory');
  return true;
}

export async function executeCleanupPlan({ resources, state }) {
  const failures = [];
  for (const action of resources ?? []) { try { await action(); } catch (error) { failures.push(error); } }
  if (failures.length) {
    const aggregate = new AggregateError(failures, 'P15C resource cleanup failed; ownership state preserved');
    aggregate.preserveOwnershipState = true;
    throw aggregate;
  }
  for (const action of state ?? []) {
    try { await action(); }
    catch (error) {
      const aggregate = new AggregateError([error], 'P15C state cleanup failed; remaining ownership state preserved');
      aggregate.preserveOwnershipState = true;
      throw aggregate;
    }
  }
  return true;
}

function canonicalWindows(value) {
  const normalizedValue = String(value ?? '').replace(/\//g, '\\');
  const parts = [];
  for (const part of normalizedValue.split('\\')) {
    if (!part || part === '.') continue;
    if (part === '..') parts.pop(); else parts.push(part);
  }
  return parts.join('\\').toLowerCase();
}

export function validateOwnedOutputPaths({ evidence, receipt, repos, runTree }) {
  for (const value of [evidence, receipt]) {
    if (!/^[A-Za-z]:[\\/]/.test(value ?? '') || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(value)) fail('output path is not canonical absolute');
    const candidate = `${canonicalWindows(value)}\\`;
    for (const root of [...(repos ?? []), runTree]) {
      const boundary = `${canonicalWindows(root)}\\`;
      if (candidate.startsWith(boundary)) fail('output path enters a source repository or owned run tree');
    }
  }
  return true;
}

export function validateRetainedOwnershipState(value) {
  const expectedRun = `${canonicalWindows(value.base)}\\${value.receipt.project}-${value.receipt.nonce}`;
  if (canonicalWindows(value.runPath) !== expectedRun || value.runMarker !== 'deep-p15c-run.v1' || value.secretMarker !== 'deep-p15c-ephemeral-secrets.v1' || value.manifestValid !== true || value.sourcePreflightPassed !== true) fail('retained owned state markers or preflight are invalid');
  const children = ['.p15c-secret-owner', 'node-1.config.json', 'node-1.seed', 'node-2.config.json', 'node-2.seed', 'node-3.config.json', 'node-3.seed'];
  if (![...value.secretChildren].sort().every((item, index) => item === children[index]) || value.secretChildren.length !== children.length) fail('retained secret directory contains missing or extra entries');
  const receipt = value.receipt;
  if (receipt.schema !== 'deep-p15c-ownership.v1' || JSON.stringify(receipt.sources) !== JSON.stringify(value.expectedSources) || receipt.images.length !== value.expectedRoles.length) fail('retained receipt envelope is invalid');
  const roles = receipt.images.map(item => item.role).sort();
  if (!same(roles, [...value.expectedRoles].sort()) || new Set(receipt.images.map(item => item.id)).size !== receipt.images.length) fail('retained receipt roles or image ids are invalid');
  return true;
}

export function validateHardhatIsolation(value) {
  if (value?.chainId !== 31337 || !Array.isArray(value.command) || !value.command.join(' ').includes('hardhat node')) fail('Hardhat local chain contract is invalid');
  if (!Array.isArray(value.volumes) || value.volumes.length !== 0) fail('Hardhat chain persistence is prohibited');
  for (const name of Object.keys(value.environment ?? {})) if (/(?:rpc|url|private|mnemonic|secret|key)/i.test(name)) fail('Hardhat external authority environment is prohibited');
  if (value.stakingAddressSource !== 'validated-local-manifest') fail('staking addresses must come only from validated local manifest');
  return true;
}

export function validateBuildPolicy(value) {
  const supplied = value?.operatorSupplied ?? {};
  const refs = [supplied.sdk, supplied.runtime, supplied.node];
  if (refs.some(reference => !/^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$/.test(reference ?? ''))) fail('operator-supplied image lock is incomplete or not digest-addressed');
  if (!Array.isArray(value.usedBases) || value.usedBases.some(reference => !refs.includes(reference)) || value.usedBases.length !== refs.length) fail('build base is not an operator-supplied exact local lock');
  if (value.pullPolicy !== 'never' || value.buildPull !== false) fail('build or runtime may pull silently');
  if (value.sdk !== supplied.sdk || value.runtime !== supplied.runtime || value.sdk === value.runtime) fail('SDK/runtime separation is invalid');
  return true;
}

export function validateIdentitySurfaces(identities, surfaces) {
  for (const identity of identities ?? []) {
    if (!/^[0-9a-f]{64}$/.test(identity)) fail('generated identity shape is invalid');
    for (const [name, value] of Object.entries(surfaces ?? {})) if (JSON.stringify(value).toLowerCase().includes(identity)) fail(`generated identity leaked into ${name}`);
  }
  return true;
}

export async function executeStagedLifecycle(operations, cleanup, { keepRunning }) {
  let complete = false;
  try {
    for (const operation of Object.values(operations ?? {})) await operation();
    complete = true;
  }
  finally {
    if (!keepRunning || !complete) await cleanup();
  }
  return true;
}

export async function executeReceiptAction(receipt, validator, dockerAction) {
  await validator(receipt);
  return dockerAction(receipt);
}

export async function removeValidatedOwnedImages(receipt, resources, runner) {
  if (!receipt || receipt.schema !== 'deep-p15c-ownership.v1' || !/^[0-9a-f]{64}$/.test(receipt.composeSha256 ?? '') || receipt.project !== resources?.[0]?.project || receipt.nonce !== resources?.[0]?.nonce || !Array.isArray(receipt.images) || receipt.images.length !== resources.length || !receipt.sources || typeof receipt.sources !== 'object') fail('image removal receipt binding is invalid');
  const expectedIds = receipt.images.map(value => value.id).sort();
  const observedIds = resources.map(value => value.id).sort();
  if (!same(expectedIds, observedIds)) fail('image removal inventory differs from receipt');
  for (const binding of receipt.images) {
    const resource = resources.find(value => value.id === binding.id && value.role === binding.role);
    const source = receipt.sources[binding.source];
    if (!resource || resource.kind !== 'image' || resource.project !== receipt.project || resource.nonce !== receipt.nonce || resource.os !== 'linux' || resource.architecture !== 'arm64' || !source || binding.sha !== source.sha || binding.tree !== source.tree) fail('image removal source/ownership binding is invalid');
    validateImageMetadata({ id: resource.id, os: resource.os, architecture: resource.architecture, labels: resource.labels }, { sha: source.sha, tree: source.tree, role: binding.role, nonce: receipt.nonce });
  }
  for (const id of expectedIds) await runner(['image', 'rm', id]);
  return true;
}

export function validateImageSourceBindings(bindings, sources) {
  for (const binding of bindings ?? []) {
    const expectedSource = binding.role === 'xnode' ? 'xnode' : binding.role === 'test-client' ? 'e2e' : binding.source;
    const expected = sources?.[expectedSource];
    if (!expected || binding.source !== expectedSource || binding.sha !== expected.sha || binding.tree !== expected.tree) fail(`image role ${binding.role} is not bound to its exact source`);
  }
  return true;
}

export function validateOwnedProjectRuntimeInventory(inventory, expected) {
  validateProjectName(expected.project);
  if (!/^[0-9a-f]{32}$/.test(expected.nonce ?? '') || !exactKeys(inventory, ['containers', 'networks', 'volumes'])) fail('owned runtime inventory envelope is invalid');
  if (!Array.isArray(inventory.volumes) || inventory.volumes.length !== 0
    || !Array.isArray(expected.volumes) || expected.volumes.length !== 0) fail('named volumes are prohibited');
  const specifications = [
    ['containers', 'service', expected.services],
    ['networks', 'network', expected.networks]
  ];
  for (const [kind, property, allowed] of specifications) {
    const records = inventory[kind];
    if (!Array.isArray(records) || !Array.isArray(allowed)) fail(`owned ${kind} inventory is incomplete`);
    const names = [];
    for (const record of records) {
      const name = record?.[property];
      if (record?.project !== expected.project || record?.nonce !== expected.nonce || record?.labels?.['com.xpoint.p15c.ownership-nonce'] !== expected.nonce || !allowed.includes(name)) fail(`foreign or injected same-project ${kind} resource exists`);
      names.push(name);
    }
    if (new Set(names).size !== names.length) fail(`duplicate owned ${kind} resource exists`);
    if (!expected.allowPartial && !same([...names].sort(), [...allowed].sort())) fail(`exact owned ${kind} topology is incomplete`);
  }
  return true;
}

export function canDeleteOwnedOutput(record, current) {
  return record?.created === true
    && typeof record.path === 'string'
    && current?.kind === 'file'
    && current.path === record.path
    && /^[0-9a-f]{64}$/.test(record.expectedSha256 ?? '')
    && current.sha256 === record.expectedSha256;
}

async function fetchJsonExact(url, expectedStatus, init) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(5000) });
  const body = await response.json();
  if (response.status !== expectedStatus) fail(`calls signaling returned status ${response.status}, expected ${expectedStatus}`);
  return body;
}

export async function runCallsSignalingE2E(baseUrl) {
  if (!/^http:\/\/(?:calls|127\.0\.0\.1|localhost)(?::\d+)?$/.test(baseUrl ?? '')) fail('calls signaling base URL is invalid');
  const sender = `05${'1'.repeat(64)}`;
  const firstRecipient = `05${'2'.repeat(64)}`;
  const secondRecipient = `05${'3'.repeat(64)}`;
  const post = (body, status = 202) => fetchJsonExact(`${baseUrl}/api/calls/signal`, status, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const malformedParties = [
    '', `04${'1'.repeat(64)}`, `05${'1'.repeat(63)}`,
    `05${'1'.repeat(65)}`, `05${'g'.repeat(64)}`, `05${'A'.repeat(64)}`
  ];
  for (const party of malformedParties) {
    for (const field of ['sender', 'recipient']) {
      const candidate = {
        callId: 'p15c-malformed',
        conversationId: 'p15c-malformed',
        sender: { value: sender },
        recipient: { value: firstRecipient },
        [field]: { value: party }
      };
      const malformed = await post(candidate, 400);
      if (malformed.error !== 'invalid-request') fail('calls malformed-party rejection is invalid');
    }
    const malformedInbox = await fetchJsonExact(`${baseUrl}/api/calls/inbox/${encodeURIComponent(party)}`, 400);
    if (malformedInbox.error !== 'invalid-request') fail('calls malformed inbox rejection is invalid');
  }
  const first = { callId: 'p15c-call-first', conversationId: 'p15c-conversation', sender: { value: sender }, recipient: { value: firstRecipient } };
  const second = { callId: 'p15c-call-pending', conversationId: 'p15c-conversation', sender: { value: sender }, recipient: { value: secondRecipient } };
  for (const signal of [first, second]) {
    const accepted = await post(signal);
    if (accepted.accepted !== true || accepted.callId !== signal.callId) fail('calls signal acceptance is invalid');
  }
  const pendingBefore = await fetchJsonExact(`${baseUrl}/stats`, 200);
  if (pendingBefore.inventory?.callSignals !== 2) fail('calls pending inventory did not retain both recipients');
  const firstInbox = await fetchJsonExact(`${baseUrl}/api/calls/inbox/${encodeURIComponent(firstRecipient)}`, 200);
  if (!Array.isArray(firstInbox) || firstInbox.length !== 1 || firstInbox[0].callId !== first.callId || firstInbox[0].sender?.value !== sender || firstInbox[0].recipient?.value !== firstRecipient) fail('calls recipient inbox delivery is invalid');
  const pendingAfterFirst = await fetchJsonExact(`${baseUrl}/stats`, 200);
  if (pendingAfterFirst.inventory?.callSignals !== 1) fail('calls unrelated recipient signal was not retained');
  const drained = await fetchJsonExact(`${baseUrl}/api/calls/inbox/${encodeURIComponent(firstRecipient)}`, 200);
  if (!Array.isArray(drained) || drained.length !== 0) fail('calls recipient inbox did not drain');
  const secondInbox = await fetchJsonExact(`${baseUrl}/api/calls/inbox/${encodeURIComponent(secondRecipient)}`, 200);
  if (!Array.isArray(secondInbox) || secondInbox.length !== 1 || secondInbox[0].callId !== second.callId) fail('calls pending recipient delivery is invalid');
  const finalStats = await fetchJsonExact(`${baseUrl}/stats`, 200);
  if (finalStats.inventory?.callSignals !== 0) fail('calls final pending inventory is not empty');
  return { malformedRejected: true, firstDrained: true, unrelatedPending: true, finalPending: 0 };
}

async function main() {
  const [command, path, expectedPath] = process.argv.slice(2);
  if (command === 'validate-compose' && path && expectedPath) {
    validateComposeModel(
      parseJsonNoDuplicateKeys(await readFile(path, 'utf8')),
      parseJsonNoDuplicateKeys(await readFile(expectedPath, 'utf8'))
    );
    return;
  }
  if (command === 'validate-receipt' && path && expectedPath) {
    validateOwnershipReceipt(
      parseJsonNoDuplicateKeys(await readFile(path, 'utf8')),
      parseJsonNoDuplicateKeys(await readFile(expectedPath, 'utf8'))
    );
    return;
  }
  if (command === 'summarize-receipt' && path && expectedPath) {
    const bytes = await readFile(path);
    const receipt = parseJsonNoDuplicateKeys(bytes.toString('utf8'));
    validateOwnershipReceipt(
      receipt,
      parseJsonNoDuplicateKeys(await readFile(expectedPath, 'utf8'))
    );
    process.stdout.write(JSON.stringify({
      receipt,
      receiptSha256: createHash('sha256').update(bytes).digest('hex')
    }));
    return;
  }
  if (command === 'validate-runtime-inventory' && path && expectedPath) {
    validateOwnedProjectRuntimeInventory(
      parseJsonNoDuplicateKeys(await readFile(path, 'utf8')),
      parseJsonNoDuplicateKeys(await readFile(expectedPath, 'utf8'))
    );
    return;
  }
  if (command === 'test-client' && path) {
    const child = spawnSync('npm', ['run', 'ci:full'], { stdio: 'inherit', shell: false });
    if (child.status !== 0) fail('exact pinned E2E suite failed');
    await runCallsSignalingE2E(path);
    process.stdout.write('P15C semantic calls signaling E2E passed.\n');
    return;
  }
  throw new Error('P15C contract command is invalid');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
