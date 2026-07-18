import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { isIP } from 'node:net';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
export const metadataSafeProfile = 'metadata-safe-v1';
export const featureFlag = 'DEEP_INFRA_PRIVACY_PROFILE';
const maximumTextBytes = 5 * 1024 * 1024;
const services = Object.freeze(['calls', 'file', 'push', 'storage', 'xnode-1', 'xnode-2', 'xnode-3']);
const routers = Object.freeze(['xnode-1', 'xnode-2', 'xnode-3']);
const ancillaryServices = Object.freeze(['calls', 'file', 'push', 'storage']);
const safeMetricLabels = new Set([
  'service',
  'operation',
  'status_code',
  'error_class',
  'route_index',
  'transport',
  'result'
]);
const textExtensions = new Set([
  '.csv', '.json', '.jsonl', '.log', '.md', '.prom', '.txt', '.yaml', '.yml'
]);
const retentionSetDomain = 'deep-local-retention-archive-set-v1';

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value ?? {}).sort()) === JSON.stringify([...expected].sort());
}

function exactJson(value, expected) {
  return JSON.stringify(value) === JSON.stringify(expected);
}

function contract(condition, message) {
  if (!condition) throw new Error(message);
}

function finding(ruleId, inputId, line = undefined) {
  const genericInputId = /^input-[1-9][0-9]*$/.test(inputId) ? inputId : 'input-1';
  return {
    ruleId,
    inputId: genericInputId,
    ...(line ? { line } : {}),
    fingerprint: createHash('sha256')
      .update(`deep-metadata-finding-v1\0${ruleId}\0${genericInputId}\0${line ?? 0}`)
      .digest('hex')
      .slice(0, 16)
  };
}

function lineNumberAt(text, offset) {
  return text.slice(0, offset).split('\n').length;
}

function addRegexFindings(text, logicalPath, ruleId, regex, findings) {
  for (const match of text.matchAll(regex)) {
    findings.push(finding(ruleId, logicalPath, lineNumberAt(text, match.index ?? 0)));
  }
}

function addIpFindings(text, logicalPath, findings) {
  for (const match of text.matchAll(/(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])/g)) {
    if (isIP(match[0]) === 4) {
      findings.push(finding('source-ip-field', logicalPath, lineNumberAt(text, match.index ?? 0)));
    }
  }
  for (const match of text.matchAll(/(?<![0-9a-f:])[0-9a-f:]{2,}(?![0-9a-f:])/gi)) {
    if (match[0].includes(':') && isIP(match[0]) === 6) {
      findings.push(finding('source-ip-field', logicalPath, lineNumberAt(text, match.index ?? 0)));
    }
  }
}

function normalizedFieldName(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function scalarHasValue(value) {
  return ['string', 'number'].includes(typeof value) && String(value).length > 0;
}

function inspectStructuredValue(value, logicalPath, findings, line = undefined, parentField = '') {
  if (Array.isArray(value)) {
    for (const item of value) inspectStructuredValue(item, logicalPath, findings, line, parentField);
    return;
  }
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string') {
      findings.push(...inspectMetadataText(value, logicalPath, line ? line - 1 : 0));
    }
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    const field = normalizedFieldName(key);
    const contextualField = `${parentField}${field}`;
    if (scalarHasValue(child)) {
      const text = String(child);
      if (
        /^(client|source|remote|origin|peer|xforwardedfor)(ip|address)?$/.test(field)
        || ((contextualField.includes('ip') || contextualField.includes('address')) && isIP(text) !== 0)
      ) {
        findings.push(finding('source-ip-field', logicalPath, line));
      }
      if (/session(id|identifier|key)?$/.test(contextualField)) {
        findings.push(finding('raw-session-identifier', logicalPath, line));
      }
      if (/(requesttarget|requesturi|requesturl|path|query|url|uri)$/.test(contextualField)) {
        findings.push(finding('sensitive-request-target', logicalPath, line));
      }
      if (/(push|provider|device).*(token|handle|identifier|id)$/.test(contextualField)) {
        findings.push(finding('raw-push-handle', logicalPath, line));
      }
      if (/(mailbox|deposit|retrieve).*(token|handle|capability|identifier|id)$/.test(contextualField)
        || field === 'capability') {
        findings.push(finding('raw-mailbox-capability', logicalPath, line));
      }
      if (/(correlation|request|trace|span).*(identifier|id)$/.test(contextualField)) {
        findings.push(finding('stable-cross-domain-correlation', logicalPath, line));
      }
    }
    inspectStructuredValue(child, logicalPath, findings, line, contextualField);
  }
}

export function inspectMetadataText(text, logicalPath = 'selected-artifact.txt', lineOffset = 0) {
  const findings = [];
  addRegexFindings(
    text,
    logicalPath,
    'raw-session-identifier',
    /(?<![0-9a-f])(?:05|15|25)[0-9a-f]{64}(?![0-9a-f])/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'source-ip-field',
    /\b(?:client|source|remote|origin|peer|x_forwarded_for|x-forwarded-for)[_. -]?(?:ip|address)?\b\s*["']?\s*[:=]\s*["']?[^\s"',}\]]+/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'sensitive-request-target',
    /(?:\/(?:subscriptions|inbox|mailbox|deposit|retrieve|storage\/(?:store|retrieve))\/[^\s"'?]+|[?&](?:pubkey|recipient|sender|mailbox|capability|push(?:_|-)?token)=)/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'raw-push-handle',
    /["']?\b(?:push|provider|device)[_. -]?(?:token|handle|identifier|id)\b["']?\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{8,}/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'raw-mailbox-capability',
    /["']?\b(?:mailbox|deposit|retrieve)[_. -]?(?:id|token|handle|capability)\b["']?\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{8,}/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'stable-cross-domain-correlation',
    /["']?\b(?:correlation|request|trace|span)[_. -]?(?:id|identifier)\b["']?\s*[:=]\s*["']?[A-Za-z0-9._~-]{8,}/gi,
    findings
  );
  addIpFindings(text, logicalPath, findings);
  if (lineOffset > 0) {
    for (const item of findings) item.line += lineOffset;
  }
  return findings;
}

export function lintMetricText(text, logicalPath = 'selected-metrics.prom') {
  const findings = [...inspectMetadataText(text, logicalPath)];
  const labelRegex = /\b([A-Za-z_:][A-Za-z0-9_:]*)\s*=\s*"[^"\r\n]*"/g;
  for (const match of text.matchAll(labelRegex)) {
    const label = match[1].toLowerCase();
    if (!safeMetricLabels.has(label)) {
      findings.push(finding(
        'metric-label-not-allowlisted',
        logicalPath,
        lineNumberAt(text, match.index ?? 0)
      ));
    }
  }

  addRegexFindings(
    text,
    logicalPath,
    'metric-sensitive-label-name',
    /["']?\b(?:session|sender|recipient|pubkey|mailbox|push|device|capability|client_ip|source_ip|remote_address)[A-Za-z0-9_:.-]*["']?\s*(?:=|:)/gi,
    findings
  );
  return findings;
}

function inspectStructuredDocument(text, logicalPath, extension, { metrics }) {
  const findings = [];
  if (extension === '.json') {
    let document;
    try {
      document = JSON.parse(text);
    } catch {
      throw new Error('selected JSON input is malformed');
    }
    inspectStructuredValue(document, logicalPath, findings);
    if (metrics) inspectMetricLabelObjects(document, logicalPath, findings);
    return [...findings, ...inspectMetadataText(text, logicalPath)];
  }
  if (extension === '.jsonl') {
    const lines = text.split(/\r?\n/);
    let records = 0;
    for (let index = 0; index < lines.length; index += 1) {
      if (!lines[index].trim()) continue;
      let record;
      try {
        record = JSON.parse(lines[index]);
      } catch {
        throw new Error('selected JSONL input is malformed');
      }
      records += 1;
      inspectStructuredValue(record, logicalPath, findings, index + 1);
      if (metrics) inspectMetricLabelObjects(record, logicalPath, findings, index + 1);
      findings.push(...inspectMetadataText(lines[index], logicalPath, index));
    }
    assert.ok(records > 0, 'selected JSONL input contains no records');
    return findings;
  }
  return metrics ? lintMetricText(text, logicalPath) : inspectMetadataText(text, logicalPath);
}

function inspectMetricLabelObjects(value, logicalPath, findings, line = undefined) {
  if (Array.isArray(value)) {
    for (const child of value) inspectMetricLabelObjects(child, logicalPath, findings, line);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (normalizedFieldName(key) === 'labels' && child && typeof child === 'object' && !Array.isArray(child)) {
      for (const label of Object.keys(child)) {
        if (!safeMetricLabels.has(label.toLowerCase())) {
          findings.push(finding('metric-label-not-allowlisted', logicalPath, line));
        }
      }
    }
    inspectMetricLabelObjects(child, logicalPath, findings, line);
  }
}

async function walkSelected(root, candidate, output) {
  const info = await lstat(candidate);
  assert.ok(!info.isSymbolicLink(), 'metadata scan input cannot be a symlink/reparse point');
  const resolvedRoot = await realpath(root);
  const resolvedCandidate = await realpath(candidate);
  assert.ok(
    resolvedCandidate === resolvedRoot || resolvedCandidate.startsWith(`${resolvedRoot}${path.sep}`),
    'metadata scan input escaped its selected root'
  );
  if (info.isDirectory()) {
    for (const entry of await readdir(candidate)) {
      await walkSelected(root, path.join(candidate, entry), output);
    }
    return;
  }
  assert.ok(info.isFile(), 'metadata scan input must contain only regular files');
  output.push(candidate);
}

export async function scanSelectedPaths(paths, { metrics = false, expectedFiles } = {}) {
  assert.ok(Array.isArray(paths) && paths.length > 0, 'at least one explicit metadata scan path is required');
  assert.ok(Number.isSafeInteger(expectedFiles) && expectedFiles > 0, 'exact positive expected file count is required');
  const findings = [];
  let scannedFiles = 0;
  const canonicalFiles = new Set();
  for (let rootIndex = 0; rootIndex < paths.length; rootIndex += 1) {
    try {
      const root = path.resolve(paths[rootIndex]);
      const files = [];
      await walkSelected(root, root, files);
      assert.ok(files.length > 0, `selection root ${rootIndex + 1} contains no files`);
      for (let fileIndex = 0; fileIndex < files.length; fileIndex += 1) {
        const file = files[fileIndex];
        const canonicalFile = await realpath(file);
        assert.ok(!canonicalFiles.has(canonicalFile), 'selected roots contain a duplicate or overlapping file');
        canonicalFiles.add(canonicalFile);
        const info = await stat(file);
        assert.ok(info.size <= maximumTextBytes, 'metadata scan input exceeds the 5 MiB text limit');
        const extension = path.extname(file).toLowerCase();
        assert.ok(textExtensions.has(extension), 'metadata scan accepts explicit text artifacts only');
        const bytes = await readFile(file);
        let text;
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch {
          throw new Error('selected input is not valid UTF-8 text');
        }
        assert.ok(
          !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text),
          'selected input contains binary data'
        );
        const inputId = `input-${scannedFiles + 1}`;
        findings.push(...inspectStructuredDocument(text, inputId, extension, { metrics }));
        scannedFiles += 1;
      }
    } catch {
      throw new Error(`selection root ${rootIndex + 1} failed closed`);
    }
  }
  assert.equal(scannedFiles, expectedFiles, 'selected file count does not match the exact expected count');
  const unique = [...new Map(findings.map(item => [
    `${item.ruleId}\0${item.inputId}\0${item.line ?? ''}`,
    item
  ])).values()];
  return { scannedFiles, findings: unique };
}

export function validateRetentionPolicy(policy) {
  assert.equal(policy?.schema, 'deep-infrastructure-metadata-privacy-policy.v1');
  assert.equal(policy.profile, metadataSafeProfile);
  assert.equal(policy.featureFlag, featureFlag);
  assert.equal(policy.humanOwner, 'Mr. X');
  assert.match(policy.clientP01?.commit ?? '', /^[0-9a-f]{40}$/);
  assert.match(policy.clientP01?.expectationsSha256 ?? '', /^[0-9a-f]{64}$/);
  assert.equal(policy.components?.length, 7);
  const components = new Map((policy.components ?? []).map(item => [item.component, item]));
  assert.equal(components.size, 7);
  assert.deepEqual(
    [...components.keys()].sort(),
    ['compat-services', 'metrics', 'provider-push', 'sanitized-evidence', 'xnode-operational', 'xray-access', 'xray-error']
  );
  const exactRetentionHours = {
    'xray-access': 0,
    'xray-error': 24,
    'xnode-operational': 24,
    'compat-services': 24,
    metrics: 168,
    'sanitized-evidence': 720,
    'provider-push': null
  };
  for (const [name, component] of components) {
    assert.equal(component.retentionHours, exactRetentionHours[name]);
    assert.ok(typeof component.deletionVerification === 'string' && component.deletionVerification.length > 10);
  }
  assert.deepEqual([...policy.metricAllowedLabels].sort(), [...safeMetricLabels].sort());
  assert.deepEqual(policy.breakGlass, {
    humanOwner: 'Mr. X',
    maximumMinutes: 60,
    receiptSchema: 'deep-metadata-break-glass-receipt.v1',
    requireClosedStatus: true,
    requireAccessRevoked: true,
    requireRawExportDeleted: true,
    requireDeletionVerified: true
  });
  assert.equal(policy.keySeparation?.mustDiffer, true);
  assert.match(policy.keySeparation?.operationalLogKeyRef ?? '', /^secretref:[a-z0-9-]+$/);
  assert.match(policy.keySeparation?.evidenceKeyRef ?? '', /^secretref:[a-z0-9-]+$/);
  assert.notEqual(policy.keySeparation.operationalLogKeyRef, policy.keySeparation.evidenceKeyRef);
  assert.deepEqual(policy.localRetention, {
    inventorySchema: 'deep-local-log-retention-inventory.v1',
    receiptSchema: 'deep-local-log-retention-observation.v1',
    maximumAgeHours: 24,
    maximumClockSkewMinutes: 5,
    requireExactArchiveSet: true,
    requireNoExpiredArchives: true
  });
  return policy;
}

export function validateBreakGlassReceipt(receipt, policy) {
  assert.equal(receipt?.schema, policy.breakGlass.receiptSchema);
  assert.equal(receipt.humanOwner, 'Mr. X');
  assert.equal(receipt.status, 'closed');
  assert.equal(receipt.accessRevoked, true);
  assert.equal(receipt.rawExportDeleted, true);
  assert.equal(receipt.deletionVerified, true);
  assert.equal(receipt.containsRawIdentifiers, false);
  assert.equal(receipt.operationalLogKeyRef, policy.keySeparation.operationalLogKeyRef);
  assert.equal(receipt.evidenceKeyRef, policy.keySeparation.evidenceKeyRef);
  assert.notEqual(receipt.operationalLogKeyRef, receipt.evidenceKeyRef);
  const openedAt = Date.parse(receipt.openedAt);
  const closedAt = Date.parse(receipt.closedAt);
  assert.ok(Number.isFinite(openedAt) && Number.isFinite(closedAt) && closedAt >= openedAt);
  assert.ok(closedAt - openedAt <= policy.breakGlass.maximumMinutes * 60_000);
  assert.match(receipt.reasonCode ?? '', /^[a-z0-9-]{3,64}$/);
  assert.match(receipt.evidence?.ticketId ?? '', /^[a-z0-9-]{8,128}$/);
  assert.match(receipt.evidence?.deletionCheckId ?? '', /^[a-z0-9-]{8,128}$/);
  assert.equal(inspectMetadataText(JSON.stringify(receipt), 'break-glass-receipt.json').length, 0);
  return receipt;
}

function canonicalizeJson(value) {
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value).sort().map(key => [key, canonicalizeJson(value[key])])
  );
}

function canonicalJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(canonicalizeJson(value), null, 2)}\n`, 'utf8');
}

function inventorySha256(inventory) {
  return createHash('sha256').update(canonicalJsonBytes(inventory)).digest('hex');
}

export async function calculateLocalRetentionRootIdentity(rootPath) {
  try {
    const root = path.resolve(rootPath);
    const info = await lstat(root);
    contract(info.isDirectory() && !info.isSymbolicLink(), 'retention root must be a real directory');
    const canonical = await realpath(root);
    const portable = canonical.replaceAll('\\', '/');
    const normalized = process.platform === 'win32' ? portable.toLowerCase() : portable;
    return createHash('sha256')
      .update(`deep-local-retention-root-v1\0${normalized}\0${info.dev}\0${info.ino}`)
      .digest('hex');
  } catch {
    throw new Error('local retention root identity failed closed');
  }
}

export async function validateLocalRetentionInventory(inventory, rootPath, policy) {
  contract(exactKeys(inventory, [
    'schema',
    'profile',
    'humanOwner',
    'inventoryId',
    'rootIdentitySha256',
    'expectedArchives',
    'countPolicy',
    'contentHashRequired',
    'pointInTimeOnly'
  ]), 'local retention inventory keys must be exact');
  contract(inventory.schema === policy.localRetention.inventorySchema, 'local retention inventory schema must be exact');
  contract(inventory.profile === metadataSafeProfile, 'local retention inventory profile must be exact');
  contract(inventory.humanOwner === 'Mr. X', 'local retention inventory owner must be Mr. X');
  contract(/^[a-z0-9-]{8,64}$/.test(inventory.inventoryId ?? ''), 'local retention inventory ID must be safe');
  contract(/^[0-9a-f]{64}$/.test(inventory.rootIdentitySha256 ?? ''), 'local retention root identity must be SHA256');
  contract(Array.isArray(inventory.expectedArchives) && inventory.expectedArchives.length > 0, 'local retention inventory must bind nonempty archives');
  const expectedArchives = inventory.expectedArchives.map(item => {
    contract(typeof item === 'string' && item.length > 0, 'local retention archive identity must be text');
    const normalized = item.replaceAll('\\', '/');
    contract(
      normalized === path.posix.normalize(normalized)
        && !path.posix.isAbsolute(normalized)
        && normalized !== '..'
        && !normalized.startsWith('../')
        && /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(normalized),
      'local retention archive identity must be safe and relative'
    );
    return normalized;
  });
  contract(new Set(expectedArchives).size === expectedArchives.length, 'local retention archive identities must be unique');
  contract(exactKeyValues(inventory.countPolicy, {
    minimum: expectedArchives.length,
    maximum: expectedArchives.length,
    allowEmpty: false
  }), 'local retention count policy must be exact and nonempty');
  contract(inventory.contentHashRequired === true, 'local retention content hashes must be required');
  contract(inventory.pointInTimeOnly === true, 'local retention claim must be point-in-time only');
  const canonicalRoot = await realpath(path.resolve(rootPath));
  const rootRelativeToRepository = path.relative(repositoryRoot, canonicalRoot);
  contract(
    rootRelativeToRepository.startsWith(`..${path.sep}`) || path.isAbsolute(rootRelativeToRepository),
    'deployment retention root must be outside the repository'
  );
  contract(
    inventory.rootIdentitySha256 === await calculateLocalRetentionRootIdentity(rootPath),
    'local retention root does not match protected inventory'
  );
  return {
    inventorySha256: inventorySha256(inventory),
    expectedArchives: [...expectedArchives].sort()
  };
}

async function observeLocalRetentionRoot(rootPath, observedAt, maximumAgeHours, inventory, policy) {
  try {
    const inventoryBinding = await validateLocalRetentionInventory(inventory, rootPath, policy);
    const root = path.resolve(rootPath);
    const files = [];
    await walkSelected(root, root, files);
    contract(files.length > 0, 'local retention root must not be empty');
    const relativeFiles = files.map(file => path.relative(root, file).replaceAll('\\', '/')).sort();
    contract(
      exactJson(relativeFiles, inventoryBinding.expectedArchives),
      'local retention archive set does not match protected inventory'
    );
    const entries = [];
    for (const relative of relativeFiles) {
      const file = path.resolve(root, relative);
      const info = await stat(file);
      const contentSha256 = createHash('sha256').update(await readFile(file)).digest('hex');
      entries.push({
        identityHash: createHash('sha256')
          .update(`deep-local-retention-relative-identity-v1\0${relative}`)
          .digest('hex'),
        size: info.size,
        mtime: new Date(info.mtimeMs).toISOString(),
        contentSha256
      });
    }
    const archiveSetSha256 = createHash('sha256')
      .update(`${retentionSetDomain}\0${entries.map(entry => (
        `${entry.identityHash}\0${entry.size}\0${entry.mtime}\0${entry.contentSha256}`
      )).join('\n')}`)
      .digest('hex');
    const cutoff = observedAt - maximumAgeHours * 60 * 60_000;
    const mtimes = entries.map(entry => Date.parse(entry.mtime));
    return {
      inventorySha256: inventoryBinding.inventorySha256,
      rootIdentitySha256: inventory.rootIdentitySha256,
      expectedArchiveCount: inventoryBinding.expectedArchives.length,
      observedArchiveCount: entries.length,
      archiveSetSha256,
      expiredArchiveCount: mtimes.filter(mtime => mtime < cutoff).length,
      oldestObservedMtime: new Date(Math.min(...mtimes)).toISOString(),
      newestObservedMtime: new Date(Math.max(...mtimes)).toISOString()
    };
  } catch (error) {
    throw new Error(`local retention observation failed closed: ${error.message}`);
  }
}

export async function validateLocalRetentionReceipt(
  receipt,
  rootPath,
  inventory,
  policy,
  { verificationNow = Date.now() } = {}
) {
  contract(exactKeys(receipt, [
    'schema',
    'profile',
    'humanOwner',
    'inventoryId',
    'inventorySha256',
    'rootIdentitySha256',
    'observedAt',
    'maximumAgeHours',
    'exactArchiveSet',
    'expectedArchiveCount',
    'observedArchiveCount',
    'archiveSetSha256',
    'expiredArchiveCount',
    'oldestObservedMtime',
    'newestObservedMtime',
    'contentHashAlgorithm',
    'pointInTimeOnly'
  ]), 'local retention receipt keys must be exact');
  contract(receipt.schema === policy.localRetention.receiptSchema, 'local retention receipt schema must be exact');
  contract(receipt.profile === metadataSafeProfile, 'local retention receipt profile must be exact');
  contract(receipt.humanOwner === 'Mr. X', 'local retention receipt owner must be Mr. X');
  contract(receipt.inventoryId === inventory.inventoryId, 'local retention inventory ID must be exact');
  contract(receipt.maximumAgeHours === policy.localRetention.maximumAgeHours, 'local retention maximum age must be exact');
  contract(receipt.exactArchiveSet === true, 'local retention receipt must bind the exact archive set');
  contract(receipt.contentHashAlgorithm === 'sha256', 'local retention content hash algorithm must be exact');
  contract(receipt.pointInTimeOnly === true, 'local retention receipt must remain point-in-time only');
  const observedAt = Date.parse(receipt.observedAt);
  contract(Number.isFinite(observedAt), 'local retention observedAt must be valid');
  contract(
    Math.abs(verificationNow - observedAt) <= policy.localRetention.maximumClockSkewMinutes * 60_000,
    'local retention observation must be fresh'
  );
  const observation = await observeLocalRetentionRoot(
    rootPath,
    observedAt,
    policy.localRetention.maximumAgeHours,
    inventory,
    policy
  );
  for (const key of [
    'inventorySha256',
    'rootIdentitySha256',
    'expectedArchiveCount',
    'observedArchiveCount',
    'archiveSetSha256',
    'expiredArchiveCount',
    'oldestObservedMtime',
    'newestObservedMtime'
  ]) {
    contract(receipt[key] === observation[key], `local retention ${key} must be exact`);
  }
  contract(
    Date.parse(observation.newestObservedMtime)
      <= observedAt + policy.localRetention.maximumClockSkewMinutes * 60_000,
    'local retention archive mtime is ahead of the observation clock'
  );
  contract(observation.expiredArchiveCount === 0, 'local retention root contains expired archives');
  return observation;
}

export async function createLocalRetentionReceipt(rootPath, observedAt, inventory, policy) {
  const parsedObservedAt = Date.parse(observedAt);
  contract(Number.isFinite(parsedObservedAt), 'local retention observedAt must be valid');
  const observation = await observeLocalRetentionRoot(
    rootPath,
    parsedObservedAt,
    policy.localRetention.maximumAgeHours,
    inventory,
    policy
  );
  return {
    schema: policy.localRetention.receiptSchema,
    profile: metadataSafeProfile,
    humanOwner: 'Mr. X',
    inventoryId: inventory.inventoryId,
    observedAt: new Date(parsedObservedAt).toISOString(),
    maximumAgeHours: policy.localRetention.maximumAgeHours,
    exactArchiveSet: true,
    contentHashAlgorithm: 'sha256',
    pointInTimeOnly: true,
    ...observation
  };
}

function expectedServiceBuild(name) {
  if (routers.includes(name)) {
    return {
      context: path.resolve(repositoryRoot, '..', 'synthetic-reviewed-xnode'),
      dockerfile: path.resolve(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'),
      args: {
        APP_DLL: 'XNode.dll',
        PROJECT: 'src/XNode/XNode.csproj',
        RUNTIME_IMAGE: `mcr.microsoft.com/dotnet/aspnet:10.0@sha256:${'22'.repeat(32)}`,
        SDK_IMAGE: `mcr.microsoft.com/dotnet/sdk:10.0@sha256:${'11'.repeat(32)}`,
        XRAY_SHA256: '33'.repeat(32),
        XRAY_VERSION: 'v0.0.0-synthetic'
      }
    };
  }
  return {
    context: repositoryRoot,
    dockerfile: `docker/${name}-service.Dockerfile`,
    args: {
      NODE_IMAGE: `node:24-bookworm-slim@sha256:${'44'.repeat(32)}`
    }
  };
}

function expectedServiceEnvironment(name) {
  const common = {
    DEEP_INFRA_PRIVACY_PROFILE: metadataSafeProfile
  };
  if (!routers.includes(name)) {
    const stateKey = name === 'calls' ? 'CALLS_STATE_DIR' : 'COMPAT_STATE_DIR';
    return {
      [stateKey]: `/var/lib/deep/i01b-private-uat/${name}`,
      ...common,
      PORT: '8080',
      ...(name === 'storage' ? { PUSH_COMPAT_NOTIFY_URL: 'http://push:8080' } : {}),
      SERVICE_NAME: `deep-i01b-private-uat-${name}`
    };
  }

  const index = routers.indexOf(name) + 1;
  const address = `172.30.81.1${index}`;
  const environment = {
    ASPNETCORE_ENVIRONMENT: 'UAT',
    ASPNETCORE_URLS: 'http://0.0.0.0:8080;http://0.0.0.0:8081',
    ...common,
    DOTNET_ENVIRONMENT: 'UAT',
    Logging__LogLevel__Default: 'Warning',
    'Logging__LogLevel__Microsoft.AspNetCore': 'Warning',
    'Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics': 'Warning',
    'Logging__LogLevel__Microsoft.AspNetCore.Server.Kestrel': 'Warning',
    'Logging__LogLevel__System.Net.Http.HttpClient': 'Warning',
    Node__ApiListenUrl: 'http://0.0.0.0:8080',
    Node__DataDirectory: `/var/lib/deep/i01b-private-uat/${name}`,
    Node__Ed25519PrivateKeyPath: '/run/secrets/i01b-private-uat-node-ed25519',
    Node__Network: 'uat',
    Node__PeerRpcListenUrl: 'http://0.0.0.0:8081',
    Node__PublicHost: address,
    Node__PublicIp: address,
    Node__PublicPeerRpcEndpoint: `http://${address}:8081/api/peer/onion`,
    Node__PublicPeerRpcPort: '8081',
    Node__PublicPort: '8443',
    Node__RouterId: `${index}`.repeat(64),
    RegistryBootstrap__BaseUrl: '',
    RegistryHeartbeat__Enabled: 'false',
    Runtime__AllowPublicPeerEndpoints: 'false',
    Runtime__BootstrapFromStorage: 'false',
    Runtime__EnablePrivateAllowlistMembership: 'true',
    Runtime__EnablePrivatePeerEndpoints: 'true'
  };
  for (let peer = 0; peer < 3; peer += 1) {
    const prefix = `Runtime__PrivatePeerEndpointAllowlist__${peer}`;
    environment[`${prefix}__IpAddress`] = `172.30.81.1${peer + 1}`;
    environment[`${prefix}__Path`] = '/api/peer/onion';
    environment[`${prefix}__Port`] = '8081';
    environment[`${prefix}__RouterId`] = `${peer + 1}`.repeat(64);
  }
  return {
    ...environment,
    Runtime__PrivatePeerNetworkIdentity: 'uat',
    Runtime__RequireSignedRelayContacts: 'true',
    StorageRpc__BaseUrl: 'http://storage:8080',
    Vless__Enabled: 'true',
    Vless__GeneratedConfigPath: '/tmp/deep/xray.generated.json',
    Vless__InboundListenHost: '0.0.0.0',
    Vless__InboundListenPort: '8443',
    Vless__MockProcess: 'false',
    Vless__PublicHost: address,
    Vless__PublicPort: '8443',
    Vless__TransportMode: 'Tcp',
    Vless__WorkingDirectory: '/tmp/deep/xray',
    Vless__XrayExecutablePath: '/usr/local/bin/xray'
  };
}

function exactKeyValues(actual, expected) {
  if (!exactKeys(actual, Object.keys(expected))) return false;
  return Object.entries(expected).every(([key, value]) => actual[key] === value);
}

function expectedServiceLabels(name) {
  if (routers.includes(name)) {
    return {
      'io.deep.i01b.public-peer-authorization': 'DenyAll',
      'io.deep.i01b.readiness-before-bootstrap': '503',
      'io.deep.i01b.supply-chain-preflight-required': 'true',
      'io.deep.i01b.xnode-dockerfile-sha256': 'e5'.repeat(32),
      'io.deep.i01b.xnode-source-commit': 'd4'.repeat(20),
      'io.deep.infrastructure-privacy-profile': metadataSafeProfile
    };
  }
  return {
    'io.deep.i01b.compat-content-sha256': '55'.repeat(32),
    'io.deep.i01b.devops-source-commit': 'f6'.repeat(20),
    'io.deep.i01b.supply-chain-preflight-required': 'true',
    'io.deep.infrastructure-privacy-profile': metadataSafeProfile
  };
}

function expectedServiceHealthcheck(name) {
  if (routers.includes(name)) {
    return {
      test: [
        'CMD-SHELL',
        'curl -fsS http://127.0.0.1:8080/health/ready >/dev/null'
      ],
      timeout: '3s',
      interval: '5s',
      retries: 30,
      start_period: '20s'
    };
  }
  return {
    test: [
      'CMD-SHELL',
      'node -e "fetch(\'http://127.0.0.1:8080/health/ready\').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"'
    ],
    timeout: '3s',
    interval: '3s',
    retries: 30
  };
}

export function validateMetadataSafeTopology(topology) {
  const rootKeys = [
    'name',
    'networks',
    'secrets',
    'services',
    'volumes',
    'x-ancillary-build-args',
    'x-ancillary-labels',
    'x-metadata-safe-environment',
    'x-metadata-safe-logging',
    'x-metadata-safe-router-environment',
    'x-router-build',
    'x-router-environment',
    'x-router-healthcheck'
  ];
  contract(exactKeys(topology, rootKeys), 'topology root keys must be exact');
  contract(topology.name === 'deep-i01b-private-uat', 'topology name must be exact');
  contract(exactKeys(topology.services, services), 'topology service set must be exact');
  contract(exactKeys(topology.networks, ['i01b-private-uat']), 'topology network set must be exact');
  contract(exactJson(topology.networks['i01b-private-uat'], {
    name: 'deep-i01b-private-uat-isolated',
    driver: 'bridge',
    ipam: { config: [{ subnet: '172.30.81.0/24' }] },
    internal: true
  }), 'metadata-safe network must be exact and internal');

  const stateVolumes = Object.fromEntries(services.map(name => [
    `i01b-private-uat-${name}-state`,
    { name: `deep-i01b-private-uat-${name}-state` }
  ]));
  contract(exactKeys(topology.volumes, Object.keys(stateVolumes)), 'topology volume set must be exact');
  contract(exactJson(topology.volumes, stateVolumes), 'topology named volumes must be exact');

  const secretNames = routers.map((_, index) => `i01b-private-uat-node-${index + 1}-ed25519`);
  contract(exactKeys(topology.secrets, secretNames), 'topology secret set must be exact');
  for (let index = 0; index < secretNames.length; index += 1) {
    const secret = topology.secrets[secretNames[index]];
    contract(exactKeys(secret, ['name', 'file']), `secret ${index + 1} keys must be exact`);
    contract(secret.name === `deep-i01b-private-uat-node-${index + 1}-ed25519`, `secret ${index + 1} name must be exact`);
    const expectedSecret = path.resolve(
      repositoryRoot,
      'secret-templates',
      'uat-private-i01b',
      `node-${index + 1}-ed25519.seed.example`
    );
    contract(path.resolve(secret.file) === expectedSecret, `secret ${index + 1} source must be the reviewed fixture`);
  }

  const serviceKeySets = {
    calls: ['build', 'cap_drop', 'command', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'ports', 'security_opt', 'volumes'],
    file: ['build', 'cap_drop', 'command', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'ports', 'security_opt', 'volumes'],
    push: ['build', 'cap_drop', 'command', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'ports', 'security_opt', 'volumes'],
    storage: ['build', 'cap_drop', 'command', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'security_opt', 'volumes'],
    'xnode-1': ['build', 'cap_drop', 'command', 'depends_on', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'ports', 'secrets', 'security_opt', 'volumes'],
    'xnode-2': ['build', 'cap_drop', 'command', 'depends_on', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'ports', 'secrets', 'security_opt', 'volumes'],
    'xnode-3': ['build', 'cap_drop', 'command', 'depends_on', 'entrypoint', 'environment', 'healthcheck', 'labels', 'logging', 'networks', 'ports', 'secrets', 'security_opt', 'volumes']
  };
  const publishedPorts = {
    calls: '29103',
    file: '29101',
    push: '29102',
    'xnode-1': '29311',
    'xnode-2': '29312',
    'xnode-3': '29313'
  };

  for (const name of services) {
    const service = topology.services[name];
    contract(exactKeys(service, serviceKeySets[name]), `${name} service keys must be exact`);
    contract(exactJson(service.build, expectedServiceBuild(name)), `${name} build source must be exact`);
    contract(service.command === null && service.entrypoint === null, `${name} command and entrypoint must remain null`);
    contract(
      exactKeyValues(service.environment, expectedServiceEnvironment(name)),
      `${name} environment must be exact`
    );
    contract(exactJson(service.labels, expectedServiceLabels(name)), `${name} labels must be exact`);
    contract(exactJson(service.healthcheck, expectedServiceHealthcheck(name)), `${name} healthcheck must be exact`);
    contract(exactJson(service.logging, {
      driver: 'local',
      options: {
        compress: 'true',
        'max-file': '2',
        'max-size': '1m'
      }
    }), `${name} bounded logging must be exact`);
    contract(exactJson(service.cap_drop, ['ALL']), `${name} must drop all capabilities`);
    contract(!Object.hasOwn(service, 'cap_add'), `${name} must not add capabilities`);
    contract(exactJson(service.security_opt, ['no-new-privileges:true']), `${name} security options must be exact`);

    const volumeName = `i01b-private-uat-${name}-state`;
    contract(exactJson(service.volumes, [{
      type: 'volume',
      source: volumeName,
      target: `/var/lib/deep/i01b-private-uat/${name}`,
      volume: {}
    }]), `${name} state volume must be exact`);

    const expectedNetwork = routers.includes(name)
      ? { 'i01b-private-uat': { ipv4_address: `172.30.81.1${routers.indexOf(name) + 1}` } }
      : { 'i01b-private-uat': null };
    contract(exactJson(service.networks, expectedNetwork), `${name} network attachment must be exact`);

    if (name === 'storage') {
      contract(!Object.hasOwn(service, 'ports'), 'storage must not publish ports');
    } else {
      contract(exactJson(service.ports, [{
        mode: 'ingress',
        host_ip: '127.0.0.1',
        target: 8080,
        published: publishedPorts[name],
        protocol: 'tcp'
      }]), `${name} loopback port must be exact`);
    }

    const listenerKeys = Object.keys(service.environment).filter(
      key => /(?:Url|URL|URLS|PORT|Port|Host|Ip|Address|Endpoint)$/.test(key)
    );
    const routerIndex = routers.indexOf(name);
    const expectedListeners = routerIndex >= 0
      ? {
          ASPNETCORE_URLS: 'http://0.0.0.0:8080;http://0.0.0.0:8081',
          Node__ApiListenUrl: 'http://0.0.0.0:8080',
          Node__PeerRpcListenUrl: 'http://0.0.0.0:8081',
          Node__PublicHost: `172.30.81.1${routerIndex + 1}`,
          Node__PublicIp: `172.30.81.1${routerIndex + 1}`,
          Node__PublicPeerRpcEndpoint: `http://172.30.81.1${routerIndex + 1}:8081/api/peer/onion`,
          Node__PublicPeerRpcPort: '8081',
          Node__PublicPort: '8443',
          RegistryBootstrap__BaseUrl: '',
          Runtime__PrivatePeerEndpointAllowlist__0__IpAddress: '172.30.81.11',
          Runtime__PrivatePeerEndpointAllowlist__0__Port: '8081',
          Runtime__PrivatePeerEndpointAllowlist__1__IpAddress: '172.30.81.12',
          Runtime__PrivatePeerEndpointAllowlist__1__Port: '8081',
          Runtime__PrivatePeerEndpointAllowlist__2__IpAddress: '172.30.81.13',
          Runtime__PrivatePeerEndpointAllowlist__2__Port: '8081',
          StorageRpc__BaseUrl: 'http://storage:8080',
          Vless__InboundListenHost: '0.0.0.0',
          Vless__InboundListenPort: '8443',
          Vless__PublicHost: `172.30.81.1${routerIndex + 1}`,
          Vless__PublicPort: '8443'
        }
      : {
          PORT: '8080',
          ...(name === 'storage' ? { PUSH_COMPAT_NOTIFY_URL: 'http://push:8080' } : {})
        };
    contract(
      exactJson(listenerKeys.sort(), Object.keys(expectedListeners).sort()),
      `${name} listener key set must be exact`
    );
    for (const [key, value] of Object.entries(expectedListeners)) {
      contract(service.environment[key] === value, `${name} ${key} must be exact`);
    }
  }

  for (let index = 0; index < routers.length; index += 1) {
    const name = routers[index];
    const environment = topology.services[name].environment;
    for (const key of [
      'Logging__LogLevel__Default',
      'Logging__LogLevel__Microsoft.AspNetCore',
      'Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics',
      'Logging__LogLevel__Microsoft.AspNetCore.Server.Kestrel',
      'Logging__LogLevel__System.Net.Http.HttpClient'
    ]) {
      contract(environment[key] === 'Warning', `${name} ${key} must remain Warning`);
    }
    contract(environment.Vless__InboundListenHost === '0.0.0.0', `${name} Vless listen host must be exact`);
    contract(exactJson(topology.services[name].secrets, [{
      source: `i01b-private-uat-node-${index + 1}-ed25519`,
      target: 'i01b-private-uat-node-ed25519',
      mode: '0400'
    }]), `${name} secret attachment must be exact`);
    contract(exactJson(topology.services[name].depends_on, {
      storage: {
        condition: 'service_healthy',
        required: true
      }
    }), `${name} depends_on must be exact`);
  }
  for (const name of ancillaryServices) {
    contract(!Object.hasOwn(topology.services[name], 'secrets'), `${name} must not receive secrets`);
  }
  return topology;
}

export function validateXrayGeneratorSource(source) {
  assert.match(source, /\["loglevel"\]\s*=\s*"warning"/);
  assert.doesNotMatch(source, /\["access"\]\s*=/);
  assert.doesNotMatch(source, /"loglevel"\s*:\s*"(?:debug|info)"/i);
  return true;
}

function syntheticComposeEnvironment() {
  return {
    ...process.env,
    COMPOSE_DISABLE_ENV_FILE: '1',
    DEEP_INFRA_PRIVACY_PROFILE: metadataSafeProfile,
    I01B_PRIVATE_UAT_XNODE_DIR: path.resolve(repositoryRoot, '..', 'synthetic-reviewed-xnode'),
    I01B_PRIVATE_UAT_XNODE_DOCKERFILE: path.resolve(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'),
    I01B_PRIVATE_UAT_EXPECTED_XNODE_COMMIT: 'd4'.repeat(20),
    I01B_PRIVATE_UAT_EXPECTED_XNODE_DOCKERFILE_SHA256: 'e5'.repeat(32),
    I01B_PRIVATE_UAT_DOTNET_SDK_DIGEST: `sha256:${'11'.repeat(32)}`,
    I01B_PRIVATE_UAT_DOTNET_RUNTIME_DIGEST: `sha256:${'22'.repeat(32)}`,
    I01B_PRIVATE_UAT_XRAY_VERSION: 'v0.0.0-synthetic',
    I01B_PRIVATE_UAT_XRAY_SHA256: '33'.repeat(32),
    I01B_PRIVATE_UAT_NODE_IMAGE_DIGEST: `sha256:${'44'.repeat(32)}`,
    I01B_PRIVATE_UAT_EXPECTED_DEVOPS_COMMIT: 'f6'.repeat(20),
    I01B_PRIVATE_UAT_EXPECTED_COMPAT_CONTENT_SHA256: '55'.repeat(32),
    ...Object.fromEntries([1, 2, 3].flatMap(index => [
      [`I01B_PRIVATE_UAT_NODE_${index}_ROUTER_ID`, `${index}`.repeat(64)],
      [`I01B_PRIVATE_UAT_NODE_${index}_ED25519_SECRET_FILE`,
        `./secret-templates/uat-private-i01b/node-${index}-ed25519.seed.example`]
    ]))
  };
}

export function renderMetadataSafeTopology() {
  const result = spawnSync(
    'docker',
    [
      'compose',
      '-f',
      'docker-compose.uat-private.yml',
      '-f',
      'docker-compose.metadata-safe.yml',
      'config',
      '--format',
      'json'
    ],
    {
      cwd: repositoryRoot,
      env: syntheticComposeEnvironment(),
      encoding: 'utf8',
      windowsHide: true
    }
  );
  if (result.error) throw new Error(`metadata-safe compose config could not run: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`metadata-safe compose config failed closed: ${result.stderr.trim()}`);
  return JSON.parse(result.stdout);
}

function gitValue(directory, args) {
  const result = spawnSync('git', ['-C', directory, ...args], {
    encoding: 'utf8',
    windowsHide: true
  });
  assert.equal(result.status, 0, `git ${args.join(' ')} failed`);
  return result.stdout.trim();
}

export async function validatePinnedInputs({ xnodeDir, clientExpectationsPath }) {
  const policyPath = path.join(repositoryRoot, 'config', 'metadata-safe', 'retention-policy.v1.json');
  const manifestPath = path.join(repositoryRoot, 'release', 'manifests', 'survival-v2.0.1-i01b.local.json');
  const policy = validateRetentionPolicy(JSON.parse(await readFile(policyPath, 'utf8')));
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const xnode = manifest.repositories.find(item => item.name === 'xnode');
  assert.ok(xnode, 'pinned manifest lacks xnode');
  assert.equal(gitValue(xnodeDir, ['rev-parse', 'HEAD']), xnode.sha);
  assert.equal(gitValue(xnodeDir, ['status', '--short']), '');
  const xraySource = await readFile(
    path.join(xnodeDir, 'src', 'XNode.Transport.Vless', 'XrayConfigGenerator.cs'),
    'utf8'
  );
  validateXrayGeneratorSource(xraySource);
  const expectationsBytes = await readFile(clientExpectationsPath);
  assert.equal(
    createHash('sha256').update(expectationsBytes).digest('hex'),
    policy.clientP01.expectationsSha256
  );
  assert.equal(gitValue(path.resolve(clientExpectationsPath, '..', '..', '..', '..'), ['rev-parse', 'HEAD']), policy.clientP01.commit);
  return { policy, xnodeCommit: xnode.sha };
}

async function readCanonicalJsonFile(filePath, { protectedInventory = false } = {}) {
  const resolved = path.resolve(filePath);
  const info = await lstat(resolved);
  contract(info.isFile() && !info.isSymbolicLink(), 'retention evidence input must be a real file');
  const canonicalPath = await realpath(resolved);
  if (protectedInventory) {
    const relative = path.relative(repositoryRoot, canonicalPath);
    contract(
      relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative),
      'protected retention inventory must be outside the repository'
    );
  }
  const bytes = await readFile(canonicalPath);
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('retention evidence JSON must be valid UTF-8 JSON');
  }
  contract(bytes.equals(canonicalJsonBytes(value)), 'retention evidence JSON must be canonical');
  return value;
}

export async function runGate(options) {
  assert.equal(process.env[featureFlag], metadataSafeProfile, `${featureFlag} must be exact ${metadataSafeProfile}`);
  const { policy, xnodeCommit } = await validatePinnedInputs(options);
  const topology = validateMetadataSafeTopology(options.topology ?? renderMetadataSafeTopology());
  const artifactScan = await scanSelectedPaths(options.artifactPaths, {
    expectedFiles: options.expectedArtifactFiles
  });
  const metricScan = await scanSelectedPaths(options.metricPaths, {
    metrics: true,
    expectedFiles: options.expectedMetricFiles
  });
  const findings = [...artifactScan.findings, ...metricScan.findings];
  let breakGlassVerified = false;
  if (options.breakGlassReceiptPath) {
    validateBreakGlassReceipt(
      JSON.parse(await readFile(options.breakGlassReceiptPath, 'utf8')),
      policy
    );
    breakGlassVerified = true;
  }
  let localRetentionStatus = 'not-run';
  let localRetentionInventorySha256 = null;
  if (
    options.localRetentionInventoryPath
    || options.localRetentionReceiptPath
    || options.localRetentionRoot
  ) {
    assert.ok(
      options.localRetentionInventoryPath
        && options.localRetentionReceiptPath
        && options.localRetentionRoot,
      'protected local retention inventory, receipt and root must be supplied together'
    );
    const inventory = await readCanonicalJsonFile(options.localRetentionInventoryPath, {
      protectedInventory: true
    });
    const receipt = await readCanonicalJsonFile(options.localRetentionReceiptPath);
    const observation = await validateLocalRetentionReceipt(
      receipt,
      options.localRetentionRoot,
      inventory,
      policy
    );
    localRetentionStatus = 'verified-point-in-time';
    localRetentionInventorySha256 = observation.inventorySha256;
  }
  return {
    schema: 'deep-infrastructure-metadata-privacy-gate.v1',
    profile: metadataSafeProfile,
    status: findings.length === 0 ? 'ok' : 'failed',
    productionReady: false,
    providerDeletionGuaranteed: false,
    p01Commit: policy.clientP01.commit,
    p01ExpectationsSha256: policy.clientP01.expectationsSha256,
    xnodeCommit,
    topologyServices: Object.keys(topology.services).length,
    scannedArtifactFiles: artifactScan.scannedFiles,
    scannedMetricFiles: metricScan.scannedFiles,
    breakGlassVerified,
    localRetentionStatus,
    localRetentionInventorySha256,
    findingCount: findings.length,
    findings
  };
}

function parseArguments(argv) {
  const options = { artifactPaths: [], metricPaths: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const key = {
      '--artifacts': 'artifactPaths',
      '--metrics': 'metricPaths',
      '--summary': 'summaryPath',
      '--xnode-dir': 'xnodeDir',
      '--client-expectations': 'clientExpectationsPath',
      '--break-glass-receipt': 'breakGlassReceiptPath',
      '--local-retention-inventory': 'localRetentionInventoryPath',
      '--local-retention-receipt': 'localRetentionReceiptPath',
      '--local-retention-root': 'localRetentionRoot',
      '--expected-artifact-files': 'expectedArtifactFiles',
      '--expected-metric-files': 'expectedMetricFiles'
    }[argument];
    assert.ok(key, `unknown argument: ${argument}`);
    const value = argv[index + 1];
    assert.ok(value && !value.startsWith('--'), `${argument} requires a value`);
    if (Array.isArray(options[key])) options[key].push(path.resolve(value));
    else if (key === 'expectedArtifactFiles' || key === 'expectedMetricFiles') {
      options[key] = Number(value);
    } else options[key] = path.resolve(value);
    index += 1;
  }
  assert.ok(options.summaryPath, '--summary is required');
  assert.ok(options.xnodeDir, '--xnode-dir is required');
  assert.ok(options.clientExpectationsPath, '--client-expectations is required');
  assert.ok(Number.isSafeInteger(options.expectedArtifactFiles) && options.expectedArtifactFiles > 0, '--expected-artifact-files must be a positive integer');
  assert.ok(Number.isSafeInteger(options.expectedMetricFiles) && options.expectedMetricFiles > 0, '--expected-metric-files must be a positive integer');
  return options;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const summary = await runGate(options);
  await mkdir(path.dirname(options.summaryPath), { recursive: true });
  await writeFile(options.summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  if (summary.status !== 'ok') {
    console.error(`Infrastructure metadata privacy gate failed with ${summary.findingCount} finding(s).`);
    for (const item of summary.findings) {
      console.error(`- ${item.ruleId} at ${item.inputId}${item.line ? `:${item.line}` : ''} [${item.fingerprint}]`);
    }
    process.exitCode = 1;
    return summary;
  }
  console.log(
    `Infrastructure metadata privacy gate passed (${summary.scannedArtifactFiles} artifacts, ${summary.scannedMetricFiles} metric files).`
  );
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(() => {
    console.error('Infrastructure metadata privacy gate failed closed: harness or contract error');
    process.exitCode = 2;
  });
}
