import { createHash } from 'node:crypto';
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const MANIFEST_SCHEMA_VERSION = '1.2.0';
const MAX_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000;
const forbiddenExtensions = new Set([
  '.bmp', '.gif', '.heic', '.jpeg', '.jpg', '.log', '.png', '.tif', '.tiff', '.webp'
]);
const opaqueExtensions = new Set([
  '.aab', '.apk', '.dll', '.dylib', '.exe', '.msix', '.node', '.so', '.wasm'
]);
const blockedArchiveExtensions = new Set([
  '.7z', '.aab', '.apk', '.gz', '.msix', '.rar', '.tar', '.tgz', '.zip'
]);
const mediaTypes = new Map([
  ['.json', 'application/json'],
  ['.md', 'text/markdown'],
  ['.txt', 'text/plain'],
  ['.trx', 'application/xml'],
  ['.xml', 'application/xml'],
  ['.yaml', 'application/yaml'],
  ['.yml', 'application/yaml'],
  ['.zip', 'application/zip'],
  ['.gz', 'application/gzip'],
  ['.tar', 'application/x-tar'],
  ['.apk', 'application/vnd.android.package-archive'],
  ['.aab', 'application/x-authorware-bin'],
  ['.msix', 'application/vnd.ms-appx']
]);

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function purlEncode(value) {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function expectedComponentPurl(name, version, ecosystem) {
  if (ecosystem === 'npm') {
    if (name.startsWith('@') && name.includes('/')) {
      const separator = name.indexOf('/');
      return `pkg:npm/${purlEncode(name.slice(0, separator))}/${purlEncode(name.slice(separator + 1))}@${purlEncode(version)}`;
    }
    return `pkg:npm/${purlEncode(name)}@${purlEncode(version)}`;
  }
  if (ecosystem === 'nuget') {
    return `pkg:nuget/${purlEncode(name)}@${purlEncode(version)}`;
  }
  if (ecosystem === 'generic') {
    return `pkg:generic/${purlEncode(name)}@${purlEncode(version)}`;
  }
  return null;
}

function containsHostPath(value) {
  if (typeof value === 'string') {
    return /^[A-Za-z]:[\\/]/.test(value)
      || /^file:\/\//i.test(value)
      || value.startsWith('/')
      || value.startsWith('\\\\');
  }
  if (Array.isArray(value)) {
    return value.some(containsHostPath);
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([key, nested]) => /workspaceRoot|artifactDir/i.test(key) || containsHostPath(nested));
  }
  return false;
}

function validCycloneDxComponent(component, ecosystem) {
  try {
    exactKeys(component, ['type', 'bom-ref', 'name', 'version', 'purl'], 'CycloneDX component');
  } catch {
    return false;
  }
  if (!['application', 'library'].includes(component.type)
    || typeof component.name !== 'string' || component.name.trim() !== component.name || component.name.length === 0
    || typeof component.version !== 'string' || component.version.trim() !== component.version || component.version.length === 0
    || typeof component.purl !== 'string'
    || component['bom-ref'] !== component.purl) {
    return false;
  }
  return component.purl === expectedComponentPurl(component.name, component.version, ecosystem);
}

function validCycloneDxSbom(document) {
  try {
    exactKeys(document, ['bomFormat', 'specVersion', 'version', 'metadata', 'components'], 'CycloneDX SBOM');
    exactKeys(
      document.metadata,
      document.metadata?.timestamp === undefined ? ['component'] : ['component', 'timestamp'],
      'CycloneDX metadata'
    );
  } catch {
    return false;
  }
  if (document.bomFormat !== 'CycloneDX'
    || document.specVersion !== '1.6'
    || document.version !== 1
    || containsHostPath(document)
    || !validCycloneDxComponent(document.metadata.component, 'generic')
    || document.metadata.component.type !== 'application'
    || document.metadata.component.name !== 'network.xpoint.deep'
    || !Array.isArray(document.components)
    || document.components.length === 0) {
    return false;
  }
  if (document.metadata.timestamp !== undefined) {
    const parsedTimestamp = new Date(document.metadata.timestamp);
    if (Number.isNaN(parsedTimestamp.getTime()) || parsedTimestamp.toISOString() !== document.metadata.timestamp) {
      return false;
    }
  }

  const purls = [];
  for (const component of document.components) {
    const ecosystem = component?.purl?.startsWith('pkg:npm/')
      ? 'npm'
      : component?.purl?.startsWith('pkg:nuget/') ? 'nuget' : null;
    if (component?.type !== 'library' || ecosystem === null || !validCycloneDxComponent(component, ecosystem)) {
      return false;
    }
    purls.push(component.purl);
  }
  const sorted = [...purls].sort((left, right) => {
    if (left === right) return 0;
    return left < right ? -1 : 1;
  });
  return new Set(purls).size === purls.length
    && purls.every((purl, index) => purl === sorted[index]);
}

function normalizeRequiredPath(value) {
  const normalized = String(value).normalize('NFKC').replaceAll('\\', '/');
  if (!normalized
    || normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || normalized.split('/').some(part => part === '' || part === '.' || part === '..')) {
    throw new Error('required artifact paths must be canonical relative paths');
  }
  return normalized;
}

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function assertRegularNoReparse(root, target) {
  const rootReal = await realpath(root);
  let current = path.resolve(target);
  if (!inside(path.resolve(root), current)) throw new Error('artifact path escapes upload root');
  while (inside(path.resolve(root), current)) {
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error('artifact upload roots cannot contain symlink/reparse points');
    if (current === path.resolve(root)) break;
    current = path.dirname(current);
  }
  const targetReal = await realpath(target);
  if (!inside(rootReal, targetReal)) throw new Error('artifact resolves outside upload root');
  const info = await stat(target);
  if (!info.isFile()) throw new Error('artifact manifest entries must be regular files');
  return info;
}

async function walk(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const currentInfo = await lstat(current);
    if (currentInfo.isSymbolicLink()) throw new Error('artifact upload roots cannot contain symlink/reparse points');
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) throw new Error('artifact upload roots cannot contain symlink/reparse points');
      if (entry.isDirectory()) pending.push(full);
      else if (entry.isFile()) files.push(full);
      else throw new Error('artifact upload roots may contain only directories and regular files');
    }
  }
  return files.sort();
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function mediaTypeFor(filePath) {
  return mediaTypes.get(path.extname(filePath).toLowerCase()) ?? 'application/octet-stream';
}

function hasBlockedArchiveMagic(buffer) {
  if (buffer.length >= 4) {
    const signature = buffer.subarray(0, 4).toString('hex');
    if (['504b0304', '504b0506', '504b0708', '52617221'].includes(signature)) return true;
  }
  if (buffer.length >= 6 && buffer.subarray(0, 6).toString('hex') === '377abcaf271c') return true;
  if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) return true;
  if (buffer.length >= 512) {
    const checksumText = buffer.subarray(148, 156).toString('ascii').replace(/\0.*$/, '').trim();
    if (/^[0-7]+$/.test(checksumText)) {
      let checksum = 0;
      for (let index = 0; index < 512; index += 1) {
        checksum += index >= 148 && index < 156 ? 0x20 : buffer[index];
      }
      if (Number.parseInt(checksumText, 8) === checksum) return true;
    }
  }
  return false;
}

function walkSemanticValue(value, label, failures) {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkSemanticValue(item, `${label}[${index}]`, failures));
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === 'status' && typeof item === 'string'
      && /^(?:failed|failure|error|blocked|skipped|cancelled)$/i.test(item)) {
      failures.push(`${label}.${key} is ${item}`);
    }
    if (/^(?:failed|failures|skipped|cancelled|todo|errors)$/i.test(key)
      && Number.isFinite(item) && item !== 0) {
      failures.push(`${label}.${key} must be zero`);
    }
    if (/^(?:failedChecks|failedCommands|failedHard|reconciliationIssues|missingFiles)$/i.test(key)
      && Array.isArray(item) && item.length !== 0) {
      failures.push(`${label}.${key} must be empty`);
    }
    walkSemanticValue(item, `${label}.${key}`, failures);
  }
}

function exactSameSet(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length > 0
    && left.length === right.length
    && [...left].sort().every((item, index) => item === [...right].sort()[index]);
}

function gitValue(args) {
  const result = spawnSync('git', args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.status !== 0 || !result.stdout.trim()) {
    throw new Error('unable to bind required evidence validation to Git');
  }
  return result.stdout.trim();
}

function currentEvidenceBinding(generatedAt = new Date().toISOString()) {
  return {
    generatedAt,
    source: {
      commit: gitValue(['rev-parse', 'HEAD']),
      tree: gitValue(['rev-parse', 'HEAD^{tree}']),
      runId: process.env.GITHUB_RUN_ID ?? 'local-not-ci',
      runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? 'local-not-ci'
    }
  };
}

function positiveStatus(document, required, failures) {
  if (!/^(?:ok|passed|success|delivered)$/i.test(document.status ?? '')) {
    failures.push(`${required}: top-level status must be explicitly successful`);
  }
}

function nonemptyPassedChecks(document, required, failures) {
  if (!Array.isArray(document.checks)
    || document.checks.length === 0
    || document.checks.some(check => check?.passed !== true)) {
    failures.push(`${required}: checks must be nonempty and every check must pass`);
  }
}

function hasPositiveNumber(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.values(value).some(item =>
    (typeof item === 'number' && Number.isFinite(item) && item > 0) || hasPositiveNumber(item));
}

function validateKnownEvidence(required, document, failures) {
  if (Object.keys(document).length === 0) {
    failures.push(`${required}: empty JSON is not evidence`);
    return;
  }
  if (required === 'runtime.gate.json') {
    if (!Array.isArray(document.failedHard)
      || document.failedHard.length !== 0
      || document.requireRouterNoMock !== true
      || document.routerTransportMocked !== false
      || document.requirePushProviderCanary !== true
      || document.pushProviderCanaryDelivered !== true
      || document.pushProviderCanaryStatus !== 'delivered') {
      failures.push(`${required}: runtime release gate did not prove required real transports`);
    }
    return;
  }
  if (required === 'release-artifact-hydration-summary.json'
    || /^(?:client-device-acceptance|ops-deployment-evidence|security-audit-signoff|ga-decision)-summary\.json$/.test(required)) {
    positiveStatus(document, required, failures);
    nonemptyPassedChecks(document, required, failures);
    if (!Array.isArray(document.failedChecks) || document.failedChecks.length !== 0) {
      failures.push(`${required}: P6 summary has failed checks`);
    }
    if (required === 'release-artifact-hydration-summary.json'
      && (!Array.isArray(document.hydratedArtifacts)
        || document.hydratedArtifacts.length === 0
        || document.hydratedArtifacts.some(item => item?.hydrated !== true))) {
      failures.push(`${required}: every selected P6 source artifact must be hydrated`);
    }
    return;
  }
  if (required === 'client-device-acceptance.json') {
    positiveStatus(document, required, failures);
    const platforms = new Map((document.platforms ?? []).map(item => [item.platform, item.status]));
    if (platforms.get('android') !== 'passed'
      || platforms.get('ios') !== 'passed'
      || platforms.get('windows') !== 'passed'
      || !Array.isArray(document.scenarios)
      || document.scenarios.length === 0
      || document.scenarios.some(item => item?.status !== 'passed')
      || document.releaseGuards?.noStubTransport !== true
      || document.releaseGuards?.noSessionEndpoints !== true) {
      failures.push(`${required}: Android/iOS/Windows scenarios and no-mock guards must pass`);
    }
    return;
  }
  if (required === 'ops-deployment-evidence.json') {
    positiveStatus(document, required, failures);
    if (document.dashboards?.deployed !== true
      || document.alerts?.routesTested !== true
      || document.postDeployVerification?.status !== 'passed'
      || document.postDeployVerification?.runtimeHealth?.status !== 'ok'
      || !document.recovery?.rollbackDrill?.url) {
      failures.push(`${required}: deployment, observability, smoke, and recovery evidence is incomplete`);
    }
    return;
  }
  if (required === 'security-audit-signoff.json') {
    if (document.status !== 'approved'
      || document.externalAudit?.status !== 'closed'
      || document.openFindings?.critical !== 0
      || document.openFindings?.high !== 0
      || document.securityGate?.status !== 'passed'
      || document.sbom?.attested !== true) {
      failures.push(`${required}: security approval, audit closure, findings, gate, or SBOM attestation failed`);
    }
    return;
  }
  if (required === 'ga-decision.json') {
    const approvals = new Map((document.approvals ?? []).map(item => [item.role, item.status]));
    if (document.decision !== 'go'
      || approvals.get('engineering') !== 'approved'
      || approvals.get('security') !== 'approved'
      || approvals.get('ops') !== 'approved'
      || !Array.isArray(document.releaseBlockers)
      || document.releaseBlockers.some(item => !['closed', 'accepted'].includes(item?.status))) {
      failures.push(`${required}: GA decision, approvals, or blocker disposition is incomplete`);
    }
    return;
  }
  if (required === 'runtime.snapshot.json') {
    if (document.schemaVersion !== '2.0.0'
      || !Array.isArray(document.snapshots)
      || document.snapshots.length === 0
      || document.snapshots.some(item => item?.ok !== true)) {
      failures.push(`${required}: every allowlisted runtime snapshot must succeed`);
    }
    return;
  }
  if (required === 'compose.topology.redacted.json') {
    positiveStatus(document, required, failures);
    if (!Array.isArray(document.containers)
      || document.containers.length === 0
      || document.containerCount !== document.containers.length) {
      failures.push(`${required}: topology must contain the exact nonempty container count`);
    }
    return;
  }
  if (required.endsWith('secret-scan-summary.json') || required === 'secret-scan.json') {
    positiveStatus(document, required, failures);
    const findings = document.findings;
    if ((Array.isArray(findings) && findings.length !== 0)
      || ('findingCount' in document && document.findingCount !== 0)) {
      failures.push(`${required}: secret scan must contain zero findings`);
    }
    return;
  }
  if (required.endsWith('/multi-node-topology.json')) {
    positiveStatus(document, required, failures);
    if (!Array.isArray(document.routers)
      || document.routers.length < 3
      || document.routers.some(router => router?.transportMocked !== false)
      || !Number.isSafeInteger(document.registryRuntime?.totalNodes)
      || document.registryRuntime.totalNodes < 3
      || !Number.isSafeInteger(document.selectedPath?.distinctHops)
      || document.selectedPath.distinctHops < 3) {
      failures.push(`${required}: three real routers and three distinct hops are required`);
    }
    return;
  }
  if (required.endsWith('/backend-load-smoke.json')) {
    if (!document.statsDelta || !document.statsAfter || !hasPositiveNumber(document.statsDelta)) {
      failures.push(`${required}: load smoke must prove positive traffic with final stats`);
    }
    return;
  }
  if (required.endsWith('/backend-restart-smoke.json')) {
    positiveStatus(document, required, failures);
    if (!document.retrievedAfterRestart
      || !document.retrievedFinal
      || !document.statsAfterRehearsal
      || document.callRegistry?.authenticatedSignalAcceptedBeforeRestart !== true
      || document.callRegistry?.registryRestarted !== true
      || document.callRegistry?.authenticatedInboxRetrievedAfterRestart !== true
      || document.callRegistry?.exactSignalCountAfterRestart !== 1) {
      failures.push(`${required}: restart smoke lacks post-restart retrieval evidence`);
    }
    return;
  }
  if (required.endsWith('/mau2-call-result.json')) {
    positiveStatus(document, required, failures);
    const requiredTrue = [
      'outgoingOfferStarted', 'incomingRingingObserved', 'incomingAnswerAccepted',
      'selectedIceCandidatePairObserved', 'bidirectionalAudioRtpObserved',
      'microphoneMuteApplied', 'microphoneRestoreApplied', 'remoteHangupObserved',
      'authenticatedMau2EnvironmentValidated', 'productionPackageUntouched'
    ];
    if (document.schema !== 'deep.physical-mau2-phase.v1'
      || document.phase !== 'Call'
      || requiredTrue.some(field => document[field] !== true)) {
      failures.push(`${required}: authenticated physical call evidence is incomplete`);
    }
    return;
  }
  if (required === 'production-readiness-status.json') {
    positiveStatus(document, required, failures);
    if (!Array.isArray(document.blockers) || document.blockers.length !== 0) {
      failures.push(`${required}: production readiness blockers must be empty`);
    }
    return;
  }
  if (required === 'production-readiness-checklist.json') {
    positiveStatus(document, required, failures);
    if (!Array.isArray(document.items)
      || document.items.length === 0
      || !Array.isArray(document.blockedItems)
      || document.blockedItems.length !== 0) {
      failures.push(`${required}: readiness checklist must be nonempty with no blocked items`);
    }
    return;
  }
  if (required === 'release-secret-preflight-summary.json') {
    positiveStatus(document, required, failures);
    nonemptyPassedChecks(document, required, failures);
    if (!Array.isArray(document.failedChecks) || document.failedChecks.length !== 0) {
      failures.push(`${required}: release secret preflight has failed checks`);
    }
    return;
  }
  if (required === 'supporting-release-evidence-summary.json') {
    positiveStatus(document, required, failures);
    nonemptyPassedChecks(document, required, failures);
    if (!Array.isArray(document.copiedArtifacts)
      || document.copiedArtifacts.filter(item => item?.copied === true).length === 0) {
      failures.push(`${required}: supporting evidence copied no artifacts`);
    }
    return;
  }
  if (required.endsWith('/push-provider-canary.json')) {
    positiveStatus(document, required, failures);
    if (document.provider?.status !== 'delivered' || document.provider?.attempts < 1) {
      failures.push(`${required}: push provider canary was not delivered`);
    }
    return;
  }
  if (required.endsWith('/rollback-drill.json')) {
    positiveStatus(document, required, failures);
    if (document.postRollbackSmoke?.status !== 'ok' || document.executed !== true) {
      failures.push(`${required}: rollback and post-rollback smoke must execute successfully`);
    }
    return;
  }
  if (required.endsWith('/registry-recovery.json')) {
    positiveStatus(document, required, failures);
    if (!exactSameSet(document.requiredTests, document.passedTests)) {
      failures.push(`${required}: every required recovery test must pass`);
    }
    return;
  }
  if (required.endsWith('/observability-gate-summary.json')) {
    positiveStatus(document, required, failures);
    if (!Array.isArray(document.failedChecks)
      || document.failedChecks.length !== 0
      || !Array.isArray(document.alertRules)
      || document.alertRules.length === 0) {
      failures.push(`${required}: observability checks and alert rules are incomplete`);
    }
    return;
  }
  if (required === 'sbom.json') {
    if (!validCycloneDxSbom(document)) {
      failures.push(`${required}: SBOM must be sanitized deterministic CycloneDX 1.6 with an exact nonempty component inventory`);
    }
    return;
  }
  if (required === 'dependency-audit.json' || required === 'security-gate-summary.json'
    || required.endsWith('/release-gate-contract-summary.json')) {
    positiveStatus(document, required, failures);
    return;
  }
  failures.push(`${required}: no explicit semantic evidence contract is registered`);
}

export async function validateRequiredEvidence(
  discovered,
  requiredFiles,
  now = new Date(),
  binding = currentEvidenceBinding(now.toISOString())
) {
  const failures = [];
  let freshnessChecked = 0;
  const evidenceBindings = [];
  let rollbackExecutedAndPassed = !requiredFiles.includes('test-results/rollback-drill.json');
  for (const required of requiredFiles) {
    if (path.posix.extname(required).toLowerCase() !== '.json') {
      failures.push(`${required}: required release evidence must be JSON`);
      continue;
    }
    const selected = discovered.find(item => item.relative === required);
    let document;
    let raw;
    try {
      raw = await readFile(selected.filePath);
      document = JSON.parse(raw.toString('utf8').replace(/^\uFEFF/, ''));
    } catch {
      failures.push(`${required}: required release evidence is not valid JSON`);
      continue;
    }
    if (!document || typeof document !== 'object' || Array.isArray(document)) {
      failures.push(`${required}: required release evidence must be an object`);
      continue;
    }
    validateKnownEvidence(required, document, failures);
    walkSemanticValue(document, required, failures);
    const observedGeneratedAt = [
      document.generatedAt,
      document.capturedAt,
      document.capturedAtUtc,
      document.evaluatedAtUtc,
      required === 'sbom.json' ? document.metadata?.timestamp : null
    ].find(value => typeof value === 'string' && value.length > 0);
    freshnessChecked += 1;
    const generated = Date.parse(observedGeneratedAt ?? '');
    const age = now.getTime() - generated;
    const immutableSbom = required === 'sbom.json';
    if (!immutableSbom
      && (!Number.isFinite(generated) || age < -5 * 60 * 1000 || age > MAX_EVIDENCE_AGE_MS)) {
      failures.push(`${required}: evidence timestamp is missing, invalid, stale, or from the future`);
    }
    evidenceBindings.push({
      path: required,
      sha256: sha256(raw),
      generatedAt: observedGeneratedAt ?? null,
      source: binding.source
    });
    if (required.endsWith('/rollback-drill.json')) {
      rollbackExecutedAndPassed = document.status === 'ok'
        && document.postRollbackSmoke?.status === 'ok'
        && document.executed === true;
      if (!rollbackExecutedAndPassed) {
        failures.push(`${required}: rollback must execute and its post-rollback smoke must pass`);
      }
    }
    if (required.endsWith('/registry-recovery.json')
      && !exactSameSet(document.requiredTests, document.passedTests)) {
      failures.push(`${required}: every required recovery test must pass`);
    }
    if (required.endsWith('secret-scan-summary.json')
      && (document.status !== 'ok' || document.findingCount !== 0)) {
      failures.push(`${required}: secret scan must be successful with zero findings`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`required evidence semantic validation failed: ${failures.join('; ')}`);
  }
  return {
    schemaVersion: 'deep-required-evidence-validation-v1',
    status: 'passed',
    requiredFileCount: requiredFiles.length,
    jsonFilesValidated: requiredFiles.length,
    freshnessChecked,
    countersValidated: true,
    rollbackExecutedAndPassed,
    skippedChecks: 0,
    schemaContractsValidated: requiredFiles.length,
    bindingFreshnessValidated: true,
    semanticContracts: [...requiredFiles],
    evidenceBindings,
    generatedAt: binding.generatedAt,
    source: binding.source
  };
}

function parse(argv) {
  const options = { roots: [], files: [], requiredFiles: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--root') options.roots.push(value);
    else if (name === '--file') options.files.push(value);
    else if (name === '--require') options.requiredFiles.push(value);
    else if (name === '--staging') options.staging = value;
    else if (name === '--manifest') options.manifest = value;
    else if (name === '--max-file-bytes') options.maxFileBytes = Number(value);
    else throw new Error(`unknown argument: ${name}`);
    index += 1;
  }
  if (options.roots.length === 0 && options.files.length === 0) {
    throw new Error('at least one --root or --file is required');
  }
  if (!options.staging) throw new Error('--staging is required');
  if (!options.manifest) throw new Error('--manifest is required');
  return options;
}

export function validatePreparedManifest(document, options = {}) {
  exactKeys(document, [
    'schemaVersion',
    'status',
    'fileCount',
    'totalBytes',
    'stagingRoot',
    'requiredFiles',
    'requiredEvidenceValidation',
    'files'
  ], 'upload manifest');
  if (document.schemaVersion !== MANIFEST_SCHEMA_VERSION
    || document.status !== 'prepared'
    || !Number.isSafeInteger(document.fileCount)
    || document.fileCount <= 0
    || !Number.isSafeInteger(document.totalBytes)
    || document.totalBytes < 0
    || typeof document.stagingRoot !== 'string'
    || !Array.isArray(document.requiredFiles)
    || !document.requiredEvidenceValidation
    || !Array.isArray(document.files)
    || document.files.length !== document.fileCount) {
    throw new Error('upload manifest has an unsupported schema or empty/inconsistent content');
  }
  const requiredFiles = document.requiredFiles.map(normalizeRequiredPath);
  if (new Set(requiredFiles).size !== requiredFiles.length) {
    throw new Error('upload manifest required paths must be unique');
  }
  exactKeys(document.requiredEvidenceValidation, [
    'schemaVersion',
    'status',
    'requiredFileCount',
    'jsonFilesValidated',
    'freshnessChecked',
    'countersValidated',
    'rollbackExecutedAndPassed',
    'skippedChecks',
    'schemaContractsValidated',
    'bindingFreshnessValidated',
    'semanticContracts',
    'evidenceBindings',
    'generatedAt',
    'source'
  ], 'required evidence validation');
  const validation = document.requiredEvidenceValidation;
  exactKeys(validation.source, ['commit', 'tree', 'runId', 'runAttempt'], 'required evidence source binding');
  const generatedAt = Date.parse(validation.generatedAt);
  const currentBinding = currentEvidenceBinding(validation.generatedAt);
  const expectedSource = options.expectedSourceRunId === undefined
    ? currentBinding.source
    : {
      commit: currentBinding.source.commit,
      tree: currentBinding.source.tree,
      runId: String(options.expectedSourceRunId),
      runAttempt: validation.source.runAttempt
    };
  if (validation.schemaVersion !== 'deep-required-evidence-validation-v1'
    || validation.status !== 'passed'
    || validation.requiredFileCount !== requiredFiles.length
    || validation.jsonFilesValidated !== requiredFiles.length
    || !Number.isSafeInteger(validation.freshnessChecked)
    || validation.freshnessChecked < 0
    || validation.freshnessChecked !== requiredFiles.length
    || validation.countersValidated !== true
    || validation.rollbackExecutedAndPassed !== true
    || validation.skippedChecks !== 0
    || validation.schemaContractsValidated !== requiredFiles.length
    || validation.bindingFreshnessValidated !== true
    || JSON.stringify(validation.semanticContracts) !== JSON.stringify(requiredFiles)
    || !Array.isArray(validation.evidenceBindings)
    || validation.evidenceBindings.length !== requiredFiles.length
    || !Number.isFinite(generatedAt)
    || Date.now() - generatedAt < -5 * 60 * 1000
    || Date.now() - generatedAt > MAX_EVIDENCE_AGE_MS
    || JSON.stringify(validation.source) !== JSON.stringify(expectedSource)) {
    throw new Error('required evidence validation receipt is invalid');
  }
  for (const [index, binding] of validation.evidenceBindings.entries()) {
    exactKeys(binding, ['path', 'sha256', 'generatedAt', 'source'], 'required evidence file binding');
    exactKeys(binding.source, ['commit', 'tree', 'runId', 'runAttempt'], 'required evidence file source');
    const required = requiredFiles[index];
    const file = document.files.find(entry => entry.path === required);
    if (binding.path !== required
      || binding.sha256 !== file?.sha256
      || !Number.isFinite(Date.parse(binding.generatedAt ?? ''))
      || JSON.stringify(binding.source) !== JSON.stringify(validation.source)) {
      throw new Error('required evidence file provenance binding is invalid');
    }
  }
  let totalBytes = 0;
  const paths = new Set();
  for (const entry of document.files) {
    exactKeys(entry, [
      'path',
      'size',
      'sha256',
      'extension',
      'mediaType',
      'handling',
      'approvedOpaqueSignedBinary'
    ], 'upload manifest entry');
    const entryPath = normalizeRequiredPath(entry.path);
    if (entryPath !== entry.path || paths.has(entryPath)) {
      throw new Error('upload manifest paths must be canonical and unique');
    }
    paths.add(entryPath);
    if (!Number.isSafeInteger(entry.size)
      || entry.size < 0
      || !/^[0-9a-f]{64}$/.test(entry.sha256 ?? '')
      || entry.extension !== path.posix.extname(entry.path).toLowerCase()
      || entry.mediaType !== mediaTypeFor(entry.path)
      || entry.handling !== 'inspect'
      || entry.approvedOpaqueSignedBinary !== false) {
      throw new Error('upload manifest entry violates the inspect-only policy');
    }
    totalBytes += entry.size;
    if (!Number.isSafeInteger(totalBytes)) throw new Error('upload manifest total size overflow');
  }
  if (totalBytes !== document.totalBytes) throw new Error('upload manifest total byte count mismatch');
  for (const required of requiredFiles) {
    if (!paths.has(required)) throw new Error(`required artifact is missing from upload manifest: ${required}`);
  }
  return document;
}

export async function verifyPreparedStaging(document, stagingRoot) {
  validatePreparedManifest(document);
  const resolvedRoot = path.resolve(stagingRoot);
  const rootInfo = await lstat(resolvedRoot);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error('staging root must be a canonical directory');
  }
  const realRoot = await realpath(resolvedRoot);
  const discovered = await walk(resolvedRoot);
  if (discovered.length !== document.fileCount) {
    throw new Error('staging root contains unmanifested or missing files');
  }
  const expectedPaths = new Set(document.files.map(entry => entry.path));
  for (const filePath of discovered) {
    const relative = toPosix(path.relative(resolvedRoot, filePath));
    if (!expectedPaths.has(relative)) throw new Error('staging root contains an unmanifested file');
  }
  for (const entry of document.files) {
    const filePath = path.resolve(resolvedRoot, ...entry.path.split('/'));
    if (!inside(resolvedRoot, filePath)) throw new Error('upload manifest path escapes staging root');
    const info = await lstat(filePath);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error('manifested artifact is not a regular file');
    if (!inside(realRoot, await realpath(filePath))) {
      throw new Error('manifested artifact resolves outside staging root');
    }
    const buffer = await readFile(filePath);
    if (buffer.length !== entry.size || sha256(buffer) !== entry.sha256) {
      throw new Error('manifested artifact changed after manifest preparation');
    }
  }
  const recomputedValidation = await validateRequiredEvidence(
    discovered.map(filePath => ({
      filePath,
      relative: toPosix(path.relative(resolvedRoot, filePath))
    })),
    document.requiredFiles,
    new Date(),
    {
      generatedAt: document.requiredEvidenceValidation.generatedAt,
      source: document.requiredEvidenceValidation.source
    }
  );
  if (JSON.stringify(recomputedValidation) !== JSON.stringify(document.requiredEvidenceValidation)) {
    throw new Error('required evidence validation receipt does not match staged content');
  }
}

export async function prepareUpload(options) {
  const roots = (options.roots ?? []).map(item => path.resolve(item));
  const explicitFiles = (options.files ?? []).map(item => path.resolve(item));
  const staging = path.resolve(options.staging);
  const manifestPath = path.resolve(options.manifest);
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const requiredFiles = [...new Set((options.requiredFiles ?? []).map(normalizeRequiredPath))].sort();
  if (requiredFiles.length > 0
    && !((roots.length === 1 && explicitFiles.length === 0)
      || (roots.length === 0 && explicitFiles.length > 0))) {
    throw new Error('required artifact contracts require one root or an explicit file set');
  }
  const discovered = [];
  for (const [rootIndex, root] of roots.entries()) {
    const rootInfo = await lstat(root);
    if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
      throw new Error('each upload root must be a canonical directory without reparse points');
    }
    for (const filePath of await walk(root)) {
      const relative = toPosix(path.relative(root, filePath));
      discovered.push({ root, rootIndex, filePath, relative });
    }
  }
  for (const [fileIndex, filePath] of explicitFiles.entries()) {
    const parent = path.dirname(filePath);
    await assertRegularNoReparse(parent, filePath);
    discovered.push({
      root: parent,
      rootIndex: roots.length + fileIndex,
      filePath,
      relative: path.basename(filePath),
      explicit: true
    });
  }
  if (discovered.length === 0) {
    throw new Error('upload selection is empty');
  }
  const discoveredRelative = new Set(discovered.map(item => item.relative));
  for (const required of requiredFiles) {
    if (!discoveredRelative.has(required)) {
      throw new Error(`required artifact is missing from upload selection: ${required}`);
    }
  }
  const requiredEvidenceValidation = await validateRequiredEvidence(discovered, requiredFiles);

  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true });
  const entries = [];
  const seen = new Set();
  for (const item of discovered) {
    const info = await assertRegularNoReparse(item.root, item.filePath);
    if (info.size > maxFileBytes) throw new Error('artifact exceeds upload size policy');
    const extension = path.extname(item.relative).toLowerCase();
    if (forbiddenExtensions.has(extension)) {
      throw new Error('raw UI bitmaps and arbitrary logs are not uploadable');
    }
    const stagedRelative = roots.length <= 1 && (roots.length === 0 || explicitFiles.length === 0)
      ? item.relative
      : `${item.rootIndex}/${item.relative}`;
    if (seen.has(stagedRelative)) throw new Error('duplicate staged artifact path');
    seen.add(stagedRelative);
    const buffer = await readFile(item.filePath);
    if (blockedArchiveExtensions.has(extension) || hasBlockedArchiveMagic(buffer)) {
      throw new Error('archive and application-package uploads are blocked pending cryptographic approval');
    }
    const digest = sha256(buffer);
    const mediaType = mediaTypeFor(item.filePath);
    if (opaqueExtensions.has(extension)) {
      throw new Error('opaque executable binaries are blocked until cryptographic approval verification exists');
    }
    const stagedPath = path.join(staging, ...stagedRelative.split('/'));
    await mkdir(path.dirname(stagedPath), { recursive: true });
    await copyFile(item.filePath, stagedPath);
    entries.push({
      path: stagedRelative,
      size: info.size,
      sha256: digest,
      extension,
      mediaType,
      handling: 'inspect',
      approvedOpaqueSignedBinary: false
    });
  }
  entries.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    status: 'prepared',
    fileCount: entries.length,
    totalBytes: entries.reduce((sum, entry) => sum + entry.size, 0),
    stagingRoot: toPosix(path.relative(repositoryRoot, staging)),
    requiredFiles,
    requiredEvidenceValidation,
    files: entries
  };
  validatePreparedManifest(manifest);
  await mkdir(path.dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parse(argv);
  const manifest = await prepareUpload(options);
  console.log(`Prepared ${manifest.fileCount} explicitly manifested artifact file(s).`);
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Artifact upload preparation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
