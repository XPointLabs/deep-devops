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
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
export const metadataSafeProfile = 'metadata-safe-v1';
export const featureFlag = 'DEEP_INFRA_PRIVACY_PROFILE';
const maximumTextBytes = 5 * 1024 * 1024;
const services = Object.freeze(['calls', 'file', 'push', 'storage', 'xnode-1', 'xnode-2', 'xnode-3']);
const routers = Object.freeze(['xnode-1', 'xnode-2', 'xnode-3']);
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

function fingerprint(ruleId, logicalPath, line) {
  return createHash('sha256')
    .update(`${ruleId}\n${logicalPath}\n${line ?? 0}`)
    .digest('hex')
    .slice(0, 16);
}

function finding(ruleId, logicalPath, line = undefined) {
  return {
    ruleId,
    path: logicalPath.replaceAll('\\', '/'),
    ...(line ? { line } : {}),
    fingerprint: fingerprint(ruleId, logicalPath, line)
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

export function inspectMetadataText(text, logicalPath = 'selected-artifact.txt') {
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
    /\b(?:client|source|remote|x_forwarded_for|x-forwarded-for)[_. -]?(?:ip|address)\b\s*[:=]\s*["']?(?:\d{1,3}\.){3}\d{1,3}\b/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'sensitive-request-target',
    /(?:\/(?:subscriptions|inbox|mailbox|storage\/(?:store|retrieve))\/[^\s"'?]+|[?&](?:pubkey|recipient|sender|mailbox|capability|push_token)=)/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'raw-push-handle',
    /\b(?:push|provider|device)[_. -]?(?:token|handle)\b\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{8,}/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'raw-mailbox-capability',
    /\b(?:mailbox|deposit|retrieve)[_. -]?(?:id|token|handle|capability)\b\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{8,}/gi,
    findings
  );
  addRegexFindings(
    text,
    logicalPath,
    'stable-cross-domain-correlation',
    /\b(?:correlation|request|trace)[_. -]?id\b\s*[:=]\s*["']?[A-Za-z0-9._~-]{8,}/gi,
    findings
  );
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

export async function scanSelectedPaths(paths, { metrics = false } = {}) {
  assert.ok(Array.isArray(paths) && paths.length > 0, 'at least one explicit metadata scan path is required');
  const findings = [];
  let scannedFiles = 0;
  for (const selected of paths) {
    const root = path.resolve(selected);
    const files = [];
    await walkSelected(root, root, files);
    for (const file of files) {
      const info = await stat(file);
      assert.ok(info.size <= maximumTextBytes, 'metadata scan input exceeds the 5 MiB text limit');
      assert.ok(textExtensions.has(path.extname(file).toLowerCase()), 'metadata scan accepts explicit text artifacts only');
      const text = await readFile(file, 'utf8');
      const logical = path.relative(root, file) || path.basename(file);
      findings.push(...(metrics ? lintMetricText(text, logical) : inspectMetadataText(text, logical)));
      scannedFiles += 1;
    }
  }
  const unique = [...new Map(findings.map(item => [
    `${item.ruleId}\0${item.path}\0${item.line ?? ''}`,
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
  const components = new Map((policy.components ?? []).map(item => [item.component, item]));
  assert.deepEqual(
    [...components.keys()].sort(),
    ['compat-services', 'metrics', 'provider-push', 'sanitized-evidence', 'xnode-operational', 'xray-access', 'xray-error']
  );
  assert.equal(components.get('xray-access').retentionHours, 0);
  assert.equal(components.get('provider-push').retentionHours, null);
  for (const [name, component] of components) {
    if (name !== 'provider-push') {
      assert.ok(Number.isSafeInteger(component.retentionHours) && component.retentionHours >= 0);
    }
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

export function validateMetadataSafeTopology(topology) {
  assert.deepEqual(Object.keys(topology?.services ?? {}).sort(), [...services].sort());
  for (const name of services) {
    const service = topology.services[name];
    assert.equal(service.environment?.DEEP_INFRA_PRIVACY_PROFILE, metadataSafeProfile, `${name} profile`);
    assert.equal(service.labels?.['io.deep.infrastructure-privacy-profile'], metadataSafeProfile, `${name} label`);
    assert.deepEqual(service.logging, {
      driver: 'local',
      options: {
        compress: 'true',
        'max-file': '2',
        'max-size': '1m'
      }
    }, `${name} bounded logging`);
  }
  for (const name of routers) {
    const environment = topology.services[name].environment;
    for (const key of [
      'Logging__LogLevel__Default',
      'Logging__LogLevel__Microsoft.AspNetCore',
      'Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics',
      'Logging__LogLevel__Microsoft.AspNetCore.Server.Kestrel',
      'Logging__LogLevel__System.Net.Http.HttpClient'
    ]) {
      assert.equal(environment[key], 'Warning', `${name} ${key}`);
    }
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

export async function runGate(options) {
  assert.equal(process.env[featureFlag], metadataSafeProfile, `${featureFlag} must be exact ${metadataSafeProfile}`);
  const { policy, xnodeCommit } = await validatePinnedInputs(options);
  const topology = validateMetadataSafeTopology(options.topology ?? renderMetadataSafeTopology());
  const artifactScan = await scanSelectedPaths(options.artifactPaths);
  const metricScan = await scanSelectedPaths(options.metricPaths, { metrics: true });
  const findings = [...artifactScan.findings, ...metricScan.findings];
  let breakGlassVerified = false;
  if (options.breakGlassReceiptPath) {
    validateBreakGlassReceipt(
      JSON.parse(await readFile(options.breakGlassReceiptPath, 'utf8')),
      policy
    );
    breakGlassVerified = true;
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
      '--break-glass-receipt': 'breakGlassReceiptPath'
    }[argument];
    assert.ok(key, `unknown argument: ${argument}`);
    const value = argv[index + 1];
    assert.ok(value && !value.startsWith('--'), `${argument} requires a value`);
    if (Array.isArray(options[key])) options[key].push(path.resolve(value));
    else options[key] = path.resolve(value);
    index += 1;
  }
  assert.ok(options.summaryPath, '--summary is required');
  assert.ok(options.xnodeDir, '--xnode-dir is required');
  assert.ok(options.clientExpectationsPath, '--client-expectations is required');
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
      console.error(`- ${item.ruleId} at ${item.path}${item.line ? `:${item.line}` : ''} [${item.fingerprint}]`);
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
  main().catch(error => {
    console.error(`Infrastructure metadata privacy gate failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
