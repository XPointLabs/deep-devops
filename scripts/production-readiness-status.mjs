import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const releaseDir = path.join(artifactRoot, 'release');
const outputPath = path.join(releaseDir, 'production-readiness-status.json');
const checklistPath = path.join(releaseDir, 'production-readiness-checklist.json');

const args = new Set(process.argv.slice(2));
const runGates = args.has('--run-gates');
const strictRelease = args.has('--strict-release');
const allowBlockedExitZero = args.has('--allow-blocked-exit-zero');
const expectedReleaseCandidate = argValue('--release-candidate')
  ?? process.env.DEEP_RELEASE_CANDIDATE
  ?? null;

const evidencePackages = [
  {
    key: 'client-device-acceptance',
    label: 'Client device acceptance',
    manifest: 'client-device-acceptance.json',
    summary: 'client-device-acceptance-summary.json',
    gate: 'client-device-acceptance-gate.mjs',
    action: 'Attach Android/iOS/Windows device-lab acceptance evidence and rerun client-device-acceptance-gate.mjs.'
  },
  {
    key: 'ops-deployment-evidence',
    label: 'Ops deployment evidence',
    manifest: 'ops-deployment-evidence.json',
    summary: 'ops-deployment-evidence-summary.json',
    gate: 'ops-deployment-evidence-gate.mjs',
    action: 'Attach staging/production dashboard, alert-route, post-deploy, backup, and rollback evidence and rerun ops-deployment-evidence-gate.mjs.'
  },
  {
    key: 'security-audit-signoff',
    label: 'Security audit sign-off',
    manifest: 'security-audit-signoff.json',
    summary: 'security-audit-signoff-summary.json',
    gate: 'security-audit-signoff-gate.mjs',
    action: 'Attach external audit/security approval evidence and rerun security-audit-signoff-gate.mjs.'
  },
  {
    key: 'ga-decision',
    label: 'GA decision',
    manifest: 'ga-decision.json',
    summary: 'ga-decision-summary.json',
    gate: 'ga-decision-gate.mjs',
    action: 'Attach go/no-go minutes, engineering/security/ops approvals, 30/60/90 plan, and post-GA backlog, then rerun ga-decision-gate.mjs.'
  }
];

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index >= 0 && index + 1 < process.argv.length) {
    const value = process.argv[index + 1];
    return value.startsWith('--') ? null : value;
  }

  const prefix = `${name}=`;
  const inline = process.argv.find(value => value.startsWith(prefix));
  return inline ? inline.slice(prefix.length) : null;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function blockerIdPart(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'unknown';
}

function outputSnippet(value) {
  const normalized = String(value ?? '').trim();
  if (normalized.length <= 2000) {
    return normalized;
  }

  return `${normalized.slice(0, 2000)}...`;
}

function gateCommandAction(commandResult) {
  switch (commandResult.label) {
    case 'session-infra-guard':
      return 'Remove forbidden upstream Session/Oxen/Lokinet hosted endpoints from production-facing config/source and rerun session-infra-guard.mjs.';
    case 'release-artifact-bundle':
      return 'Attach the complete RC artifact bundle and rerun release-artifact-bundle.mjs --release-candidate <rc>.';
    case 'strict-release-evidence':
      return 'Attach strict release evidence, including attached CI and staging provider canary evidence, then rerun release-evidence-gate.mjs.';
    case 'client-device-acceptance':
      return 'Attach Android/iOS/Windows device-lab acceptance evidence and rerun client-device-acceptance-gate.mjs.';
    case 'ops-deployment-evidence':
      return 'Attach ops deployment evidence and rerun ops-deployment-evidence-gate.mjs.';
    case 'security-audit-signoff':
      return 'Attach security audit sign-off evidence and rerun security-audit-signoff-gate.mjs.';
    case 'ga-decision':
      return 'Attach the GA decision record and rerun ga-decision-gate.mjs.';
    case 'production-readiness':
      return 'Resolve upstream release evidence and P6 evidence failures, then rerun production-readiness-gate.mjs.';
    default:
      return 'Inspect the command output, resolve the failing gate or runner issue, and rerun production-readiness-status.mjs --run-gates.';
  }
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJsonArtifact(label, filePath) {
  const absolutePath = path.resolve(filePath);
  if (!await fileExists(absolutePath)) {
    return {
      label,
      path: absolutePath,
      exists: false,
      parsed: null,
      parseError: null
    };
  }

  try {
    const raw = await readFile(absolutePath, 'utf8');
    return {
      label,
      path: absolutePath,
      exists: true,
      parsed: JSON.parse(raw.replace(/^\uFEFF/, '')),
      parseError: null
    };
  } catch (error) {
    return {
      label,
      path: absolutePath,
      exists: true,
      parsed: null,
      parseError: error.message
    };
  }
}

function runNode(scriptName, scriptArgs, label) {
  const result = spawnSync(process.execPath, [path.join('scripts', scriptName), ...scriptArgs], {
    cwd: devopsRoot,
    env: process.env,
    encoding: 'utf8'
  });

  return {
    label,
    command: ['node', path.join('scripts', scriptName), ...scriptArgs].join(' '),
    status: result.status,
    passed: result.status === 0,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim()
  };
}

function addBlocker(blockers, id, area, description, action, evidence = {}) {
  blockers.push({
    id,
    area,
    severity: 'release-blocking',
    description,
    action,
    evidence
  });
}

function blockersFor(blockers, prefixes) {
  return blockers.filter(blocker => prefixes.some(prefix => blocker.id === prefix || blocker.id.startsWith(`${prefix}:`)));
}

function checklistItem(blockers, definition) {
  const matchingBlockers = blockersFor(blockers, definition.blockerPrefixes);
  return {
    id: definition.id,
    area: definition.area,
    ownerRole: definition.ownerRole,
    status: matchingBlockers.length === 0 ? 'ready' : 'blocked',
    requiredArtifacts: definition.requiredArtifacts,
    commands: definition.commands,
    docs: definition.docs,
    blockerIds: matchingBlockers.map(blocker => blocker.id),
    nextAction: matchingBlockers[0]?.action ?? definition.readyAction
  };
}

function buildChecklist(blockers, releaseCandidate) {
  const definitions = [
    {
      id: 'release-artifact-bundle',
      area: 'Release artifact bundle',
      ownerRole: 'Release / Ops lead',
      blockerPrefixes: ['gate-command:session-infra-guard', 'gate-command:release-artifact-bundle', 'release-artifact-bundle'],
      requiredArtifacts: [
        'artifacts/runtime.gate.json',
        'artifacts/test-results/backend-load-smoke.json',
        'artifacts/test-results/backend-restart-smoke.json',
        'artifacts/test-results/push-provider-canary.json',
        'artifacts/test-results/multi-node-topology.json',
        'artifacts/test-results/registry-recovery.json',
        'artifacts/test-results/rollback-drill.json',
        'artifacts/security/security-gate-summary.json',
        'artifacts/observability/observability-gate-summary.json',
        'artifacts/release/session-infra-guard-summary.json',
        'artifacts/router-c3-latest.json',
        'artifacts/release/attached-ci-artifacts.json',
        'artifacts/release/attached-ci-manifest-summary.json',
        'artifacts/release/client-device-acceptance.json',
        'artifacts/release/ops-deployment-evidence.json',
        'artifacts/release/security-audit-signoff.json',
        'artifacts/release/ga-decision.json',
        'artifacts/release/release-artifact-bundle-summary.json'
      ],
      commands: [
        'node .\\deep-devops\\scripts\\bundle-supporting-release-evidence.mjs --source-root <artifact-root> --output-dir <bundle-dir>',
        'node .\\deep-devops\\scripts\\hydrate-release-artifact-bundle.mjs --input-dir <downloaded-artifacts> --allow-missing',
        'node .\\deep-devops\\scripts\\session-infra-guard.mjs',
        'node .\\deep-devops\\scripts\\release-artifact-bundle.mjs --release-candidate <rc>'
      ],
      docs: ['deep-devops/docs/PRODUCTION_READINESS_GATE.md', 'deep-devops/docs/MESSENGER_NODE_PRODUCTION_RUNBOOK.md'],
      readyAction: 'All raw release artifacts are present, parseable, and tied to this release candidate.'
    },
    {
      id: 'strict-release-evidence',
      area: 'Release evidence',
      ownerRole: 'Release / Ops lead',
      blockerPrefixes: ['gate-command:strict-release-evidence', 'release-evidence'],
      requiredArtifacts: [
        'artifacts/release/attached-ci-artifacts.json',
        'artifacts/release/attached-ci-manifest-summary.json',
        'artifacts/test-results/push-provider-canary.json',
        'artifacts/test-results/rollback-drill.json',
        'artifacts/release/release-artifact-bundle-summary.json',
        'artifacts/release/release-evidence-summary.json'
      ],
      commands: [
        'node .\\deep-devops\\scripts\\collect-attached-ci-source.mjs --owner <org> --branch master --release-candidate <rc>',
        'node .\\deep-devops\\scripts\\registry-recovery-drill.mjs',
        'node .\\deep-devops\\scripts\\bundle-supporting-release-evidence.mjs --source-root <artifact-root> --output-dir <bundle-dir>',
        'node .\\deep-devops\\scripts\\hydrate-release-artifact-bundle.mjs --input-dir <downloaded-artifacts> --allow-missing',
        'node .\\deep-devops\\scripts\\attached-ci-manifest.mjs --input C:\\path\\to\\attached-ci-source.json --release-candidate <rc>',
        'node .\\deep-devops\\scripts\\session-infra-guard.mjs',
        'node .\\deep-devops\\scripts\\release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary'
      ],
      docs: ['deep-devops/docs/ATTACHED_CI_EVIDENCE.md', 'deep-devops/docs/MESSENGER_NODE_PRODUCTION_RUNBOOK.md'],
      readyAction: 'Strict release evidence is green for this release candidate.'
    },
    {
      id: 'client-device-acceptance',
      area: 'Client device acceptance',
      ownerRole: 'QA / E2E lead',
      blockerPrefixes: ['gate-command:client-device-acceptance', 'client-device-acceptance'],
      requiredArtifacts: [
        'artifacts/release/client-device-acceptance.json',
        'artifacts/release/client-device-acceptance-summary.json'
      ],
      commands: ['node .\\deep-devops\\scripts\\client-device-acceptance-gate.mjs'],
      docs: ['deep-devops/docs/CLIENT_DEVICE_ACCEPTANCE.md'],
      readyAction: 'Client device acceptance evidence is green for Android, iOS, and Windows.'
    },
    {
      id: 'ops-deployment-evidence',
      area: 'Ops deployment evidence',
      ownerRole: 'SRE / Ops lead',
      blockerPrefixes: ['gate-command:ops-deployment-evidence', 'ops-deployment-evidence'],
      requiredArtifacts: [
        'artifacts/release/ops-deployment-evidence.json',
        'artifacts/release/ops-deployment-evidence-summary.json'
      ],
      commands: ['node .\\deep-devops\\scripts\\ops-deployment-evidence-gate.mjs'],
      docs: ['deep-devops/docs/OPS_DEPLOYMENT_EVIDENCE.md'],
      readyAction: 'Ops deployment, dashboard, alert-route, recovery, and post-deploy evidence is green.'
    },
    {
      id: 'security-audit-signoff',
      area: 'Security audit sign-off',
      ownerRole: 'Security lead',
      blockerPrefixes: ['gate-command:security-audit-signoff', 'security-audit-signoff'],
      requiredArtifacts: [
        'artifacts/release/security-audit-signoff.json',
        'artifacts/release/security-audit-signoff-summary.json'
      ],
      commands: ['node .\\deep-devops\\scripts\\security-audit-signoff-gate.mjs'],
      docs: ['deep-devops/docs/SECURITY_AUDIT_SIGNOFF.md'],
      readyAction: 'Security audit sign-off is green with no unaccepted critical/high launch findings.'
    },
    {
      id: 'ga-decision',
      area: 'GA decision',
      ownerRole: 'Engineering / Security / Ops DRIs',
      blockerPrefixes: ['gate-command:ga-decision', 'ga-decision'],
      requiredArtifacts: [
        'artifacts/release/ga-decision.json',
        'artifacts/release/ga-decision-summary.json'
      ],
      commands: ['node .\\deep-devops\\scripts\\ga-decision-gate.mjs'],
      docs: ['deep-devops/docs/GA_DECISION.md'],
      readyAction: 'GA go decision is approved and tied to this release candidate.'
    },
    {
      id: 'final-production-readiness',
      area: 'Production readiness',
      ownerRole: 'Release / Ops lead',
      blockerPrefixes: ['gate-command:production-readiness', 'production-readiness'],
      requiredArtifacts: [
        'artifacts/release/production-readiness-summary.json',
        'artifacts/release/production-readiness-status.json',
        'artifacts/release/production-readiness-checklist.json'
      ],
      commands: [
        'node .\\deep-devops\\scripts\\production-readiness-gate.mjs',
        'node .\\deep-devops\\scripts\\production-readiness-status.mjs --run-gates --strict-release --release-candidate <rc>'
      ],
      docs: ['deep-devops/docs/PRODUCTION_READINESS_GATE.md'],
      readyAction: 'Final production readiness gate is green.'
    }
  ];

  const items = definitions.map(definition => checklistItem(blockers, definition));
  return {
    status: items.every(item => item.status === 'ready') ? 'ready' : 'blocked',
    generatedAt: new Date().toISOString(),
    artifactRoot,
    releaseCandidate,
    items,
    blockedItems: items.filter(item => item.status !== 'ready').map(item => item.id),
    readyItems: items.filter(item => item.status === 'ready').map(item => item.id)
  };
}

const commandResults = [];
if (runGates) {
  if (strictRelease) {
    commandResults.push(runNode(
      'session-infra-guard.mjs',
      [],
      'session-infra-guard'
    ));

    commandResults.push(runNode(
      'release-artifact-bundle.mjs',
      hasText(expectedReleaseCandidate) ? ['--release-candidate', expectedReleaseCandidate.trim()] : [],
      'release-artifact-bundle'
    ));
  }

  commandResults.push(runNode(
    'release-evidence-gate.mjs',
    strictRelease
      ? ['--require-attached-ci', '--require-rollback-drill', '--require-staging-provider-canary']
      : ['--require-rollback-drill'],
    strictRelease ? 'strict-release-evidence' : 'local-release-evidence'
  ));

  for (const evidencePackage of evidencePackages) {
    commandResults.push(runNode(evidencePackage.gate, [], evidencePackage.key));
  }

  commandResults.push(runNode('production-readiness-gate.mjs', [], 'production-readiness'));
}

const releaseArtifactBundle = await readJsonArtifact('release-artifact-bundle-summary', path.join(releaseDir, 'release-artifact-bundle-summary.json'));
const releaseEvidence = await readJsonArtifact('release-evidence-summary', path.join(releaseDir, 'release-evidence-summary.json'));
const productionReadiness = await readJsonArtifact('production-readiness-summary', path.join(releaseDir, 'production-readiness-summary.json'));
const observedReleaseCandidate = releaseEvidence.parsed?.releaseCandidate
  ?? productionReadiness.parsed?.releaseCandidate
  ?? releaseArtifactBundle.parsed?.expectedReleaseCandidate
  ?? null;

const packageStates = [];
for (const evidencePackage of evidencePackages) {
  const manifest = await readJsonArtifact(`${evidencePackage.key}-manifest`, path.join(releaseDir, evidencePackage.manifest));
  const summary = await readJsonArtifact(`${evidencePackage.key}-summary`, path.join(releaseDir, evidencePackage.summary));
  packageStates.push({ ...evidencePackage, manifest, summary });
}

const blockers = [];
for (const commandResult of commandResults.filter(result => !result.passed)) {
  addBlocker(
    blockers,
    `gate-command:${blockerIdPart(commandResult.label)}`,
    'Gate execution',
    `Gate command failed while generating the production readiness status: ${commandResult.label}.`,
    gateCommandAction(commandResult),
    {
      command: commandResult.command,
      exitCode: commandResult.status,
      stdout: outputSnippet(commandResult.stdout),
      stderr: outputSnippet(commandResult.stderr)
    }
  );
}

if (strictRelease) {
  if (!releaseArtifactBundle.exists || !releaseArtifactBundle.parsed) {
    addBlocker(
      blockers,
      'release-artifact-bundle:summary-missing',
      'Release artifact bundle',
      'Release artifact bundle preflight summary is missing or unreadable.',
      'Attach the complete RC artifact bundle and rerun release-artifact-bundle.mjs --release-candidate <rc>.',
      { path: releaseArtifactBundle.path, parseError: releaseArtifactBundle.parseError }
    );
  } else if (releaseArtifactBundle.parsed.status !== 'ok') {
    addBlocker(
      blockers,
      'release-artifact-bundle:status',
      'Release artifact bundle',
      'Release artifact bundle preflight is not green.',
      'Attach every required raw release artifact for the requested RC and rerun release-artifact-bundle.mjs --release-candidate <rc>.',
      { failedChecks: asArray(releaseArtifactBundle.parsed.failedChecks) }
    );
  }
}

if (!releaseEvidence.exists || !releaseEvidence.parsed) {
  addBlocker(
    blockers,
    'release-evidence:summary-missing',
    'Release evidence',
    'Strict release evidence summary is missing or unreadable.',
    'Run release-evidence-gate.mjs with rollback, attached CI, and staging provider canary evidence.',
    { path: releaseEvidence.path, parseError: releaseEvidence.parseError }
  );
} else {
  const releaseSummary = releaseEvidence.parsed;
  if (releaseSummary.status !== 'ok') {
    addBlocker(
      blockers,
      'release-evidence:status',
      'Release evidence',
      'Release evidence summary is not green.',
      'Resolve failed release evidence checks and rerun release-evidence-gate.mjs.',
      { failedChecks: asArray(releaseSummary.failedChecks) }
    );
  }
  if (!hasText(releaseSummary.releaseCandidate)) {
    addBlocker(
      blockers,
      'release-evidence:release-candidate',
      'Release evidence',
      'Release evidence is not tied to a named release candidate.',
      'Attach a strict attached-CI manifest with releaseCandidate and rerun release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary.',
      { observed: releaseSummary.releaseCandidate ?? null }
    );
  }
  if (releaseSummary.requireAttachedCi !== true) {
    addBlocker(
      blockers,
      'release-evidence:attached-ci',
      'Release evidence',
      'Strict attached CI evidence has not been required for the current release summary.',
      'Attach green CI artifacts and rerun release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary.',
      { observed: releaseSummary.requireAttachedCi }
    );
  }
  if (releaseSummary.requireStagingProviderCanary !== true) {
    addBlocker(
      blockers,
      'release-evidence:staging-provider-canary',
      'Release evidence',
      'Credentialed staging provider canary evidence has not been required for the current release summary.',
      'Run a real APNs/FCM/Huawei provider canary from the selected staging lane and rerun strict release evidence.',
      { observed: releaseSummary.requireStagingProviderCanary }
    );
  }
}

if (hasText(expectedReleaseCandidate) && expectedReleaseCandidate.trim() !== observedReleaseCandidate) {
  addBlocker(
    blockers,
    'release-evidence:release-candidate-mismatch',
    'Release evidence',
    'Production readiness status is not tied to the expected release candidate.',
    'Attach strict release evidence for the requested release candidate and rerun production-readiness-status.mjs.',
    {
      expected: expectedReleaseCandidate.trim(),
      observed: observedReleaseCandidate
    }
  );
}

for (const packageState of packageStates) {
  if (!packageState.manifest.exists || !packageState.manifest.parsed) {
    addBlocker(
      blockers,
      `${packageState.key}:manifest`,
      packageState.label,
      `${packageState.label} manifest is missing or unreadable.`,
      packageState.action,
      { path: packageState.manifest.path, parseError: packageState.manifest.parseError }
    );
  }

  if (!packageState.summary.exists || !packageState.summary.parsed) {
    addBlocker(
      blockers,
      `${packageState.key}:summary`,
      packageState.label,
      `${packageState.label} verifier summary is missing or unreadable.`,
      packageState.action,
      { path: packageState.summary.path, parseError: packageState.summary.parseError }
    );
    continue;
  }

  if (packageState.summary.parsed.status !== 'ok') {
    addBlocker(
      blockers,
      `${packageState.key}:summary-status`,
      packageState.label,
      `${packageState.label} verifier summary is not green.`,
      packageState.action,
      { failedChecks: asArray(packageState.summary.parsed.failedChecks) }
    );
  }
}

if (!productionReadiness.exists || !productionReadiness.parsed) {
  addBlocker(
    blockers,
    'production-readiness:summary',
    'Production readiness',
    'Production readiness summary is missing or unreadable.',
    'Run production-readiness-gate.mjs after strict release and all P6 evidence gates.',
    { path: productionReadiness.path, parseError: productionReadiness.parseError }
  );
} else if (productionReadiness.parsed.status !== 'ok') {
  addBlocker(
    blockers,
    'production-readiness:status',
    'Production readiness',
    'Final production readiness gate is not green.',
    'Resolve the production-readiness failed checks and rerun production-readiness-gate.mjs.',
    { failedChecks: asArray(productionReadiness.parsed.failedChecks) }
  );
}

const status = blockers.length === 0 ? 'ok' : 'blocked';
const checklist = buildChecklist(blockers, observedReleaseCandidate);
const report = {
  status,
  generatedAt: new Date().toISOString(),
  artifactRoot,
  expectedReleaseCandidate: hasText(expectedReleaseCandidate) ? expectedReleaseCandidate.trim() : null,
  releaseCandidate: observedReleaseCandidate,
  runGates,
  strictRelease,
  commandResults,
  summaries: {
    releaseArtifactBundle: {
      path: releaseArtifactBundle.path,
      exists: releaseArtifactBundle.exists,
      status: releaseArtifactBundle.parsed?.status ?? null,
      failedChecks: asArray(releaseArtifactBundle.parsed?.failedChecks)
    },
    releaseEvidence: {
      path: releaseEvidence.path,
      exists: releaseEvidence.exists,
      status: releaseEvidence.parsed?.status ?? null,
      failedChecks: asArray(releaseEvidence.parsed?.failedChecks)
    },
    productionReadiness: {
      path: productionReadiness.path,
      exists: productionReadiness.exists,
      status: productionReadiness.parsed?.status ?? null,
      failedChecks: asArray(productionReadiness.parsed?.failedChecks)
    },
    packages: packageStates.map(packageState => ({
      key: packageState.key,
      manifestPath: packageState.manifest.path,
      manifestExists: packageState.manifest.exists,
      summaryPath: packageState.summary.path,
      summaryExists: packageState.summary.exists,
      summaryStatus: packageState.summary.parsed?.status ?? null,
      summaryFailedChecks: asArray(packageState.summary.parsed?.failedChecks)
    }))
  },
  blockers,
  checklist: {
    path: checklistPath,
    status: checklist.status,
    blockedItems: checklist.blockedItems,
    readyItems: checklist.readyItems
  },
  nextCommands: [
    'node .\\deep-devops\\scripts\\collect-attached-ci-source.mjs --owner <org> --branch master --release-candidate <rc>',
    'node .\\deep-devops\\scripts\\hydrate-release-artifact-bundle.mjs --input-dir <downloaded-artifacts> --allow-missing',
    'node .\\deep-devops\\scripts\\attached-ci-manifest.mjs --release-candidate <rc>',
    'node .\\deep-devops\\scripts\\session-infra-guard.mjs',
    'node .\\deep-devops\\scripts\\release-artifact-bundle.mjs --release-candidate <rc>',
    'node .\\deep-devops\\scripts\\release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary',
    'node .\\deep-devops\\scripts\\client-device-acceptance-gate.mjs',
    'node .\\deep-devops\\scripts\\ops-deployment-evidence-gate.mjs',
    'node .\\deep-devops\\scripts\\security-audit-signoff-gate.mjs',
    'node .\\deep-devops\\scripts\\ga-decision-gate.mjs',
    'node .\\deep-devops\\scripts\\production-readiness-gate.mjs',
    'node .\\deep-devops\\scripts\\production-readiness-status.mjs'
  ]
};

await mkdir(releaseDir, { recursive: true });
await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
await writeFile(checklistPath, `${JSON.stringify(checklist, null, 2)}\n`, 'utf8');

if (status !== 'ok') {
  console.error(`Production readiness status: blocked (${blockers.length} blockers). Report: ${outputPath}. Checklist: ${checklistPath}`);
  for (const blocker of blockers) {
    console.error(`- ${blocker.id}: ${blocker.description}`);
  }
  if (!allowBlockedExitZero) {
    process.exit(1);
  }
} else {
  console.log(`Production readiness status: ok. Report: ${outputPath}. Checklist: ${checklistPath}`);
}
