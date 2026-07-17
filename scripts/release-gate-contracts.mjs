import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_CONTRACT_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_CONTRACT_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts', 'release-gate-contracts');
const releaseDir = path.join(artifactRoot, 'release');
const testResultsDir = path.join(artifactRoot, 'test-results');
const securityDir = path.join(artifactRoot, 'security');
const observabilityDir = path.join(artifactRoot, 'observability');
const routerC3Path = path.join(artifactRoot, 'router-c3-latest.json');
const negativeLocalPathDir = path.join(artifactRoot, 'negative-local-paths');
const negativeLocalPathReleaseDir = path.join(negativeLocalPathDir, 'release');
const negativeClientDeviceAcceptancePath = path.join(negativeLocalPathReleaseDir, 'client-device-acceptance.json');
const negativeStaleEvidenceDir = path.join(artifactRoot, 'negative-stale-evidence');
const negativeStaleEvidenceReleaseDir = path.join(negativeStaleEvidenceDir, 'release');
const negativeStaleClientDeviceAcceptancePath = path.join(negativeStaleEvidenceReleaseDir, 'client-device-acceptance.json');
const summaryPath = path.join(releaseDir, 'release-gate-contract-summary.json');

const scriptNames = [
  'pinned-integration-manifest.mjs',
  'secret-scan.mjs',
  'release-ci-lanes.mjs',
  'release-evidence-guards.mjs',
  'release-secret-preflight.mjs',
  'collect-attached-ci-source.mjs',
  'bundle-supporting-release-evidence.mjs',
  'hydrate-release-artifact-bundle.mjs',
  'attached-ci-manifest.mjs',
  'registry-recovery-drill.mjs',
  'session-infra-guard.mjs',
  'release-artifact-bundle.mjs',
  'release-evidence-gate.mjs',
  'client-device-acceptance-gate.mjs',
  'ops-deployment-evidence-gate.mjs',
  'security-audit-signoff-gate.mjs',
  'ga-decision-gate.mjs',
  'production-readiness-gate.mjs',
  'production-readiness-status.mjs'
];

const templateMappings = [
  ['attached-ci-artifacts.example.json', 'attached-ci-artifacts.json'],
  ['client-device-acceptance.example.json', 'client-device-acceptance.json'],
  ['ops-deployment-evidence.example.json', 'ops-deployment-evidence.json'],
  ['security-audit-signoff.example.json', 'security-audit-signoff.json'],
  ['ga-decision.example.json', 'ga-decision.json']
];

const commandResults = [];

function runNode(args, label, extraEnv = {}) {
  const result = spawnSync(process.execPath, args, {
    cwd: devopsRoot,
    env: { ...process.env, ...extraEnv },
    encoding: 'utf8'
  });

  const commandResult = {
    label,
    command: [process.execPath, ...args].join(' '),
    status: result.status,
    passed: result.status === 0,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim()
  };
  commandResults.push(commandResult);

  if (result.stdout.trim().length > 0) {
    console.log(result.stdout.trim());
  }
  if (result.stderr.trim().length > 0) {
    console.error(result.stderr.trim());
  }

  return commandResult;
}

function runExpectedFailure(args, label, expectedText, extraEnv = {}) {
  const result = spawnSync(process.execPath, args, {
    cwd: devopsRoot,
    env: { ...process.env, ...extraEnv },
    encoding: 'utf8'
  });
  const combinedOutput = `${result.stdout.trim()}\n${result.stderr.trim()}`;
  const commandResult = {
    label,
    command: [process.execPath, ...args].join(' '),
    status: result.status,
    passed: result.status !== 0 && combinedOutput.includes(expectedText),
    expectedFailure: true,
    expectedText,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim()
  };
  commandResults.push(commandResult);

  if (!commandResult.passed) {
    if (result.stdout.trim().length > 0) {
      console.log(result.stdout.trim());
    }
    if (result.stderr.trim().length > 0) {
      console.error(result.stderr.trim());
    }
  } else {
    console.log(`Expected failure observed for ${label}: ${expectedText}`);
  }

  return commandResult;
}

await mkdir(releaseDir, { recursive: true });
await mkdir(testResultsDir, { recursive: true });
await mkdir(securityDir, { recursive: true });
await mkdir(observabilityDir, { recursive: true });
await mkdir(negativeLocalPathReleaseDir, { recursive: true });
await mkdir(negativeStaleEvidenceReleaseDir, { recursive: true });

for (const scriptName of scriptNames) {
  const result = runNode(['--check', path.join('scripts', scriptName)], `syntax:${scriptName}`);
  if (!result.passed) {
    break;
  }
}

if (commandResults.every(result => result.passed)) {
  runNode(
    ['scripts/pinned-integration-manifest.mjs', '--validate-only'],
    'pinned-integration-manifest:validate'
  );
}

if (commandResults.every(result => result.passed)) {
  runNode(
    ['--test', 'scripts/pinned-integration-manifest.test.mjs'],
    'pinned-integration-manifest:tests'
  );
}

if (commandResults.every(result => result.passed)) {
  runNode(
    ['--test', 'scripts/secret-scan.test.mjs'],
    'secret-scan:tests'
  );
}

if (commandResults.every(result => result.passed)) {
  runNode([
    'scripts/secret-scan.mjs',
    '--artifacts',
    artifactRoot,
    '--summary',
    path.join(securityDir, 'secret-scan-summary.json')
  ], 'secret-scan:tracked-and-artifacts');
}

if (commandResults.every(result => result.passed)) {
  for (const [templateName, targetName] of templateMappings) {
    const targetPath = path.join(releaseDir, targetName);
    await copyFile(path.join(devopsRoot, 'docs', 'templates', templateName), targetPath);
    await refreshGeneratedAt(targetPath);
  }

  await writeFixtureArtifacts();

  const gateEnv = {
    DEEP_RELEASE_ARTIFACT_ROOT: artifactRoot
  };
  const releaseGateEnv = {
    ...gateEnv,
    DEEP_ALLOW_PLACEHOLDER_EVIDENCE: 'true',
    XNODE_C3_ARTIFACT: routerC3Path
  };
  runNode([
    'scripts/attached-ci-manifest.mjs',
    '--input',
    path.join(releaseDir, 'attached-ci-artifacts.json'),
    '--output',
    path.join(releaseDir, 'attached-ci-artifacts.json'),
    '--release-candidate',
    'deep-messenger-rc.1'
  ], 'template:attached-ci-manifest.mjs', releaseGateEnv);

  if (commandResults.every(result => result.passed)) {
    runNode([
      'scripts/session-infra-guard.mjs'
    ], 'template:session-infra-guard.mjs', gateEnv);
  }

  if (commandResults.every(result => result.passed)) {
    runNode([
      'scripts/release-artifact-bundle.mjs',
      '--release-candidate',
      'deep-messenger-rc.1'
    ], 'template:release-artifact-bundle.mjs', releaseGateEnv);
  }

  const strictRelease = commandResults.every(result => result.passed)
    ? runNode([
      'scripts/release-evidence-gate.mjs',
      '--require-attached-ci',
      '--require-rollback-drill',
      '--require-staging-provider-canary'
    ], 'template:release-evidence-gate.mjs', releaseGateEnv)
    : { passed: false };

  for (const scriptName of [
    'client-device-acceptance-gate.mjs',
    'ops-deployment-evidence-gate.mjs',
    'security-audit-signoff-gate.mjs',
    'ga-decision-gate.mjs'
  ]) {
    if (!strictRelease.passed) {
      break;
    }

    const result = runNode([path.join('scripts', scriptName)], `template:${scriptName}`, {
      ...gateEnv,
      DEEP_ALLOW_PLACEHOLDER_EVIDENCE: 'true'
    });
    if (!result.passed) {
      break;
    }
  }

  if (commandResults.every(result => result.passed)) {
    runNode(['scripts/production-readiness-gate.mjs'], 'template:production-readiness-gate.mjs', {
      ...gateEnv,
      DEEP_ALLOW_PLACEHOLDER_EVIDENCE: 'true'
    });
    runNode([
      'scripts/production-readiness-status.mjs',
      '--run-gates',
      '--strict-release',
      '--release-candidate',
      'deep-messenger-rc.1'
    ], 'template:production-readiness-status.mjs', releaseGateEnv);
  }

  if (commandResults.every(result => result.passed)) {
    await writeNegativeLocalPathFixture();
    runExpectedFailure(
      [path.join('scripts', 'client-device-acceptance-gate.mjs')],
      'negative:client-device-local-paths',
      'manifest:local-paths-exist',
      {
        DEEP_RELEASE_ARTIFACT_ROOT: negativeLocalPathDir,
        DEEP_CLIENT_DEVICE_ACCEPTANCE: negativeClientDeviceAcceptancePath,
        DEEP_EVIDENCE_NOW: '2026-06-02T00:00:00.000Z'
      }
    );
  }

  if (commandResults.every(result => result.passed)) {
    await writeNegativeStaleEvidenceFixture();
    runExpectedFailure(
      [path.join('scripts', 'client-device-acceptance-gate.mjs')],
      'negative:client-device-stale-evidence',
      'manifest:generated-at-fresh',
      {
        DEEP_RELEASE_ARTIFACT_ROOT: negativeStaleEvidenceDir,
        DEEP_CLIENT_DEVICE_ACCEPTANCE: negativeStaleClientDeviceAcceptancePath,
        DEEP_EVIDENCE_NOW: '2026-06-02T00:00:00.000Z'
      }
    );
  }
}

const failed = commandResults.filter(result => !result.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  artifactRoot,
  releaseDir,
  commands: commandResults,
  failedCommands: failed.map(result => result.label),
  note: 'Contract test only: validates gate scripts and template schemas, not real GA evidence.'
};

await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Release gate contract validation failed (${failed.length} commands). Summary: ${summaryPath}`);
  process.exit(1);
}

console.log(`Release gate contract validation passed (${commandResults.length} commands). Summary: ${summaryPath}`);

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function refreshGeneratedAt(filePath) {
  const parsed = JSON.parse((await readFile(filePath, 'utf8')).replace(/^\uFEFF/, ''));
  parsed.generatedAt = new Date().toISOString();
  await writeJson(filePath, parsed);
}

async function writeFixtureArtifacts() {
  await writeJson(path.join(artifactRoot, 'runtime.gate.json'), {
    failedHard: [],
    failedSoft: [],
    requireRouterNoMock: true,
    routerTransportMocked: false,
    routerTransportMode: 'xray',
    requirePushProviderCanary: true,
    pushProviderCanaryDelivered: true,
    pushProviderCanaryStatus: 'delivered'
  });

  await writeJson(path.join(testResultsDir, 'backend-load-smoke.json'), {
    statsDelta: {
      storage: {
        storageStore: 3,
        storageRetrieve: 3
      },
      file: {
        fileUpload: 2,
        fileDownload: 2,
        fileInfo: 2,
        fileExtend: 1,
        avatarUpload: 1,
        avatarDownload: 1,
        avatarInfo: 1
      },
      push: {
        pushSubscribe: 2,
        pushUnsubscribe: 1,
        pushNotificationsQueued: 2
      }
    },
    statsAfter: {
      storage: { stats: { errors: 0 } },
      file: { stats: { errors: 0 } },
      push: { stats: { errors: 0 } }
    }
  });

  await writeJson(path.join(testResultsDir, 'backend-restart-smoke.json'), {
    status: 'ok',
    retrievedAfterRestart: { messages: [{ id: 'message-after-restart' }] },
    retrievedFinal: { messages: [{ id: 'message-final' }] },
    fileInfoBeforeRestart: { size: 1024 },
    fileInfoAfterRestart: { size: 1024 },
    avatarInfoBeforeRestart: { fileId: 'avatar-file-id' },
    avatarInfoAfterRestart: { fileId: 'avatar-file-id' },
    subscriptionsAfterRestart: { deliveries: [{ id: 'delivery-after-restart' }] },
    statsAfterRehearsal: {
      storage: { stats: { errors: 0 } },
      file: { stats: { errors: 0 } },
      push: { stats: { errors: 0 } }
    }
  });

  await writeJson(path.join(testResultsDir, 'push-provider-canary.json'), {
    status: 'ok',
    releaseLane: 'staging',
    tokenSource: 'env',
    provider: {
      status: 'delivered',
      attempts: 1,
      hasConfiguredUrl: true
    },
    providerEvidence: {
      releaseLane: 'staging',
      tokenSource: 'env',
      providerAuthConfigured: true,
      providerHost: 'push-provider.staging.deep.example.com',
      providerUrlSource: 'PUSH_PROVIDER_FIREBASE_URL'
    },
    statsAfterDelivery: {
      inventory: {
        pushProviderFailed: 0
      }
    }
  });

  await writeJson(path.join(testResultsDir, 'multi-node-topology.json'), {
    status: 'ok',
    routers: [
      { routerId: 'xnode-1', transportMocked: false, xrayRunning: true, xrayDegraded: false },
      { routerId: 'xnode-2', transportMocked: false, xrayRunning: true, xrayDegraded: false },
      { routerId: 'xnode-3', transportMocked: false, xrayRunning: true, xrayDegraded: false }
    ],
    registryRuntime: {
      totalNodes: 3
    },
    reconciliationIssues: [],
    selectedPath: {
      distinctHops: 3,
      hops: ['xnode-1', 'xnode-2', 'xnode-3']
    }
  });

  await writeJson(path.join(testResultsDir, 'registry-recovery.json'), {
    status: 'ok',
    exitCode: 0,
    requiredTests: [
      'NodeRegistry_PersistsAndReloadsFromSnapshot',
      'NodeRegistry_RecoversFromCorruptedStateFile',
      'RuntimeEndpoint_ReturnsRegistryStats',
      'NodeRegistry_ReconciliationJob_TracksLastReportAndRuns'
    ],
    passedTests: [
      'NodeRegistry_PersistsAndReloadsFromSnapshot',
      'NodeRegistry_RecoversFromCorruptedStateFile',
      'RuntimeEndpoint_ReturnsRegistryStats',
      'NodeRegistry_ReconciliationJob_TracksLastReportAndRuns'
    ],
    coverage: {
      snapshotPersistenceReload: true,
      corruptedSnapshotQuarantine: true,
      runtimeRecoveryCounters: true,
      reconciliationJobStatus: true
    }
  });

  await writeJson(path.join(testResultsDir, 'rollback-drill.json'), {
    status: 'ok',
    mttrSeconds: 90,
    postRollbackSmoke: {
      status: 'ok'
    }
  });

  await writeJson(path.join(securityDir, 'security-gate-summary.json'), {
    status: 'ok',
    secretFindings: 0,
    dependencyFailures: 0,
    sbomComponents: 42
  });

  await writeJson(path.join(observabilityDir, 'observability-gate-summary.json'), {
    status: 'ok',
    failedChecks: [],
    alertRules: [
      'router-runtime-down',
      'storage-error-budget',
      'file-error-budget',
      'push-provider-failures'
    ]
  });

  await writeJson(routerC3Path, {
    sloBaseline: {
      passed: true
    },
    soak: {
      successRate: 0.995
    },
    chaos: {
      successRate: 0.56
    },
    load: {
      successRate: 0.995,
      latencyP95Ms: 5
    },
    restartStorm: {
      degraded: true,
      mode: 'expected-degraded'
    }
  });
}

async function writeNegativeLocalPathFixture() {
  const missingPath = 'missing-evidence/client-device-run.json';
  await writeJson(negativeClientDeviceAcceptancePath, {
    status: 'passed',
    generatedAt: '2026-06-02T00:00:00.000Z',
    releaseCandidate: 'deep-messenger-rc.1',
    deepSessionStack: {
      path: missingPath
    },
    platforms: [
      { platform: 'android', status: 'passed', evidenceType: 'device-lab', deviceLabRunId: 'android-run-id', path: missingPath },
      { platform: 'ios', status: 'passed', evidenceType: 'device-lab', deviceLabRunId: 'ios-run-id', path: missingPath },
      { platform: 'windows', status: 'passed', evidenceType: 'device-lab', deviceLabRunId: 'windows-run-id', path: missingPath }
    ],
    scenarios: [
      'onboarding-recovery',
      'one-to-one-messaging',
      'offline-retrieval',
      'groups-lifecycle',
      'attachments',
      'avatars-profile-image',
      'push-lifecycle',
      'release-no-stub-no-mock-guards'
    ].map(name => ({
      name,
      status: 'passed',
      evidenceType: 'device-lab',
      platforms: ['android', 'ios', 'windows'],
      path: missingPath
    })),
    releaseGuards: {
      noStubTransport: true,
      noSessionEndpoints: true,
      deepSessionFileUrlRequired: true,
      deepSessionPushUrlRequired: true
    }
  });
}

async function writeNegativeStaleEvidenceFixture() {
  await writeJson(negativeStaleClientDeviceAcceptancePath, {
    status: 'passed',
    generatedAt: '2025-01-01T00:00:00.000Z',
    releaseCandidate: 'deep-messenger-rc.1',
    deepSessionStack: {
      id: 'staging-stack-evidence'
    },
    platforms: [
      { platform: 'android', status: 'passed', evidenceType: 'device-lab', deviceLabRunId: 'android-run-id', id: 'android-device-run' },
      { platform: 'ios', status: 'passed', evidenceType: 'device-lab', deviceLabRunId: 'ios-run-id', id: 'ios-device-run' },
      { platform: 'windows', status: 'passed', evidenceType: 'device-lab', deviceLabRunId: 'windows-run-id', id: 'windows-device-run' }
    ],
    scenarios: [
      'onboarding-recovery',
      'one-to-one-messaging',
      'offline-retrieval',
      'groups-lifecycle',
      'attachments',
      'avatars-profile-image',
      'push-lifecycle',
      'release-no-stub-no-mock-guards'
    ].map(name => ({
      name,
      status: 'passed',
      evidenceType: 'device-lab',
      platforms: ['android', 'ios', 'windows'],
      id: `${name}-evidence`
    })),
    releaseGuards: {
      noStubTransport: true,
      noSessionEndpoints: true,
      deepSessionFileUrlRequired: true,
      deepSessionPushUrlRequired: true
    }
  });
}
