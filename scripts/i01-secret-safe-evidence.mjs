import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { scan as scanSecrets } from './secret-scan.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const PROGRAM_REVISION_SHA = 'ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383';

function argumentValue(argv, name, fallback) {
  const index = argv.indexOf(name);
  if (index < 0) return fallback;
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  return value;
}

function relativeOutput(filePath) {
  const relative = path.relative(repositoryRoot, filePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('I01 evidence output must remain inside the repository');
  }
  return relative.split(path.sep).join('/');
}

function runMachineCheck(args, label) {
  const result = spawnSync(process.execPath, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 120_000
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${label} failed closed`);
  }
  return `${result.stdout}\n${result.stderr}`;
}

function tapCounters(output) {
  const value = name => Number.parseInt(output.match(new RegExp(`^# ${name} (\\d+)$`, 'm'))?.[1] ?? '', 10);
  const counters = {
    tests: value('tests'),
    passed: value('pass'),
    failed: value('fail')
  };
  if (Object.values(counters).some(item => !Number.isSafeInteger(item))) {
    throw new Error('unable to derive adversarial test counters');
  }
  return counters;
}

export async function main(argv = process.argv.slice(2)) {
  const outputDir = path.resolve(argumentValue(
    argv,
    '--output-dir',
    path.join(repositoryRoot, 'artifacts', 'release')
  ));
  const evidencePath = path.join(outputDir, 'i01-sec-evidence.json');
  const handoffPath = path.join(outputDir, 'i01-sec-handoff.json');
  const generatedAt = process.env.DEEP_EVIDENCE_NOW ?? new Date().toISOString();
  const initialScan = await scanSecrets({
    root: repositoryRoot,
    artifactRoots: [path.join(repositoryRoot, 'artifacts')]
  });
  if (initialScan.status !== 'ok') {
    throw new Error(`secret scan has ${initialScan.findingCount} finding(s)`);
  }
  const adversarialCounters = tapCounters(runMachineCheck(
    ['--test', '--test-reporter=tap', 'scripts/secret-scan.test.mjs'],
    'secret scanner adversarial tests'
  ));
  const uploadGateCounters = tapCounters(runMachineCheck(
    ['--test', '--test-reporter=tap', 'scripts/artifact-upload-gate.test.mjs'],
    'artifact upload fail-closed tests'
  ));
  const rotationGateCounters = tapCounters(runMachineCheck(
    ['--test', '--test-reporter=tap', 'scripts/uat-rotation-preflight.test.mjs'],
    'offline rotation attestation tests'
  ));
  const workflowOutput = runMachineCheck(
    ['scripts/workflow-upload-contracts.mjs'],
    'workflow upload contracts'
  );
  const stagedUploadCount = Number.parseInt(
    workflowOutput.match(/passed \((\d+) exact staged uploads\)/)?.[1] ?? '',
    10
  );
  if (!Number.isSafeInteger(stagedUploadCount)) {
    throw new Error('unable to derive staged upload workflow count');
  }

  const evidence = {
    schemaVersion: '1.0.0',
    workPackage: 'I01A.2-SEC-CORRECTIVE',
    status: 'blocked-pending-rotation-and-independent-chain-verification',
    codeStatus: 'ready-for-review',
    productionReady: false,
    uatRestartAuthorized: false,
    programRevisionSha256: PROGRAM_REVISION_SHA,
    generatedAt,
    verification: {
      secretScan: {
        status: initialScan.status,
        scannedFiles: initialScan.scannedFiles,
        scannedTextEntries: initialScan.scannedTextEntries,
        archiveEntriesInspected: initialScan.archiveEntriesInspected,
        findingCount: initialScan.findingCount
      },
      adversarialTests: adversarialCounters,
      uploadFailClosedTests: uploadGateCounters,
      offlineRotationAttestationTests: rotationGateCounters,
      exactStagedArtifactUploads: stagedUploadCount
    },
    controls: [
      'tracked-secret-literals-removed',
      'uat-secret-env-files',
      'ephemeral-local-node-identities',
      'redacted-allowlisted-evidence',
      'schema-allowlisted-runtime-evidence',
      'fail-closed-inspect-only-exact-manifest-pre-and-post-scan-verification',
      'normalized-sensitive-artifact-filename-denylist',
      'exact-placeholder-allowlist',
      'mr-x-signed-offline-exact-node-rotation-attestation'
    ],
    blockers: [
      'Mr. X must rotate the retired UAT deployer and all three Ed25519/BLS identities.',
      'Mr. X must complete on-chain exit/revocation or redeploy affected UAT contracts before restart.',
      'Independent chain verification is not implemented; the offline attestation never authorizes UAT restart.'
    ],
    evidenceFiles: [
      relativeOutput(evidencePath),
      relativeOutput(handoffPath),
      'artifacts/security/secret-scan-summary.json'
    ]
  };
  const handoff = {
    schemaVersion: '1.0.0',
    workPackage: 'I01A.2-SEC-CORRECTIVE',
    status: 'blocked',
    codeStatus: 'ready-for-review',
    productionReady: false,
    uatRestartAuthorized: false,
    accountableHuman: 'Mr. X',
    evidencePath: relativeOutput(evidencePath),
    blockers: evidence.blockers,
    rollback: {
      strategy: 'keep-uat-stopped-and-remove-only-new-local-secret-files',
      restoresCompromisedCredentials: false,
      gitHistoryRewriteRequired: false
    }
  };

  await mkdir(outputDir, { recursive: true });
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
  await writeFile(handoffPath, `${JSON.stringify(handoff, null, 2)}\n`, 'utf8');

  const finalScan = await scanSecrets({
    root: repositoryRoot,
    includeTracked: false,
    artifactRoots: [outputDir]
  });
  if (finalScan.status !== 'ok') {
    throw new Error(`generated I01 artifacts failed secret scan with ${finalScan.findingCount} finding(s)`);
  }
  console.log('I01A.2 corrective security evidence generated; UAT remains blocked pending independent chain verification.');
  return { evidence, handoff };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01-SEC evidence generation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
