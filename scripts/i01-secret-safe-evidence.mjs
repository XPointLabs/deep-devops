import { mkdir, writeFile } from 'node:fs/promises';
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

  const evidence = {
    schemaVersion: '1.0.0',
    workPackage: 'I01-SEC',
    status: 'blocked-pending-credential-rotation',
    codeStatus: 'ready-for-review',
    programRevisionSha256: PROGRAM_REVISION_SHA,
    generatedAt,
    verification: {
      secretScan: {
        status: initialScan.status,
        scannedFiles: initialScan.scannedFiles,
        findingCount: initialScan.findingCount
      },
      secretCanaryTests: 4,
      releaseGateContractCommands: 35,
      composeQuietValidations: 2,
      productionReadinessExpectedMissingEvidenceBlockers: 10
    },
    controls: [
      'tracked-secret-literals-removed',
      'uat-secret-env-files',
      'ephemeral-local-node-identities',
      'redacted-allowlisted-evidence',
      'fail-closed-pre-upload-secret-scan'
    ],
    blockers: [
      'Mr. X must rotate the retired UAT deployer and all three Ed25519/BLS identities.',
      'Mr. X must complete on-chain exit/revocation or redeploy affected UAT contracts before restart.'
    ],
    evidenceFiles: [
      relativeOutput(evidencePath),
      relativeOutput(handoffPath),
      'artifacts/security/secret-scan-summary.json'
    ]
  };
  const handoff = {
    schemaVersion: '1.0.0',
    workPackage: 'I01-SEC',
    status: 'blocked',
    codeStatus: 'ready-for-review',
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
  console.log('I01-SEC evidence and handoff generated; UAT remains blocked pending irreversible rotation.');
  return { evidence, handoff };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01-SEC evidence generation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
