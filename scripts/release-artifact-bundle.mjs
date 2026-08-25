import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan as scanSecrets } from './secret-scan.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const releaseDir = path.join(artifactRoot, 'release');
const outputPath = argValue('--output')
  ? path.resolve(argValue('--output'))
  : path.join(releaseDir, 'release-artifact-bundle-summary.json');
const expectedReleaseCandidate = argValue('--release-candidate')
  ?? process.env.DEEP_RELEASE_CANDIDATE
  ?? null;
const routerC3Path = process.env.XNODE_C3_ARTIFACT
  ? path.resolve(process.env.XNODE_C3_ARTIFACT)
  : path.join(artifactRoot, 'router-c3-latest.json');

const requiredArtifacts = [
  {
    id: 'runtime-gate',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'runtime.gate.json')
  },
  {
    id: 'backend-load-smoke',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'test-results', 'backend-load-smoke.json')
  },
  {
    id: 'backend-restart-smoke',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'test-results', 'backend-restart-smoke.json')
  },
  {
    id: 'physical-call',
    area: 'Client device acceptance',
    path: path.join(artifactRoot, 'test-results', 'mau2-call-result.json')
  },
  {
    id: 'push-provider-canary',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'test-results', 'push-provider-canary.json')
  },
  {
    id: 'multi-node-topology',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'test-results', 'multi-node-topology.json')
  },
  {
    id: 'registry-recovery',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'test-results', 'registry-recovery.json')
  },
  {
    id: 'rollback-drill',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'test-results', 'rollback-drill.json')
  },
  {
    id: 'security-gate-summary',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'security', 'security-gate-summary.json')
  },
  {
    id: 'observability-gate-summary',
    area: 'Release evidence',
    path: path.join(artifactRoot, 'observability', 'observability-gate-summary.json')
  },
  {
    id: 'session-infra-guard-summary',
    area: 'Release evidence',
    path: path.join(releaseDir, 'session-infra-guard-summary.json')
  },
  {
    id: 'router-c3-latest',
    area: 'Release evidence',
    path: routerC3Path
  },
  {
    id: 'attached-ci-artifacts',
    area: 'Attached CI',
    path: path.join(releaseDir, 'attached-ci-artifacts.json'),
    releaseCandidateField: 'releaseCandidate'
  },
  {
    id: 'attached-ci-manifest-summary',
    area: 'Attached CI',
    path: path.join(releaseDir, 'attached-ci-manifest-summary.json'),
    releaseCandidateField: 'releaseCandidate'
  },
  {
    id: 'client-device-acceptance',
    area: 'Client device acceptance',
    path: path.join(releaseDir, 'client-device-acceptance.json'),
    releaseCandidateField: 'releaseCandidate'
  },
  {
    id: 'ops-deployment-evidence',
    area: 'Ops deployment evidence',
    path: path.join(releaseDir, 'ops-deployment-evidence.json'),
    releaseCandidateField: 'releaseCandidate'
  },
  {
    id: 'security-audit-signoff',
    area: 'Security audit sign-off',
    path: path.join(releaseDir, 'security-audit-signoff.json'),
    releaseCandidateField: 'releaseCandidate'
  },
  {
    id: 'ga-decision',
    area: 'GA decision',
    path: path.join(releaseDir, 'ga-decision.json'),
    releaseCandidateField: 'releaseCandidate'
  }
];

const checks = [];

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

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function get(value, pathExpression) {
  return pathExpression.split('.').reduce((current, key) => current?.[key], value);
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(filePath) {
  try {
    const raw = await readFile(filePath, 'utf8');
    return {
      parsed: JSON.parse(raw.replace(/^\uFEFF/, '')),
      parseError: null
    };
  } catch (error) {
    return {
      parsed: null,
      parseError: error.message
    };
  }
}

addCheck('release-candidate:present', hasText(expectedReleaseCandidate), {
  observed: expectedReleaseCandidate ?? null
});

const secretScan = await scanSecrets({
  root: devopsRoot,
  artifactRoots: [artifactRoot]
});
addCheck('secret-scan:no-findings', secretScan.status === 'ok', {
  scannedFiles: secretScan.scannedFiles,
  findingCount: secretScan.findingCount,
  findings: secretScan.findings
});

const artifacts = [];
for (const artifact of requiredArtifacts) {
  const absolutePath = path.resolve(artifact.path);
  const exists = await fileExists(absolutePath);
  addCheck(`${artifact.id}:exists`, exists, { path: absolutePath });

  let parsed = null;
  let parseError = null;
  let releaseCandidate = null;
  if (exists) {
    const result = await readJson(absolutePath);
    parsed = result.parsed;
    parseError = result.parseError;
    addCheck(`${artifact.id}:json-parse`, Boolean(parsed), { path: absolutePath, error: parseError });
  }

  if (parsed && artifact.releaseCandidateField) {
    releaseCandidate = get(parsed, artifact.releaseCandidateField);
    addCheck(`${artifact.id}:release-candidate-present`, hasText(releaseCandidate), {
      observed: releaseCandidate ?? null
    });
    if (hasText(expectedReleaseCandidate)) {
      addCheck(`${artifact.id}:release-candidate-match`, releaseCandidate === expectedReleaseCandidate.trim(), {
        expected: expectedReleaseCandidate.trim(),
        observed: releaseCandidate ?? null
      });
    }
  }

  artifacts.push({
    id: artifact.id,
    area: artifact.area,
    path: absolutePath,
    exists,
    parseError,
    releaseCandidate
  });
}

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  artifactRoot,
  workspaceRoot,
  expectedReleaseCandidate: hasText(expectedReleaseCandidate) ? expectedReleaseCandidate.trim() : null,
  routerC3Path,
  artifacts,
  checks,
  failedChecks: failed.map(check => check.name)
};

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Release artifact bundle preflight failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Release artifact bundle preflight passed (${checks.length} checks). Summary: ${outputPath}`);
