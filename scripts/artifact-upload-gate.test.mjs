import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { prepareUpload } from './artifact-upload-manifest.mjs';
import { gate } from './artifact-upload-gate.mjs';
import {
  extractSealedEvidenceBundle,
  verifySealedEvidenceBundle
} from './sealed-evidence-bundle.mjs';

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-gate-'));
  const source = path.join(root, 'source');
  const stagingRoot = path.join(root, 'staging');
  const manifest = path.join(root, 'manifest.json');
  const summary = path.join(root, 'summary.json');
  const bundle = path.join(root, 'sealed-evidence.json');
  const evidenceName = 'release-secret-preflight-summary.json';
  await mkdir(source);
  await writeFile(path.join(source, evidenceName), `${JSON.stringify({
    status: 'ok',
    generatedAt: new Date().toISOString(),
    checks: [{ name: 'fixture', passed: true }],
    failedChecks: []
  })}\n`);
  const requiredFiles = [evidenceName];
  await prepareUpload({ roots: [source], requiredFiles, staging: stagingRoot, manifest });
  return { root, stagingRoot, manifest, summary, bundle, requiredFiles, evidenceName };
}

test('passes only with a fresh result bound to the exact selected manifest', async () => {
  const item = await fixture();
  try {
    const result = await gate(item);
    assert.equal(result.status, 'ok');
    assert.equal(result.manifestedFiles, 1);
    assert.match(result.bundleSha256, /^[0-9a-f]{64}$/);
    const receipt = await verifySealedEvidenceBundle({
      bundle: item.bundle,
      expectedSha256: result.bundleSha256
    });
    assert.equal(receipt.payloadFilesVerified, 1);
    assert.equal(receipt.trustedArtifactPublication, false);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('sealed bundle mutation before upload or after download fails verification', async () => {
  for (const mutation of ['before-upload', 'after-download']) {
    const item = await fixture();
    try {
      const result = await gate(item);
      const original = await readFile(item.bundle);
      const mutated = Buffer.from(original);
      mutated[Math.floor(mutated.length / 2)] ^= 1;
      await writeFile(item.bundle, mutated);
      await assert.rejects(
        verifySealedEvidenceBundle({
          bundle: item.bundle,
          expectedSha256: result.bundleSha256,
          actionsArtifactId: '123',
          actionsArtifactDigest: `sha256:${'a'.repeat(64)}`
        }),
        /SHA256 mismatch/
      );
      assert.ok(mutation);
    } finally {
      await rm(item.root, { recursive: true, force: true });
    }
  }
});

test('sealing from a non-repository cwd and verified source-run extraction succeed', async () => {
  const previousCwd = process.cwd();
  const previousRunId = process.env.GITHUB_RUN_ID;
  process.env.GITHUB_RUN_ID = '12345';
  const item = await fixture();
  try {
    process.chdir(item.root);
    const result = await gate(item);
    process.chdir(previousCwd);
    process.env.GITHUB_RUN_ID = '67890';
    const extracted = path.join(item.root, 'extracted');
    const receipt = await extractSealedEvidenceBundle({
      bundle: item.bundle,
      expectedSha256: result.bundleSha256,
      expectedSourceRunId: '12345',
      extractDir: extracted
    });
    assert.equal(receipt.payloadFilesVerified, 1);
    assert.equal(
      JSON.parse(await readFile(path.join(extracted, item.evidenceName), 'utf8')).status,
      'ok'
    );
  } finally {
    process.chdir(previousCwd);
    if (previousRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = previousRunId;
    await rm(item.root, { recursive: true, force: true });
  }
});

test('scanner nonzero/crash prevents upload', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'crash.mjs');
    await writeFile(scannerPath, 'process.exitCode = 7;\n');
    await assert.rejects(gate({ ...item, scannerPath }), /crashed or returned nonzero/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('scanner success without a fresh result prevents upload', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'missing-result.mjs');
    await writeFile(scannerPath, 'process.exitCode = 0;\n');
    await assert.rejects(gate({ ...item, scannerPath }), /result is missing or unreadable/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('scanner timeout prevents upload', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'timeout.mjs');
    await writeFile(scannerPath, 'setInterval(() => {}, 1000);\n');
    await assert.rejects(gate({ ...item, scannerPath, timeoutMs: 100 }), /timed out/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('empty upload roots and missing required lane evidence fail closed', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-empty-'));
  try {
    const source = path.join(root, 'source');
    await mkdir(source);
    await assert.rejects(
      prepareUpload({
        roots: [source],
        staging: path.join(root, 'staging'),
        manifest: path.join(root, 'manifest.json')
      }),
      /upload selection is empty/
    );
    await writeFile(path.join(source, 'present.json'), '{"status":"ok"}\n');
    await assert.rejects(
      prepareUpload({
        roots: [source],
        requiredFiles: ['required-lane-evidence.json'],
        staging: path.join(root, 'staging'),
        manifest: path.join(root, 'manifest.json')
      }),
      /required artifact is missing/
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('empty or unknown required JSON and unsigned APK/AAB/MSIX packages fail closed', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-unknown-'));
  try {
    const source = path.join(root, 'source');
    await mkdir(source);
    await writeFile(path.join(source, 'unknown.json'), '{}\n');
    await assert.rejects(
      prepareUpload({
        roots: [source],
        requiredFiles: ['unknown.json'],
        staging: path.join(root, 'staging'),
        manifest: path.join(root, 'manifest.json')
      }),
      /no explicit semantic evidence contract|empty JSON/
    );
    for (const extension of ['apk', 'aab', 'msix']) {
      await rm(source, { recursive: true, force: true });
      await mkdir(source);
      await writeFile(path.join(source, `app.${extension}`), Buffer.from('PK-safe-package-shape'));
      await assert.rejects(
        prepareUpload({
          roots: [source],
          staging: path.join(root, 'staging'),
          manifest: path.join(root, 'manifest.json')
        }),
        /archive and application-package uploads are blocked/
      );
    }
    await rm(source, { recursive: true, force: true });
    await mkdir(source);
    await writeFile(path.join(source, 'disguised.txt'), Buffer.from([
      0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0
    ]));
    await assert.rejects(
      prepareUpload({
        roots: [source],
        staging: path.join(root, 'staging'),
        manifest: path.join(root, 'manifest.json')
      }),
      /archive and application-package uploads are blocked/
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('gate invocation independently binds the required lane evidence contract', async () => {
  const item = await fixture();
  try {
    const document = JSON.parse(await readFile(item.manifest, 'utf8'));
    document.requiredFiles = [];
    document.requiredEvidenceValidation.requiredFileCount = 0;
    document.requiredEvidenceValidation.jsonFilesValidated = 0;
    document.requiredEvidenceValidation.freshnessChecked = 0;
    document.requiredEvidenceValidation.schemaContractsValidated = 0;
    document.requiredEvidenceValidation.semanticContracts = [];
    document.requiredEvidenceValidation.evidenceBindings = [];
    await writeFile(item.manifest, `${JSON.stringify(document, null, 2)}\n`);
    await assert.rejects(
      gate(item),
      /required-file contract differs/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('required evidence semantics reject failed, stale, skipped, and incomplete rollback evidence', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-semantics-'));
  try {
    const source = path.join(root, 'source');
    await mkdir(path.join(source, 'test-results'), { recursive: true });
    const rollback = path.join(source, 'test-results', 'rollback-drill.json');
    const invalidDocuments = [
      { status: 'failed', postRollbackSmoke: { status: 'ok' } },
      { status: 'ok', generatedAt: '2000-01-01T00:00:00.000Z', postRollbackSmoke: { status: 'ok' } },
      { status: 'ok', skipped: 1, postRollbackSmoke: { status: 'ok' } },
      { status: 'ok', postRollbackSmoke: { status: 'failed' } },
      { status: 'ok', generatedAt: new Date().toISOString(), postRollbackSmoke: { status: 'ok' } }
    ];
    for (const document of invalidDocuments) {
      await writeFile(rollback, `${JSON.stringify(document)}\n`);
      await assert.rejects(
        prepareUpload({
          roots: [source],
          requiredFiles: ['test-results/rollback-drill.json'],
          staging: path.join(root, 'staging'),
          manifest: path.join(root, 'manifest.json')
        }),
        /semantic validation failed/
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('multi-node evidence cannot omit registry or distinct-hop counters', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-topology-'));
  try {
    const source = path.join(root, 'source', 'test-results');
    await mkdir(source, { recursive: true });
    const topology = {
      status: 'ok',
      generatedAt: new Date().toISOString(),
      routers: Array.from({ length: 3 }, (_, index) => ({
        routerId: `router-${index}`,
        transportMocked: false
      })),
      reconciliationIssues: []
    };
    for (const mutation of [
      value => { value.registryRuntime = { totalNodes: 3 }; },
      value => { value.selectedPath = { distinctHops: 3 }; }
    ]) {
      const document = structuredClone(topology);
      mutation(document);
      await writeFile(path.join(source, 'multi-node-topology.json'), `${JSON.stringify(document)}\n`);
      await assert.rejects(
        prepareUpload({
          roots: [path.join(root, 'source')],
          requiredFiles: ['test-results/multi-node-topology.json'],
          staging: path.join(root, 'staging'),
          manifest: path.join(root, 'manifest.json')
        }),
        /three real routers/
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('SBOM evidence rejects legacy, host-bound, duplicate, and unsorted inventories', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-sbom-'));
  try {
    const source = path.join(root, 'source');
    await mkdir(source);
    const sbomPath = path.join(source, 'sbom.json');
    const component = (name, version = '1.0.0') => ({
      type: 'library',
      'bom-ref': `pkg:npm/${name}@${version}`,
      name,
      version,
      purl: `pkg:npm/${name}@${version}`
    });
    const valid = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      metadata: {
        timestamp: '2026-06-02T00:00:00.000Z',
        component: {
          type: 'application',
          'bom-ref': 'pkg:generic/network.xpoint.deep@rc.1',
          name: 'network.xpoint.deep',
          version: 'rc.1',
          purl: 'pkg:generic/network.xpoint.deep@rc.1'
        }
      },
      components: [component('alpha'), component('zulu')]
    };

    const invalidDocuments = [
      {
        bomFormat: 'Deep-SBOM',
        specVersion: '0.1',
        componentCount: 1,
        components: [component('alpha')]
      },
      { ...structuredClone(valid), workspaceRoot: 'C:\\Users\\builder\\workspace' },
      { ...structuredClone(valid), components: [component('alpha'), component('alpha')] },
      { ...structuredClone(valid), components: [component('zulu'), component('alpha')] }
    ];

    for (const document of invalidDocuments) {
      await writeFile(sbomPath, `${JSON.stringify(document)}\n`);
      await assert.rejects(
        prepareUpload({
          roots: [source],
          requiredFiles: ['sbom.json'],
          staging: path.join(root, 'staging'),
          manifest: path.join(root, 'manifest.json')
        }),
        /sanitized deterministic CycloneDX 1\.6/
      );
    }

    await writeFile(sbomPath, `${JSON.stringify(valid)}\n`);
    const manifest = await prepareUpload({
      roots: [source],
      requiredFiles: ['sbom.json'],
      staging: path.join(root, 'staging'),
      manifest: path.join(root, 'manifest.json')
    });
    assert.equal(manifest.requiredEvidenceValidation.schemaContractsValidated, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('P6 explicit file set requires all nine semantically valid fresh manifests', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-p6-'));
  try {
    const generatedAt = new Date().toISOString();
    const passedSummary = {
      status: 'ok',
      generatedAt,
      checks: [{ name: 'fixture', passed: true }],
      failedChecks: []
    };
    const documents = new Map([
      ['release-artifact-hydration-summary.json', {
        ...passedSummary,
        hydratedArtifacts: [{ id: 'p6', hydrated: true }]
      }],
      ['client-device-acceptance.json', {
        status: 'passed',
        generatedAt,
        platforms: ['android', 'ios', 'windows'].map(platform => ({ platform, status: 'passed' })),
        scenarios: [{ name: 'e2e', status: 'passed' }],
        releaseGuards: { noStubTransport: true, noSessionEndpoints: true }
      }],
      ['client-device-acceptance-summary.json', passedSummary],
      ['ops-deployment-evidence.json', {
        status: 'passed',
        generatedAt,
        dashboards: { deployed: true },
        alerts: { routesTested: true },
        postDeployVerification: { status: 'passed', runtimeHealth: { status: 'ok' } },
        recovery: { rollbackDrill: { url: 'https://example.invalid/rollback' } }
      }],
      ['ops-deployment-evidence-summary.json', passedSummary],
      ['security-audit-signoff.json', {
        status: 'approved',
        generatedAt,
        externalAudit: { status: 'closed' },
        openFindings: { critical: 0, high: 0 },
        securityGate: { status: 'passed' },
        sbom: { attested: true }
      }],
      ['security-audit-signoff-summary.json', passedSummary],
      ['ga-decision.json', {
        decision: 'go',
        generatedAt,
        approvals: ['engineering', 'security', 'ops'].map(role => ({ role, status: 'approved' })),
        releaseBlockers: [{ id: 'closed', status: 'closed' }]
      }],
      ['ga-decision-summary.json', passedSummary]
    ]);
    for (const [name, document] of documents) {
      await writeFile(path.join(root, name), `${JSON.stringify(document)}\n`);
    }
    const options = {
      files: [...documents.keys()].map(name => path.join(root, name)),
      requiredFiles: [...documents.keys()],
      staging: path.join(root, 'staging'),
      manifest: path.join(root, 'manifest.json')
    };
    const manifest = await prepareUpload(options);
    assert.equal(manifest.fileCount, 9);
    assert.deepEqual(manifest.requiredFiles, [...documents.keys()].sort());
    await writeFile(path.join(root, 'ga-decision.json'), '{}\n');
    await assert.rejects(prepareUpload(options), /empty JSON|GA decision/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('gate independently revalidates semantics even when a tampered manifest rehashes failed evidence', async () => {
  const item = await fixture();
  try {
    const failed = Buffer.from('{"status":"failed"}\n');
    await writeFile(path.join(item.stagingRoot, item.evidenceName), failed);
    const document = JSON.parse(await readFile(item.manifest, 'utf8'));
    document.files[0].size = failed.length;
    document.files[0].sha256 = createHash('sha256').update(failed).digest('hex');
    document.requiredEvidenceValidation.evidenceBindings[0].sha256 = document.files[0].sha256;
    document.totalBytes = failed.length;
    await writeFile(item.manifest, `${JSON.stringify(document, null, 2)}\n`);
    await assert.rejects(gate(item), /semantic validation failed/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('manifest mutation while scanner runs fails closed', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'mutate-manifest.mjs');
    await writeFile(scannerPath, [
      "import { appendFile, readFile, writeFile } from 'node:fs/promises';",
      "import { createHash } from 'node:crypto';",
      "const value = name => process.argv[process.argv.indexOf(name) + 1];",
      "const manifest = value('--manifest');",
      "const summary = value('--summary');",
      "const raw = await readFile(manifest);",
      "await appendFile(manifest, ' ');",
      "await writeFile(summary, JSON.stringify({",
      "schemaVersion:'2.0.0',status:'ok',findingCount:0,scannedFiles:1,",
      "selectedManifestSha256:createHash('sha256').update(raw).digest('hex')",
      "}));"
    ].join('\n'));
    await assert.rejects(
      gate({ ...item, scannerPath }),
      /manifest changed while the scanner was running/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('staged file mutation while scanner runs fails closed', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'mutate-staging.mjs');
    const stagedFile = path.join(item.stagingRoot, item.evidenceName);
    await writeFile(scannerPath, [
      "import { readFile, writeFile } from 'node:fs/promises';",
      "import { createHash } from 'node:crypto';",
      "const value = name => process.argv[process.argv.indexOf(name) + 1];",
      "const manifest = value('--manifest');",
      "const summary = value('--summary');",
      `await writeFile(${JSON.stringify(stagedFile)}, '{"status":"mutated"}\\n');`,
      "const raw = await readFile(manifest);",
      "await writeFile(summary, JSON.stringify({",
      "schemaVersion:'2.0.0',status:'ok',findingCount:0,scannedFiles:1,",
      "selectedManifestSha256:createHash('sha256').update(raw).digest('hex')",
      "}));"
    ].join('\n'));
    await assert.rejects(
      gate({ ...item, scannerPath }),
      /changed after manifest preparation/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});
