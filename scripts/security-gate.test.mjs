import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(scriptsDir, '..');
const securityGatePath = path.join(scriptsDir, 'security-gate.mjs');

async function createWorkspace(prefix) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  const repo = path.join(root, 'repo-a');
  await mkdir(repo);
  await writeFile(path.join(repo, 'package.json'), `\uFEFF${JSON.stringify({
    name: 'fixture',
    version: '1.0.0',
    dependencies: {
      alpha: '1.0.0',
      '@scope/pkg': '^2.0.0'
    },
    devDependencies: {
      alpha: '1.0.0'
    }
  }, null, 2)}\n`);
  await writeFile(path.join(repo, 'Fixture.csproj'), [
    '<Project Sdk="Microsoft.NET.Sdk">',
    '  <ItemGroup>',
    '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />',
    '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />',
    '  </ItemGroup>',
    '</Project>',
    ''
  ].join('\n'));
  return root;
}

function runGate(root, artifactDir, extraEnv = {}) {
  return spawnSync(process.execPath, [securityGatePath], {
    cwd: devopsRoot,
    env: {
      ...process.env,
      DEEP_DEVOPS_DIR: devopsRoot,
      DEEP_ROOT: root,
      DEEP_SECURITY_ARTIFACT_DIR: artifactDir,
      DEEP_SECURITY_REPOS: 'repo-a',
      DEEP_SECURITY_SKIP_DEP_AUDIT: 'true',
      DEEP_RELEASE_VERSION: 'rc.1',
      SOURCE_DATE_EPOCH: '1784332800',
      ...extraEnv
    },
    encoding: 'utf8'
  });
}

async function createLockedWorkspace(prefix, reverse = false) {
  const root = await createWorkspace(prefix);
  const repo = path.join(root, 'repo-a');
  const packageEntries = [
    ['node_modules/alpha', { version: '1.0.1', resolved: 'https://registry.invalid/alpha.tgz' }],
    ['node_modules/@scope/pkg', { version: '2.4.0' }],
    ['node_modules/alpha/node_modules/transitive', { version: '3.2.1' }]
  ];
  if (reverse) packageEntries.reverse();
  await writeFile(path.join(repo, 'package-lock.json'), `${JSON.stringify({
    name: 'fixture',
    lockfileVersion: 3,
    packages: Object.fromEntries([
      ['', { name: 'fixture', version: '1.0.0' }],
      ...packageEntries
    ])
  }, null, 2)}\n`);
  await writeFile(path.join(repo, 'packages.lock.json'), `${JSON.stringify({
    version: 1,
    dependencies: {
      'net10.0': reverse
        ? {
            'Transitive.NuGet': { type: 'Transitive', resolved: '4.5.6' },
            'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.3, )', resolved: '13.0.3' },
            'Local.Project': { type: 'Project', resolved: null }
          }
        : {
            'Local.Project': { type: 'Project', resolved: null },
            'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.3, )', resolved: '13.0.3' },
            'Transitive.NuGet': { type: 'Transitive', resolved: '4.5.6' }
          }
    }
  }, null, 2)}\n`);

  const pnpmDir = path.join(repo, 'pnpm-app');
  await mkdir(pnpmDir);
  await writeFile(path.join(pnpmDir, 'package.json'), `${JSON.stringify({
    name: 'pnpm-fixture',
    dependencies: { gamma: '^5.0.0' }
  })}\n`);
  const pnpmPackages = reverse
    ? ["  '@scope/delta@6.0.0(peer@1.0.0)':", '    resolution: {}', '', '  gamma@5.1.0:', '    resolution: {}']
    : ['  gamma@5.1.0:', '    resolution: {}', '', "  '@scope/delta@6.0.0(peer@1.0.0)':", '    resolution: {}'];
  await writeFile(path.join(pnpmDir, 'pnpm-lock.yaml'), [
    "lockfileVersion: '9.0'",
    '',
    'packages:',
    '',
    ...pnpmPackages,
    '',
    'snapshots:',
    ''
  ].join('\n'));

  const assetsDir = path.join(repo, 'assets-project');
  await mkdir(path.join(assetsDir, 'obj'), { recursive: true });
  await writeFile(path.join(assetsDir, 'Assets.csproj'), [
    '<Project Sdk="Microsoft.NET.Sdk">',
    '  <ItemGroup><PackageReference Include="Assets.Direct" Version="7.*" /></ItemGroup>',
    '</Project>',
    ''
  ].join('\n'));
  await writeFile(path.join(assetsDir, 'obj', 'project.assets.json'), `${JSON.stringify({
    version: 3,
    libraries: reverse
      ? {
          'Assets.Transitive/8.1.0': { type: 'package', path: 'C:\\private\\nuget\\assets.transitive' },
          'Assets.Direct/7.4.2': { type: 'package', path: '/home/private/.nuget/assets.direct' },
          'Local.Project/1.0.0': { type: 'project', path: 'C:\\private\\source' }
        }
      : {
          'Local.Project/1.0.0': { type: 'project', path: 'C:\\private\\source' },
          'Assets.Direct/7.4.2': { type: 'package', path: '/home/private/.nuget/assets.direct' },
          'Assets.Transitive/8.1.0': { type: 'package', path: 'C:\\private\\nuget\\assets.transitive' }
        },
    packageFolders: { 'C:\\Users\\private\\.nuget\\packages\\': {} }
  }, null, 2)}\n`);
  return root;
}

test('security gate emits reproducible sanitized CycloneDX 1.6 inventory', async () => {
  const roots = [
    await createWorkspace('deep-sbom-builder-a-'),
    await createWorkspace('deep-sbom-builder-b-')
  ];
  try {
    const outputs = [];
    for (const [index, root] of roots.entries()) {
      const artifactDir = path.join(root, `evidence-${index}`);
      const result = runGate(root, artifactDir);
      assert.equal(result.status, 0, result.stderr || result.stdout);
      outputs.push(await readFile(path.join(artifactDir, 'sbom.json'), 'utf8'));
    }

    assert.equal(outputs[0], outputs[1]);
    assert.doesNotMatch(outputs[0], /deep-sbom-builder|workspaceRoot|artifactDir|[A-Za-z]:\\\\/);
    const sbom = JSON.parse(outputs[0]);
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.equal(sbom.specVersion, '1.6');
    assert.equal(sbom.version, 1);
    assert.equal(sbom.metadata.timestamp, new Date(1784332800 * 1000).toISOString());
    assert.equal(sbom.metadata.component.name, 'network.xpoint.deep');
    assert.equal(sbom.components.length, 3);
    assert.equal(new Set(sbom.components.map(component => component.purl)).size, 3);
    assert.ok(sbom.components.some(component => component.purl === 'pkg:npm/%40scope/pkg@%5E2.0.0'));
    assert.ok(sbom.components.some(component => component.purl === 'pkg:nuget/Newtonsoft.Json@13.0.3'));
    assert.deepEqual(
      sbom.components.map(component => component.purl),
      [...sbom.components.map(component => component.purl)].sort((left, right) => {
        if (left === right) return 0;
        return left < right ? -1 : 1;
      })
    );
    for (const component of sbom.components) {
      assert.equal(component.type, 'library');
      assert.equal(component['bom-ref'], component.purl);
      assert.ok(component.name.length > 0);
      assert.ok(component.version.length > 0);
    }
  } finally {
    await Promise.all(roots.map(root => rm(root, { recursive: true, force: true })));
  }
});

test('security gate emits the complete available resolved lock and restore closure deterministically', async () => {
  const roots = [
    await createLockedWorkspace('deep-sbom-lock-a-'),
    await createLockedWorkspace('deep-sbom-lock-b-', true)
  ];
  try {
    const outputs = [];
    for (const [index, root] of roots.entries()) {
      const artifactDir = path.join(root, `evidence-${index}`);
      const result = runGate(root, artifactDir);
      assert.equal(result.status, 0, result.stderr || result.stdout);
      outputs.push(await readFile(path.join(artifactDir, 'sbom.json'), 'utf8'));
    }

    assert.equal(outputs[0], outputs[1]);
    assert.doesNotMatch(outputs[0], /deep-sbom-lock|private|packageFolders|resolved|[A-Za-z]:\\\\/);
    const sbom = JSON.parse(outputs[0]);
    const purls = sbom.components.map(component => component.purl);
    assert.deepEqual(purls, [
      'pkg:npm/%40scope/delta@6.0.0',
      'pkg:npm/%40scope/pkg@2.4.0',
      'pkg:npm/alpha@1.0.1',
      'pkg:npm/gamma@5.1.0',
      'pkg:npm/transitive@3.2.1',
      'pkg:nuget/Assets.Direct@7.4.2',
      'pkg:nuget/Assets.Transitive@8.1.0',
      'pkg:nuget/Newtonsoft.Json@13.0.3',
      'pkg:nuget/Transitive.NuGet@4.5.6'
    ]);
    assert.ok(!purls.some(purl => /%5E|%2A|unspecified/.test(purl)));
    assert.equal(new Set(purls).size, purls.length);
  } finally {
    await Promise.all(roots.map(root => rm(root, { recursive: true, force: true })));
  }
});

test('security gate includes nested npm v1 transitive dependencies', async () => {
  const root = await createWorkspace('deep-sbom-npm-v1-');
  try {
    await writeFile(path.join(root, 'repo-a', 'package-lock.json'), `${JSON.stringify({
      name: 'fixture',
      lockfileVersion: 1,
      dependencies: {
        parent: {
          version: '1.2.3',
          dependencies: { child: { version: '4.5.6' } }
        }
      }
    }, null, 2)}\n`);
    const artifactDir = path.join(root, 'evidence');
    const result = runGate(root, artifactDir);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const sbom = JSON.parse(await readFile(path.join(artifactDir, 'sbom.json'), 'utf8'));
    assert.ok(sbom.components.some(component => component.purl === 'pkg:npm/parent@1.2.3'));
    assert.ok(sbom.components.some(component => component.purl === 'pkg:npm/child@4.5.6'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('security gate fails closed on malformed relevant dependency metadata', async t => {
  const cases = [
    {
      name: 'package-lock',
      prepare: async repo => writeFile(path.join(repo, 'package-lock.json'), '{not-json\n')
    },
    {
      name: 'pnpm-lock',
      prepare: async repo => writeFile(path.join(repo, 'pnpm-lock.yaml'), [
        "lockfileVersion: 'host-path'", 'packages:', '  alpha@1.0.0:', ''
      ].join('\n'))
    },
    {
      name: 'packages-lock',
      prepare: async repo => writeFile(path.join(repo, 'packages.lock.json'), `${JSON.stringify({
        version: 1,
        dependencies: { 'net10.0': { Hostile: { type: 'Transitive', resolved: 'C:\\private\\leak' } } }
      })}\n`)
    },
    {
      name: 'project-assets',
      prepare: async repo => {
        await mkdir(path.join(repo, 'obj'), { recursive: true });
        await writeFile(path.join(repo, 'obj', 'project.assets.json'), `${JSON.stringify({
          version: 3,
          libraries: { 'Broken.Package': { type: 'package' } }
        })}\n`);
      }
    }
  ];

  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const root = await createWorkspace(`deep-sbom-hostile-${fixture.name}-`);
      try {
        await fixture.prepare(path.join(root, 'repo-a'));
        const result = runGate(root, path.join(root, 'evidence'));
        assert.notEqual(result.status, 0);
        assert.match(`${result.stdout}\n${result.stderr}`, /Malformed dependency metadata/);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test('security gate rejects a non-canonical SOURCE_DATE_EPOCH', async () => {
  const root = await createWorkspace('deep-sbom-epoch-');
  try {
    const result = runGate(root, path.join(root, 'evidence'), { SOURCE_DATE_EPOCH: 'now' });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /SOURCE_DATE_EPOCH must be a non-negative integer/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('secret scan excludes protected scratch and permits only the Android public client config path', async () => {
  const root = await createWorkspace('deep-secret-boundary-');
  const sourceRepo = path.join(root, 'repo-a');
  const clientRepo = path.join(root, 'deep-client-maui');
  const clientConfig = path.join(
    clientRepo, 'src', 'Deep.Client.Maui', 'Platforms', 'Android', 'google-services.json');
  try {
    await mkdir(path.join(sourceRepo, '.secrets'), { recursive: true });
    await writeFile(path.join(sourceRepo, '.secrets', 'local.key'), [
      '-----BEGIN ' + 'PRIVATE KEY-----',
      'not-release-input',
      '-----END PRIVATE KEY-----',
      ''
    ].join('\n'));
    await mkdir(path.dirname(clientConfig), { recursive: true });
    await writeFile(clientConfig, `${JSON.stringify({
      client: [{ api_key: [{ current_key: `AIza${'A'.repeat(35)}` }] }]
    }, null, 2)}\n`);

    const artifactDir = path.join(root, 'evidence');
    const result = runGate(root, artifactDir, {
      DEEP_SECURITY_REPOS: 'repo-a,deep-client-maui'
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const scan = JSON.parse(await readFile(path.join(artifactDir, 'secret-scan.json'), 'utf8'));
    assert.equal(scan.status, 'ok');
    assert.deepEqual(scan.findings, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('secret scan never excludes a tracked secret merely because it is under .secrets', async () => {
  const root = await createWorkspace('deep-secret-tracked-');
  const sourceRepo = path.join(root, 'repo-a');
  try {
    const secretPath = path.join(sourceRepo, '.secrets', 'tracked.key');
    await mkdir(path.dirname(secretPath), { recursive: true });
    await writeFile(secretPath, [
      '-----BEGIN ' + 'PRIVATE KEY-----',
      'tracked-release-leak',
      '-----END PRIVATE KEY-----',
      ''
    ].join('\n'));
    assert.equal(spawnSync('git', ['init'], { cwd: sourceRepo }).status, 0);
    assert.equal(spawnSync('git', ['add', '--', '.secrets/tracked.key'], { cwd: sourceRepo }).status, 0);

    const result = runGate(root, path.join(root, 'evidence'));
    assert.notEqual(result.status, 0);
    const scan = JSON.parse(await readFile(path.join(root, 'evidence', 'secret-scan.json'), 'utf8'));
    assert.equal(scan.status, 'failed');
    assert.ok(scan.findings.some(finding => finding.file === 'repo-a/.secrets/tracked.key'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('secret scan still rejects the same key outside the exact public client config boundary', async () => {
  const root = await createWorkspace('deep-secret-hostile-');
  try {
    await writeFile(path.join(root, 'repo-a', 'leaked.txt'), `AIza${'B'.repeat(35)}\n`);
    const artifactDir = path.join(root, 'evidence');
    const result = runGate(root, artifactDir);
    assert.notEqual(result.status, 0);
    const scan = JSON.parse(await readFile(path.join(artifactDir, 'secret-scan.json'), 'utf8'));
    assert.equal(scan.status, 'failed');
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0].rule, 'google-api-key');
    assert.equal(scan.findings[0].file, 'repo-a/leaked.txt');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
