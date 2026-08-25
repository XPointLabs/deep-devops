import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repositoryRoot = resolve(import.meta.dirname, '..');
const composePath = join(repositoryRoot, 'docker-compose.rc6-application-recovery.yml');
const verifierPath = join(repositoryRoot, 'scripts', 'rc6-application-recovery-verifier.mjs');
const composeSource = readFileSync(composePath, 'utf8');
const verifierSource = readFileSync(verifierPath, 'utf8');
const digest = 'a'.repeat(64);
const alternateDigest = 'b'.repeat(64);
const exactImage = name => `registry.invalid/${name}@sha256:${digest}`;

function expectations(overrides = {}) {
  const base = {
    schemaVersion: 1,
    images: {
      xnode: exactImage('xnode'),
      registry: exactImage('registry'),
      compat: exactImage('compat'),
      verifier: exactImage('verifier')
    },
    storage: {
      messageCount: 1,
      ownerEd25519PublicKey: '1'.repeat(64),
      ownerPublicKey: `05${'2'.repeat(64)}`,
      ownerPublicFingerprintSha256: '3'.repeat(64),
      namespaces: [{ namespace: 0, messageHashes: ['4'.repeat(64)] }]
    },
    file: {
      fileCount: 1,
      avatarCount: 0,
      objects: [{
        kind: 'file',
        publicId: 'public-canary-id',
        sha256: '5'.repeat(64),
        size: 12,
        metadataSha256: '6'.repeat(64)
      }]
    },
    push: {
      subscriptionCount: 1,
      deliveryCount: 1,
      canaries: [{ publicKey: `05${'7'.repeat(64)}`, snapshotSha256: '8'.repeat(64) }]
    },
    registry: { membershipCatalogSha256: '9'.repeat(64) }
  };
  return { ...base, ...overrides };
}

function runVerifier(args, options = {}) {
  return spawnSync(process.execPath, [verifierPath, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: { ...process.env, ...options.env },
    timeout: 10_000,
    windowsHide: true
  });
}

function onlyJsonLine(result) {
  assert.equal(result.stderr, '');
  const lines = result.stdout.trim().split(/\r?\n/);
  assert.equal(lines.length, 1);
  return JSON.parse(lines[0]);
}

test('recovery compose is isolated, immutable, external-volume-only, and has no bootstrap mutation', () => {
  assert.doesNotMatch(composeSource, /^\s+ports:/m);
  assert.doesNotMatch(composeSource, /^\s+build:/m);
  assert.doesNotMatch(composeSource, /docker\.sock|network_mode:\s*host|privileged:\s*true/);
  assert.match(composeSource, /^\s+internal:\s*true$/m);
  assert.match(verifierSource, /'--no-build'/);
  assert.doesNotMatch(composeSource, /membership-artifact-(?:owner-)?init|command:\s*\[[^\]]*clear/);
  const imageLines = composeSource.split(/\r?\n/).filter(line => /^\s+image:/.test(line));
  assert.equal(imageLines.length, 6);
  for (const line of imageLines) assert.match(line, /^\s+image:\s+\$\{RC6_RECOVERY_/);
  for (const name of [
    'MEMBERSHIP', 'REGISTRY', 'STORAGE', 'FILE', 'PUSH',
    'XNODE_1', 'XNODE_2', 'XNODE_3', 'XNODE_4', 'XNODE_5', 'XNODE_6', 'VERIFIER_STATE'
  ]) {
    assert.match(composeSource, new RegExp(`RC6_RECOVERY_${name}_VOLUME:\\?`));
  }
  assert.equal((composeSource.match(/external:\s*true/g) ?? []).length, 12);
  assert.ok((composeSource.match(/recovery-membership-artifact:\/run\/deep-membership:ro/g) ?? []).length >= 7);
  assert.match(composeSource, /expectations\.json:ro/);
  assert.match(composeSource, /canary-signer\.pem:ro/);
  assert.match(composeSource, /ASPNETCORE_ENVIRONMENT: Development/);
  assert.doesNotMatch(composeSource, /\.\/scripts\/rc6-application-recovery-verifier\.mjs:/);
  assert.match(composeSource, /cap_drop:\s*\[ALL\]/);
  assert.match(composeSource, /no-new-privileges:true/);
  assert.match(verifierSource, /\.\.\.compose, 'down', '--remove-orphans'/);
  assert.doesNotMatch(verifierSource, /'down'[^\r\n]*--volumes/);
});

test('docker compose resolves the recovery topology without publishing ports or builds', t => {
  const probe = spawnSync('docker', ['compose', 'version'], { encoding: 'utf8', windowsHide: true });
  if (probe.status !== 0) {
    t.skip('docker compose is unavailable');
    return;
  }

  const root = mkdtempSync(join(tmpdir(), 'rc6-recovery-compose-'));
  try {
    const emptyFile = join(root, 'protected-input');
    const envFile = join(root, 'protected.env');
    const expectationsFile = join(root, 'expectations.json');
    writeFileSync(emptyFile, 'placeholder\n');
    writeFileSync(envFile, 'RC6_TEST_PUBLIC_VALUE=placeholder\n');
    writeFileSync(expectationsFile, `${JSON.stringify(expectations())}\n`);
    const env = {
      ...process.env,
      RC6_RECOVERY_XNODE_IMAGE: exactImage('xnode'),
      RC6_RECOVERY_REGISTRY_IMAGE: exactImage('registry'),
      RC6_RECOVERY_COMPAT_IMAGE: exactImage('compat'),
      RC6_RECOVERY_VERIFIER_IMAGE: exactImage('verifier'),
      RC6_RECOVERY_EXPECTATIONS_FILE: expectationsFile,
      RC6_RECOVERY_CANARY_SIGNER_FILE: emptyFile,
      RC6_RECOVERY_MAILBOX_AUTHORITY_ENV_FILE: envFile,
      RC6_RECOVERY_MAILBOX_CLIENT_AUTHORITY_ENV_FILE: envFile,
      RC6_RECOVERY_TURN_SHARED_SECRET_FILE: emptyFile,
      RC6_RECOVERY_MEMBERSHIP_VOLUME: 'restored-membership',
      RC6_RECOVERY_REGISTRY_VOLUME: 'restored-registry',
      RC6_RECOVERY_STORAGE_VOLUME: 'restored-storage',
      RC6_RECOVERY_FILE_VOLUME: 'restored-file',
      RC6_RECOVERY_PUSH_VOLUME: 'restored-push',
      RC6_RECOVERY_VERIFIER_STATE_VOLUME: 'recovery-verifier-scratch'
    };
    for (let index = 1; index <= 6; index += 1) {
      env[`RC6_RECOVERY_XNODE_${index}_PRIVACY_ENV_FILE`] = envFile;
      env[`RC6_RECOVERY_XNODE_${index}_PUBLIC_HOST`] = `xnode-${index}`;
      env[`RC6_RECOVERY_XNODE_${index}_ROUTER_ID`] = String(index).repeat(64);
      env[`RC6_RECOVERY_XNODE_${index}_PUBLIC_PEER_BASE_URL`] = `http://xnode-${index}:8081/`;
      env[`RC6_RECOVERY_XNODE_${index}_VOLUME`] = `restored-xnode-${index}`;
      env[`RC6_RECOVERY_XNODE_${index}_ED25519_FILE`] = emptyFile;
      env[`RC6_RECOVERY_XNODE_${index}_X25519_FILE`] = emptyFile;
    }
    const result = spawnSync('docker', [
      'compose', '-f', composePath, 'config', '--format', 'json'
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env,
      timeout: 30_000,
      windowsHide: true
    });
    assert.equal(result.status, 0, result.stderr);
    const config = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(config.services).sort(), [
      'file', 'push', 'recovery-verifier', 'registry', 'storage',
      'xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6'
    ]);
    for (const service of Object.values(config.services)) {
      assert.equal(service.build, undefined);
      assert.deepEqual(service.ports ?? [], []);
      assert.deepEqual(service.networks, { recovery: null });
      assert.match(service.image, /@sha256:[0-9a-f]{64}$/);
    }
    assert.equal(config.networks.recovery.internal, true);
    for (const volume of Object.values(config.volumes)) assert.equal(volume.external, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validate-only emits a machine-checkable fail-closed scaffold for a valid public manifest', () => {
  const root = mkdtempSync(join(tmpdir(), 'rc6-recovery-validator-'));
  try {
    const manifest = join(root, 'expectations.json');
    writeFileSync(manifest, `${JSON.stringify(expectations())}\n`);
    const result = runVerifier(['--validate-only', '--expectations', manifest]);
    assert.equal(result.status, 0);
    const output = onlyJsonLine(result);
    assert.equal(output.status, 'scaffold');
    assert.equal(output.partialApplicationServicesValidated, false);
    assert.equal(output.applicationContourValidated, false);
    assert.deepEqual(output.blockers, ['runtime-recovery-not-executed']);
    assert.ok(!result.stdout.includes(manifest));
    assert.ok(!result.stdout.includes('public-canary-id'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('manifest extensions and mutable images reject without echoing input', () => {
  const root = mkdtempSync(join(tmpdir(), 'rc6-recovery-invalid-'));
  try {
    const sentinel = 'SensitiveCanaryValueMustNotAppear';
    const extended = join(root, 'extended.json');
    writeFileSync(extended, JSON.stringify({ ...expectations(), privateSecret: sentinel }));
    const extendedResult = runVerifier(['--validate-only', '--expectations', extended]);
    assert.equal(extendedResult.status, 1);
    assert.deepEqual(onlyJsonLine(extendedResult).blockers, ['expectations-shape-invalid']);
    assert.ok(!extendedResult.stdout.includes(sentinel));
    assert.ok(!extendedResult.stdout.includes(extended));

    const mutable = join(root, 'mutable.json');
    const document = expectations();
    document.images.registry = `registry.invalid/registry:${alternateDigest}`;
    writeFileSync(mutable, JSON.stringify(document));
    const mutableResult = runVerifier(['--validate-only', '--expectations', mutable]);
    assert.equal(mutableResult.status, 1);
    assert.deepEqual(onlyJsonLine(mutableResult).blockers, ['expectations-image-not-immutable']);
    assert.ok(!mutableResult.stdout.includes(document.images.registry));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('controller fails before Docker when the protected signer fixture is absent', () => {
  const root = mkdtempSync(join(tmpdir(), 'rc6-recovery-controller-'));
  try {
    const manifest = join(root, 'expectations.json');
    writeFileSync(manifest, JSON.stringify(expectations()));
    const result = runVerifier([
      '--compose-file', composePath,
      '--project-name', 'rc6-recovery-test',
      '--expectations', manifest
    ], {
      env: {
        RC6_RECOVERY_XNODE_IMAGE: exactImage('xnode'),
        RC6_RECOVERY_REGISTRY_IMAGE: exactImage('registry'),
        RC6_RECOVERY_COMPAT_IMAGE: exactImage('compat'),
        RC6_RECOVERY_VERIFIER_IMAGE: exactImage('verifier'),
        RC6_RECOVERY_CANARY_SIGNER_FILE: ''
      }
    });
    assert.equal(result.status, 1);
    const output = onlyJsonLine(result);
    assert.equal(output.partialApplicationServicesValidated, false);
    assert.equal(output.applicationContourValidated, false);
    assert.deepEqual(output.blockers, ['protected-canary-signer-file-not-supplied']);
    assert.ok(!result.stdout.includes(composePath));
    assert.ok(!result.stdout.includes('@sha256'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifier has bounded orchestration and sanitized output contracts', () => {
  assert.match(verifierSource, /const commandTimeoutMs = 120_000/);
  assert.match(verifierSource, /const restartCommandTimeoutMs = 60_000/);
  assert.match(verifierSource, /const readyTimeoutMs = 45_000/);
  assert.match(verifierSource, /timeout: timeoutMs/);
  assert.match(verifierSource, /maxBuffer: 1024 \* 1024/);
  assert.doesNotMatch(verifierSource, /stdio:\s*['"]inherit['"]|console\.(?:error|warn|log)|process\.stderr/);
  assert.doesNotMatch(verifierSource, /result\.stderr|error\.stack|error\.message/);
  assert.doesNotMatch(verifierSource, /applicationContourValidated:\s*true/);
  assert.match(verifierSource, /partialApplicationServicesValidated: true/);
  assert.match(verifierSource, /applicationContourValidated: false/);
  assert.match(verifierSource, /scope: 'isolated-restored-application-services-partial'/);
  assert.match(verifierSource, /unvalidated: \['xnode-identity', 'privacy-routing', 'turn'\]/);
  assert.match(verifierSource, /after-partial-services-probe-not-validated/);
  assert.match(verifierSource, /calls-v2-exactly-once-failed/);
  assert.match(verifierSource, /calls-v2-negative-auth-not-rejected/);
  assert.match(verifierSource, /runtime-image-fingerprint-mismatch/);
  assert.match(verifierSource, /restored-volume-already-mounted/);
  assert.match(verifierSource, /compose-file-not-supported/);
  assert.match(verifierSource, /storage-canary-hash-mismatch/);
  assert.match(verifierSource, /push-canary-hash-mismatch/);
  assert.match(verifierSource, /membership-catalog-hash-mismatch/);
});
