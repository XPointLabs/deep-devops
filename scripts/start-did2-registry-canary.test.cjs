'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path');
const { createHash } = require('node:crypto');
const { prepareCanary, verifyImage, createArguments, sameSource, withCurrentView } = require('./start-did2-registry-canary.cjs');
const expected = { sourceImage: 'sha256:' + '1'.repeat(64), image: 'sha256:' + '3'.repeat(64), revision: '4'.repeat(40) };
function source() {
  return { Image: expected.sourceImage, State: { Running: true }, HostConfig: { NetworkMode: 'retained_network' },
    Mounts: [{ Type: 'bind', Source: '/private/state', Destination: '/state', RW: true }],
    Config: { Env: ['DeepIdV2DirectoryAuthority__Enabled=true', 'DeepIdV2DirectoryAuthority__ProofEnabled=true',
      'DeepIdV2DirectoryAuthority__StatePath=/state/directory.ada2', 'DeepIdV2DirectoryAuthority__NetworkIdHex=' + '2'.repeat(32),
      'ContactResolveProductionAuthority__Enabled=true', 'ContactResolveProductionAuthority__NetworkIdHex=' + '2'.repeat(32),
      'ContactResolveProductionAuthority__TrustedTimeStatePath=/state/manual.state',
      'ContactResolveProductionAuthority__TrustedTimeIntegrityKeyPath=/state/time.key',
      'DeepIdV2DirectoryAuthority__LatestHeadFloorPostgreSqlConnectionString=synthetic-private-value'] } };
}
test('keeps current custody exact, strips only disabled retired configuration and explicitly disables renewal', () => {
  const old = source(); old.Config.Env.push('AccountDirectoryAuthority__Enabled=false');
  const before = structuredClone(old); const prepared = prepareCanary(old, expected);
  assert.deepEqual(old, before);
  for (const entry of source().Config.Env) assert.ok(prepared.entries.includes(entry));
  assert.ok(prepared.entries.includes('DeepIdV2DirectoryAuthority__HeadRenewalEnabled=false'));
  assert.ok(!prepared.entries.some(entry => entry.startsWith('AccountDirectoryAuthority__')));
});
test('host network, active renewal, missing independent floor and malformed image binding reject', () => {
  for (const mutate of [s => s.HostConfig.NetworkMode = 'host', s => s.HostConfig.NetworkMode = 'none',
    s => s.Config.Env.push('DeepIdV2DirectoryAuthority__HeadRenewalEnabled=true'), s => s.Config.Env.pop()]) {
    const old = source(); mutate(old); assert.throws(() => prepareCanary(old, expected));
  }
  assert.throws(() => prepareCanary(source(), { ...expected, revision: 'not-a-revision' }));
});
test('catalog writes are never silently disabled; current DID2 input is mandatory when enabled', () => {
  const old = source(); old.Config.Env.push('DirectoryPublication__MirrorEnabled=true', 'DirectoryPublication__WriteEnabled=true');
  assert.throws(() => prepareCanary(old, expected));
  old.Config.Env.push('DirectoryPublication__RequestedDid2Path=/state/public.did2');
  assert.equal(prepareCanary(old, expected).catalogWritesEnabled, true);
});
test('exact Linux amd64 image and Registry revision are required', () => {
  const image = { Id: expected.image, Os: 'linux', Architecture: 'amd64', Config: { Labels: { 'org.opencontainers.image.revision': expected.revision } } };
  verifyImage([image], expected);
  for (const change of [{ Architecture: 'arm64' }, { Id: expected.sourceImage }, { Config: { Labels: {} } }])
    assert.throws(() => verifyImage([{ ...image, ...change }], expected));
});
test('Docker create has no published ports, aliases, restart loop or destructive command', () => {
  const prepared = prepareCanary(source(), expected);
  const args = createArguments(prepared, expected.image, 'deep-did2-registry-canary-test', '/var/tmp/private/canary.env');
  for (const forbidden of ['-p', '--publish', '-P', '--publish-all', '--network-alias', '--rm', '--privileged'])
    assert.ok(!args.includes(forbidden));
  assert.ok(args.includes('--read-only')); assert.ok(args.includes('--cap-drop'));
  assert.throws(() => createArguments(prepared, expected.image, 'production-registry', '/var/tmp/private/canary.env'));
});
test('source CAS accepts unordered inspection mounts but rejects actual custody, environment or network changes', () => {
  const old = source(); old.Mounts.push({ Type: 'bind', Source: '/private/keys', Destination: '/keys', RW: false });
  const reordered = structuredClone(old); reordered.Mounts.reverse(); reordered.Config.Env.reverse();
  assert.equal(sameSource(old, reordered, expected), true);
  for (const mutate of [s => s.Mounts[0].Source = '/private/substituted', s => s.Mounts[1].RW = true,
    s => s.Config.Env.push('EXTRA=changed'), s => s.HostConfig.NetworkMode = 'substituted_network']) {
    const current = structuredClone(old); mutate(current); assert.equal(sameSource(old, current, expected), false);
  }
});
test('independently hashed public view overrides only the diagnostic view through a read-only mount', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'deep-canary-view-test-'));
  const file = path.join(temporary, 'view.xnv1');
  const linuxPath = process.platform === 'win32' ? file.slice(2).replaceAll('\\', '/') : file;
  try {
    const exact = Buffer.alloc(64, 1); exact.write('XNV1');
    fs.writeFileSync(file, exact);
    const hash = createHash('sha256').update(exact).digest('hex');
    const original = prepareCanary(source(), expected);
    const prepared = withCurrentView(original, linuxPath, hash);
    assert.deepEqual(prepared.entries.slice(0, original.entries.length), original.entries);
    assert.equal(prepared.entries.at(-1), 'DeepIdV2DirectoryAuthority__CurrentXnv1Path=/run/did2-canary-view/current.xnv1');
    assert.equal(prepared.mounts.at(-1), 'type=bind,src=' + linuxPath + ',dst=/run/did2-canary-view/current.xnv1,readonly');
    assert.throws(() => withCurrentView(original, linuxPath, 'f'.repeat(64)));
    assert.throws(() => withCurrentView(prepared, linuxPath, hash));
    for (const hostile of [Buffer.alloc(10), Buffer.alloc(65536), Buffer.alloc(64)]) {
      fs.writeFileSync(file, hostile);
      assert.throws(() => withCurrentView(original, linuxPath, createHash('sha256').update(hostile).digest('hex')));
    }
  } finally {
    // Exactly this test's known file and empty temporary directory, no recursion.
    fs.unlinkSync(file); fs.rmdirSync(temporary);
  }
});
