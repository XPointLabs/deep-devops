'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { prepareTimeUpgrade: prepare, prepareDid2TimeUpgrade, parseObservation } = require('./upgrade-did2-registry-time.cjs');
const expected = { sourceImage: 'sha256:' + '1'.repeat(64) };
function source() {
  return { Image: expected.sourceImage, State: { Running: true },
    HostConfig: { NetworkMode: 'retained_network' },
    Mounts: [{ Type: 'bind', Source: '/private/state', Destination: '/state', RW: true },
      { Type: 'bind', Source: '/private/keys', Destination: '/keys', RW: false }],
    Config: { Env: ['DeepIdV2DirectoryAuthority__Enabled=true', 'DeepIdV2DirectoryAuthority__ProofEnabled=true',
      'DeepIdV2DirectoryAuthority__StatePath=/state/directory.ada2', 'DeepIdV2DirectoryAuthority__NetworkIdHex=' + '2'.repeat(32),
      'ContactResolveProductionAuthority__Enabled=true', 'ContactResolveProductionAuthority__NetworkIdHex=' + '2'.repeat(32),
      'ContactResolveProductionAuthority__TrustedTimeStatePath=/state/manual.state',
      'ContactResolveProductionAuthority__TrustedTimeIntegrityKeyPath=/keys/time.key',
      'DeepIdV2DirectoryAuthority__LatestHeadFloorPostgreSqlConnectionString=Password=synthetic-private-value',
      'DeepIdV2DirectoryAuthority__ForwardCheckpointPaths__0=/state/checkpoint.bin'] } };
}
test('only automatic-time settings change; floor DSN, head, keys, state and checkpoints are byte-identical', () => {
  const old = source(); const prepared = prepare(old, expected);
  assert.deepEqual(prepared.entries.slice(0, old.Config.Env.length), old.Config.Env);
  assert.deepEqual(prepared.entries.slice(old.Config.Env.length), [
    'ContactResolveProductionAuthority__AutomaticTrustedTimeEnabled=true',
    'ContactResolveProductionAuthority__NtsObserverExecutablePath=/usr/local/bin/deep-nts-observer',
    'ContactResolveProductionAuthority__NtsLowerFloorPath=/state/nts-lower-floor.state']);
  assert.equal(prepared.network, old.HostConfig.NetworkMode);
  assert.deepEqual(prepared.mounts, ['type=bind,src=/private/state,dst=/state', 'type=bind,src=/private/keys,dst=/keys,readonly']);
});
test('retained explicit floor is reused, never selected afresh on automatic composition', () => {
  const old = source(); old.Config.Env.push('ContactResolveProductionAuthority__AutomaticTrustedTimeEnabled=true',
    'ContactResolveProductionAuthority__NtsLowerFloorPath=/state/retained.state');
  assert.ok(prepare(old, expected).entries.includes('ContactResolveProductionAuthority__NtsLowerFloorPath=/state/retained.state'));
  old.Config.Env.pop(); assert.throws(() => prepare(old, expected));
});

test('explicit DID2 source mode removes only disabled retired sections and preserves custody verbatim', () => {
  const old = source();
  old.Config.Env.push('AccountDirectoryAuthority__Enabled=false',
    'AccountDirectoryAuthority__StatePath=/private/retired-state',
    'ContactResolveDirectoryArtifacts__Enabled=false',
    'TargetedCurrentValueDirectoryPackages__Enabled=false');
  const before = structuredClone(old);
  const prepared = prepareDid2TimeUpgrade(old, expected);
  assert.deepEqual(old, before);
  assert.deepEqual(prepared.mounts, prepare(old, expected).mounts);
  assert.deepEqual(prepared.entries, prepare(source(), expected).entries);
  assert.ok(prepare(old, expected).entries.includes('AccountDirectoryAuthority__Enabled=false'));
});

test('active or ambiguous retired directory sections reject before changing inputs or disclosing values', () => {
  for (const entry of ['AccountDirectoryAuthority__Enabled=true',
    'ContactResolveDirectoryArtifacts__StatePath=/private/synthetic-secret',
    'TargetedCurrentValueDirectoryPackages__Enabled=FALSE']) {
    const old = source(); old.Config.Env.push(entry); const before = structuredClone(old);
    assert.throws(() => prepareDid2TimeUpgrade(old, expected), error => !error.message.includes('synthetic-secret'));
    assert.deepEqual(old, before);
  }
});
test('source CAS, stopped source, disabled scope and foreign network reject without mutation', () => {
  for (const mutate of [s => s.Image = 'sha256:' + '3'.repeat(64), s => s.State.Running = false,
    s => s.Config.Env[0] = 'DeepIdV2DirectoryAuthority__Enabled=false',
    s => s.Config.Env[5] = 'ContactResolveProductionAuthority__NetworkIdHex=' + '3'.repeat(32)]) {
    const old = source(); mutate(old); const before = structuredClone(old);
    assert.throws(() => prepare(old, expected)); assert.deepEqual(old, before);
  }
});
test('duplicate, case-duplicate, newline, oversized and malformed values reject without disclosure', () => {
  for (const extra of [source().Config.Env[0], source().Config.Env[0].toLowerCase(),
    'EXTRA=synthetic-private-value\ninvalid', 'EXTRA=' + 'x'.repeat(65537), 'malformed']) {
    const old = source(); old.Config.Env.push(extra);
    assert.throws(() => prepare(old, expected), error => !error.message.includes('synthetic-private-value'));
  }
});
test('read-only or missing floor parent, volume, duplicate destination, noncanonical and unsafe bind paths reject', () => {
  for (const mutate of [s => s.Mounts[0].RW = false, s => s.Mounts.shift(),
    s => s.Mounts[0].Type = 'volume', s => s.Mounts.push({ ...s.Mounts[0] }),
    s => s.Mounts[0].Source = '/private/../state', s => s.Mounts[0].Source = '/private,state']) {
    const old = source(); mutate(old); assert.throws(() => prepare(old, expected));
  }
});
test('output alias, pending/fence alias and direct-file floor mount reject', () => {
  for (const extra of ['Other__Key=/state/nts-lower-floor.state',
    'Other__Key=/state/nts-lower-floor.state.manual-upgrade-fence',
    'Other__Key=/state/nts-lower-floor.state.manual-upgrade-pending']) {
    const old = source(); old.Config.Env.push(extra); assert.throws(() => prepare(old, expected));
  }
  const old = source(); old.Mounts.push({ Type: 'bind', Source: '/private/floor', Destination: '/state/nts-lower-floor.state', RW: true });
  assert.throws(() => prepare(old, expected));
});

test('only a closed bounded authenticated observation is admitted for proposing a renewal window', () => {
  const valid = { schema: 'deep.registry.authenticated-time-observation.v1', reusableFreshnessEvidence: false,
    observedUnixSeconds: 1700000100, uncertaintySeconds: 3 };
  assert.deepEqual(parseObservation(JSON.stringify(valid)), valid);
  for (const hostile of [{ ...valid, reusableFreshnessEvidence: true }, { ...valid, extra: 'synthetic-private-value' },
    { ...valid, uncertaintySeconds: 0 }, { ...valid, observedUnixSeconds: 1 },
    { ...valid, observedUnixSeconds: 1.5 }, { ...valid, observedUnixSeconds: Number.MAX_SAFE_INTEGER + 1 }])
    assert.throws(() => parseObservation(JSON.stringify(hostile)));
});
