'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { appendDid2CheckpointEnvironment: append } = require('./append-did2-checkpoint-env.cjs');
const expected = { sourceImage: 'synthetic-image', statePath: '/run/did2/probe.state',
  floorSchema: 'probe', networkId: '11'.repeat(16), previous: '/run/did2/first.bin', next: '/run/did2/second.bin' };
const env = ['AccountDirectoryAuthority__Enabled=false', 'DeepIdV2DirectoryAuthority__Enabled=true',
  'DeepIdV2DirectoryAuthority__ProofEnabled=true', 'DeepIdV2DirectoryAuthority__StatePath=' + expected.statePath,
  'DeepIdV2DirectoryAuthority__NetworkIdHex=' + expected.networkId,
  'DeepIdV2DirectoryAuthority__LatestHeadFloorPostgreSqlConnectionString=Password=synthetic-secret;Search Path=probe',
  'DeepIdV2DirectoryAuthority__ForwardCheckpointPaths__0=' + expected.previous];
const inspect = entries => [{ Config: { Image: expected.sourceImage, Env: entries } }];
test('append retains every exact prior value and adds only the successor path', () => {
  const result = append(inspect(env), expected);
  assert.deepEqual(result.slice(0, env.length), env);
  assert.deepEqual(result.slice(env.length), ['DeepIdV2DirectoryAuthority__ForwardCheckpointPaths__1=' + expected.next]);
});
test('wrong predecessor, duplicate, preexisting successor, changed state/floor/network and malformed entries reject', () => {
  for (const entries of [ [...env, env[0]], [...env, env[0].toLowerCase()],
    [...env, 'DeepIdV2DirectoryAuthority__ForwardCheckpointPaths__1=/run/did2/other.bin'],
    env.map(v => v.replace(expected.previous, '/run/did2/other.bin')),
    env.map(v => v.replace(expected.statePath, '/run/did2/other.state')),
    env.map(v => v.replace('Search Path=probe', 'Search Path=other')),
    env.map(v => v.replace(expected.networkId, '22'.repeat(16))),
    env.map(v => v.replace('Enabled=true', 'Enabled=false')),
    [...env, 'EXTRA=synthetic-secret\ninvalid'], [...env, 'OVERSIZE=' + 'x'.repeat(65_536)] ])
    assert.throws(() => append(inspect(entries), expected), error => !error.message.includes('synthetic-secret'));
});
test('invalid target paths, same predecessor, wrong image and extra inspections reject', () => {
  for (const inputs of [ { ...expected, next: expected.previous }, { ...expected, next: '/run/secrets/root.bin' },
    { ...expected, next: '/run/did2/../root.bin' }, { ...expected, next: '/run/did2/new.bin\nkey' },
    { ...expected, sourceImage: 'different' }, { ...expected, networkId: '0'.repeat(32) } ])
    assert.throws(() => append(inspect(env), inputs));
  assert.throws(() => append([...inspect(env), ...inspect(env)], expected));
});
