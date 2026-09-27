import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { auditDid2ContainerEnvironment } from './check-did2-registry-container-env.mjs';

const script = fileURLToPath(new URL('./check-did2-registry-container-env.mjs',
  import.meta.url));
const inspect = entries => [{ Config: { Env: entries } }];

test('one DID2 value per key passes without exposing values', () => {
  const result = auditDid2ContainerEnvironment(inspect([
    'DeepIdV2DirectoryAuthority__Enabled=true',
    'DeepIdV2DirectoryAuthority__StatePath=secret-one',
    'OTHER=secret-two'
  ]));
  assert.deepEqual(result, { uniqueKeyCount: 2, repeatedKeys: [] });
});

test('same and conflicting DID2 duplicates both fail the container preflight', () => {
  for (const second of ['secret-one', 'secret-two']) {
    const input = JSON.stringify(inspect([
      'DeepIdV2DirectoryAuthority__StatePath=secret-one',
      `DeepIdV2DirectoryAuthority__StatePath=${second}`
    ]));
    const result = spawnSync(process.execPath, [script, '--stdin'],
      { input, encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Repeated DID2 authority environment keys/);
    assert.equal(result.stderr.includes('secret-one'), false);
    assert.equal(result.stderr.includes('secret-two'), false);
    assert.equal(result.stdout, '');
  }
});

test('case variants cannot bypass the .NET configuration-key collision check', () => {
  const result = auditDid2ContainerEnvironment(inspect([
    'DeepIdV2DirectoryAuthority__StatePath=secret-one',
    'DEEPIDV2DIRECTORYAUTHORITY__STATEPATH=secret-two'
  ]));
  assert.deepEqual(result, {
    uniqueKeyCount: 1,
    repeatedKeys: ['deepidv2directoryauthority__statepath']
  });
});

test('malformed or absent DID2 environment fails closed', () => {
  assert.throws(() => auditDid2ContainerEnvironment(inspect(['malformed'])));
  const result = spawnSync(process.execPath, [script, '--stdin'],
    { input: JSON.stringify(inspect(['OTHER=value'])), encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /no DID2 authority environment keys/);
});
