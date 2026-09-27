'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { prepareDid2ForwardProbeEnvironment, writePrivateEnvironment } =
  require('./prepare-did2-forward-probe-env.cjs');

const key = name => 'DeepIdV2DirectoryAuthority__' + name;
const source = [
  'ASPNETCORE_ENVIRONMENT=UAT',
  key('Enabled') + '=true',
  key('ProofEnabled') + '=true',
  key('ProductionCutoverAttested') + '=false',
  key('StatePath') + '=/run/did2/old.state',
  key('ProofRequestLedgerRootPath') + '=/run/did2/old-ledger',
  key('LatestHeadFloorPostgreSqlConnectionString') + '=Password=secret-old;Search Path=public',
  'Registry__StatePath=/run/did2/old-registry.json',
  'ContactResolveProductionAuthority__TrustedTimeStatePath=/run/did2/old-time.state',
  'ContactResolveProductionAuthority__RequestLedgerRootPath=/run/did2/old-contact-ledger',
  key('ForwardCheckpointPaths__0') + '=/run/did2/forward.adf1',
  key('StatePath') + '=/run/did2/probe.state',
  key('ProofRequestLedgerRootPath') + '=/run/did2/probe-ledger',
  key('LatestHeadFloorPostgreSqlConnectionString') + '=Password=secret-new;Search Path=probe-schema',
  'Registry__StatePath=/run/did2/probe-registry.json',
  'ContactResolveProductionAuthority__TrustedTimeStatePath=/run/did2/probe-time.state',
  'ContactResolveProductionAuthority__RequestLedgerRootPath=/run/did2/probe-contact-ledger'
];
const expected = {
  state: 'probe.state', ledger: 'probe-ledger',
  registryState: 'probe-registry.json', trustedTime: 'probe-time.state',
  contactLedger: 'probe-contact-ledger',
  floorSchema: 'probe-schema', adf1: 'forward.adf1'
};
const inspect = entries => [{ Config: { Env: entries } }];

test('only reviewed last values survive in a unique private env file', () => {
  const prepared = prepareDid2ForwardProbeEnvironment(inspect(source), expected);
  assert.equal(prepared.replacedKeys.length, 6);
  assert.equal(prepared.entries.length, source.length - 6);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'did2-env-test-'));
  const output = path.join(directory, 'private.env');
  try {
    writePrivateEnvironment(output, prepared.entries);
    const written = fs.readFileSync(output, 'utf8');
    assert.match(written, /StatePath=\/run\/did2\/probe.state/);
    assert.doesNotMatch(written, /old.state|secret-old|old-ledger|old-registry|old-time|old-contact/);
    assert.match(written, /secret-new/);
    assert.throws(() => writePrivateEnvironment(output, prepared.entries));
    assert.equal(fs.readFileSync(output, 'utf8'), written);
    if (process.platform !== 'win32')
      assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  } finally {
    if (fs.existsSync(output)) fs.unlinkSync(output);
    fs.rmdirSync(directory);
  }
});

test('wrong source scope, extra duplicate and newline fail without printing values', () => {
  for (const entries of [
    source.filter(entry => !entry.startsWith(key('ForwardCheckpointPaths__0'))),
    [...source, 'OTHER=secret-a', 'OTHER=secret-b'],
    source.map(entry => entry.startsWith(key('StatePath') + '=/run/did2/probe.state')
      ? key('StatePath') + '=/run/did2/wrong.state' : entry),
    source.map(entry => entry.includes('Search Path=probe-schema')
      ? entry.replace('Search Path=probe-schema', 'Search Path=public;Note=probe-schema') : entry),
    [...source, 'EXTRA=secret\nleak']
  ]) {
    let message = '';
    try { prepareDid2ForwardProbeEnvironment(inspect(entries), expected); }
    catch (error) { message = error.message; }
    assert.notEqual(message, '');
    assert.equal(message.includes('secret-a'), false);
    assert.equal(message.includes('secret-b'), false);
    assert.equal(message.includes('secret-new'), false);
  }
});
