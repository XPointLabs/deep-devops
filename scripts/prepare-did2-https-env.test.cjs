'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { prepareDid2HttpsEnvironment } = require('./prepare-did2-https-env.cjs');
const expected = { sourceImage: 'synthetic-image', stateBasename: 'probe.state',
  floorSchema: 'probe', networkId: '11'.repeat(16), knownProxy: '127.0.0.1',
  bundlePath: '/app/public-network/current.ncp2' };
const env = [ 'ASPNETCORE_ENVIRONMENT=UAT', 'AccountDirectoryAuthority__Enabled=false',
  'DeepIdV2DirectoryAuthority__Enabled=true', 'DeepIdV2DirectoryAuthority__ProofEnabled=true',
  'DeepIdV2DirectoryAuthority__ProductionCutoverAttested=false',
  'DeepIdV2DirectoryAuthority__StatePath=/run/did2/probe.state',
  'DeepIdV2DirectoryAuthority__LatestHeadFloorPostgreSqlConnectionString=Password=synthetic-secret;Search Path=probe',
  'DeepIdV2DirectoryAuthority__NetworkIdHex=' + expected.networkId,
  'ContactResolveProductionAuthority__NetworkIdHex=' + expected.networkId ];
const inspect = entries => [{ Config: { Image: expected.sourceImage, Env: entries } }];
test('HTTPS extension preserves the exact UAT state and appends four unique keys', () => {
  const output = prepareDid2HttpsEnvironment(inspect(env), expected);
  assert.deepEqual(output.slice(0, env.length), env);
  assert.equal(output.length, env.length + 4);
  assert.ok(output.includes('ReverseProxy__KnownProxyIp=127.0.0.1'));
  assert.ok(output.includes('XPointNetworkClosureDistribution__BundlePath=' + expected.bundlePath));
});
test('duplicate, production, repinned, substituted state and existing extension fail closed', () => {
  const mutations = [ [...env, 'OTHER=synthetic-secret', 'other=synthetic-secret'],
    [...env, 'EXTRA=synthetic-secret\nleak'],
    env.map(v => v.replace('ASPNETCORE_ENVIRONMENT=UAT', 'ASPNETCORE_ENVIRONMENT=Production')),
    env.map(v => v.replace('ProductionCutoverAttested=false', 'ProductionCutoverAttested=true')),
    env.map(v => v.replace('AccountDirectoryAuthority__Enabled=false', 'AccountDirectoryAuthority__Enabled=true')),
    env.map(v => v.replace('/run/did2/probe.state', '/run/did2/other.state')),
    env.map(v => v.replace('Search Path=probe', 'Search Path=public')),
    env.map(v => v.replace(expected.networkId, '22'.repeat(16))),
    [...env, 'ReverseProxy__KnownProxyIp=127.0.0.1'],
    [...env, 'xpointnetworkclosuredistribution__enabled=false'] ];
  for (const changed of mutations)
    assert.throws(() => prepareDid2HttpsEnvironment(inspect(changed), expected),
      error => !error.message.includes('synthetic-secret'));
});
test('wrong image, unbounded and noncanonical public mount inputs reject before output', () => {
  for (const inputs of [ { ...expected, sourceImage: 'wrong-image' },
    { ...expected, networkId: '0'.repeat(32) }, { ...expected, knownProxy: 'any' },
    { ...expected, bundlePath: '/run/secrets/private.key' },
    { ...expected, bundlePath: '/app/public-network/injected\nkey.ncp2' },
    { ...expected, bundlePath: '/app/public-network/../private.ncp2' } ])
    assert.throws(() => prepareDid2HttpsEnvironment(inspect(env), inputs));
  assert.throws(() => prepareDid2HttpsEnvironment(inspect([...env, 'OVERSIZE=' + 'a'.repeat(65_536)]), expected));
});
