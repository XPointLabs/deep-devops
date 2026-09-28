'use strict';

const { spawnSync } = require('child_process');
const net = require('net');
const path = require('path');
const { writePrivateEnvironment } = require('./prepare-did2-forward-probe-env.cjs');

// Only a reviewed, already-unique closed UAT canary may be extended. Existing
// account/floor/key/state values are retained verbatim, never printed or moved.
function prepareDid2HttpsEnvironment(inspection, expected) {
  const source = Array.isArray(inspection) && inspection.length === 1 ? inspection[0] : null;
  if (!source || !source.Config || !Array.isArray(source.Config.Env) || source.Config.Env.length > 512 ||
      !expected || source.Config.Image !== expected.sourceImage ||
      !/^[A-Za-z0-9_.-]+$/.test(expected.stateBasename || '') ||
      !/^[A-Za-z0-9_.-]+$/.test(expected.floorSchema || '') ||
      !/^[0-9a-f]{32}$/.test(expected.networkId || '') || /^0+$/.test(expected.networkId) ||
      net.isIP(expected.knownProxy || '') === 0 ||
      !/^\/app\/public-network\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.ncp2$/.test(expected.bundlePath || ''))
    throw new Error('The closed HTTPS UAT source or public extension inputs are invalid.');
  const selected = new Map();
  for (const entry of source.Config.Env) {
    if (typeof entry !== 'string' || entry.length > 65_536 || /[\r\n\0]/.test(entry))
      throw new Error('The source UAT environment contains a malformed entry.');
    const split = entry.indexOf('=');
    const name = entry.slice(0, split);
    const normalized = name.toLowerCase();
    if (split < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || selected.has(normalized))
      throw new Error('The source UAT environment is not unique and canonical.');
    selected.set(normalized, { name, value: entry.slice(split + 1) });
  }
  const value = name => {
    const item = selected.get(name.toLowerCase());
    return item && item.value;
  };
  const prefix = 'DeepIdV2DirectoryAuthority__';
  const state = value(prefix + 'StatePath');
  const floor = value(prefix + 'LatestHeadFloorPostgreSqlConnectionString');
  const schemas = typeof floor === 'string' ? floor.split(';')
    .map(part => /^\s*Search Path\s*=\s*(.*?)\s*$/i.exec(part)).filter(Boolean) : [];
  if (value('ASPNETCORE_ENVIRONMENT') !== 'UAT' ||
      value(prefix + 'Enabled') !== 'true' || value(prefix + 'ProofEnabled') !== 'true' ||
      value(prefix + 'ProductionCutoverAttested') !== 'false' ||
      value('AccountDirectoryAuthority__Enabled') !== 'false' ||
      value(prefix + 'NetworkIdHex') !== expected.networkId ||
      value('ContactResolveProductionAuthority__NetworkIdHex') !== expected.networkId ||
      typeof state !== 'string' || !path.posix.isAbsolute(state) ||
      path.posix.basename(state) !== expected.stateBasename ||
      schemas.length !== 1 || schemas[0][1] !== expected.floorSchema)
    throw new Error('The source is not the independently selected closed DID2 UAT state.');
  const extension = {
    ReverseProxy__KnownProxyIp: expected.knownProxy,
    XPointNetworkClosureDistribution__Enabled: 'true',
    XPointNetworkClosureDistribution__NetworkIdHex: expected.networkId,
    XPointNetworkClosureDistribution__BundlePath: expected.bundlePath
  };
  for (const [name, field] of Object.entries(extension)) {
    if (selected.has(name.toLowerCase()))
      throw new Error('A source UAT HTTPS extension key already exists.');
    selected.set(name.toLowerCase(), { name, value: field });
  }
  return [...selected.values()].map(entry => entry.name + '=' + entry.value);
}

function main() {
  const args = process.argv.slice(2);
  const names = ['--container', '--output', '--source-image', '--state-basename',
    '--floor-schema', '--network-id-hex', '--known-proxy-ip', '--bundle-container-path'];
  if (args.length !== names.length * 2 || names.some((name, index) => args[index * 2] !== name) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[1] || ''))
    throw new Error('Expected the exact closed DID2 HTTPS UAT extension arguments.');
  const inspected = spawnSync('docker', ['inspect', '--type', 'container', args[1]],
    { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  if (inspected.error || inspected.status !== 0)
    throw new Error('The selected UAT container inspection failed.');
  let parsed;
  try { parsed = JSON.parse(inspected.stdout); }
  catch { throw new Error('The selected UAT container inspection is malformed.'); }
  const entries = prepareDid2HttpsEnvironment(parsed, {
    sourceImage: args[5], stateBasename: args[7], floorSchema: args[9],
    networkId: args[11], knownProxy: args[13], bundlePath: args[15]
  });
  writePrivateEnvironment(args[3], entries);
  process.stdout.write(`Closed DID2 HTTPS UAT environment prepared: ${entries.length} unique keys; no custody values disclosed.\n`);
}

if (require.main === module) {
  try { main(); }
  catch (error) { process.stderr.write(error.message + '\n'); process.exitCode = 1; }
}
module.exports = { prepareDid2HttpsEnvironment };
