'use strict';
const { spawnSync } = require('child_process');
const { writePrivateEnvironment } = require('./prepare-did2-forward-probe-env.cjs');

// Configuration only: exact ADF1 signatures/lineage are verified by Protocol.
// Never reset state, replace a checkpoint or disclose Docker custody values.
function appendDid2CheckpointEnvironment(inspection, expected) {
  const source = Array.isArray(inspection) && inspection.length === 1 ? inspection[0] : null;
  const checkpointPath = value => /^\/run\/did2\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.bin$/.test(value || '');
  if (!source || !source.Config || !Array.isArray(source.Config.Env) || source.Config.Env.length > 512 ||
      !expected || source.Config.Image !== expected.sourceImage ||
      !checkpointPath(expected.previous) || !checkpointPath(expected.next) || expected.previous === expected.next ||
      !/^[0-9a-f]{32}$/.test(expected.networkId || '') || /^0+$/.test(expected.networkId) ||
      !/^[A-Za-z0-9_.-]+$/.test(expected.floorSchema || ''))
    throw new Error('The exact DID2 checkpoint configuration inputs are invalid.');
  const selected = new Map();
  for (const entry of source.Config.Env) {
    if (typeof entry !== 'string' || entry.length > 65_536 || /[\r\n\0]/.test(entry))
      throw new Error('The source environment is malformed or oversized.');
    const split = entry.indexOf('=');
    const name = entry.slice(0, split);
    const normalized = name.toLowerCase();
    if (split < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || selected.has(normalized))
      throw new Error('The source environment is not unique and canonical.');
    selected.set(normalized, { name, value: entry.slice(split + 1) });
  }
  const value = name => { const item = selected.get(name.toLowerCase()); return item && item.value; };
  const prefix = 'DeepIdV2DirectoryAuthority__';
  const floor = value(prefix + 'LatestHeadFloorPostgreSqlConnectionString');
  const schemas = typeof floor === 'string' ? floor.split(';').map(part =>
    /^\s*Search Path\s*=\s*(.*?)\s*$/i.exec(part)).filter(Boolean) : [];
  const checkpoints = [...selected.keys()].filter(key =>
    key.startsWith((prefix + 'ForwardCheckpointPaths__').toLowerCase()));
  const checkpointPrefix = (prefix + 'ForwardCheckpointPaths__').toLowerCase();
  // Keep the complete imported chain. The supplied predecessor names its
  // last element, never permission to replace an earlier signed checkpoint.
  const orderedPaths = [];
  if (checkpoints.length < 1 || checkpoints.length >= 64)
    throw new Error('The retained checkpoint chain cannot accept another successor.');
  for (let index = 0; index < checkpoints.length; index++) {
    const path = value(checkpointPrefix + index);
    if (!checkpointPath(path) || orderedPaths.includes(path))
      throw new Error('The retained checkpoint chain is not contiguous and unique.');
    orderedPaths.push(path);
  }
  if (value(prefix + 'Enabled') !== 'true' || value(prefix + 'ProofEnabled') !== 'true' ||
      value('AccountDirectoryAuthority__Enabled') !== 'false' ||
      value(prefix + 'NetworkIdHex') !== expected.networkId ||
      value(prefix + 'StatePath') !== expected.statePath ||
      schemas.length !== 1 || schemas[0][1] !== expected.floorSchema ||
      orderedPaths[orderedPaths.length - 1] !== expected.previous || orderedPaths.includes(expected.next))
    throw new Error('The source DID2 state, floor or retained checkpoint differs from the selected closure.');
  return [...selected.values()].map(entry => entry.name + '=' + entry.value)
    .concat(prefix + 'ForwardCheckpointPaths__' + orderedPaths.length + '=' + expected.next);
}

function main() {
  const args = process.argv.slice(2);
  const names = ['--container', '--output', '--source-image', '--state-container-path',
    '--floor-schema', '--network-id-hex', '--previous-checkpoint-container-path', '--next-checkpoint-container-path'];
  if (args.length !== names.length * 2 || names.some((name, index) => args[index * 2] !== name) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[1] || ''))
    throw new Error('The exact DID2 checkpoint append arguments are required.');
  const result = spawnSync('docker', ['inspect', '--type', 'container', args[1]],
    { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('Selected Registry inspection failed.');
  let inspection;
  try { inspection = JSON.parse(result.stdout); }
  catch { throw new Error('Selected Registry inspection is malformed.'); }
  const entries = appendDid2CheckpointEnvironment(inspection, { sourceImage: args[5],
    statePath: args[7], floorSchema: args[9], networkId: args[11], previous: args[13], next: args[15] });
  writePrivateEnvironment(args[3], entries);
  process.stdout.write('PASS checkpoint appended; prior state, floor and custody values retained without disclosure.\n');
}
if (require.main === module) {
  try { main(); } catch (error) { process.stderr.write(error.message + '\n'); process.exitCode = 1; }
}
module.exports = { appendDid2CheckpointEnvironment };
