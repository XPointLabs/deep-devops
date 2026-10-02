'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { randomBytes } = require('crypto');
const { writePrivateEnvironment } = require('./prepare-did2-forward-probe-env.cjs');

const digest = value => /^sha256:[0-9a-f]{64}$/.test(value || '');
const absolute = value => typeof value === 'string' && /^\/[A-Za-z0-9_./-]+$/.test(value) &&
  path.posix.normalize(value) === value && value !== '/';

// Exact environment/mount preservation, not a new directory provisioner or
// production promotion. Both one-shot commands are owned by Registry.
function prepareTimeUpgrade(source, expected) {
  if (!source || !source.State || !source.State.Running || !expected || !digest(expected.sourceImage) || source.Image !== expected.sourceImage ||
      !source.Config || !Array.isArray(source.Config.Env) || source.Config.Env.length > 512 ||
      !Array.isArray(source.Mounts) || source.Mounts.length < 1 || source.Mounts.length > 64 ||
      !source.HostConfig || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(source.HostConfig.NetworkMode || ''))
    throw new Error('Registry time upgrade source scope rejected.');
  const env = new Map();
  for (const entry of source.Config.Env) {
    if (typeof entry !== 'string' || entry.length > 65536 || /[\r\n\0]/.test(entry))
      throw new Error('Registry environment rejected.');
    const separator = entry.indexOf('='); const name = entry.slice(0, separator);
    const normalized = name.toLowerCase();
    if (separator < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || env.has(normalized))
      throw new Error('Registry environment rejected.');
    env.set(normalized, { name, value: entry.slice(separator + 1) });
  }
  const value = name => { const entry = env.get(name.toLowerCase()); return entry && entry.value; };
  const prefix = 'ContactResolveProductionAuthority__';
  const state = value('DeepIdV2DirectoryAuthority__StatePath');
  if (value('DeepIdV2DirectoryAuthority__Enabled') !== 'true' ||
      value('DeepIdV2DirectoryAuthority__ProofEnabled') !== 'true' ||
      value(prefix + 'Enabled') !== 'true' ||
      !absolute(state) || !absolute(value(prefix + 'TrustedTimeStatePath')) ||
      !absolute(value(prefix + 'TrustedTimeIntegrityKeyPath')) ||
      value('DeepIdV2DirectoryAuthority__NetworkIdHex') !== value(prefix + 'NetworkIdHex'))
    throw new Error('Initialized DID2/time composition rejected.');
  const configured = value(prefix + 'NtsLowerFloorPath');
  const floor = configured || path.posix.join(path.posix.dirname(state), 'nts-lower-floor.state');
  if (!absolute(floor) || value(prefix + 'AutomaticTrustedTimeEnabled') === 'true' && !configured)
    throw new Error('Automatic floor selection rejected.');
  const destinations = new Set();
  for (const mount of source.Mounts) {
    if (mount.Type !== 'bind' || !absolute(mount.Source) || !absolute(mount.Destination) ||
        typeof mount.RW !== 'boolean' || destinations.has(mount.Destination))
      throw new Error('Registry bind mount preservation rejected.');
    destinations.add(mount.Destination);
  }
  const parents = source.Mounts.filter(mount => floor.startsWith(mount.Destination + '/'))
    .sort((a, b) => b.Destination.length - a.Destination.length);
  if (parents.length === 0 || !parents[0].RW || source.Mounts.some(mount => mount.Destination === floor))
    throw new Error('The separate time floor needs its retained writable parent.');
  const targets = [floor, floor + '.lock', floor + '.manual-upgrade-pending', floor + '.manual-upgrade-fence'];
  if ([...env.values()].some(entry => targets.includes(entry.value) && entry.name.toLowerCase() !== (prefix + 'NtsLowerFloorPath').toLowerCase()))
    throw new Error('Time output aliases retained custody.');
  for (const [name, replacement] of [[prefix + 'AutomaticTrustedTimeEnabled', 'true'],
    [prefix + 'NtsObserverExecutablePath', '/usr/local/bin/deep-nts-observer'], [prefix + 'NtsLowerFloorPath', floor]])
    env.set(name.toLowerCase(), { name, value: replacement });
  return { entries: [...env.values()].map(entry => entry.name + '=' + entry.value),
    mounts: source.Mounts.map(mount => `type=bind,src=${mount.Source},dst=${mount.Destination}${mount.RW ? '' : ',readonly'}`),
    network: source.HostConfig.NetworkMode };
}

function docker(args, timeout = 15000) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout, maxBuffer: 4 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('Scoped Registry time Docker operation rejected.');
  return result.stdout;
}

function runOperator(prepared, environment, image, network, action) {
  const name = 'deep-did2-nts-operator-' + randomBytes(16).toString('hex');
  let created = false;
  try {
    const create = ['create', '--name', name, '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--network', network,
      '--env-file', environment, '--entrypoint', '/bin/sh'];
    for (const mount of prepared.mounts) create.push('--mount', mount);
    create.push(image, '-c', 'umask 077; exec dotnet Deep.Registry.Api.dll "$@"', 'deep-time-operator',
      'did2-directory', ...action);
    docker(create); created = true;
    const output = docker(['start', '--attach', name], 45000).trim();
    const completed = JSON.parse(docker(['inspect', '--type', 'container', name]));
    if (completed.length !== 1 || completed[0].State.Running || completed[0].State.ExitCode !== 0)
      throw new Error('Registry time command failed closed.');
    return output;
  } finally { if (created) docker(['rm', '--force', name]); }
}

function parseObservation(output) {
  const report = JSON.parse(output);
  if (Object.keys(report).length !== 4 || report.schema !== 'deep.registry.authenticated-time-observation.v1' ||
      report.reusableFreshnessEvidence !== false || !Number.isSafeInteger(report.observedUnixSeconds) ||
      !Number.isSafeInteger(report.uncertaintySeconds) || report.uncertaintySeconds < 1 ||
      report.observedUnixSeconds <= report.uncertaintySeconds)
    throw new Error('Registry authenticated observation report rejected.');
  return report;
}

function main(args) {
  const names = ['--mode', '--container', '--source-image', '--image', '--revision', '--manual-sha256'];
  if (args.length !== 12 || names.some((name, i) => args[i * 2] !== name) ||
      !['provision', 'observe', 'renew'].includes(args[1]) || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[3]) ||
      !digest(args[5]) || !digest(args[7]) || !/^[0-9a-f]{40}$/.test(args[9]) || !/^[0-9a-f]{64}$/.test(args[11]))
    throw new Error('Exact Registry time operator arguments required.');
  const source = JSON.parse(docker(['inspect', '--type', 'container', args[3]]));
  if (source.length !== 1) throw new Error('Registry source cardinality rejected.');
  const prepared = prepareTimeUpgrade(source[0], { sourceImage: args[5] });
  const image = JSON.parse(docker(['image', 'inspect', args[7]]));
  if (image.length !== 1 || image[0].Id !== args[7] || image[0].Architecture !== 'amd64' || image[0].Os !== 'linux' ||
      !image[0].Config || !image[0].Config.Labels || image[0].Config.Labels['org.opencontainers.image.revision'] !== args[9])
    throw new Error('Registry candidate image binding rejected.');
  process.umask(0o077);
  const temporary = fs.mkdtempSync('/var/tmp/deep-did2-nts-');
  const environment = path.join(temporary, 'operator.env');
  try {
    writePrivateEnvironment(environment, prepared.entries);
    const action = args[1] === 'provision' ? ['provision-nts-floor', args[11]] : ['observe-trusted-time'];
    const output = runOperator(prepared, environment, args[7], args[1] === 'provision' ? 'none' : prepared.network, action);
    if (args[1] === 'provision') {
      if (output !== 'DID2 NTS lower floor provisioned; fresh authenticated acquisition is still required.')
        throw new Error('Registry time provisioning report rejected.');
      process.stdout.write(JSON.stringify({ schema: 'deep.registry.time-upgrade.v1',
        floorProvisioned: true, currentTimeEvidence: false, activeContainerChanged: false }) + '\n');
    } else if (args[1] === 'observe') {
      const report = parseObservation(output);
      process.stdout.write(JSON.stringify(report) + '\n');
    } else {
      const observed = parseObservation(output);
      const validityEntry = prepared.entries.find(entry => entry.toLowerCase().startsWith('deepidv2directoryauthority__headvalidityseconds='));
      const validity = validityEntry ? Number(validityEntry.slice(validityEntry.indexOf('=') + 1)) : 3600;
      if (!Number.isSafeInteger(validity) || validity < 300 || validity > 86400 || observed.uncertaintySeconds > 30)
        throw new Error('Directory head renewal window rejected.');
      const from = observed.observedUnixSeconds - 60;
      // Registry reacquires NTS again for the mutation and independently checks
      // this proposed interval; the earlier report never authorizes the write.
      const renewed = runOperator(prepared, environment, args[7], prepared.network,
        ['refresh-current-head', String(from), String(from + validity)]);
      const lines = /^Refreshed DID2 ADH1 generation\/tree: ([0-9]+)\/([0-9]+)\r?\nRefreshed DID2 ADH1 core hash: ([A-F0-9]{64})$/.exec(renewed);
      if (!lines || !Number.isSafeInteger(Number(lines[1])) || !Number.isSafeInteger(Number(lines[2])))
        throw new Error('Directory head renewal report rejected.');
      process.stdout.write(JSON.stringify({ schema: 'deep.registry.content-preserving-head-renewal.v1',
        generation: Number(lines[1]), treeSize: Number(lines[2]), coreHash: lines[3].toLowerCase(), activeContainerChanged: false }) + '\n');
    }
  } finally {
    // Only this invocation's disposable container and private environment are
    // removed. The activated floor/fence and every retained mount survive.
    if (fs.existsSync(environment)) fs.unlinkSync(environment);
    fs.rmdirSync(temporary);
  }
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (error) {
    const reason = error.message === 'Registry time command failed closed.' ? 'registry-command' :
      error.message === 'Scoped Registry time Docker operation rejected.' ? 'docker-operation' : 'operator-preflight';
    process.stderr.write('DID2 time upgrade failed closed (' + reason + '); retained state was not reset.\n');
    process.exitCode = 1;
  }
}
module.exports = { prepareTimeUpgrade, parseObservation };
