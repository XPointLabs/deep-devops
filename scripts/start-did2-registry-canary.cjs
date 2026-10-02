'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { createHash } = require('crypto');
const { prepareDid2TimeUpgrade } = require('./upgrade-did2-registry-time.cjs');
const { writePrivateEnvironment } = require('./prepare-did2-forward-probe-env.cjs');
let phase = 'preflight';

// Existing-state diagnostic only: no head renewal, ingress, aliases, ports,
// key rotation or provisioning. NTS may advance its retained protected floor.
function prepareCanary(source, expected) {
  const prepared = prepareDid2TimeUpgrade(source, expected);
  if (prepared.network === 'host' || prepared.network === 'none' ||
      !/^[0-9a-f]{40}$/.test(expected.revision || '') ||
      !/^sha256:[0-9a-f]{64}$/.test(expected.image || ''))
    throw new Error('Canary scope rejected.');
  const env = new Map(prepared.entries.map(entry => {
    const index = entry.indexOf('=');
    return [entry.slice(0, index).toLowerCase(), { name: entry.slice(0, index), value: entry.slice(index + 1) }];
  }));
  const value = key => { const entry = env.get(key.toLowerCase()); return entry && entry.value; };
  const renewalKey = 'DeepIdV2DirectoryAuthority__HeadRenewalEnabled';
  const renewal = value(renewalKey);
  if (renewal !== undefined && renewal !== 'false')
    throw new Error('Readiness canary requires no active head renewal.');
  env.set(renewalKey.toLowerCase(), { name: renewalKey, value: 'false' });
  const writes = value('DirectoryPublication__WriteEnabled');
  const mirror = value('DirectoryPublication__MirrorEnabled');
  if ([writes, mirror].some(flag => flag !== undefined && flag !== 'true' && flag !== 'false') ||
      writes === 'true' && (mirror !== 'true' ||
        !/^\/[A-Za-z0-9_./-]+$/.test(value('DirectoryPublication__RequestedDid2Path') || '')))
    throw new Error('Current catalog composition rejected.');
  if (!value('DeepIdV2DirectoryAuthority__LatestHeadFloorPostgreSqlConnectionString'))
    throw new Error('Independent directory floor required.');
  return { ...prepared, entries: [...env.values()].map(item => item.name + '=' + item.value),
    catalogWritesEnabled: writes === 'true', headRenewalEnabled: false };
}

function verifyImage(image, expected) {
  if (!Array.isArray(image) || image.length !== 1 || image[0].Id !== expected.image ||
      image[0].Architecture !== 'amd64' || image[0].Os !== 'linux' ||
      !image[0].Config || !image[0].Config.Labels ||
      image[0].Config.Labels['org.opencontainers.image.revision'] !== expected.revision)
    throw new Error('Canary image binding rejected.');
}

function createArguments(prepared, image, name, environment) {
  if (!/^deep-did2-registry-canary-[a-z0-9-]{1,48}$/.test(name || '') ||
      !/^sha256:[0-9a-f]{64}$/.test(image || '') || !path.posix.isAbsolute(environment))
    throw new Error('Canary create scope rejected.');
  const args = ['create', '--name', name, '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--restart', 'no',
    '--network', prepared.network, '--env-file', environment,
    '--entrypoint', '/bin/sh'];
  for (const mount of prepared.mounts) args.push('--mount', mount);
  args.push(image, '-c', 'umask 077; exec dotnet Deep.Registry.Api.dll');
  return args;
}

function sameSource(source, current, expected) {
  // Docker returns bind mounts from an unordered map. Compare the validated
  // mount closure as a set, not inspection array order; real changes still fail.
  const original = prepareDid2TimeUpgrade(source, expected);
  const retained = prepareDid2TimeUpgrade(current, expected);
  return current.Image === source.Image && current.State.Running &&
    retained.network === original.network &&
    JSON.stringify([...current.Config.Env].sort()) === JSON.stringify([...source.Config.Env].sort()) &&
    JSON.stringify([...retained.mounts].sort()) === JSON.stringify([...original.mounts].sort());
}

function withCurrentView(prepared, file, expectedHash) {
  if (!/^\/[A-Za-z0-9_./-]+$/.test(file || '') || path.posix.normalize(file) !== file ||
      !/^[0-9a-f]{64}$/.test(expectedHash || ''))
    throw new Error('Current view input scope rejected.');
  for (let item = file; item !== '/'; item = path.posix.dirname(item))
    if (fs.lstatSync(item).isSymbolicLink()) throw new Error('Current view input link rejected.');
  const fd = fs.openSync(file, 'r');
  let exact;
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size < 32 || info.size > 65535)
      throw new Error('Current view input bound rejected.');
    exact = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < exact.length) {
      const count = fs.readSync(fd, exact, offset, exact.length - offset, null);
      if (!count) throw new Error('Current view input changed.');
      offset += count;
    }
    if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null) ||
        exact.subarray(0, 4).toString('ascii') !== 'XNV1' ||
        createHash('sha256').update(exact).digest('hex') !== expectedHash)
      throw new Error('Current view independent digest rejected.');
  } finally { fs.closeSync(fd); }
  const destination = '/run/did2-canary-view/current.xnv1';
  if (prepared.mounts.some(mount => mount.includes('dst=/run/did2-canary-view')) ||
      prepared.entries.some(entry => entry.slice(entry.indexOf('=') + 1).startsWith('/run/did2-canary-view')))
    throw new Error('Current view aliases retained inputs.');
  const key = 'DeepIdV2DirectoryAuthority__CurrentXnv1Path';
  const remaining = prepared.entries.filter(entry => entry.slice(0, entry.indexOf('=')).toLowerCase() !== key.toLowerCase());
  // This does not adopt network topology or install traffic keys. Registry's
  // actual signed-view verifier independently decides proof readiness.
  return { ...prepared, entries: [...remaining, key + '=' + destination],
    mounts: [...prepared.mounts, 'type=bind,src=' + file + ',dst=' + destination + ',readonly'] };
}

function docker(args) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 20000, maxBuffer: 4 * 1024 * 1024 });
  if (result.error || result.status !== 0) {
    const error = new Error('Canary Docker operation rejected.');
    const reasons = ['invalid mount', 'no such image', 'read-only file system',
      'no space left', 'already in use', 'permission denied', 'invalid reference'];
    error.closedReason = reasons.find(reason => (result.stderr || '').toLowerCase().includes(reason)) || 'docker-operation';
    throw error;
  }
  return result.stdout;
}

function main(args) {
  const keys = ['--mode', '--container', '--source-image', '--image', '--revision', '--canary'];
  if (![12, 16].includes(args.length) || keys.some((key, index) => args[index * 2] !== key) ||
      args.length === 16 && (args[12] !== '--view-file' || args[14] !== '--view-sha256') ||
      !['preflight', 'start'].includes(args[1]) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[3]) ||
      !/^deep-did2-registry-canary-[a-z0-9-]{1,48}$/.test(args[11]))
    throw new Error('Exact canary arguments required.');
  const expected = { sourceImage: args[5], image: args[7], revision: args[9] };
  const source = JSON.parse(docker(['inspect', '--type', 'container', args[3]]));
  if (!Array.isArray(source) || source.length !== 1) throw new Error('Canary source cardinality rejected.');
  let prepared = prepareCanary(source[0], expected);
  if (args.length === 16) prepared = withCurrentView(prepared, args[13], args[15]);
  verifyImage(JSON.parse(docker(['image', 'inspect', expected.image])), expected);
  let started = false;
  if (args[1] === 'start') {
    process.umask(0o077);
    const temporary = fs.mkdtempSync('/var/tmp/deep-did2-canary-');
    const environment = path.join(temporary, 'canary.env');
    try {
      phase = 'private-environment';
      writePrivateEnvironment(environment, prepared.entries);
      // Recheck source CAS immediately before create. Never remove a colliding
      // name or the failed canary; preserve it for scoped diagnosis.
      phase = 'source-cas';
      const current = JSON.parse(docker(['inspect', '--type', 'container', args[3]]));
      if (!Array.isArray(current) || current.length !== 1 || !sameSource(source[0], current[0], expected))
        throw new Error('Canary source changed before create.');
      phase = 'create';
      docker(createArguments(prepared, expected.image, args[11], environment));
      phase = 'start';
      docker(['start', args[11]]);
      started = true;
    } finally {
      if (fs.existsSync(environment)) fs.unlinkSync(environment);
      fs.rmdirSync(temporary);
    }
  }
  process.stdout.write(JSON.stringify({ schema: 'deep.registry.readiness-canary.v1',
    started, publicPortsPublished: false, ingressChanged: false,
    activeContainerChanged: false, headRenewalEnabled: false,
    catalogWritesEnabled: prepared.catalogWritesEnabled,
    currentTimeOrDeviceEvidence: false }) + '\n');
}
if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write('DID2 readiness canary failed closed (' + phase + '/' +
    (error.closedReason || 'scope-or-filesystem') + '); retained state was not reset.\n'); process.exitCode = 1; }
}
module.exports = { prepareCanary, verifyImage, createArguments, sameSource, withCurrentView };
