'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const maximumInspectionBytes = 4 * 1024 * 1024;
const overrideKeys = new Set([
  'registry__statepath',
  'contactresolveproductionauthority__trustedtimestatepath',
  'contactresolveproductionauthority__requestledgerrootpath',
  'deepidv2directoryauthority__latestheadfloorpostgresqlconnectionstring',
  'deepidv2directoryauthority__statepath',
  'deepidv2directoryauthority__proofrequestledgerrootpath'
]);

function prepareDid2ForwardProbeEnvironment(inspection, expected) {
  if (!Array.isArray(inspection) || inspection.length !== 1 ||
      !inspection[0] || !inspection[0].Config ||
      !Array.isArray(inspection[0].Config.Env)) {
    throw new Error('Expected exactly one Docker Config.Env inspection.');
  }
  if (!expected || !expected.state || !expected.ledger ||
      !expected.registryState || !expected.trustedTime || !expected.contactLedger ||
      !expected.floorSchema || !expected.adf1 ||
      !/^[A-Za-z0-9_.-]+$/.test(expected.floorSchema)) {
    throw new Error('Expected UAT state, ledger, floor schema and ADF1 names.');
  }

  const selected = new Map();
  const replaced = new Set();
  for (const entry of inspection[0].Config.Env) {
    if (typeof entry !== 'string' || entry.includes('\n') ||
        entry.includes('\r') || entry.includes('\0')) {
      throw new Error('Docker environment has a malformed entry.');
    }
    const separator = entry.indexOf('=');
    if (separator < 1) {
      throw new Error('Docker environment has a malformed entry.');
    }
    const name = entry.slice(0, separator);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      throw new Error('Docker environment has an invalid key name.');
    }
    const normalized = name.toLowerCase();
    if (selected.has(normalized)) {
      if (!overrideKeys.has(normalized)) {
        throw new Error('Unexpected repeated environment key: ' + normalized);
      }
      replaced.add(normalized);
    }
    selected.set(normalized, { name, value: entry.slice(separator + 1) });
  }
  if (replaced.size !== overrideKeys.size ||
      [...overrideKeys].some(key => !replaced.has(key))) {
    throw new Error('The expected six UAT override keys were not all present.');
  }

  const value = name => {
    const item = selected.get(name.toLowerCase());
    if (!item || item.value.length === 0) {
      throw new Error('Required UAT key is absent: ' + name.toLowerCase());
    }
    return item.value;
  };
  if (value('ASPNETCORE_ENVIRONMENT') !== 'UAT' ||
      value('DeepIdV2DirectoryAuthority__Enabled') !== 'true' ||
      value('DeepIdV2DirectoryAuthority__ProofEnabled') !== 'true' ||
      value('DeepIdV2DirectoryAuthority__ProductionCutoverAttested') !== 'false') {
    throw new Error('The source container is not a closed DID2 UAT probe.');
  }
  const state = value('DeepIdV2DirectoryAuthority__StatePath');
  const ledger = value('DeepIdV2DirectoryAuthority__ProofRequestLedgerRootPath');
  const registryState = value('Registry__StatePath');
  const trustedTime = value('ContactResolveProductionAuthority__TrustedTimeStatePath');
  const contactLedger = value('ContactResolveProductionAuthority__RequestLedgerRootPath');
  const adf1 = value('DeepIdV2DirectoryAuthority__ForwardCheckpointPaths__0');
  const floor = value('DeepIdV2DirectoryAuthority__LatestHeadFloorPostgreSqlConnectionString');
  const searchPath = floor.split(';')
    .map(part => /^\s*Search Path\s*=\s*(.*?)\s*$/i.exec(part))
    .filter(Boolean);
  if (!path.posix.isAbsolute(state) || path.posix.basename(state) !== expected.state ||
      !path.posix.isAbsolute(ledger) || path.posix.basename(ledger) !== expected.ledger ||
      !path.posix.isAbsolute(registryState) || path.posix.basename(registryState) !== expected.registryState ||
      !path.posix.isAbsolute(trustedTime) || path.posix.basename(trustedTime) !== expected.trustedTime ||
      !path.posix.isAbsolute(contactLedger) || path.posix.basename(contactLedger) !== expected.contactLedger ||
      !path.posix.isAbsolute(adf1) || path.posix.basename(adf1) !== expected.adf1 ||
      searchPath.length !== 1 || searchPath[0][1] !== expected.floorSchema) {
    throw new Error('The selected UAT state, ledger, floor or ADF1 differs from the expected closure.');
  }
  return {
    entries: [...selected.values()].map(item => item.name + '=' + item.value),
    replacedKeys: [...replaced].sort()
  };
}

function writePrivateEnvironment(output, entries) {
  if (!path.isAbsolute(output) || !Array.isArray(entries) || entries.length === 0) {
    throw new Error('A new absolute private output and nonempty environment are required.');
  }
  const parent = path.dirname(output);
  const info = fs.lstatSync(parent);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('The output parent must be an existing real directory.');
  }
  let descriptor;
  let created = false;
  try {
    descriptor = fs.openSync(output, 'wx', 0o600);
    created = true;
    fs.writeSync(descriptor, entries.join('\n') + '\n');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (created) fs.unlinkSync(output);
    throw new Error('The private UAT environment could not be written.');
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 18 ||
      args[0] !== '--container' || args[2] !== '--output' ||
      args[4] !== '--expect-state' || args[6] !== '--expect-ledger' ||
      args[8] !== '--expect-registry-state' || args[10] !== '--expect-trusted-time' ||
      args[12] !== '--expect-contact-ledger' || args[14] !== '--expect-floor-schema' ||
      args[16] !== '--expect-adf1' ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[1])) {
    throw new Error('Usage: --container NAME --output ABS --expect-state BASENAME --expect-ledger BASENAME --expect-registry-state BASENAME --expect-trusted-time BASENAME --expect-contact-ledger BASENAME --expect-floor-schema NAME --expect-adf1 BASENAME');
  }
  const result = spawnSync('docker', ['inspect', '--type', 'container', args[1]],
    { encoding: 'utf8', maxBuffer: maximumInspectionBytes });
  if (result.error || result.status !== 0) {
    throw new Error('Docker inspection failed.');
  }
  let inspection;
  try { inspection = JSON.parse(result.stdout); }
  catch { throw new Error('Docker inspection is not valid JSON.'); }
  const prepared = prepareDid2ForwardProbeEnvironment(inspection, {
    state: args[5], ledger: args[7], registryState: args[9], trustedTime: args[11],
    contactLedger: args[13], floorSchema: args[15], adf1: args[17]
  });
  writePrivateEnvironment(args[3], prepared.entries);
  process.stdout.write(`Private DID2 UAT environment prepared: ${prepared.entries.length} unique keys; ${prepared.replacedKeys.length} reviewed overrides.\n`);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    process.stderr.write(error.message + '\n');
    process.exitCode = 1;
  }
}

module.exports = { prepareDid2ForwardProbeEnvironment, writePrivateEnvironment };
