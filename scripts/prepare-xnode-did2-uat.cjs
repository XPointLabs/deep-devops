'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const names = ['seed1', 'seed2', 'seed3'];
const fail = () => { throw new Error('DID2 UAT preparation rejected its bounded custody or configuration inputs.'); };
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();

function noLinks(candidate) {
  for (let current = path.resolve(candidate); ; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) fail();
    if (current === path.dirname(current)) break;
  }
}
function read(candidate, maximum = 65535) {
  noLinks(candidate);
  const descriptor = fs.openSync(candidate, 'r');
  try {
    const info = fs.fstatSync(descriptor);
    if (!info.isFile() || info.size < 1 || info.size > maximum) fail();
    const bytes = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) fail();
      offset += count;
    }
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, null) !== 0) fail();
    return bytes;
  } finally { fs.closeSync(descriptor); }
}
function hex(bytes, length, permitPrefix = false) {
  let value;
  try { value = bytes.toString('ascii').trim(); }
  finally { bytes.fill(0); }
  if (permitPrefix && value.startsWith('0x')) value = value.slice(2);
  if (!new RegExp('^[0-9a-fA-F]{' + (length * 2) + '}$').test(value) || /^0+$/.test(value)) fail();
  return value.toLowerCase();
}
function environment(file) {
  const entries = new Map();
  for (const line of read(file, 65536).toString('utf8').split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1 || entries.has(line.slice(0, separator))) fail();
    entries.set(line.slice(0, separator), line.slice(separator + 1));
  }
  const id = entries.get('DEEP_NODE_ED25519_PUBLIC_KEY');
  const ip = entries.get('DEEP_NODE_PUBLIC_IP');
  if (!/^[0-9a-f]{64}$/.test(id || '') || /^0+$/.test(id) || net.isIP(ip || '') !== 4) fail();
  const octets = ip.split('.').map(Number);
  if ([0, 10, 127].includes(octets[0]) || octets[0] >= 224 ||
      (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && (octets[1] === 168 || (octets[1] === 0 && octets[2] <= 2))) ||
      (octets[0] === 198 && [18, 19].includes(octets[1])) ||
      (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) ||
      (octets[0] === 203 && octets[1] === 0 && octets[2] === 113)) fail();
  return { id, origin: 'https://' + ip + '/' };
}

function prepare(input) {
  if (!names.includes(input.node) || !path.isAbsolute(input.output)) fail();
  const output = path.resolve(input.output);
  noLinks(output);
  if (fs.existsSync(output) || !fs.statSync(path.dirname(output)).isDirectory()) fail();
  const manifest = JSON.parse(read(path.join(input.assets, 'public-assets.v2.json')).toString('utf8'));
  if (manifest.schema !== 'deep-xnode-did2-public-assets.v2' || manifest.authorityOwner !== 'Mr. X' ||
      manifest.currentTimeEvidence !== false || manifest.deploymentEvidence !== false ||
      !Array.isArray(manifest.artifacts) || manifest.artifacts.length < 8 || manifest.artifacts.length > 4096) fail();
  const publicFiles = new Map();
  const roles = ['xna1', 'dts1', 'xvp1', 'xnv1', 'xnh1', 'xnd1', 'pmt2', 'pma2'];
  for (const entry of manifest.artifacts) {
    if (!roles.includes(entry.Role) ||
        !Number.isSafeInteger(entry.Ordinal) || entry.Ordinal < 0 || entry.Ordinal > 4095 ||
        entry.FileName !== entry.Role + '.' + String(entry.Ordinal).padStart(4, '0') + '.bin' ||
        publicFiles.has(entry.FileName)) fail();
    const bytes = read(path.join(input.assets, entry.FileName));
    if (bytes.length !== entry.Length || hash(bytes) !== entry.Sha256Hex) fail();
    publicFiles.set(entry.FileName, bytes);
  }
  for (const role of roles) {
    const ordinals = manifest.artifacts.filter(entry => entry.Role === role)
      .map(entry => entry.Ordinal).sort((a, b) => a - b);
    if (!ordinals.length || ordinals.some((ordinal, index) => ordinal !== index)) fail();
  }
  const head = read(path.join(input.assets, 'genesis.adh1'));
  if (hash(head) !== manifest.genesisHeadSha256) fail();
  const observer = read(path.join(input.assets, 'observer.did2'), 2052);
  if (observer.length !== 2052 || observer.subarray(0, 4).toString('ascii') !== 'DID2' ||
      hash(observer) !== manifest.observerDid2Sha256) fail();
  publicFiles.set('genesis.adh1', head);
  publicFiles.set('observer.did2', observer);
  publicFiles.set('public-assets.v2.json', read(path.join(input.assets, 'public-assets.v2.json')));
  const configurationBytes = read(path.join(input.assets, 'xnode.did2.json'));
  if (hash(configurationBytes) !== manifest.configurationSha256) fail();
  const config = JSON.parse(configurationBytes.toString('utf8'));
  publicFiles.set('xnode.did2.json', configurationBytes);
  if (Object.keys(config).sort().join(',') !== 'DeepIdV2DirectoryProof,DeepIdV2NetworkPlacement,DeepIdV2ReplicaStage' ||
      config.DeepIdV2DirectoryProof.Enabled !== true || config.DeepIdV2NetworkPlacement.Enabled !== true ||
      config.DeepIdV2ReplicaStage.Enabled !== true) fail();
  const publicPaths = [config.DeepIdV2DirectoryProof.ExactAuthorityPaths,
    config.DeepIdV2DirectoryProof.ExactTimePolicyPaths,
    config.DeepIdV2NetworkPlacement.ExactPolicyPaths, config.DeepIdV2NetworkPlacement.ExactViewPaths,
    config.DeepIdV2NetworkPlacement.ExactHeadPaths, config.DeepIdV2NetworkPlacement.ExactActiveNodePaths,
    config.DeepIdV2NetworkPlacement.ExactMailboxProjectionPaths];
  // PMA2 is retained public distribution, not a placement/receive authority
  // path. The Protocol exporter deliberately omits it from this host config.
  const placementFiles = new Set(manifest.artifacts.filter(entry => entry.Role !== 'pma2').map(entry => entry.FileName));
  if (publicPaths.some(group => !Array.isArray(group) || group.length < 1) ||
      publicPaths.flat().length !== placementFiles.size ||
      new Set(publicPaths.flat()).size !== placementFiles.size ||
      publicPaths.flat().some(value => !value.startsWith('/run/did2-network/') ||
        !placementFiles.has(value.slice('/run/did2-network/'.length))) ||
      config.DeepIdV2DirectoryProof.GenesisHeadPath !== '/run/did2-network/genesis.adh1' ||
      config.DeepIdV2NetworkPlacement.PublicObservationDid2Path !== '/run/did2-network/observer.did2') fail();
  const candidates = names.map(name => {
    const candidate = environment(path.join(input[name], '.env.node.prod'));
    const rollover = path.join(input.rollover, name);
    const current = hex(read(path.join(rollover, 'current-origin.spki-sha256'), 66), 32);
    const next = hex(read(path.join(rollover, 'next-origin.spki-sha256'), 66), 32);
    if (current === next) fail();
    return { name, ...candidate, current, next };
  });
  if (new Set(candidates.map(value => value.id)).size !== 3 ||
      new Set(candidates.map(value => value.origin)).size !== 3) fail();
  const selected = candidates.find(value => value.name === input.node);
  const secretFiles = new Map();
  try {
    const ed = hex(read(path.join(input[input.node], 'secrets', 'key_ed25519'), 68), 32, true);
    const seed = Buffer.from(ed, 'hex');
    try {
      const privateKey = crypto.createPrivateKey({ format: 'der', type: 'pkcs8',
        key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]) });
      const derived = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
      if (derived.subarray(-32).toString('hex') !== selected.id) fail();
    } finally { seed.fill(0); }
    secretFiles.set('key_ed25519', Buffer.from(ed + '\n', 'ascii'));
    const onion = read(path.join(input.rollover, input.node, 'current.x25519.seed'), 32);
    try {
      if (onion.length !== 32 || onion.every(value => value === 0)) fail();
      secretFiles.set('key_x25519', Buffer.from(onion.toString('hex') + '\n', 'ascii'));
    } finally { onion.fill(0); }
    const protection = read(path.join(input[input.node], 'secrets', 'onion-state-protection.key'), 32);
    if (protection.length !== 32 || protection.every(value => value === 0)) { protection.fill(0); fail(); }
    secretFiles.set('onion-state-protection.key', protection);
    for (const epoch of ['current', 'next']) {
      const certificate = read(path.join(input.rollover, input.node, epoch + '-origin.cer'), 8192);
      const key = read(path.join(input.rollover, input.node, epoch + '-origin.key'), 8192);
      const prefix = epoch === 'current' ? 'origin' : 'next-origin';
      secretFiles.set(prefix + '.key', key);
      const parsed = new crypto.X509Certificate(certificate);
      if (!parsed.checkPrivateKey(crypto.createPrivateKey(key)) ||
          hash(parsed.publicKey.export({ format: 'der', type: 'spki' })).toLowerCase() !== selected[epoch]) fail();
      publicFiles.set(prefix + '.crt', certificate);
      publicFiles.set(prefix + '.spki-sha256', Buffer.from(selected[epoch] + '\n', 'ascii'));
    }
    Object.assign(config, {
      Logging: { LogLevel: { Default: 'Warning', 'Microsoft.AspNetCore': 'Warning' } },
      Node: { DataDirectory: '/var/lib/xnode', RouterId: selected.id,
        Ed25519PrivateKeyPath: '/run/secrets/key_ed25519', IsRelay: true,
        ApiListenUrl: 'http://0.0.0.0:8080', PeerRpcListenUrl: 'http://0.0.0.0:8081',
        ManagedIngressH2ListenUrl: '', PrivacyPeerH2ListenUrl: '' },
      Vless: { Enabled: false, MockProcess: false }, RegistryHeartbeat: { Enabled: false },
      ContactService: { RuntimeActivation: false, MapReplicaEndpoint: false },
      GroupControlService: { RuntimeActivation: false, MapReplicaEndpoint: false },
      RequiredTerminals: { Contact: false, GroupControl: false },
      PrivacyRouting: { Enabled: true, X25519PrivateKeyPath: '/run/secrets/key_x25519',
        PublicPeerBaseUrl: selected.origin, StateProtectionKeyPath: '/run/secrets/onion-state-protection.key',
        ReplayStateRelativePath: 'did2-onion-replay.state', EntropyStateRelativePath: 'did2-onion-entropy.state',
        KeyVaultDirectoryRelativePath: 'did2-onion-key-vault', AllowInsecureHttpPeerTransport: false,
        Peers: candidates.filter(value => value !== selected).map(value => ({ RouterId: value.id,
          BaseUrl: value.origin, CurrentSpkiSha256: value.current, NextSpkiSha256: value.next })) }
    });
    const staging = output + '.staging-' + crypto.randomUUID();
    fs.mkdirSync(staging, { mode: 0o700 });
    try {
      for (const directory of ['public', 'secrets', 'state']) fs.mkdirSync(path.join(staging, directory), { mode: 0o700 });
      for (const [name, bytes] of publicFiles) fs.writeFileSync(path.join(staging, 'public', name), bytes, { flag: 'wx', mode: 0o600 });
      for (const [name, bytes] of secretFiles) fs.writeFileSync(path.join(staging, 'secrets', name), bytes, { flag: 'wx', mode: 0o600 });
      fs.writeFileSync(path.join(staging, 'appsettings.UAT.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
      if (fs.existsSync(output)) fail();
      fs.renameSync(staging, output);
    } finally { if (fs.existsSync(staging)) fs.rmSync(staging, { recursive: true }); }
  } finally { for (const bytes of secretFiles.values()) bytes.fill(0); }
  return { publicRecords: manifest.artifacts.length, peers: 2, carrierEnabled: false, deploymentEvidence: false };
}

module.exports = { prepare };
if (require.main === module) {
  try {
    const allowed = new Set(['assets', 'seed1', 'seed2', 'seed3', 'rollover', 'node', 'output']);
    const input = {};
    const argv = process.argv.slice(2);
    if (argv.length !== allowed.size * 2) fail();
    for (let index = 0; index < argv.length; index += 2) {
      const name = argv[index].slice(2);
      if (!argv[index].startsWith('--') || !allowed.has(name) || name in input || !argv[index + 1]) fail();
      input[name] = argv[index + 1];
    }
    console.log(JSON.stringify(prepare(input)));
  } catch { console.error('DID2 UAT preparation rejected; no production state was changed.'); process.exitCode = 1; }
}
