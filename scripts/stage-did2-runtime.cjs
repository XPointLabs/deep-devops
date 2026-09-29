'use strict';
// Canonical DevOps asset, vendored byte-identically by the standalone installer.
// This verifies bounded custody inputs, not live protocol authority or delivery.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const reject = () => { throw new Error('DID2 runtime custody/configuration rejected before activation.'); };
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
function noLinks(file) {
  for (let current = path.resolve(file); ; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) reject();
    if (current === path.dirname(current)) break;
  }
}
function read(file, maximum = 65536) {
  noLinks(file);
  const fd = fs.openSync(file, 'r');
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size < 1 || info.size > maximum) reject();
    const bytes = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (!count) reject();
      offset += count;
    }
    if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null)) reject();
    return bytes;
  } finally { fs.closeSync(fd); }
}
function exactHex(bytes, width, prefix = false) {
  try {
    let value = bytes.toString('ascii').trim();
    if (prefix && value.startsWith('0x')) value = value.slice(2);
    if (!new RegExp('^[a-fA-F0-9]{' + width * 2 + '}$').test(value) || /^0+$/.test(value)) reject();
    return value.toLowerCase();
  } finally { bytes.fill(0); }
}
function publicOrigin(value) {
  const uri = new URL(value);
  if (uri.protocol !== 'https:' || uri.href !== value || uri.pathname !== '/' ||
      uri.username || uri.password || uri.search || uri.hash || uri.port || net.isIP(uri.hostname) !== 4) reject();
  const [a,b,c] = uri.hostname.split('.').map(Number);
  if ([0,10,127].includes(a) || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && [0,88,168].includes(b)) || (a === 198 && [18,19].includes(b)) ||
      (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) reject();
  return uri;
}
function registryOrigin(value) {
  if (typeof value !== 'string' || value !== value.trim()) reject();
  const uri = new URL(value);
  if (uri.protocol !== 'https:' || uri.username || uri.password || uri.search || uri.hash ||
      uri.pathname !== '/' || !uri.hostname) reject();
  return uri.href;
}
function stage(source, installation) {
  source = path.resolve(source); installation = path.resolve(installation);
  noLinks(source); noLinks(installation);
  const env = new Map();
  for (const line of read(path.join(installation, '.env.node.prod')).toString('utf8').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1 || env.has(line.slice(0,i))) reject();
    env.set(line.slice(0,i),line.slice(i+1));
  }
  const publicFiles = new Map(), privateFiles = new Map();
  try {
    const manifest = JSON.parse(read(path.join(source,'public','public-assets.v2.json')).toString('utf8'));
    if (manifest.schema !== 'deep-xnode-did2-public-assets.v2' || manifest.authorityOwner !== 'Mr. X' ||
        manifest.currentTimeEvidence !== false || manifest.deploymentEvidence !== false ||
        !Array.isArray(manifest.artifacts) || manifest.artifacts.length < 7 || manifest.artifacts.length > 4096) reject();
    let total = 0;
    for (const item of manifest.artifacts) {
      if (!['xna1','dts1','xvp1','xnv1','xnh1','xnd1','pmt2'].includes(item.Role) ||
          !Number.isSafeInteger(item.Ordinal) || item.Ordinal < 0 || item.Ordinal > 4095 ||
          item.FileName !== item.Role+'.'+String(item.Ordinal).padStart(4,'0')+'.bin' || publicFiles.has(item.FileName)) reject();
      const bytes = read(path.join(source,'public',item.FileName),65535);
      if (bytes.length !== item.Length || digest(bytes) !== item.Sha256Hex) reject();
      total += bytes.length;
      if (total > 32*1024*1024) reject();
      publicFiles.set(item.FileName,bytes);
    }
    for (const [name,pin] of [['genesis.adh1',manifest.genesisHeadSha256],
      ['observer.did2',manifest.observerDid2Sha256],['xnode.did2.json',manifest.configurationSha256]]) {
      const bytes = read(path.join(source,'public',name),65535);
      if (digest(bytes) !== pin) reject();
      publicFiles.set(name,bytes);
    }
    const observer = publicFiles.get('observer.did2');
    if (observer.length !== 2052 || observer.subarray(0,4).toString('ascii') !== 'DID2') reject();
    const config = JSON.parse(publicFiles.get('xnode.did2.json').toString('utf8'));
    if (Object.keys(config).sort().join(',') !== 'DeepIdV2DirectoryProof,DeepIdV2NetworkPlacement,DeepIdV2ReplicaStage' ||
        config.DeepIdV2DirectoryProof.Enabled !== true || config.DeepIdV2NetworkPlacement.Enabled !== true ||
        config.DeepIdV2ReplicaStage.Enabled !== true ||
        config.DeepIdV2DirectoryProof.NetworkIdHex?.toLowerCase() !== env.get('DEEP_XPOINT_NETWORK_ID_HEX') ||
        config.DeepIdV2DirectoryProof.GenesisAuthorityCoreHashHex?.toLowerCase() !== env.get('DEEP_XPOINT_GENESIS_PIN_HEX') ||
        config.DeepIdV2DirectoryProof.RegistryOrigin !== registryOrigin(env.get('DEEP_REGISTRY_URL')) ||
        config.DeepIdV2DirectoryProof.GenesisHeadPath !== '/run/did2-network/genesis.adh1' ||
        config.DeepIdV2NetworkPlacement.PublicObservationDid2Path !== '/run/did2-network/observer.did2') reject();
    const paths = [config.DeepIdV2DirectoryProof.ExactAuthorityPaths,config.DeepIdV2DirectoryProof.ExactTimePolicyPaths,
      config.DeepIdV2NetworkPlacement.ExactPolicyPaths,config.DeepIdV2NetworkPlacement.ExactViewPaths,
      config.DeepIdV2NetworkPlacement.ExactHeadPaths,config.DeepIdV2NetworkPlacement.ExactActiveNodePaths,
      config.DeepIdV2NetworkPlacement.ExactMailboxProjectionPaths];
    if (paths.some(group=>!Array.isArray(group)||!group.length) || paths.flat().length !== manifest.artifacts.length ||
        new Set(paths.flat()).size !== manifest.artifacts.length ||
        paths.flat().some(file=>!file.startsWith('/run/did2-network/') || !publicFiles.has(file.slice(18)))) reject();
    const diagnostic = JSON.parse(read(path.join(source,'appsettings.UAT.json')).toString('utf8'));
    const origin = publicOrigin(diagnostic.PrivacyRouting.PublicPeerBaseUrl);
    if (origin.hostname !== env.get('DEEP_NODE_PUBLIC_IP') || env.get('DEEP_NODE_PUBLIC_PORT') !== '443' ||
        diagnostic.Node.RouterId !== env.get('DEEP_NODE_ED25519_PUBLIC_KEY')) reject();
    const suppliedEd = exactHex(read(path.join(source,'secrets','key_ed25519'),68),32,true);
    const retainedEd = exactHex(read(path.join(installation,'secrets','key_ed25519'),68),32,true);
    if (suppliedEd !== retainedEd) reject();
    const seed = Buffer.from(retainedEd,'hex');
    try {
      const key = crypto.createPrivateKey({format:'der',type:'pkcs8',key:Buffer.concat([
        Buffer.from('302e020100300506032b657004220420','hex'),seed])});
      if (crypto.createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('hex') !== diagnostic.Node.RouterId) reject();
    } finally { seed.fill(0); }
    const protection = read(path.join(source,'secrets','onion-state-protection.key'),32);
    privateFiles.set('onion-state-protection.key',protection);
    const retainedProtection = read(path.join(installation,'secrets','onion-state-protection.key'),32);
    try { if (protection.length !== 32 || protection.every(b=>b===0) ||
      retainedProtection.length !== 32 || !crypto.timingSafeEqual(protection,retainedProtection)) reject();
    } finally { retainedProtection.fill(0); }
    privateFiles.set('key_x25519',Buffer.from(exactHex(read(path.join(source,'secrets','key_x25519'),66),32)+'\n'));
    const peers = diagnostic.PrivacyRouting.Peers;
    if (!Array.isArray(peers) || peers.length !== 2 || new Set(peers.map(p=>p.RouterId)).size !== 2) reject();
    for (const peer of peers) {
      publicOrigin(peer.BaseUrl);
      if (Object.keys(peer).sort().join(',') !== 'BaseUrl,CurrentSpkiSha256,NextSpkiSha256,RouterId' ||
          !/^[a-f0-9]{64}$/.test(peer.RouterId) || /^0+$/.test(peer.RouterId) || peer.RouterId === diagnostic.Node.RouterId ||
          peer.BaseUrl === origin.href || !/^[a-f0-9]{64}$/.test(peer.CurrentSpkiSha256) ||
          !/^[a-f0-9]{64}$/.test(peer.NextSpkiSha256) || /^0+$/.test(peer.CurrentSpkiSha256) ||
          /^0+$/.test(peer.NextSpkiSha256) || peer.CurrentSpkiSha256 === peer.NextSpkiSha256) reject();
    }
    if (new Set(peers.map(p=>p.BaseUrl)).size !== 2) reject();
    for (const name of ['origin','next-origin']) {
      const cert = read(path.join(source,'public',name+'.crt'),8192);
      const key = read(path.join(source,'secrets',name+'.key'),8192);
      privateFiles.set(name+'.key',key);
      const parsed = new crypto.X509Certificate(cert);
      const pin = exactHex(read(path.join(source,'public',name+'.spki-sha256'),66),32);
      if (!parsed.checkPrivateKey(crypto.createPrivateKey(key)) || !parsed.checkIP(origin.hostname) ||
          Date.parse(parsed.validFrom) > Date.now() || Date.parse(parsed.validTo) < Date.now()+86400000 ||
          digest(parsed.publicKey.export({format:'der',type:'spki'})).toLowerCase() !== pin) reject();
      publicFiles.set(name+'.crt',cert); publicFiles.set(name+'.spki-sha256',Buffer.from(pin+'\n'));
    }
    if (publicFiles.get('origin.spki-sha256').equals(publicFiles.get('next-origin.spki-sha256'))) reject();
    // Do not import a diagnostic state snapshot or replace the production volume.
    // The runtime verifies and advances its existing protected floors independently.
    const root = path.join(installation,'config','did2-runtime');
    noLinks(root);
    fs.mkdirSync(root,{recursive:true,mode:0o700});
    let target;
    const current = env.get('DEEP_DID2_CONFIG_FILE');
    if (current) {
      if (!/^\.\/config\/did2-runtime\/bundle-[A-Za-z0-9_-]+\/appsettings\.Production\.json$/.test(current)) reject();
      const retained = path.dirname(path.join(installation,current));
      let same = read(path.join(retained,'appsettings.Production.json')).equals(Buffer.from(JSON.stringify(config,null,2)));
      // A successor adds signed-history paths. Once configuration differs it
      // cannot be an exact rerun; do not require those new files in the old
      // immutable bundle. New inputs and retained identity/state custody have
      // already been checked above. The runtime still verifies the predecessor.
      if (same) for (const [name,bytes] of publicFiles) {
        if (!read(path.join(retained,'public',name)).equals(bytes)) { same = false; break; }
      }
      if (same) for (const [name,bytes] of privateFiles) {
        const old = read(path.join(retained,'secrets',name));
        try { same = old.equals(bytes) && same; } finally { old.fill(0); }
      }
      if (same) target = retained;
    }
    const reused = !!target;
    target ||= fs.mkdtempSync(path.join(root,'bundle-'));
    try {
      if (!reused) {
      for (const sub of ['public','secrets']) fs.mkdirSync(path.join(target,sub),{mode:0o700});
      for (const [name,bytes] of publicFiles) fs.writeFileSync(path.join(target,'public',name),bytes,{flag:'wx',mode:0o600});
      for (const [name,bytes] of privateFiles) fs.writeFileSync(path.join(target,'secrets',name),bytes,{flag:'wx',mode:0o600});
      fs.writeFileSync(path.join(target,'appsettings.Production.json'),JSON.stringify(config,null,2),{flag:'wx',mode:0o600});
      }
      const relative = './'+path.relative(installation,target).split(path.sep).join('/');
      const updates = {
        // UAT is a diagnostic runtime profile on the authorized production fleet,
        // not a separate environment or permission to bypass release gates.
        DEEP_NODE_RUNTIME_ENVIRONMENT:'UAT',
        DEEP_DID2_CONFIG_FILE:relative+'/appsettings.Production.json',DEEP_DID2_PUBLIC_DIR:relative+'/public',
        DEEP_DID2_ORIGIN:origin.href,DEEP_INGRESS_HOST:origin.hostname,DEEP_INGRESS_CERTIFICATE_PROFILE:'pinned-self-issued',
        DEEP_NODE_X25519_PRIVATE_KEY_FILE:relative+'/secrets/key_x25519',
        DEEP_NODE_ONION_STATE_PROTECTION_FILE:relative+'/secrets/onion-state-protection.key',
        DEEP_INGRESS_CURRENT_CERT_FILE:relative+'/public/origin.crt',DEEP_INGRESS_CURRENT_KEY_FILE:relative+'/secrets/origin.key',
        DEEP_INGRESS_CURRENT_SPKI_FILE:relative+'/public/origin.spki-sha256',
        DEEP_INGRESS_NEXT_CERT_FILE:relative+'/public/next-origin.crt',DEEP_INGRESS_NEXT_KEY_FILE:relative+'/secrets/next-origin.key',
        DEEP_INGRESS_NEXT_SPKI_FILE:relative+'/public/next-origin.spki-sha256'
      };
      peers.forEach((peer,index)=>{
        const prefix='DEEP_PRIVACY_PEER_'+(index+1)+'_';
        updates[prefix+'ROUTER_ID']=peer.RouterId; updates[prefix+'BASE_URL']=peer.BaseUrl;
        updates[prefix+'CURRENT_SPKI_SHA256']=peer.CurrentSpkiSha256; updates[prefix+'NEXT_SPKI_SHA256']=peer.NextSpkiSha256;
      });
      return {updates,records:manifest.artifacts.length};
    } catch(error) { if (!reused) fs.rmSync(target,{recursive:true}); throw error; }
  } finally { for(const bytes of privateFiles.values()) bytes.fill(0); }
}
module.exports={stage};
if(require.main===module) {
  try {
    if(process.argv.length!==5) reject();
    const output=path.resolve(process.argv[4]), root=path.resolve(process.argv[3])+path.sep;
    noLinks(output);
    if(!output.startsWith(root) || fs.existsSync(output)) reject();
    const result=stage(process.argv[2],process.argv[3]);
    fs.writeFileSync(output,Object.entries(result.updates).map(([k,v])=>k+'='+v).join('\n')+'\n',{flag:'wx',mode:0o600});
    console.log('DID2 runtime inputs staged; live TLS/publication remains unverified.');
  } catch { console.error('DID2 runtime inputs rejected; activation was not attempted.'); process.exitCode=1; }
}
