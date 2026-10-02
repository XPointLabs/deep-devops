'use strict';
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const { spawnSync } = require('child_process');
const target = '/etc/nginx/snippets/deep-did2-https-uat.conf';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function addHistory(text, port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || text.length > 16384)
    throw new Error('Route input scope rejected.');
  const routes = ['/api/v2/account-directory/genesis-admissions', '/api/v2/account-directory/proofs',
    '/api/v2/network/closure', '/health/did2/ready'];
  const block = endpoint => `location = ${endpoint} {\n  proxy_pass http://127.0.0.1:${port};\n  include /etc/nginx/snippets/deep-did2-https-proxy.conf;\n}\n`;
  // Closed existing snippet only; never rewrite a server block, TLS setting,
  // arbitrary upstream, auth header, other location or another service.
  if (text !== routes.map(block).join('')) throw new Error('Retained route closure rejected.');
  return text.replace(block(routes[1]), block('/api/v2/account-directory/history') + block(routes[1]));
}
function regular(file) {
  for (let current = file; current !== '/'; current = path.posix.dirname(current))
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Route link rejected.');
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.size < 1 || info.size > 16384) throw new Error('Route file rejected.');
  return info;
}
function nginx(args) {
  const result = spawnSync('nginx', args, { encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
  if (result.error || result.status !== 0) throw new Error('Scoped nginx operation rejected.');
}
function main(args) {
  const keys=['--mode','--sha256','--loopback-port','--backup'];
  if(args.length!==8 || keys.some((k,i)=>args[i*2]!==k) || !['preflight','apply'].includes(args[1]) ||
      !/^[0-9a-f]{64}$/.test(args[3]) || !/^[1-9][0-9]{3,4}$/.test(args[5]) ||
      !/^\/var\/tmp\/deep-registry-did2-[A-Za-z0-9-]+\/[A-Za-z0-9.-]+\.conf$/.test(args[7]))
    throw new Error('Exact route arguments required.');
  const info=regular(target); const original=fs.readFileSync(target);
  if(hash(original)!==args[3]) throw new Error('Route source CAS rejected.');
  const updated=Buffer.from(addHistory(original.toString('utf8'),Number(args[5])));
  nginx(['-t']);
  let applied=false;
  if(args[1]==='apply') {
    const parent=path.posix.dirname(args[7]);
    for(let current=parent;current!=='/';current=path.posix.dirname(current))
      if(fs.lstatSync(current).isSymbolicLink()) throw new Error('Backup scope rejected.');
    if(hash(fs.readFileSync(target))!==args[3]) throw new Error('Route changed.');
    fs.writeFileSync(args[7],original,{flag:'wx',mode:0o600});
    const temporary=target+'.history-'+crypto.randomBytes(12).toString('hex');
    try {
      fs.writeFileSync(temporary,updated,{flag:'wx',mode:info.mode & 0o777});
      fs.chownSync(temporary,info.uid,info.gid);
      fs.renameSync(temporary,target);
      try { nginx(['-t']); }
      catch(error) {
        // Restore only this invocation's exact snippet, never state or floors.
        fs.writeFileSync(temporary,original,{flag:'wx',mode:info.mode & 0o777});
        fs.chownSync(temporary,info.uid,info.gid);fs.renameSync(temporary,target);throw error;
      }
      nginx(['-s','reload']); applied=true;
    } finally { if(fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  }
  console.log(JSON.stringify({schema:'deep.registry.history-route.v1',applied,
    snippetSha256:hash(applied?updated:original),otherConfigurationChanged:false,deviceDeliveryVerified:false}));
}
if(require.main===module) { try{main(process.argv.slice(2));}catch{console.error('DID2 history route failed closed; retained private backup and authority floors were not reset.');process.exitCode=1;} }
module.exports={addHistory};
