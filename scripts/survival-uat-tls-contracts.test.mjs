import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.survival-uat-tls.dev.yml'), 'utf8');
const proxy = fs.readFileSync(path.join(root, 'config', 'survival-uat-tls', 'haproxy.cfg'), 'utf8');
const fixture = fs.readFileSync(path.join(root, 'tools', 'membership-fixture', 'Program.cs'), 'utf8');
const bootstrap = fs.readFileSync(path.join(root, 'scripts', 'Initialize-SurvivalUatTls.ps1'), 'utf8');

for (const service of ['xnode-1','xnode-2','xnode-3','xnode-4','xnode-5','xnode-6','registry','storage','file','push','calls']) {
  assert.ok(compose.includes(`${service}: { ports: !reset [] }`), `${service} must not publish cleartext`);
}
assert.match(compose, /haproxy:3\.2\.4-alpine3\.22@sha256:[0-9a-f]{64}/);
assert.match(compose, /SURVIVAL_UAT_TLS_SECRET_DIR:\?set SURVIVAL_UAT_TLS_SECRET_DIR/);
assert.doesNotMatch(compose, /41820:41820/);
assert.match(compose, /41824:8080/);
assert.match(compose, /\/public:ro/);
assert.match(compose, /--advertised-scheme, https/);
assert.match(compose, /DEEP_UAT_XNODE_1_UPSTREAM: xnode-1/);
assert.match(proxy, /ssl-min-ver TLSv1\.2 no-tls-tickets/);
assert.doesNotMatch(proxy, /verify none|ca-ignore-err|ssl_c_verify/);
assert.match(proxy, /deny_status 404/);
assert.match(proxy, /http-request del-header Forwarded/);
assert.match(proxy, /req\.hdr\(content-length\).*33554432/);
assert.equal((proxy.match(/acl public_post path \/api\/ingress\/v1\/frame/g) ?? []).length, 6);
assert.equal((proxy.match(/\/api\/network\/privacy-contact/g) ?? []).length, 6);
assert.doesNotMatch(proxy, /api\/session\/rpc|api\/peer\/onion|api\/network\/contact/);
assert.match(proxy, /server xnode-1 "\$DEEP_UAT_XNODE_1_UPSTREAM:8080" check/);
assert.match(fixture, /advertisedScheme\}:\/\//);
assert.match(bootstrap, /subjectAltName=IP:\$LanHost/);
assert.match(bootstrap, /basicConstraints=critical,CA:TRUE,pathlen:0/);
assert.match(bootstrap, /verify_ip/);
assert.match(bootstrap, /crlDistributionPoints=URI:http:\/\/\$\{LanHost\}:41824/);
assert.doesNotMatch(bootstrap, /InstallWindowsCurrentUserRoot/);
assert.doesNotMatch(bootstrap, /expected-pin|SPKI|DangerousAcceptAny/);

console.log('survival UAT TLS contracts passed');
