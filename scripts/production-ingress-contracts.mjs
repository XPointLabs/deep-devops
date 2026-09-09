import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.node.prod.yml'), 'utf8');
const config = fs.readFileSync(path.join(root, 'config/production-ingress/haproxy.cfg.template'), 'utf8');
const entrypoint = fs.readFileSync(path.join(root, 'scripts/production-ingress-entrypoint.sh'), 'utf8');
const preflight = fs.readFileSync(path.join(root, 'scripts/production-ingress-spki.mjs'), 'utf8');
const storage = fs.readFileSync(path.join(root, 'tools/storage-service/storage-service-runtime.mjs'), 'utf8');
const preflightBlock = compose.match(/^  ingress-preflight:[\s\S]*?(?=^  ingress:)/m)?.[0] ?? '';
const ingressBlock = compose.match(/^  ingress:[\s\S]*?(?=^  xnode:)/m)?.[0] ?? '';

const checks = [
  ['only ingress publishes ports', /^ {4}ports:/m.test(ingressBlock) && !/^ {4}ports:/m.test(compose.replace(ingressBlock, ''))],
  ['ingress publishes 443', /DEEP_INGRESS_HTTPS_BIND:-443}:443/.test(compose)],
  ['ingress image is digest pinned', /haproxy:3\.2\.22-alpine3\.24@sha256:[0-9a-f]{64}/.test(compose)],
  ['upstream network is internal', /ingress-upstream:\s*\n {4}internal: true/.test(compose)],
  ['plaintext listeners bind only loopback and internal IPs', !/ASPNETCORE_URLS:.*0\.0\.0\.0/.test(compose) && /LISTEN_HOST: 172\.31\.241\.20/.test(compose) && /server\.listen\(port, listenHost/.test(storage)],
  ['storage RPC is pinned to internal address', /StorageRpc__BaseUrl: http:\/\/172\.31\.241\.20:8080/.test(compose)],
  ['native privacy ingress is the only public message route', /acl public_post path \/api\/ingress\/v1\/frame/.test(config) && !/api\/session\/rpc|api\/peer\/onion/.test(config)],
  ['privacy peer route is isolated to peer listener', /acl peer_post path \/api\/peer\/privacy\/v1\/frame/.test(config) && /use_backend xnode_peer if post_method peer_post/.test(config)],
  ['independent privacy key is mounted as a secret', /PrivacyRouting__X25519PrivateKeyPath: \/run\/secrets\/node-x25519-private-key/.test(compose) && /source: node-x25519-private-key/.test(compose)],
  ['ONION durable state is role-bound and protected', /PrivacyRouting__StateProtectionKeyPath: \/run\/secrets\/node-onion-state-protection/.test(compose) && /PrivacyRouting__ReceivePosition: \$\{DEEP_NODE_ONION_RECEIVE_POSITION:\?set/.test(compose) && /PrivacyRouting__ReplayStateRelativePath: privacy-routing\/replay\.state/.test(compose) && /source: node-onion-state-protection/.test(compose)],
  ['VLESS credentials use only protected file paths', /Vless__ClientIdFile: \/run\/secrets\/node-vless-client-id/.test(compose) && /Vless__Reality__PrivateKeyFile: \/run\/secrets\/node-reality-private-key/.test(compose) && !/Vless__ClientId:|Vless__Reality__PrivateKey:/.test(compose)],
  ['VLESS credential values are absent from the compose environment model', /source: node-vless-client-id[\s\S]*target: node-vless-client-id/.test(compose) && /source: node-reality-private-key[\s\S]*target: node-reality-private-key/.test(compose) && !/DEEP_NODE_VLESS_CLIENT_ID(?!_FILE)|DEEP_NODE_REALITY_PRIVATE_KEY(?!_FILE)/.test(compose)],
  ['privacy peers require router authority and dual SPKI pins', /PrivacyRouting__Peers__0__RouterId:/.test(compose) && /PrivacyRouting__Peers__0__BaseUrl:/.test(compose) && /PrivacyRouting__Peers__0__CurrentSpkiSha256:/.test(compose) && /PrivacyRouting__Peers__0__NextSpkiSha256:/.test(compose) && /PrivacyRouting__AllowInsecureHttpPeerTransport: "false"/.test(compose)],
  ['three-router seed topology configures exactly two distinct next hops per node', (compose.match(/PrivacyRouting__Peers__\d+__RouterId:/g) ?? []).length === 2 && !/DEEP_PRIVACY_PEER_3_/.test(compose)],
  ['development UAT private peer addresses are absent', !/DevelopmentUatPrivatePeerAddresses/.test(compose)],
  ['TLS 1.2 minimum', /ssl-min-ver TLSv1\.2/.test(config)],
  ['unknown SNI is rejected while IP clients without SNI use pinned HTTPS', /tcp-request content reject if has_sni !deep_https_sni !deep_reality_sni/.test(config) && /default_backend local_https_terminator/.test(config)],
  ['host and SNI are exact allowlists', /ssl_fc_sni -i \$\{DEEP_INGRESS_HOST}/.test(config) && /hdr\(host\).* -i \$\{DEEP_INGRESS_HOST}/.test(config)],
  ['forwarding headers stripped', ['Forwarded', 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Port', 'X-Forwarded-Proto', 'X-Real-IP', 'True-Client-IP', 'CF-Connecting-IP', 'Client-IP'].every((name) => config.includes(`del-header ${name}`))],
  ['public response hardening uses request-scoped transaction state', /set-var\(txn\.is_public_post\).*if post_method public_post/.test(config) && (config.match(/var\(txn\.is_public_post\) -m bool/g) ?? []).length === 3],
  ['admin paths absent', !/\/status|\/metrics|\/stats|\/debug/.test(config)],
  ['quorum path is source restricted', /quorum_post path \/api\/staking\/quorum\/sign/.test(config) && /quorum_source src \$\{DEEP_QUORUM_COORDINATOR_CIDR}/.test(config) && /post_method quorum_post quorum_source/.test(config)],
  ['request body bounded', /content_length_too_large req\.hdr\(content-length\) -m int gt \$\{DEEP_INGRESS_MAX_BODY_BYTES}/.test(config) && /has_transfer_encoding/.test(config) && /single_content_length/.test(config)],
  ['timeouts are numeric and bounded', /timeout" -lt 5.*timeout" -gt 120/s.test(entrypoint) && /CLIENT_TIMEOUT_SECONDS/.test(compose)],
  ['only explicit routes', /http-request deny deny_status 404/.test(config)],
  ['next key is isolated to preflight', /source: ingress-next-key/.test(preflightBlock) && !/source: ingress-next-key/.test(ingressBlock)],
  ['automatic pin preflight gates every ingress start', /network_mode: none/.test(preflightBlock) && /condition: service_completed_successfully/.test(ingressBlock) && /production-ingress-spki\.mjs/.test(preflightBlock) && /ingress-preflight-attestation:\/run\/ingress-attestation:ro/.test(ingressBlock) && /Ingress preflight attestation is stale or invalid/.test(entrypoint)],
  ['self-issued certificates remain exact-host dual-pin gated', /pinned-self-issued/.test(preflight) && /pinned-self-issued/.test(entrypoint) && /checkHost\(host/.test(preflight) && /Current and next ingress certificates must use distinct public keys/.test(preflight)],
  ['container is read-only and bounded', /read_only: true/.test(compose) && /pids_limit: 128/.test(compose) && /mem_limit:/.test(compose)],
  ['entrypoint fails on missing artifacts', /exit 78/.test(entrypoint)],
];

const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
const result = { schema: 'deep-production-ingress-contracts.v1', status: failed.length ? 'failed' : 'ok', checked: checks.length, failed };
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (failed.length) process.exitCode = 1;
