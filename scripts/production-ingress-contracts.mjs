import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.node.prod.yml'), 'utf8');
const config = fs.readFileSync(path.join(root, 'config/production-ingress/haproxy.cfg.template'), 'utf8');
const entrypoint = fs.readFileSync(path.join(root, 'scripts/production-ingress-entrypoint.sh'), 'utf8');
const storage = fs.readFileSync(path.join(root, 'tools/storage-service/storage-service-runtime.mjs'), 'utf8');
const preflightBlock = compose.match(/^  ingress-preflight:[\s\S]*?(?=^  ingress:)/m)?.[0] ?? '';
const ingressBlock = compose.match(/^  ingress:[\s\S]*?(?=^  xnode:)/m)?.[0] ?? '';

const checks = [
  ['only ingress publishes ports', /^ {4}ports:/m.test(ingressBlock) && !/^ {4}ports:/m.test(compose.replace(ingressBlock, ''))],
  ['ingress publishes 443', /DEEP_INGRESS_HTTPS_BIND:-443}:443/.test(compose)],
  ['ingress image is digest pinned', /haproxy:3\.2\.4-alpine3\.22@sha256:[0-9a-f]{64}/.test(compose)],
  ['upstream network is internal', /ingress-upstream:\s*\n {4}internal: true/.test(compose)],
  ['plaintext listeners bind only loopback and internal IPs', !/ASPNETCORE_URLS:.*0\.0\.0\.0/.test(compose) && /LISTEN_HOST: 172\.31\.241\.20/.test(compose) && /server\.listen\(port, listenHost/.test(storage)],
  ['storage RPC is pinned to internal address', /StorageRpc__BaseUrl: http:\/\/172\.31\.241\.20:8080/.test(compose)],
  ['TLS 1.2 minimum', /ssl-min-ver TLSv1\.2/.test(config)],
  ['strict SNI', /strict-sni/.test(config)],
  ['host and SNI are exact allowlists', /ssl_fc_sni -i \$\{DEEP_INGRESS_HOST}/.test(config) && /hdr\(host\).* -i \$\{DEEP_INGRESS_HOST}/.test(config)],
  ['forwarding headers stripped', ['Forwarded', 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Port', 'X-Forwarded-Proto', 'X-Real-IP', 'True-Client-IP', 'CF-Connecting-IP', 'Client-IP'].every((name) => config.includes(`del-header ${name}`))],
  ['admin paths absent', !/\/status|\/metrics|\/stats|\/debug/.test(config)],
  ['quorum path is source restricted', /quorum_post path \/api\/staking\/quorum\/sign/.test(config) && /quorum_source src \$\{DEEP_QUORUM_COORDINATOR_CIDR}/.test(config) && /post_method quorum_post quorum_source/.test(config)],
  ['request body bounded', /content_length_too_large req\.hdr\(content-length\) -m int gt \$\{DEEP_INGRESS_MAX_BODY_BYTES}/.test(config) && /has_transfer_encoding/.test(config) && /single_content_length/.test(config)],
  ['timeouts are numeric and bounded', /timeout" -lt 5.*timeout" -gt 120/s.test(entrypoint) && /CLIENT_TIMEOUT_SECONDS/.test(compose)],
  ['only explicit routes', /http-request deny deny_status 404/.test(config)],
  ['next key is isolated to preflight', /source: ingress-next-key/.test(preflightBlock) && !/source: ingress-next-key/.test(ingressBlock)],
  ['automatic pin preflight gates every ingress start', /network_mode: none/.test(preflightBlock) && /condition: service_completed_successfully/.test(ingressBlock) && /production-ingress-spki\.mjs/.test(preflightBlock) && /ingress-preflight-attestation:\/run\/ingress-attestation:ro/.test(ingressBlock) && /Ingress preflight attestation is stale or invalid/.test(entrypoint)],
  ['container is read-only and bounded', /read_only: true/.test(compose) && /pids_limit: 128/.test(compose) && /mem_limit:/.test(compose)],
  ['entrypoint fails on missing artifacts', /exit 78/.test(entrypoint)],
];

const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
const result = { schema: 'deep-production-ingress-contracts.v1', status: failed.length ? 'failed' : 'ok', checked: checks.length, failed };
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (failed.length) process.exitCode = 1;
