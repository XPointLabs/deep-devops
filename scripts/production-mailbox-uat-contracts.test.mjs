import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8');
const compose = read('docker-compose.production-mailbox-uat.dev.yml');
const tlsCompose = read('docker-compose.survival-uat-tls.dev.yml');
const proxy = read('config', 'survival-uat-tls', 'haproxy.cfg');
const bootstrap = read('scripts', 'Initialize-SurvivalUatProductionMailbox.ps1');
const tlsBootstrap = read('scripts', 'Initialize-SurvivalUatTls.ps1');
const publisher = read('tools', 'survival-mailbox-driver', 'ProductionMailboxUatPublisher.cs');
const xnodeEnvironment = bootstrap.match(
  /Write-PublicEnvironment \(Join-Path \$output 'xnode\.env'\) @\([\s\S]*?(?=\r?\n\r?\n\[pscustomobject\])/,
)?.[0] ?? '';

assert.match(compose, /ASPNETCORE_ENVIRONMENT: Production/);
assert.match(compose, /PrivacyRouting__AllowInsecureHttpPeerTransport: "false"/);
assert.doesNotMatch(compose, /DevelopmentUatOnlyAllowPrivateResolvedPeerAddresses/);
assert.match(compose, /MailboxAuthorityForwarding__Enabled: "false"/);
assert.match(compose, /MailboxAuthorityForwarding__AuthorityRouterId: ""/);
assert.equal((compose.match(/^  xnode-[1-6]:$/gm) ?? []).length, 6);
assert.match(bootstrap, /ProductionMailbox__Enabled=true/);
assert.match(bootstrap, /ProductionMailbox__UseDevelopmentInMemoryState=true/);
assert.match(xnodeEnvironment, /'DevelopmentUatPrivatePeerAddresses__Scope=DEVELOPMENT-UAT-ONLY'/);
assert.match(xnodeEnvironment, /"DevelopmentUatPrivatePeerAddresses__Addresses__0=\$LanHost"/);
assert.match(bootstrap, /DevelopmentSoftwareSignerSeedPath=\/run\/secrets\/production-mailbox-issuer/);
assert.match(compose, /production-mailbox-route-state-hmac/);
assert.match(compose, /survival-uat-production-mailbox-state-init:[\s\S]*?user: "65532:65532"/);
assert.doesNotMatch(compose, /cap_add: \[CHOWN|chown -R/);
assert.match(compose, /:\/bootstrap\/artifacts:ro/);
assert.match(compose, /production-mailbox-artifacts/);
assert.match(compose, /chmod 0400/);
assert.doesNotMatch(compose.match(/x-uat-production-mailbox-xnode:[\s\S]*?depends_on:/)?.[0] ?? '', /:\/run\/deep-production-mailbox:ro/);
assert.match(compose, /\/ca\.crt:\/run\/deep-uat-ca\/ca\.crt:ro/);
assert.doesNotMatch(compose, /ca\.key|mrx\.seed|SURVIVAL_UAT_TLS_SECRET_DIR[^\n]+}:\/run\/deep-uat-tls:/);
assert.doesNotMatch(tlsCompose, /ca\.key|SURVIVAL_UAT_TLS_SECRET_DIR[^\n]+}:\/run\/deep-uat-tls:/);
assert.match(tlsCompose, /\/server\.pem:\/run\/deep-uat-tls\/server\.pem:ro/);
assert.match(tlsCompose, /\/server\.key:\/run\/deep-uat-tls\/server\.key:ro/);

const registry = proxy.match(/frontend registry_public[\s\S]*?\n\nfrontend file_public/)?.[0] ?? '';
assert.match(registry, /path_reg \^\/api\/production-mailbox\/artifacts\//);
assert.match(registry, /path \/api\/production-mailbox\/challenges/);
assert.match(registry, /\/api\/production-mailbox\/credentials \/api\/production-mailbox\/route-enrollments/);
assert.match(registry, /stick-table type ip/);
assert.match(registry, /deny_status 429/);
assert.doesNotMatch(registry, /owner|internal|admin|path_beg/);
for (const route of [
  '/api/peer/privacy/v1/frame',
  '/api/peer/mailbox/v2/store',
  '/api/peer/mailbox/v2/tombstone',
  '/api/peer/production-mailbox/closure',
  '/api/peer/production-mailbox/closure-capacity',
  '/api/peer/production-mailbox/closure-capacity-reconciliation',
  '/api/production-mailbox/closure',
]) assert.match(proxy, new RegExp(route.replaceAll('/', '\\/')));

assert.match(bootstrap, /must stay outside the repository/);
assert.match(bootstrap, /RandomNumberGenerator\]::Fill/);
assert.match(bootstrap, /issuer\.seed/);
assert.match(bootstrap, /mrx\.seed/);
assert.match(bootstrap, /closure-publisher\.seed/);
assert.match(bootstrap, /owner-control\.seed/);
assert.match(bootstrap, /route-state-hmac\.key/);
assert.match(bootstrap, /AndroidApplicationId/);
assert.match(bootstrap, /AndroidVersionCode/);
assert.match(bootstrap, /AndroidSignerLineageSha256/);
assert.match(bootstrap, /publish-production-uat-successor/);
assert.match(bootstrap, /PreviousTrustFloorBundle/);
assert.match(bootstrap, /PreviousAuthorityArtifact/);
assert.match(bootstrap, /UAT Windows approval rotation requires both exact signing and build hashes/);
assert.match(bootstrap, /\$windowsInputs = @\(\s*@\(\$WindowsSigningCertificateSha256, \$WindowsBuildArtifactSha256\)/);
assert.match(bootstrap, /privateMaterialIncluded = \$false/);
assert.match(bootstrap, /caPrivateKeyMounted = \$false/);
assert.doesNotMatch(bootstrap, /Get-Content[^\n]+(?:seed|key)/i);

assert.match(tlsBootstrap, /next-server\.key/);
assert.match(tlsBootstrap, /next-server\.crt/);
assert.match(tlsBootstrap, /DNS:\$DnsHost/);
assert.match(publisher, /DevelopmentOnly = false/);
assert.match(publisher, /Environment = ProductionMailboxAuthorityEnvironment\.Production/);
assert.match(publisher, /EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy\.PublicHttpsOnly/);
assert.match(publisher, /ProductionMailboxAuthorityVerifier\.Verify/);
assert.match(publisher, /ProductionMailboxTopologyVerifier\.Verify/);
assert.match(publisher, /CryptographicOperations\.ZeroMemory/);
assert.match(publisher, /--public-host must be a DNS name accepted by PublicHttpsOnly/);
assert.match(publisher, /unknown, duplicate, or empty argument/);
assert.match(publisher, /string PublicHost/);
assert.match(publisher, /input\.PublicHost/);
assert.match(publisher, /RemovePublishedArtifacts\(proofRoot, "\*\.mip1"\)/);
assert.match(publisher, /WritePrivacyPeerEnvironments/);
assert.match(publisher, /buildIdSha256 = Lower\(input\.AndroidBuildArtifactSha256\)/);
assert.match(publisher, /applicationId = input\.AndroidApplicationId/);
assert.match(publisher, /playAppSigningLineageSha256/);
assert.match(publisher, /AndroidReleaseBuildArtifactSha256 = \[input\.AndroidBuildArtifactSha256\]/);
assert.match(publisher, /input\.WindowsSigningCertificateSha256 is \{ \} windowsSigner/);
assert.match(publisher, /input\.WindowsBuildArtifactSha256 is \{ \} windowsArtifact/);
assert.match(publisher, /publish-production-uat-routes/);
assert.match(publisher, /schemaVersion = 2/);
assert.match(publisher, /production-mailbox-privacy-routes\.v2\.sig/);
assert.match(publisher, /xnode-\{index \+ 1\}-x25519\.record\.v2\.json/);
assert.match(publisher, /\["routerOwnerId", "keyId", "epoch", "x25519PublicKey"\]/);
assert.match(publisher, /Hex\("keyId", 32\)/);
assert.match(publisher, /epoch != descriptor\.Epoch/);
assert.match(publisher, /FixedTimeEquals\(publicKeyBytes, actualPublicKey\)/);
assert.match(publisher, /PublicKeyAuth\.SignDetached\(json, mrX\.PrivateKey\)/);
assert.match(publisher, /Previous UAT authority does not match its trust floor or Mr\. X root/);
assert.match(publisher, /MaximumRevocationSnapshotLifetimeSeconds/);
assert.match(publisher, /revocation-head\/v2/);
assert.match(publisher, /PrivacyRouting__Peers__\{peer\}__CurrentSpkiSha256/);
assert.equal((compose.match(/privacy-routing-xnode-[1-6]\.env/g) ?? []).length, 6);
assert.equal((compose.match(/SURVIVAL_UAT_PUBLIC_HOST:\?set SURVIVAL_UAT_PUBLIC_HOST/g) ?? []).length, 6);
assert.doesNotMatch(publisher, /Console\.WriteLine\([^\n]*(?:seed|private|key)/i);

console.log('production mailbox UAT contracts passed');
