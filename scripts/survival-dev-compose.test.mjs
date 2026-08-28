import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  assertDevLocalMembershipUrl,
  deriveDevMembershipOpaqueProfileKey,
  DEV_MEMBERSHIP_PROFILE_KEY_BASE,
  sha256Hex,
  validateDevMembershipArtifact,
  verifyPinnedDevMembershipArtifact
} from './survival-dev-membership-trust.mjs';

const compose = readFileSync(new URL('../docker-compose.survival.dev.yml', import.meta.url), 'utf8');
const uatTlsCompose = readFileSync(new URL('../docker-compose.survival-uat-tls.dev.yml', import.meta.url), 'utf8');
const resendChaosCompose = readFileSync(new URL('../docker-compose.survival-resend-chaos.dev.yml', import.meta.url), 'utf8');
const productionCompose = readFileSync(new URL('../docker-compose.node.prod.yml', import.meta.url), 'utf8');
const productionNodeEnvironment = readFileSync(new URL('../.env.node.prod.example', import.meta.url), 'utf8');
const docs = readFileSync(new URL('../docs/SURVIVAL_DEV_STACK.md', import.meta.url), 'utf8');
const launcher = readFileSync(new URL('./survival-dev.ps1', import.meta.url), 'utf8');
const verify = readFileSync(new URL('./survival-dev-verify.mjs', import.meta.url), 'utf8');
const contextExport = readFileSync(new URL('./survival-dev-context-export.mjs', import.meta.url), 'utf8');
const fixture = readFileSync(new URL('../tools/membership-fixture/Program.cs', import.meta.url), 'utf8');
const artifactInit = readFileSync(new URL('../tools/membership-artifact-init/membership-artifact-init.mjs', import.meta.url), 'utf8');
const membershipRepeat = readFileSync(new URL('./survival-dev-membership-fixture-repeat.ps1', import.meta.url), 'utf8');
const mailboxIntegration = readFileSync(new URL('./survival-dev-mailbox.integration.test.ps1', import.meta.url), 'utf8');
const mailboxEvidenceTest = readFileSync(new URL('./survival-dev-mailbox-evidence.test.ps1', import.meta.url), 'utf8');
const chaos = readFileSync(new URL('./survival-dev-chaos.ps1', import.meta.url), 'utf8');
const resendChaosIntegration = readFileSync(new URL('./survival-dev-resend-chaos.integration.test.ps1', import.meta.url), 'utf8');
const resendChaosProxy = readFileSync(new URL('../tools/survival-resend-chaos/resend-chaos-proxy.mjs', import.meta.url), 'utf8');
const haproxy = readFileSync(new URL('../config/survival-uat-tls/haproxy.cfg', import.meta.url), 'utf8');
const mailboxDriver = readFileSync(new URL('../tools/survival-mailbox-driver/Program.cs', import.meta.url), 'utf8');
const mailboxProvisionDriver = readFileSync(new URL('../tools/survival-mailbox-driver/MailboxGrantProvisioner.cs', import.meta.url), 'utf8');
const privateCrossProcessState = readFileSync(new URL('../tools/survival-mailbox-driver/PrivateCrossProcessState.cs', import.meta.url), 'utf8');
const chaosStateTest = readFileSync(new URL('./survival-dev-chaos-state.test.ps1', import.meta.url), 'utf8');
const mailboxBuildInputs = readFileSync(new URL('./survival-dev-mailbox-build-inputs.ps1', import.meta.url), 'utf8');
const membershipNuget = readFileSync(new URL('../tools/membership-fixture/NuGet.Config', import.meta.url), 'utf8');
const membershipLock = JSON.parse(readFileSync(new URL('../tools/membership-fixture/packages.lock.json', import.meta.url), 'utf8'));
const hardhatEntrypoint = readFileSync(new URL('./survival-hardhat-entrypoint.sh', import.meta.url), 'utf8');
const gitAttributes = readFileSync(new URL('../.gitattributes', import.meta.url), 'utf8');

function serviceBlock(name) {
  const match = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-z][a-z0-9-]*:\\r?$|^networks:|^volumes:)`, 'm'));
  assert.ok(match, `missing service ${name}`);
  return match[1];
}

function serviceBlockFrom(source, name) {
  const match = source.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-z][a-z0-9-]*:\\r?$|^networks:|^secrets:)`, 'm'));
  assert.ok(match, `missing service ${name}`);
  return match[1];
}

test('daily stack has a fixed isolated project, persistent services, and one chain volume initializer', () => {
  assert.match(compose, /^name: deep-survival-dev$/m);
  assert.doesNotMatch(compose, /P15C_|ownership-nonce|evidence|\buat\b|sepolia/i);
  const servicesSection = compose.match(/^services:\r?\n([\s\S]*?)(?=^networks:)/m)?.[1] ?? '';
  const services = [...servicesSection.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map(match => match[1]).sort();
  assert.deepEqual(services, [
    'contracts-deploy', 'contracts-deployments-init', 'contracts-devnet', 'contracts-smoke', 'file', 'mailbox-driver', 'mailbox-driver-state-init', 'membership-artifact-init', 'membership-artifact-owner-init', 'membership-fixture', 'push', 'registry', 'staking-backend',
    'storage', 'xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6'
  ]);
  assert.match(compose, /^networks:\r?\n  runtime:\r?\n    driver: bridge$/m);
});

test('shared images have one incremental build producer and persistent consumers', () => {
  const xnodeBuild = compose.match(/^x-xnode-build: &xnode-build\r?\n([\s\S]*?)(?=^x-xnode:)/m)?.[1] ?? '';
  const driverBuild = compose.match(/^x-mailbox-driver-build: &mailbox-driver-build\r?\n([\s\S]*?)(?=^x-membership-fixture-build:)/m)?.[1] ?? '';
  const membershipBuild = compose.match(/^x-membership-fixture-build: &membership-fixture-build\r?\n([\s\S]*?)(?=^x-compat-build:)/m)?.[1] ?? '';
  assert.match(serviceBlock('xnode-1'), /\n    build:/);
  assert.doesNotMatch(serviceBlock('xnode-2'), /\n    build:/);
  assert.doesNotMatch(serviceBlock('xnode-3'), /\n    build:/);
  assert.match(serviceBlock('storage'), /\n    build:/);
  for (const role of ['file', 'push']) assert.doesNotMatch(serviceBlock(role), /\n    build:/);
  assert.match(compose, /^x-xnode: &xnode[\s\S]*?^  image: deep-survival\/xnode:dev$/m);
  for (const role of ['xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6']) assert.match(serviceBlock(role), /<<: \*xnode/);
  for (const role of ['storage', 'file', 'push']) assert.match(serviceBlock(role), /image: deep-survival\/compat:dev/);
  assert.doesNotMatch(compose, /tools\/calls-service|^  calls:/m);
  assert.doesNotMatch(compose, /--no-cache/);
  assert.match(compose, /^x-service: &service\r?\n  platform: linux\/arm64$/m);
  assert.match(
    xnodeBuild,
    /RUN dotnet publish src\/XNode\/XNode\.csproj -c Debug -o \/out --runtime linux-arm64 --self-contained false -p:UseAppHost=false/
  );
  for (const build of [xnodeBuild, driverBuild]) {
    assert.match(build, /XNODE_REVISION: [0-9a-f]{40}/);
    assert.match(build, /XNODE_SOURCE_CONTEXT_MANIFEST_SHA256: [0-9a-f]{64}/);
    assert.match(build, /sha256sum -c -/);
    assert.match(build, /LABEL org\.opencontainers\.image\.revision/);
    assert.match(build, /com\.xpoint\.source-context\.manifest-sha256/);
  }
  assert.doesNotMatch(membershipBuild, /XNODE_REVISION|source-context\.manifest-sha256/);
});

test('only local Hardhat and loopback host ports are configured', () => {
  const deploymentsInit = serviceBlock('contracts-deployments-init');
  const contracts = serviceBlock('contracts-devnet');
  const deploy = serviceBlock('contracts-deploy');
  const smoke = serviceBlock('contracts-smoke');
  const staking = serviceBlock('staking-backend');
  assert.match(deploymentsInit, /profiles: \[chain\]/);
  assert.match(deploymentsInit, /user: "0:0"/);
  assert.match(deploymentsInit, /restart: "no"/);
  assert.match(deploymentsInit, /cap_drop: \[ALL\]/);
  assert.match(deploymentsInit, /cap_add: \[CHOWN\]/);
  assert.match(deploymentsInit, /no-new-privileges:true/);
  assert.match(deploymentsInit, /network_mode: none/);
  assert.match(deploymentsInit, /contracts-deployments:\/workspace\/deployments/);
  assert.match(deploymentsInit, /chown -R 1000:1000 \/workspace\/deployments/);
  assert.doesNotMatch(deploymentsInit, /build:/);
  assert.match(contracts, /command: \[pnpm, exec, hardhat, node, --hostname, 0\.0\.0\.0\]/);
  assert.match(contracts, /COPY --from=contracts_source package\.json pnpm-lock\.yaml \.\//);
  assert.match(contracts, /pnpm install --frozen-lockfile/);
  assert.match(contracts, /COREPACK_HOME=\/opt\/corepack corepack prepare pnpm@9\.1\.3 --activate/);
  assert.match(contracts, /ENV COREPACK_HOME=\/opt\/corepack/);
  assert.match(contracts, /ENV COREPACK_ENABLE_NETWORK=0/);
  assert.match(contracts, /cp -a \/workspace\/cache \/opt\/hardhat-cache/);
  assert.match(contracts, /ENTRYPOINT \["\/usr\/local\/bin\/survival-hardhat-entrypoint"\]/);
  assert.match(contracts, /COPY --from=contracts_source \. \./);
  assert.match(contracts, /USER node/);
  assert.match(contracts, /restart: "no"/);
  assert.match(contracts, /contracts-deployments-init: \{ condition: service_completed_successfully \}/);
  assert.match(deploy, /profiles: \[chain\]/);
  assert.match(deploy, /restart: "no"/);
  assert.match(deploy, /network_mode: service:contracts-devnet/);
  assert.doesNotMatch(deploy, /<<: \*service|networks:/);
  assert.match(deploy, /cap_drop: \[ALL\]/);
  assert.match(deploy, /no-new-privileges:true/);
  assert.match(deploy, /contracts-deployments:\/workspace\/deployments/);
  assert.match(deploy, /contracts-devnet: \{ condition: service_healthy \}/);
  assert.match(deploy, /rm -f \/workspace\/deployments\/localhost\.latest\.json/);
  assert.match(deploy, /hardhat run --no-compile scripts\/deploy-local-devnet\.js --network localhost/);
  assert.match(deploy, /chmod 0644 \/workspace\/deployments\/localhost\.latest\.json/);
  assert.match(smoke, /profiles: \[chain\]/);
  assert.match(smoke, /restart: "no"/);
  assert.match(smoke, /network_mode: service:contracts-devnet/);
  assert.doesNotMatch(smoke, /<<: \*service|networks:/);
  assert.match(smoke, /cap_drop: \[ALL\]/);
  assert.match(smoke, /no-new-privileges:true/);
  assert.match(smoke, /contracts-deployments:\/workspace\/deployments:ro/);
  assert.match(smoke, /contracts-deploy: \{ condition: service_completed_successfully \}/);
  assert.match(smoke, /hardhat, run, --no-compile, scripts\/local-devnet-smoke\.js/);
  assert.match(staking, /contracts-smoke: \{ condition: service_completed_successfully \}/);
  assert.doesNotMatch(staking, /contracts-devnet: \{ condition: service_healthy \}/);
  assert.match(staking, /Contracts__DeploymentManifestPath: \/run\/deep-contracts\/localhost\.latest\.json/);
  assert.match(staking, /Contracts__ExpectedDeploymentNetwork: localhost/);
  assert.match(staking, /Contracts__ExpectedDeploymentChainId: "31337"/);
  assert.match(staking, /contracts-deployments:\/run\/deep-contracts:ro/);
  assert.match(staking, /GET \/health\/ready HTTP\/1\.1/);
  assert.doesNotMatch(staking, /test -r \/proc\/1\/status/);
  assert.match(contracts, /eth_chainId/);
  assert.doesNotMatch(
    compose,
    /https?:\/\/(?!127\.0\.0\.1|0\.0\.0\.0|172\.30\.82\.1[1-6]:|[a-z][a-z0-9-]*:)/i);
  const bindings = [...compose.matchAll(/"\$\{SURVIVAL_BIND_HOST:-127\.0\.0\.1\}:(\d+):(\d+)"/g)];
  assert.equal(bindings.length, 13);
  assert.equal(new Set(bindings.map(match => match[1])).size, bindings.length);
});

test('runtime root filesystems are immutable and writable paths are explicitly bounded', () => {
  const sharedRuntime = compose.match(/^x-service: &service\r?\n([\s\S]*?)(?=^x-health:)/m)?.[1] ?? '';
  assert.match(sharedRuntime, /^  read_only: true$/m);
  assert.match(sharedRuntime, /^  tmpfs:\r?\n    - \/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777$/m);
  assert.match(compose.match(/^x-xnode: &xnode\r?\n([\s\S]*?)(?=^x-membership-fixture-build:)/m)?.[1] ?? '', /<<: \*service/);
  for (const role of ['registry', 'staking-backend', 'storage', 'file', 'push', 'contracts-devnet']) {
    assert.match(serviceBlock(role), /<<: \*service/);
    assert.doesNotMatch(serviceBlock(role), /read_only: false|tmpfs:\s*\[\s*\]/);
  }
  for (const role of ['xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6']) assert.match(serviceBlock(role), /<<: \*xnode/);

  for (const role of ['membership-artifact-owner-init', 'membership-artifact-init', 'membership-fixture', 'contracts-deployments-init', 'contracts-deploy', 'contracts-smoke']) {
    assert.match(serviceBlock(role), /\n    read_only: true/);
  }
  for (const role of ['membership-fixture', 'contracts-deploy', 'contracts-smoke']) {
    assert.match(serviceBlock(role), /\n    tmpfs:\r?\n      - \/tmp:rw,noexec,nosuid,nodev,size=(?:32|64)m,mode=1777/);
  }
  for (const role of ['contracts-devnet', 'contracts-deploy', 'contracts-smoke']) {
    assert.match(serviceBlock(role), /\/workspace\/cache:rw,noexec,nosuid,nodev,size=64m,mode=1777/);
  }
  assert.match(hardhatEntrypoint, /cp -R \/opt\/hardhat-cache\/\. \/workspace\/cache\//);
  assert.match(hardhatEntrypoint, /exec "\$@"/);
  assert.doesNotMatch(hardhatEntrypoint, /curl|wget|pnpm|npm|corepack/);
  assert.match(gitAttributes, /^scripts\/survival-hardhat-entrypoint\.sh text eol=lf$/m);

  for (const role of ['xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6', 'registry', 'staking-backend', 'storage', 'file', 'push']) {
    const volumes = serviceBlock(role).match(/volumes: \[[^\]]+\]|volumes:\r?\n(?:      - [^\r\n]+\r?\n?)+/)?.[0] ?? '';
    assert.match(volumes, /\/state/);
    assert.doesNotMatch(volumes, /:(?:\/app|\/service|\/workspace)(?::|\s|$)/);
  }
  assert.match(serviceBlock('staking-backend'), /contracts-deployments:\/run\/deep-contracts:ro/);
  assert.match(serviceBlock('contracts-smoke'), /contracts-deployments:\/workspace\/deployments:ro/);
});

test('LAN opt-in binds only the supplied IPv4 address and documents exact device forwarding', () => {
  assert.match(launcher, /\$env:SURVIVAL_BIND_HOST = \$advertisedHost/);
  assert.doesNotMatch(launcher, /SURVIVAL_BIND_HOST\s*=.*0\.0\.0\.0/);
  assert.match(launcher, /Name = 'client\.windows\.env'; Host = \$HostName/);
  assert.match(launcher, /survival-dev-verify\.mjs'\) '--host' \$advertisedHost/);
  assert.match(verify, /isIP\(host\) !== 4/);
  assert.match(verify, /scheme !== 'http' && scheme !== 'https'/);
  assert.match(docs, /41801, 41802, 41803, 41804, 41805, 41806, 41810, 41821, 41822, 41823/);
  assert.match(docs, /41545, 41811/);
});

test('every stateful service uses a named volume and operator commands are documented', () => {
  for (const volume of [
    'contracts-deployments', 'xnode-1-state', 'xnode-2-state', 'xnode-3-state',
    'xnode-4-state', 'xnode-5-state', 'xnode-6-state',
    'registry-state', 'staking-state', 'storage-state', 'file-state', 'push-state', 'membership-route-artifact', 'mailbox-rehearsal-state'
  ]) assert.match(compose, new RegExp(`^  ${volume}:$`, 'm'));
  assert.match(serviceBlock('registry'), /Calls__StatePath: \/state\/calls-v2\.json/);
  assert.match(serviceBlock('registry'), /41823:8080/);
  assert.match(docs, /survival-dev\.ps1 -Action Up/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml ps/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml logs -f --tail=200/);
  assert.match(docs, /docker compose -f docker-compose\.survival\.dev\.yml down/);
  assert.match(docs, /current strict\s+client, service and production-readiness gates/i);
  assert.match(docs, /raw `docker compose .*up.*` is not supported/i);
  assert.doesNotMatch(docs, /The chain profile is currently unsupported/i);
  assert.match(docs, /Direct `docker compose` chain\s+restarts are unsupported/i);
  assert.match(docs, /contracts-deployments-init/);
  assert.doesNotMatch(docs, /вЂ|Ã|â|�/);
  assert.doesNotMatch(docs, /--no-cache/);
});

test('membership catalog is a local-only one-shot with pinned packages and read-only consumers', () => {
  const ownerInit = serviceBlock('membership-artifact-owner-init');
  const init = serviceBlock('membership-artifact-init');
  const generator = serviceBlock('membership-fixture');
  assert.match(ownerInit, /user: "0:0"/);
  assert.match(ownerInit, /network_mode: none/);
  assert.match(ownerInit, /cap_drop: \[ALL\]/);
  assert.match(ownerInit, /cap_add: \[CHOWN\]/);
  assert.doesNotMatch(ownerInit, /FOWNER|SETUID|SETGID/);
  assert.match(ownerInit, /membership-artifact-init:\/opt\/deep-membership-init:ro/);
  assert.match(ownerInit, /membership-artifact-init\.mjs, owner/);
  assert.match(init, /user: "65532:65532"/);
  assert.match(init, /network_mode: none/);
  assert.match(init, /cap_drop: \[ALL\]/);
  assert.doesNotMatch(init, /cap_add|FOWNER|SETUID|SETGID/);
  assert.match(init, /membership-artifact-owner-init: \{ condition: service_completed_successfully \}/);
  assert.match(init, /membership-artifact-init\.mjs, clear/);
  assert.match(generator, /network_mode: none/);
  assert.match(generator, /restart: "no"/);
  assert.match(generator, /membership-artifact-init: \{ condition: service_completed_successfully \}/);
  assert.match(generator, /command: \[--advertised-host, "\$\{SURVIVAL_BIND_HOST:-127\.0\.0\.1\}"\]/);
  assert.doesNotMatch(generator, /sh, -[ec]+|0\.0\.0\.0/);
  assert.match(compose, /SURVIVAL_MEMBERSHIP_PACKAGES_BUILD_CONTEXT/);
  assert.match(compose, /MembershipArtifact__ArtifactPath: \/run\/deep-membership\/membership-route-catalog\.json/);
  assert.match(serviceBlock('registry'), /Registry__MembershipRouteArtifactPath/);
  for (const role of ['xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6', 'registry']) {
    assert.match(serviceBlock(role), /membership-route-artifact:\/run\/deep-membership:ro/);
    assert.match(serviceBlock(role), /membership-fixture: \{ condition: service_completed_successfully \}/);
  }
  assert.match(launcher, /Prepare-SurvivalMembershipFixturePackages/);
  assert.match(launcher, /Reset-SurvivalMembershipFixture/);
  assert.match(launcher, /'membership-artifact-owner-init'/);
  assert.match(artifactInit, /lstatSync\(outputDirectory\)/);
  assert.match(artifactInit, /state\.uid === runtimeUid && state\.gid === runtimeGid/);
  assert.match(artifactInit, /state\.uid !== 0 \|\| state\.gid !== 0/);
  assert.match(artifactInit, /chmodSync\(outputDirectory, privateDirectoryMode\)/);
  assert.match(artifactInit, /chownSync\(outputDirectory, runtimeUid, runtimeGid\)/);
  assert.match(artifactInit, /process\.getuid\?\.\(\) !== runtimeUid/);
  assert.match(artifactInit, /unexpected entry/);
  assert.match(artifactInit, /VerifiedPublishedArtifactSha256=/);
  assert.doesNotMatch(artifactInit, /exec|spawn|setuid|setgid|rmSync|rmdirSync/);
  assert.match(membershipRepeat, /foreach \(\$iteration in 1\.\.2\)/);
  assert.match(membershipRepeat, /\[string\]\$AdvertisedHost = '127\.0\.0\.1'/);
  assert.match(membershipRepeat, /\$env:SURVIVAL_BIND_HOST = \$AdvertisedHost/);
  assert.match(membershipRepeat, /'up', '--no-build', 'membership-fixture'/);
  assert.match(membershipRepeat, /'probe',\s+\$hash/s);
  assert.match(membershipRepeat, /Same-volume membership fixture repeat passed/);
  const packageFunction = launcher.match(/function Prepare-SurvivalMembershipFixturePackages\(\) \{([\s\S]*?)\r?\n\}/)?.[1] ?? '';
  const packagePins = [...packageFunction.matchAll(
    /@\{ Name = '([^']+\.nupkg)'; Hash = '([0-9A-F]{64})'; Path = '([^']+)' \}/g)]
    .map(([, name, hash, path]) => ({ name, hash, path }));
  assert.deepEqual(packagePins, [
    { name: 'Deep.Protocol.0.3.0-p04.b887fa0.nupkg', hash: '8EF4E70AD0B6C1CC0087F25C0313D6AB6A5387D16246679E4C10A3C00898A442', path: 'vendor\\p14a2\\packages\\Deep.Protocol.0.3.0-p04.b887fa0.nupkg' },
    { name: 'Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg', hash: 'FC1212A6765F5778188FCB3866EF923023C2253C3EAD299A542271F4CC4F844F', path: 'vendor\\p14a2\\packages\\Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg' },
    { name: 'Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg', hash: '755A027C58BE670151456CC0BCA4764731F7C493932D9EEDD00C02E704BAF818', path: 'vendor\\p14a2\\packages\\Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg' },
    { name: 'Deep.Protocol.MembershipRoutes.0.1.0-p15.local.nupkg', hash: 'FE7B5E638C1AB5E7505F45BB7D5804048D2A4AD273C88DD75D7D46AE80DB641A', path: 'vendor\\p15\\packages\\Deep.Protocol.MembershipRoutes.0.1.0-p15.local.nupkg' },
    { name: 'Google.Protobuf.3.32.1.nupkg', hash: '02A4A40AD4B81AAE6652A4B163EB5622D1B3B3519CCA348B3CB79AC71D9B2CAB', path: 'vendor\\p14a2\\packages\\Google.Protobuf.3.32.1.nupkg' },
    { name: 'Sodium.Core.1.4.1.nupkg', hash: 'DE0B567D19BD1C0B9974EE5D98FC4DA87045924B94FFA1B4378BB14E623A65B7', path: 'vendor\\p14a2\\packages\\Sodium.Core.1.4.1.nupkg' },
    { name: 'libsodium.1.0.22.nupkg', hash: 'F66EAC31EA413C1D5D068B46ADE11D3295C86EC9D6CD29FF158BA58EF51DB51A', path: 'vendor\\p14a2\\packages\\libsodium.1.0.22.nupkg' }
  ]);
  assert.doesNotMatch(packageFunction, /Hash = ''|\$input\.Hash -and/);
  const mappedPackages = [...membershipNuget.matchAll(/<package pattern="([^"]+)" \/>/g)]
    .map(match => match[1]);
  assert.deepEqual(mappedPackages, [
    'Deep.Protocol',
    'Deep.Protocol.Abstractions',
    'Deep.Protocol.Protobuf',
    'Deep.Protocol.MembershipRoutes',
    'Google.Protobuf',
    'Sodium.Core',
    'libsodium'
  ]);
  assert.deepEqual(
    Object.keys(membershipLock.dependencies['net10.0']).sort(),
    [
      'Deep.Protocol',
      'Deep.Protocol.Abstractions',
      'Deep.Protocol.MembershipRoutes',
      'Deep.Protocol.Protobuf',
      'Google.Protobuf',
      'Sodium.Core',
      'libsodium'
    ].sort());
  assert.match(fixture, /DEV-LOCAL-ONLY/);
  assert.match(fixture, /ParseOptions\(args\)/);
  assert.match(fixture, /"--advertised-host"/);
  assert.match(fixture, /"--advertised-scheme"/);
  assert.match(fixture, /octets\[0\] == 127/);
  assert.match(fixture, /octets\[0\] == 192 && octets\[1\] == 168/);
  assert.match(fixture, /octets\[0\] == 172 && octets\[1\] is >= 16 and <= 31/);
  assert.match(fixture, /octets\[0\] == 169 && octets\[1\] == 254/);
  assert.match(fixture, /RpcEndpoint = \$"\{advertisedScheme\}:\/\/\{advertisedHost\}:\{41801 \+ index\}\//);
  assert.match(fixture, /Enumerable\.Range\(41801, 6\)/);
  assert.match(fixture, /seenEndpoints\.SetEquals\(requiredEndpoints\)/);
  assert.doesNotMatch(fixture, /xnode-\{index \+ 1\}|:8080|0\.0\.0\.0/);
  assert.match(fixture, /File\.SetUnixFileMode\(/);
  assert.match(fixture, /UnixFileMode\.UserRead \| UnixFileMode\.UserWrite \| UnixFileMode\.UserExecute/);
  assert.match(fixture, /PublicKeyAuth\.GenerateKeyPair\(seed\)/);
  assert.match(fixture, /ConvertEd25519PublicKeyToCurve25519PublicKey\(pair\.PublicKey\)/);
  assert.match(fixture, /Development node seed does not match its configured router id/);
  assert.doesNotMatch(fixture, /x25519-local-only/);
  assert.match(fixture, /PublicKeyAuth\.SignDetached\(framed, signer\.PrivateKey\)/);
  assert.match(fixture, /PublicKeyAuth\.VerifyDetached\(signature\.ToArray\(\), signingBytes\.ToArray\(\), publicKey\.ToArray\(\)\)/);
  assert.match(fixture, /VerifyPublishedArtifact\(target, genesis, genesisLkg, delegation, context, verifier, descriptors, advertisedHost, advertisedScheme\)/);
  assert.match(fixture, /trustBootstrap = new/);
  assert.match(fixture, /expectedCanonicalGenesisSha256/);
  assert.match(fixture, /signedDelegation = Convert\.ToBase64String\(canonicalDelegation\)/);
  assert.match(fixture, /bridgeAnchor = trustAnchor/);
  assert.match(fixture, /membershipAnchor = trustAnchor/);
  assert.match(fixture, /publishedVerifiedDelegation\.NextAuthorityLastKnownGood\.Sequence/);
  assert.match(fixture, /DevFixtureTrust\.ValidateDerivedProfileKey\(publishedArtifactSha256\)/);
  assert.ok(
    fixture.indexOf('VerifyPublishedArtifact(target') <
      fixture.indexOf('PublishedArtifactSha256='),
    'whole-artifact pin must be emitted only after Sodium read-after-publication verification');
  assert.doesNotMatch(fixture, /LocalOnlyDeterministicVerifier|SignFramed/);
  assert.match(fixture, /MembershipPolicy\.Beta/);
  assert.match(fixture, /const ushort clientProtocol = 2/);
  assert.match(fixture, /MinimumProtocol = clientProtocol, MaximumProtocol = clientProtocol/);
  assert.match(fixture, /ClientProtocol = clientProtocol/);
  assert.match(fixture, /roots\.Take\(3\)/);
  assert.match(fixture, /online\.Take\(2\)/);
  assert.match(fixture, /two disjoint three-hop development routes/);
  assert.match(fixture, /MembershipRouteDescriptorCodec\.BuildProofs/);
  assert.match(fixture, /File\.Move\(temporary, target, true\)/);
  assert.match(readFileSync(new URL('../tools/membership-fixture/MembershipFixture.csproj', import.meta.url), 'utf8'), /RestoreLockedMode>true/);
  assert.match(verify, /MSM1/);
  assert.match(verify, /MRL1/);
  assert.match(docs, /DEV-LOCAL-ONLY/);
  assert.match(docs, /TOFU, remote trust-root fallback, and production activation.*prohibited/is);
  assert.match(docs, /Docker-only\s+hostnames and container port `8080` are never signed/is);
  assert.match(productionNodeEnvironment, /^DEEP_REGISTRY_URL=https:\/\/registry\.deep\.example$/m);
  assert.match(productionNodeEnvironment, /^DEEP_STAKING_BACKEND_URL=https:\/\/staking-api\.deep\.example$/m);
  assert.doesNotMatch(productionCompose, /SURVIVAL_BIND_HOST|membership-fixture|DEV-LOCAL-ONLY/);
  assert.match(launcher, /Assert-SurvivalMembershipFixtureVerified/);
  assert.match(
    launcher,
    /\$baseArguments \+ @\('ps', '-q', '--all', 'membership-fixture'\)/,
    'the verified one-shot must be resolved from exited Compose services'
  );
  assert.match(launcher, /Get-SurvivalVerifiedMembershipPin/);
  assert.match(launcher, /survival-dev-membership-trust\.mjs/);
  assert.match(launcher, /'--expected-sha256' \$ExpectedSha256/);
  assert.match(launcher, /DEEP_DEV_LOCAL_MEMBERSHIP_TRUST_URL/);
  assert.match(launcher, /DEEP_DEV_LOCAL_MEMBERSHIP_TRUST_SHA256/);
  assert.ok(
    launcher.indexOf('Assert-SurvivalMembershipFixtureVerified') <
      launcher.lastIndexOf('$verifiedMembershipPin = Get-SurvivalVerifiedMembershipPin') &&
    launcher.lastIndexOf('$verifiedMembershipPin = Get-SurvivalVerifiedMembershipPin') <
      launcher.lastIndexOf('Write-ClientEnvironment $advertisedHost $membershipPin'),
    'client pin must be written only after the one-shot Sodium verification check');
  assert.ok(
    launcher.lastIndexOf('Remove-SurvivalClientEnvironment') <
      launcher.lastIndexOf('Reset-SurvivalMembershipFixture'),
    'stale client pins must be removed before fixture regeneration');
  assert.doesNotMatch(launcher, /DEEP_MEMBERSHIP.*PRIVATE|MEMBERSHIP.*PRIVATE.*DEEP/i);
});

test('future DEV consumer contract rejects TOFU, pin mismatch, remote roots, and malformed trust', () => {
  const genesis = Buffer.from('canonical-dev-genesis');
  const hash = createHash('sha256').update(genesis).digest();
  const anchor = { sequence: 2, canonicalHash: Buffer.alloc(32, 3).toString('base64') };
  const document = {
    version: 'deep-membership-route-catalog-v1',
    trustBootstrap: {
      version: 'deep-membership-trust-bootstrap-v1',
      scope: 'DEV-LOCAL-ONLY',
      opaqueProfileKey: 'install:deep-survival-dev-v2',
      canonicalGenesis: genesis.toString('base64'),
      expectedNetworkId: Buffer.alloc(16, 1).toString('base64'),
      expectedCanonicalGenesisSha256: hash.toString('base64'),
      signedDelegation: Buffer.from('signed-delegation').toString('base64'),
      bridgeAnchor: anchor,
      membershipAnchor: anchor
    },
    signedMembership: Buffer.from('signed-membership').toString('base64'),
    members: Array.from({ length: 6 }, (_, leafIndex) => ({
      leaf: Buffer.from(`leaf-${leafIndex}`).toString('base64'),
      leafIndex,
      memberCount: 6,
      siblingHashes: [Buffer.alloc(32, leafIndex).toString('base64')]
    }))
  };
  const bytes = Buffer.from(JSON.stringify(document));
  const pin = sha256Hex(bytes);
  const secondPin = sha256Hex(Buffer.concat([bytes, Buffer.from('\n')]));
  assert.equal(validateDevMembershipArtifact(bytes).length, bytes.length);
  assert.equal(verifyPinnedDevMembershipArtifact(bytes, pin).length, bytes.length);
  assert.equal(
    deriveDevMembershipOpaqueProfileKey(pin),
    `${DEV_MEMBERSHIP_PROFILE_KEY_BASE}:${pin}`);
  assert.notEqual(
    deriveDevMembershipOpaqueProfileKey(pin),
    deriveDevMembershipOpaqueProfileKey(secondPin));
  assert.throws(() => verifyPinnedDevMembershipArtifact(bytes), /TOFU is prohibited/);
  assert.throws(() => verifyPinnedDevMembershipArtifact(bytes, '0'.repeat(64)), /pin mismatches/);
  assert.throws(
    () => deriveDevMembershipOpaqueProfileKey(pin.toUpperCase()),
    /lowercase SHA-256 pin/);
  assert.throws(
    () => deriveDevMembershipOpaqueProfileKey(pin, 'install:deep-survival-dev-v1'),
    /profile key base is invalid/);
  assert.throws(
    () => validateDevMembershipArtifact(Buffer.from(JSON.stringify({
      ...document,
      trustBootstrap: { ...document.trustBootstrap, privateSeed: 'forbidden' }
    }))),
    /unknown or missing fields|private-material/);
  assert.equal(
    assertDevLocalMembershipUrl('http://127.0.0.1:41810/api/network/membership-route-catalog').hostname,
    '127.0.0.1');
  assert.equal(
    assertDevLocalMembershipUrl('http://192.168.1.45:41810/api/network/membership-route-catalog').hostname,
    '192.168.1.45');
  assert.throws(
    () => assertDevLocalMembershipUrl('https://registry.example/api/network/membership-route-catalog'),
    /DEV-LOCAL-ONLY HTTP IPv4/);
  assert.throws(
    () => assertDevLocalMembershipUrl('http://203.0.113.5:41810/api/network/membership-route-catalog'),
    /DEV-LOCAL-ONLY HTTP IPv4/);
});

test('daily launcher always uses the fixed project without release-gate ceremony', () => {
  assert.match(launcher, /'deep-survival-dev'/);
  assert.match(launcher, /ValidateSet\('Prepare','Up','Down','Status','Logs','Build','Restart','ChaosBegin','ChaosEnd','ChaosStatus'\)/);
  assert.match(launcher,
    /\$baseArguments = @\('compose'\) \+ \$projectDirectoryArguments \+ @\('-p', \$Project, '-f', \$ComposePath\)/);
  assert.match(launcher, /\[string\]\$LanHost/);
  assert.match(launcher, /SURVIVAL_BIND_HOST/);
  assert.match(launcher, /client\.android\.env/);
  assert.match(launcher, /client\.windows\.env/);
  assert.doesNotMatch(launcher, /DEEP_STAKING_URL/);
  assert.match(launcher, /DEEP_STAKING_BACKEND_URL/);
  for (const routerId of [
    '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
    '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
    'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b',
    'fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b',
    'fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def',
    'b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075'
  ]) assert.match(launcher, new RegExp(routerId));
  assert.doesNotMatch(launcher, /survival-dev-seed\.mjs|relay-bootstrap/);
  assert.match(launcher, /survival-dev-context-export\.mjs/);
  assert.match(launcher, /function Reset-SurvivalChainLifecycle/);
  assert.match(launcher, /function Invoke-SurvivalDockerBounded/);
  assert.match(launcher, /completed without an observable integer exit code/);
  assert.match(launcher, /'contracts-deploy', 'contracts-smoke', 'staking-backend'/);
  assert.match(launcher, /if \(\$Chain\) \{ Reset-SurvivalChainLifecycle \}/);
  assert.match(launcher, /if \(\$Chain\) \{ \$arguments \+= @\('--profile', 'chain'\) \}[\s\S]*?\$arguments \+= 'down'/);
  const buildIndex = launcher.indexOf("($buildArguments + @('build') + $Service)");
  const authorityIndex = launcher.indexOf('Prepare-SurvivalMailboxPeerAuthority', buildIndex);
  const upIndex = launcher.indexOf("@('up', '-d', '--no-build', '--wait')", authorityIndex);
  assert.ok(buildIndex >= 0 && authorityIndex > buildIndex && upIndex > authorityIndex,
    'images must build before fresh authority generation and no-build startup');
  assert.match(launcher, /Up -Chain always recreates the complete chain lifecycle/);
  assert.match(launcher, /Chain lifecycle services cannot be restarted independently/);
  assert.match(launcher, /41811\/health\/ready/);
  assert.match(launcher, /eth_chainId/);
  assert.match(launcher, /tokenAddress/);
  assert.doesNotMatch(launcher, /Up requires -LanHost/);
  assert.match(verify, /api\/network\/privacy-contact/);
  assert.match(verify, /api\/peer\/privacy\/v1\/frame/);
  assert.match(verify, /privacy-routing-v1/);
  assert.match(verify, /exact other-five/);
  assert.doesNotMatch(verify, /api\/session\/rpc|api\/peer\/onion/);
  assert.match(serviceBlock('contracts-devnet'), /profiles: \[chain\]/);
  assert.match(serviceBlock('staking-backend'), /profiles: \[chain\]/);
  assert.doesNotMatch(compose, /Runtime__|RegistryBootstrap__|relay-bootstrap/);
  assert.match(compose, /PrivacyRouting__Enabled: "true"/);
  assert.match(compose, /Node__ManagedIngressH2ListenUrl: http:\/\/0\.0\.0\.0:8082/);
  assert.match(compose, /Node__PrivacyPeerH2ListenUrl: http:\/\/0\.0\.0\.0:8083/);
  assert.match(compose, /PrivacyRouting__X25519PrivateKeyPath: \/run\/secrets\/xnode-x25519\.private/);
  for (let index = 0; index < 6; index += 1) {
    assert.match(compose, new RegExp(`ipv4_address: 172\\.30\\.82\\.${11 + index}`));
  }
  assert.doesNotMatch(launcher, /nonce|evidence|receipt|P15C_/i);
  assert.match(contextExport, /git.*ls-files/si);
  assert.match(contextExport, /safe\.directory=\$\{source\}/);
  assert.doesNotMatch(contextExport, /config.*--global|safe\.directory=\*/si);
  assert.match(contextExport, /prohibited source entries/i);
});

test('resend uncertainty chaos is a bounded survival-only real-ingress interposer', () => {
  assert.match(resendChaosCompose, /profiles: \[resend-chaos\]/);
  assert.match(resendChaosCompose, /DEEP_CHAOS_UPSTREAM_ORIGIN: http:\/\/xnode-3:8082/);
  assert.match(resendChaosCompose, /DEEP_UAT_XNODE_3_UPSTREAM: resend-chaos:8080/);
  assert.doesNotMatch(resendChaosCompose, /ports:/);
  assert.match(uatTlsCompose, /DEEP_UAT_XNODE_1_UPSTREAM: xnode-1:8082/);
  assert.match(uatTlsCompose, /DEEP_UAT_XNODE_3_UPSTREAM: xnode-3:8082/);
  assert.match(resendChaosCompose, /DEEP_CHAOS_CONTROL_SOCKET: \/run\/deep-chaos\/control\.sock/);
  assert.match(resendChaosCompose, /read_only: true/);
  assert.match(resendChaosCompose, /cap_drop: \[ALL\]/);
  assert.match(resendChaosCompose, /resend-chaos-token/);
  assert.doesNotMatch(resendChaosCompose, /8081:8081|control.*ports/);
  assert.doesNotMatch(productionCompose, /resend-chaos|DEEP_CHAOS_/);
  assert.match(launcher, /New-SurvivalChaosToken/);
  assert.match(launcher, /Protect-SurvivalDevPrivateFile/);
  assert.match(launcher, /docker-compose\.survival-uat-tls\.dev\.yml/);
  assert.match(launcher, /Assert-SurvivalUatTlsEndpoint/);
  assert.match(launcher, /foreach \(\$attempt in 1\.\.60\)[\s\S]*?Start-Sleep -Milliseconds 500/);
  assert.match(launcher, /Invoke-SurvivalChaosControl 'arm'/);
  assert.match(launcher, /Stop-SurvivalChaos/);
  assert.match(resendChaosProxy, /\/api\/ingress\/v1\/frame/);
  assert.doesNotMatch(resendChaosProxy, /\/api\/client\/mailbox\/v2\/(?:store|retrieve|acknowledge)/);
  assert.match(resendChaosProxy, /node:http/);
  assert.match(resendChaosProxy, /node:http2/);
  assert.match(resendChaosProxy, /http2\.connect/);
  assert.match(resendChaosProxy, /post-durable-ack-response-drop/);
  assert.match(resendChaosProxy, /primary-ingress-rejected-before-forward/);
  assert.match(resendChaosProxy, /application\/vnd\.xpoint\.deep\.ingress-error-v1/);
  assert.match(resendChaosProxy, /errorFrame\.write\('DIE1'/);
  assert.match(resendChaosProxy, /operation: 'mailbox-ack'/);
  assert.match(resendChaosProxy, /post-durable-response-drop'[\s\S]*?route: '\/api\/ingress\/v1\/frame'/);
  assert.match(resendChaosProxy, /post-durable-ack-response-drop'[\s\S]*?route: '\/api\/ingress\/v1\/frame'/);
  assert.match(resendChaosProxy, /upstreamRequest\.on\('end'/);
  assert.match(resendChaosProxy, /response\.stream\.session\.destroy\(\)/);
  assert.match(resendChaosProxy, /copyHttp2RequestHeaders\(request, requestPath, upstream\.protocol\.slice\(0, -1\)\)/);
  assert.match(resendChaosProxy, /':scheme': upstreamScheme/);
  assert.match(resendChaosProxy, /upstream\.protocol\.slice\(0, -1\)/);
  assert.match(resendChaosProxy, /':authority': authority/);
  assert.match(resendChaosProxy, /'x-forwarded-proto': 'https'/);
  assert.match(resendChaosProxy, /lower !== 'x-forwarded-proto'/);
  assert.equal(
    [...haproxy.matchAll(/http-request set-uri http:\/\/%\[req\.hdr\(host\)\]%\[path\] if post public_post/g)].length,
    6,
    'every public privacy frontend must translate TLS :scheme to h2c before the trusted forwarded-scheme boundary'
  );
  assert.match(uatTlsCompose, /haproxy:3\.2\.22-alpine3\.24@sha256:79799e8b2977e60802774fa53d29e6b54e045402cdd8a8b9fe43923e7095a047/);
  assert.match(compose, /Node__ManagedIngressTrustedProxyAddresses__0: 172\.30\.82\.7/);
  assert.match(compose, /Node__ManagedIngressTrustedProxyAddresses__1: 172\.30\.82\.8/);
  assert.match(
    serviceBlockFrom(uatTlsCompose, 'survival-uat-tls-ingress'),
    /ipv4_address: 172\.30\.82\.7/);
  assert.doesNotMatch(serviceBlockFrom(uatTlsCompose, 'turn'), /ipv4_address:/);
  assert.match(resendChaosCompose, /ipv4_address: 172\.30\.82\.8/);
  assert.match(resendChaosProxy, /state\.postDurableResponseDropCount \+= 1/);
  assert.match(resendChaosProxy, /state\.postDurableAckResponseDropCount \+= 1/);
  assert.match(resendChaosProxy, /state\.preDispatchOutageCount \+= 1/);
  assert.match(resendChaosProxy, /operationAttemptCount/);
  assert.match(resendChaosProxy, /ttlSeconds < 5 \|\| ttlSeconds > 300/);
  assert.match(resendChaosProxy, /payloadInspected: false/);
  assert.doesNotMatch(resendChaosProxy, /console\.(?:log|error).*request|operationId|deduplicationDigest/i);
  assert.match(resendChaosIntegration, /client-uncertain-resend/);
  assert.match(resendChaosIntegration, /--test-force-exit/);
  assert.match(resendChaosIntegration, /New-SurvivalMailboxIsolatedSource/);
  assert.match(resendChaosIntegration, /Set-MailboxTreeReadOnly \$SourceRoot/);
  assert.match(resendChaosIntegration, /Open-MailboxTreeReadLocks \$SourceRoot/);
  assert.match(resendChaosIntegration, /'publish', \$isolated\.DriverProject/);
  assert.match(resendChaosIntegration, /'--artifacts-path', \$BuildArtifacts/);
  assert.match(resendChaosIntegration, /Assert-SurvivalMailboxIsolatedSource \$verified/);
  assert.ok(resendChaosIntegration.indexOf('Assert-SurvivalMailboxIsolatedSource $verified')
    < resendChaosIntegration.indexOf("'-Action', 'ChaosBegin'"));
  assert.doesNotMatch(resendChaosIntegration, /dotnet @\([^)]*\$PinnedXNode/);
  assert.match(resendChaosIntegration, /serverItemCount -ne 1/);
  assert.match(resendChaosIntegration, /post-durable-response-drop/);
  assert.match(resendChaosIntegration, /pre-dispatch-outage/);
  assert.match(resendChaosIntegration, /post-durable-ack-response-drop/);
  assert.match(resendChaosIntegration, /client-prepare-ack-loss/);
  assert.match(resendChaosIntegration, /client-ack-loss/);
  assert.match(resendChaosIntegration, /client-retry-ack-loss/);
  assert.match(resendChaosIntegration, /client-replay-ack-loss/);
  assert.match(resendChaosIntegration, /Set-MailboxDirectoryExclusiveWritable \$State/);
  assert.match(resendChaosIntegration, /postDurableAckResponseDropCount/);
  assert.match(resendChaosIntegration, /operationAttemptCount -ne 4/);
  assert.match(resendChaosIntegration, /https:\/\/\$\{BindHost\}:41801/);
  assert.match(resendChaosIntegration, /'--output-privacy-routes-android'/);
  assert.match(resendChaosIntegration, /'--output-privacy-routes-windows'/);
  assert.match(resendChaosIntegration, /'--privacy-entry-host', \$BindHost/);
  assert.match(resendChaosIntegration, /'--privacy-routes', \(Join-Path \$BuildWork 'privacy-routes\.android\.v1\.json'\)/);
  assert.match(resendChaosIntegration, /function Assert-OrdinaryStack\(\)/);
  for (const role of ['file', 'push', 'registry', 'storage', 'survival-uat-crl',
    'survival-uat-tls-ingress', 'turn', 'xnode-1', 'xnode-2', 'xnode-3',
    'xnode-4', 'xnode-5', 'xnode-6']) {
    assert.match(resendChaosIntegration, new RegExp(`'${role}'`));
  }
  assert.doesNotMatch(resendChaosIntegration, /ordinary 14-container|Get-RunningStackCount/);
  assert.match(resendChaosIntegration, /'ChaosEnd'/);
  assert.match(resendChaosIntegration, /deep-survival-resend-chaos-evidence\.v2/);
  assert.match(resendChaosIntegration, /evidenceSha256/);
  assert.match(resendChaosIntegration, /Protect-SurvivalDevPrivateFile \$temporaryEvidencePath/);
  assert.doesNotMatch(resendChaosIntegration, /docker\s+compose/i);
  assert.match(mailboxDriver, /PrivateCrossProcessState\.WriteAckLossState/);
  assert.match(mailboxDriver, /PrivateCrossProcessState\.ReadAckLossState/);
  assert.match(privateCrossProcessState, /AssertNoReparseTraversal/);
  assert.match(privateCrossProcessState, /AreAccessRulesProtected/);
  assert.match(privateCrossProcessState, /GetOwner\(typeof\(SecurityIdentifier\)\)/);
  assert.match(privateCrossProcessState, /Unix mode 0700/);
  assert.match(privateCrossProcessState, /Unix mode 0600/);
  assert.match(privateCrossProcessState, /FileMode\.CreateNew/);
  assert.match(privateCrossProcessState, /FileOptions\.WriteThrough/);
  assert.match(privateCrossProcessState, /Flush\(flushToDisk: true\)/);
  assert.match(privateCrossProcessState, /File\.Move\(temporary, path, overwrite: true\)/);
  assert.match(privateCrossProcessState, /Atomic private ACK state reread hash mismatch/);
  assert.match(privateCrossProcessState, /ReadOnly/);
  assert.match(chaosStateTest, /changed-ack/);
  assert.match(chaosStateTest, /unsafe-before-write/);
  assert.match(chaosStateTest, /broad-directory/);
  assert.match(chaosStateTest, /S-1-5-11/);
  assert.match(chaosStateTest, /Junction|SymbolicLink/);
  assert.match(chaosStateTest, /wrong-type/);
  assert.match(chaosStateTest, /locked private state deletion did not fail closed/i);
  assert.match(chaosStateTest, /read-only state/i);
  assert.match(mailboxBuildInputs, /function Remove-MailboxPrivateStateDirectory/);
  assert.match(mailboxBuildInputs, /direct child of its exact parent/);
  assert.match(mailboxBuildInputs, /Remove-Item -LiteralPath \$full -Recurse -Force -ErrorAction Stop/);
  assert.match(mailboxBuildInputs, /still exists after terminating deletion/);
  assert.match(resendChaosIntegration, /AggregateException/);
  assert.match(resendChaosIntegration, /Final chaos status is not the exact off baseline/);
  assert.match(resendChaosIntegration, /Private ACK state survived terminating final cleanup/);
  assert.ok(resendChaosIntegration.indexOf('Private ACK state survived terminating final cleanup')
    < resendChaosIntegration.indexOf("schema = 'deep-survival-resend-chaos-evidence.v2'"));
  assert.match(mailboxDriver, /PrivatePeerOrigin\(int zeroBasedNodeIndex\)/);
  assert.match(mailboxDriver, /http:\/\/172\.30\.82\.\{zeroBasedNodeIndex \+ 11\}:8083/);
  assert.match(mailboxDriver, /coordinator\.Scheme == expectedCoordinator\.Scheme/);
  assert.match(mailboxDriver, /response\.StatusCode is 502 or 503/);
  assert.match(mailboxDriver, /body\.Length <= 4096/);
  assert.match(mailboxIntegration, /NODE_EXTRA_CA_CERTS = \$TlsCaPath/);
  assert.match(mailboxIntegration, /'--scheme', 'https'/);
});

test('native privacy authority needs no legacy seed or post-start XNode restart', () => {
  const upAction = launcher.match(/'Up' \{([\s\S]*?)\r?\n    \}\r?\n    'Down'/)?.[1] ?? '';
  assert.notEqual(upAction, '', 'launcher Up action is missing');
  assert.equal(
    (upAction.match(/Reset-SurvivalMembershipFixture/g) ?? []).length,
    1,
    'supported Up must reset the membership fixture exactly once');
  assert.equal(
    (upAction.match(/Get-SurvivalVerifiedMembershipPin/g) ?? []).length,
    1,
    'supported Up must derive exactly one Sodium-verified pin');
  assert.doesNotMatch(upAction, /survival-dev-seed|relay-bootstrap|@\('restart', 'xnode-1'/);
  const afterReadiness = upAction.slice(upAction.indexOf('Assert-SurvivalHostEndpoints'));
  assert.match(
    afterReadiness,
    /Assert-SurvivalHostEndpoints \$advertisedHost -IncludeChain:\$Chain[\s\S]*?survival-dev-verify\.mjs/,
    'bounded endpoint readiness must immediately precede native privacy verification');
  assert.match(afterReadiness, /Get-SurvivalVerifiedMembershipPin/);
});

test('P10E uses real current/next MIP1/RIP1 authority, bounded client ingress, a live driver, and pinned image provenance', () => {
  assert.doesNotMatch(compose, /Node__Ed25519PrivateKey:/);
  assert.match(compose, /Node__Ed25519PrivateKeyPath: \/run\/secrets\/xnode-ed25519\.seed/);
  assert.match(compose, /Mailbox__Enabled: "true"/);
  assert.match(compose, /Mailbox__PeerTimeout: "00:00:15"/);
  assert.match(compose, /Mailbox__ReplicationFactor: "2"/);
  assert.match(compose, /Mailbox__WriteQuorum: "2"/);
  assert.match(compose, /Mailbox__AllowInsecureHttpPeerTransport: "true"/);
  assert.match(compose, /SURVIVAL_MAILBOX_AUTHORITY_ENV/);
  assert.match(serviceBlock('xnode-1'), /SURVIVAL_MAILBOX_CLIENT_AUTHORITY_ENV/);
  assert.match(serviceBlock('xnode-1'), /Node__PublicHost: \$\{SURVIVAL_BIND_HOST:-127\.0\.0\.1\}/);
  assert.match(serviceBlock('xnode-1'), /Node__PublicPort: "41801"/);
  assert.match(serviceBlock('xnode-1'), /MailboxAuthorityForwarding__AllowedExitRouterIds__0: 7422b988/);
  assert.doesNotMatch(serviceBlock('xnode-2'), /MAILBOX_CLIENT_AUTHORITY_ENV/);
  assert.match(serviceBlock('xnode-2'), /Node__PublicHost: xnode-2/);
  assert.match(serviceBlock('xnode-2'), /Node__PublicPort: "41802"/);
  assert.match(serviceBlock('xnode-2'), /MailboxAuthorityForwarding__Enabled: "true"/);
  assert.match(serviceBlock('xnode-2'), /MailboxAuthorityForwarding__AuthorityRouterId: 4cb5abf6/);
  assert.doesNotMatch(compose, /SURVIVAL_MAILBOX_FALLBACK_CLIENT_AUTHORITY_ENV/);
  for (const index of [3, 4, 5, 6]) {
    assert.doesNotMatch(serviceBlock(`xnode-${index}`), /SURVIVAL_MAILBOX_CLIENT_AUTHORITY_ENV/);
  }
  assert.doesNotMatch(compose, /:4180[1-6]:8081/);
  for (const index of [1, 2, 3, 4, 5, 6]) {
    assert.match(serviceBlock(`xnode-${index}`), new RegExp(`privacy-routing-xnode-${index}\\.env`));
    assert.match(serviceBlock(`xnode-${index}`), new RegExp(`PrivacyRouting__PublicPeerBaseUrl: http:\\/\\/172\\.30\\.82\\.${10 + index}:8083\\/`));
    assert.match(serviceBlock(`xnode-${index}`), new RegExp(`source: xnode-${index}-ed25519`));
    assert.match(serviceBlock(`xnode-${index}`), /target: xnode-ed25519\.seed/);
    assert.match(serviceBlock(`xnode-${index}`), new RegExp(`source: xnode-${index}-x25519`));
    assert.match(serviceBlock(`xnode-${index}`), /target: xnode-x25519\.private/);
    assert.match(compose, new RegExp(`xnode-${index}-ed25519: \\{ file: \\.\\/.secrets\\/survival-dev\\/xnode-${index}-ed25519\\.seed \\}`));
    assert.match(compose, new RegExp(`xnode-${index}-x25519: \\{ file: \\.\\/.secrets\\/survival-dev\\/xnode-${index}-x25519\\.private \\}`));
  }
  assert.match(launcher, /\$SurvivalXNodeCommit = '00280a643cfdc1e0780147eceb1da5c7b6fd2799'/);
  assert.match(launcher, /Prepare-SurvivalXNodeIdentitySecrets/);
  assert.match(launcher, /Prepare-SurvivalMailboxPeerAuthority/);
  assert.match(launcher, /'--coordinator-url', "https:\/\/\$coordinatorHost`:41801"/);
  assert.doesNotMatch(launcher, /fallback-coordinator-url/);
  assert.doesNotMatch(launcher, /'--coordinator-url', "http:\/\/\$coordinatorHost`:41801"/);
  assert.match(launcher, /mailbox-client-xnode-1\.env/);
  assert.doesNotMatch(launcher, /mailbox-client-xnode-2\.env/);
  assert.match(launcher, /'Prepare' \{/);
  assert.match(launcher, /function Invoke-SurvivalMailboxDriverImmutable/);
  assert.match(launcher, /function Get-PinnedSurvivalXNodeContext/);
  assert.match(launcher, /Mailbox authority generation requires the exact verified pinned XNode build context/);
  assert.match(launcher, /New-SurvivalMailboxIsolatedSource/);
  assert.match(launcher, /Set-MailboxTreeReadOnly \$sourceRoot/);
  assert.match(launcher, /Open-MailboxTreeReadLocks \$sourceRoot/);
  assert.match(launcher, /--artifacts-path \$artifactsRoot/);
  assert.match(launcher, /Assert-SurvivalMailboxIsolatedSource \$isolated/);
  assert.doesNotMatch(launcher, /dotnet run[\s\S]*?XNodeSource=/);
  assert.doesNotMatch(launcher, /deep-survival-dev-p10c-mip1-rip1-v1/);
  assert.match(compose, /profiles: \[mailbox-rehearsal\]/);
  assert.match(serviceBlock('mailbox-driver'), /networks: \[runtime\]|<<: \*service/);
  assert.match(serviceBlock('mailbox-driver'), /mailbox-rehearsal-state:\/state/);
  assert.match(serviceBlock('mailbox-driver'), /SURVIVAL_MAILBOX_PUBLIC_AUTHORITY[\s\S]*?:\/run\/survival\/mailbox-peer-authority\.public\.json:ro/);
  assert.match(serviceBlock('mailbox-driver'), /source: xnode-1-ed25519/);
  assert.doesNotMatch(serviceBlock('mailbox-driver'), /source: xnode-[2-6]-ed25519/);
  const mailboxDriverStateInit = serviceBlock('mailbox-driver-state-init');
  assert.match(mailboxDriverStateInit, /network_mode: none/);
  assert.match(mailboxDriverStateInit, /user: "0:0"/);
  assert.match(mailboxDriverStateInit, /cap_add: \[CHOWN\]/);
  assert.match(
    mailboxDriverStateInit,
    /chown 65532:65532 \/state \/state\/driver/);
  assert.doesNotMatch(mailboxDriverStateInit, /chmod|777|DAC_OVERRIDE/);
  assert.match(compose, /XNODE_REVISION: 00280a643cfdc1e0780147eceb1da5c7b6fd2799/);
  assert.match(compose, /XNODE_SOURCE_CONTEXT_MANIFEST_SHA256: bd8cb5a16fb1d396716adc14d0adf95b005c0cccdf476cffd1cd65e5938aa102/);
  assert.match(compose, /org\.opencontainers\.image\.revision/);
  assert.match(compose, /com\.xpoint\.source-context\.manifest-sha256/);
  assert.match(compose, /sha256sum -c -/);
  assert.match(launcher, /\$SurvivalXNodeContextManifestSha256 = 'bd8cb5a16fb1d396716adc14d0adf95b005c0cccdf476cffd1cd65e5938aa102'/);
  const revisions = [
    ...compose.matchAll(/XNODE_REVISION: ([0-9a-f]{40})/g),
    ...launcher.matchAll(/\$SurvivalXNodeCommit = '([0-9a-f]{40})'/g),
    ...mailboxIntegration.matchAll(/\$expectedCommit = '([0-9a-f]{40})'/g),
    ...docs.matchAll(/`([0-9a-f]{40})`/g)
  ].map(match => match[1]);
  const manifests = [
    ...compose.matchAll(/XNODE_SOURCE_CONTEXT_MANIFEST_SHA256: ([0-9a-f]{64})/g),
    ...launcher.matchAll(/\$SurvivalXNodeContextManifestSha256 = '([0-9a-f]{64})'/g),
    ...mailboxIntegration.matchAll(/\$expectedManifest = '([0-9a-f]{64})'/g),
    ...docs.matchAll(/`([0-9a-f]{64})`/g)
  ].map(match => match[1]);
  assert.equal(new Set(revisions).size, 1);
  assert.equal(new Set(manifests).size, 1);
  assert.match(contextExport, /assertExactCleanGitSource/);
  assert.match(contextExport, /\.survival-source-manifest\.json/);
  assert.match(contextExport, /SourceContextManifestSha256=/);
  assert.match(contextExport, /status', '--porcelain=v1', '--untracked-files=all'/);
  assert.match(contextExport, /source is not the required clean pinned revision/);
  assert.match(mailboxIntegration, /ReplicatedMailboxTests/);
  assert.match(mailboxIntegration, /ReplicatedMailboxIntegrationTests/);
  assert.match(mailboxIntegration, /DurableMailboxCapabilityReplayJournalTests/);
  assert.match(mailboxIntegration, /MailboxNativeMau2BusinessInvariantTests/);
  assert.match(mailboxIntegration, /survival-dev-mailbox-driver\.test\.ps1/);
  assert.match(mailboxIntegration, /MailboxClientActivatedEndToEndTests/);
  assert.match(mailboxIntegration, /Remove-Item -LiteralPath \$EvidencePath -Force/);
  assert.match(mailboxIntegration, /failed rehearsal must never leave stale passed:true evidence/i);
  assert.match(mailboxEvidenceTest, /`"passed`":true/);
  assert.match(mailboxEvidenceTest, /missing-xnode/);
  assert.match(mailboxEvidenceTest, /Test-Path -LiteralPath \$evidence/);
  assert.match(mailboxIntegration, /mailbox-driver/);
  assert.match(mailboxIntegration, /MQR3|mqr3/);
  assert.match(mailboxIntegration, /selected-peer-loss/);
  assert.match(mailboxIntegration, /client-lifecycle/);
  assert.match(mailboxIntegration, /client-loss/);
  assert.match(mailboxIntegration, /client-retry-loss/);
  assert.match(mailboxDriver, /MembershipRouteDescriptorCodec\.ComputeRoot/);
  assert.match(mailboxDriver, /MembershipRouteDescriptorCodec\.BuildProofs/);
  assert.match(mailboxDriver, /MailboxPeerWireV2Codec\.Encode/);
  assert.match(mailboxDriver, /MailboxReceiptV2Codec|MRR2/);
  assert.match(mailboxDriver, /MailboxReplicationCoordinator/);
  assert.match(mailboxDriver, /Version = HttpVersion\.Version20/);
  assert.match(mailboxDriver, /VersionPolicy = HttpVersionPolicy\.RequestVersionExact/);
  assert.match(mailboxDriver, /response\.Version != HttpVersion\.Version20/);
  assert.match(mailboxDriver, /PartialFailure/);
  assert.match(mailboxDriver, /CryptographicOperations\.FixedTimeEquals/);
  assert.match(mailboxDriver, /The only mounted sender seed does not match xnode-1/);
  assert.match(mailboxDriver, /restricted to the xnode-1 sender identity/);
  assert.match(mailboxDriver, /schemaVersion = 2/);
  assert.match(mailboxIntegration, /schemaVersion = 3/);
  assert.match(mailboxIntegration, /stateVolumes = \$volumeBindingsAfter/);
  assert.match(mailboxIntegration, /Get-StateVolumeBindings/);
  assert.match(mailboxDriver, /P10E\/MCP2\/MAU2\/MIP1\/RIP1\/PRQ2/);
  assert.match(mailboxDriver, /MailboxAuthenticatedClientRequestCodec\.Encode/);
  assert.doesNotMatch(mailboxDriver, /(?:mst1|mrt1|mak1)(?:Bytes|")/i);
  assert.match(mailboxDriver, /MailboxClient__Enabled=false/);
  assert.match(mailboxDriver, /MailboxClient__Enabled=true/);
  assert.match(mailboxDriver, /MailboxClientAdapter__Enabled=true/);
  assert.match(mailboxDriver, /CurrentLocalMembershipProof/);
  assert.match(mailboxDriver, /NextLocalMembershipProof/);
  assert.match(mailboxDriver, /MailboxAuthenticatedRequestTranscript\.ForStore/);
  assert.match(mailboxDriver, /MailboxAuthenticatedRequestTranscript\.ForRetrieve/);
  assert.match(mailboxDriver, /MailboxAuthenticatedRequestTranscript\.ForAck/);
  assert.match(mailboxDriver, /crypto\.SignPresentation/);
  assert.match(mailboxDriver, /MailboxClientCodec\.DecodeRetrievePage/);
  assert.match(mailboxDriver, /MailboxAggregateAckCodec\.DecodeMqr3/);
  assert.match(mailboxDriver, /requireNonLoopbackCoordinator/);
  assert.match(mailboxDriver, /now \+ 1800 > nextAuthority\.ExpiresAtUnixSeconds/);
  assert.match(mailboxDriver, /bounded E\/E\+1 bridge with a live successor/);
  assert.match(mailboxProvisionDriver, /currentVerificationTime = Math\.Min/);
  assert.match(mailboxDriver, /boundedEpochWindows = true/);
  assert.match(mailboxDriver, /MailboxAuthenticatedCapabilityRuntime/);
  assert.match(mailboxDriver, /runtime\.CollectExpired\(retainUntil \+ 1, 1\)/);
  assert.match(mailboxDriver, /MailboxClientCanonicalOutcomeStore/);
  assert.match(mailboxDriver, /MailboxClientTerminalOutcome\.DurableStateRejected/);
  assert.match(mailboxDriver, /replayOutcomeCoordinated = true/);
  assert.doesNotMatch(mailboxDriver, /journal\.CollectExpired\(/);
  assert.doesNotMatch(mailboxDriver, /ePlusOneReservation/);
  assert.doesNotMatch(mailboxDriver, /2_145_000_000|2_145_916_800/);
  assert.match(mailboxIntegration, /\[Parameter\(Mandatory\)\][\s\S]*?\[string\]\$BindHost/);
  assert.match(mailboxIntegration, /-Action Build/);
  assert.match(mailboxIntegration, /-Action Prepare -LanHost \$BindHost/);
  assert.match(mailboxIntegration, /-Action Build -Service @\('mailbox-driver'\)/);
  assert.match(mailboxIntegration, /--require-non-loopback-coordinator/);
  assert.match(mailboxIntegration, /docker-compose\.survival-uat-tls\.dev\.yml/);
  assert.match(mailboxIntegration, /SURVIVAL_UAT_TLS_SECRET_DIR is required for the clean-break HTTPS privacy-route rehearsal/);
  assert.match(mailboxIntegration, /'--client-url', "https:\/\/\$\{BindHost\}:41801"/);
  assert.match(mailboxIntegration, /'--privacy-routes', '\/run\/survival\/privacy-routes\.v1\.json'/);
  assert.match(mailboxIntegration, /SSL_CERT_FILE=\/run\/survival\/ca\.crt/);
  assert.match(mailboxIntegration, /survival-uat-tls-ingress/);
  assert.doesNotMatch(mailboxIntegration, /--client-url', 'http:\/\/xnode-1:8080/);
  assert.match(mailboxIntegration, /publicClientPrivacyRouted = \$true/);
  assert.match(mailboxIntegration, /directCleartextClientIngress = \$false/);
  assert.doesNotMatch(mailboxIntegration, /-Action Up -LanHost \$BindHost/);
});

test('development identities remain exact strings and Up proves host HTTP reachability', () => {
  assert.match(compose, /SURVIVAL_XNODE_BUILD_CONTEXT/);
  assert.match(compose, /SURVIVAL_REGISTRY_BUILD_CONTEXT/);
  assert.match(compose, /SURVIVAL_STAKING_BUILD_CONTEXT/);
  assert.match(compose, /SURVIVAL_CONTRACTS_BUILD_CONTEXT/);
  assert.doesNotMatch(compose, /additional_contexts:[\s\S]*?SURVIVAL_(?:XNODE|REGISTRY|STAKING|CONTRACTS)_PATH/);
  assert.match(compose, /health\/live/);
  assert.match(compose, /^x-xnode:[\s\S]*?GET \/health\/ready HTTP\/1\.1[\s\S]*?^x-mailbox-driver-build:/m);
  assert.doesNotMatch(compose.match(/^x-xnode:[\s\S]*?^x-mailbox-driver-build:/m)?.[0] ?? '', /GET \/health\/live/);
  assert.match(serviceBlock('registry'), /GET \/health\/live HTTP\/1\.1/);
  assert.doesNotMatch(serviceBlock('xnode-1'), /test -r \/proc\/1\/status/);
  assert.doesNotMatch(serviceBlock('registry'), /test -r \/proc\/1\/status/);
  const ordinaryUp = launcher.match(/'Up' \{([\s\S]*?)\r?\n    \}\r?\n    'Down'/)?.[1] ?? '';
  assert.doesNotMatch(ordinaryUp, /--force-recreate/);
  assert.match(launcher, /Assert-SurvivalHostEndpoints/);
  assert.match(launcher, /DEEP_TRANSPORT_PROTOCOL=authenticated-mau2/);
  assert.match(launcher, /DEEP_TRANSPORT_OWNERSHIP=user-managed/);
  for (const port of [41545, 41801, 41802, 41803, 41804, 41805, 41806, 41810, 41811, 41820, 41821, 41822, 41823, 41999]) {
    assert.match(launcher, new RegExp(String(port)));
  }
});

test('expired DEV mailbox authority recovery is explicit, monotonic, and recoverable', () => {
  assert.match(launcher, /\[switch\]\$RecoverExpiredMailboxAuthority/);
  assert.match(launcher, /if \(-not \$RecoverExpiredMailboxAuthority\)/);
  assert.match(launcher, /currentEpoch = \$nextEpoch\r?\n\s+currentNotBeforeUnixSeconds = \$nextNotBefore\r?\n\s+currentExpiresAtUnixSeconds = \$nextExpires/);
  assert.match(launcher, /nextEpoch = \$nextEpoch \+ 1/);
  assert.match(launcher, /\$bridgeSuccessorNotBefore = \$nextExpires/);
  assert.match(launcher, /nextExpiresAtUnixSeconds = \$bridgeSuccessorNotBefore \+ 43260/);
  assert.match(launcher, /expired too long ago to form an exact live recovery bridge/);
  assert.match(launcher, /\.retired-through-/);
  assert.match(launcher, /\[IO\.File\]::Copy\(\$path, \$retired, \$false\)/);
  assert.match(launcher, /retired E\+1 preserved as an exact bridge/);
  assert.match(launcher, /accepted only by Prepare or Up/);
});

test('chaos rehearsal follows the exported LAN host and invalidates stale evidence', () => {
  assert.match(chaos, /\$env:XNODE_URLS/);
  assert.match(chaos, /\$RuntimeHost = \$runtimeHosts\[0\]/);
  assert.match(chaos, /\$env:SURVIVAL_BIND_HOST = \$RuntimeHost/);
  assert.match(chaos, /survival-dev-verify\.mjs'\), '--host', \$RuntimeHost/);
  assert.match(chaos, /Remove-Item -LiteralPath \$EvidencePath -Force/);
  assert.doesNotMatch(chaos, /survival-dev-verify\.mjs'\), '--host', '127\.0\.0\.1'/);
});

test('physical chaos compose and host tools are a closed authority', () => {
  assert.match(resendChaosCompose,
    /image: node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf/);
  assert.doesNotMatch(resendChaosCompose, /SURVIVAL_NODE_IMAGE/);
  assert.match(resendChaosCompose, /pull_policy: never/);
  assert.match(resendChaosCompose, /SURVIVAL_CHAOS_TOOLS_ROOT:\?set SURVIVAL_CHAOS_TOOLS_ROOT/);
  assert.match(launcher, /DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_PATH/);
  assert.match(launcher, /COMPOSE_DISABLE_ENV_FILE = 'true'/);
  assert.match(launcher, /PhysicalDockerHost = 'npipe:\/{4}\.\/pipe\/docker_engine'/);
  assert.doesNotMatch(launcher, /& docker\b|FilePath 'docker'/);
});
