import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const read = p => readFile(new URL(p, import.meta.url), 'utf8');

test('historical custody actions use one stopped retained owner and never provision or reset', async () => {
  const script = await read('./deep-dev.ps1');
  const recovery = script.split("if ($Action -in @('ExportStoreRecovery','ReconcileStoreCustody')) {")[1].split("if ($Action -eq 'Build') {")[0];
  assert.match(recovery, /\$ProjectName -cne 'deep-dev-current'/);
  assert.match(recovery, /secrets\/dev/);
  assert.match(recovery, /ReparsePoint/);
  assert.match(recovery, /Test-Path -LiteralPath \$proofPath/);
  assert.match(recovery, /current-mailbox-export-store-recovery/);
  assert.match(recovery, /current-mailbox-reconcile-store/);
  assert.match(recovery, /\$inspection.State.Running/);
  assert.ok(recovery.indexOf("@('stop','--timeout','10',$service)") < recovery.indexOf("@('run','--rm','--no-deps'"));
  assert.match(recovery, /finally\s*\{[\s\S]*@\('start',\$service\)/);
  assert.doesNotMatch(recovery, /@\('down'|--volumes|volume','rm|current-mailbox-enroll|provision-node|offline-root/);
});

test('dev builds cache only locked public packages, not source outputs or custody', async () => {
  const dockerfile = await read('../docker/deep-dev.Dockerfile');
  assert.match(dockerfile, /ENV NUGET_HTTP_CACHE_PATH=\/root\/\.nuget\/packages\/\.http-cache/);
  assert.doesNotMatch(dockerfile, /NuGetAudit=false|NUGET_AUDIT_MODE=off|--ignore-failed-sources/);
  const mounts = dockerfile.split('\n').filter(line => line.includes('--mount='));
  assert.equal(mounts.length, 4); // publish + Protocol, signer and node-authority test targets
  for (const line of mounts) {
    assert.match(line, /^RUN --mount=type=cache,id=deep-dev-nuget,target=\/root\/\.nuget\/packages,sharing=locked dotnet (publish|test) /);
    assert.doesNotMatch(line, /type=(bind|secret|ssh)|--no-restore/);
  }
});

test('physical ingress failure location is bounded owned metadata without exception text', async () => {
  const program = await read('../tools/deep-dev/Program.cs');
  const observation = program.split('var trace = new StackTrace(exception, false);')[1].split('Environment.ExitCode = 2;')[0];
  assert.match(observation, /GetFrames\(\)\.Take\(24\)/);
  assert.match(observation, /"Deep.Dev" or "Deep.Protocol" or "Deep.Protocol.MembershipRoutes"/);
  assert.match(observation, /location.Length <= 240/);
  assert.match(observation, /Math.Clamp\(frame.GetILOffset\(\), -1, 1048575\)/);
  assert.doesNotMatch(observation, /exception\.(Message|Data|ToString)|GetFileName|GetFileLineNumber/);
});

test('incremental dev build selects one closed service without changing default full build', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /ValidateSet\('all','registry','node-1','publisher'\).*BuildService = 'all'/);
  assert.match(script, /ContainsKey\('BuildService'\).*\$Action -cne 'Build'/);
  const build = script.split("if ($Action -eq 'Build') {")[1].split('function Test-CurrentCapabilities')[0];
  assert.match(build, /\$BuildService -ceq 'all'/);
  assert.match(build, /@\('build','registry','node-1','publisher'\)/);
  assert.match(build, /@\('build',\$BuildService\)/);
  assert.ok(build.indexOf("'validate-physical-ingress'") < build.indexOf("@('build',$BuildService)"));
  assert.doesNotMatch(build, /remove|down|--no-cache|--force-recreate/);
});

test('contact diagnostic explicitly selects another retained owner without fallback or reset', async () => {
  const script = await read('./deep-dev.ps1');
  const program = await read('../tools/deep-dev/Program.cs');
  const probe = await read('../tools/deep-dev/DevOwnedMailboxExercise.cs');
  assert.match(script, /ValidateSet\('primary','contact-diagnostic','contact-replication','contact-acceptance'\).*OwnedClientScope = 'primary'/);
  assert.match(script, /ContainsKey\('OwnedClientScope'\).*\$Action -cne 'ExerciseOwnedMailboxWindows'/);
  assert.match(program, /args.Length == 3 && args\[0\] == "exercise-owned-mailbox" && args\[2\] is \("contact-diagnostic" or "contact-replication" or "contact-acceptance"\)/);
  assert.match(probe, /clientScope != "primary" && !windows/);
  assert.match(probe, /"contact-diagnostic" => "client-probes\/windows-contact-diagnostic"/);
  assert.match(probe, /"contact-replication" => "client-probes\/windows-contact-replication"/);
  assert.match(probe, /_ => throw new ArgumentException\("Unknown retained test owner/);
  assert.doesNotMatch(probe, /Directory\.Delete|File\.Delete|catch[^\n]*RunAsync/);
});

test('rebuilding installed physical dev validates sealed images without reconfiguring them', async () => {
  const source = await read('./deep-dev.ps1');
  const build = source.split("if ($Action -eq 'Build') {")[1].split('function Test-CurrentCapabilities')[0];
  const physical = build.split('if ($physicalEnabled) {')[1].split('} else {')[0];
  assert.match(physical, /'validate-physical-ingress'/);
  assert.doesNotMatch(physical, /'configure'|install-|prepare-|provision/);
  assert.ok(build.indexOf("'validate-physical-ingress'") < build.indexOf("@('build','registry','node-1','publisher')"));
});

test('repeated physical Up checks the running ingress without allocating its static address twice', async () => {
  const source = await read('./deep-dev.ps1');
  const up = source.slice(source.lastIndexOf("switch ($Action) {")).split("'Status'")[0];
  assert.match(up, /'ps','--status','running','-q','ingress'/);
  assert.match(up, /\$runningIngress.Count -gt 1/);
  assert.match(up, /\$runningIngress.Count -eq 1/);
  assert.match(up, /'exec','-T','ingress','\/bin\/sh','\/usr\/local\/bin\/deep-dev-physical-ingress','--check'/);
  assert.match(up, /else \{\s*Run-Native docker \(\$compose \+ @\('run','--rm','--no-deps','ingress','--check'\)\)/);
});

test('physical current-dev overlay exposes exact LAN listeners without changing service or custody owners', () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const overlays = ['', '.mailbox', '.mailbox-nodes', '.contacts', '.coordination', '.pki', '.physical'];
  const args = ['compose', '--project-name', 'deep-dev-current', ...overlays.flatMap(s => ['--file', `${root}/docker-compose.deep-dev${s}.yml`]), 'config', '--format', 'json'];
  const env = { ...process.env, DEEP_DEV_ROOT: 'C:/Work/DeepSession/secrets/dev/deep-dev-current', DEEP_DEV_PROJECT: 'deep-dev-current',
    DEEP_DEV_IPV4_PREFIX: '172.31.241', DEEP_DEV_PORT_PREFIX: '282', DEEP_DEV_REGISTRY_PORT: '28543',
    DEEP_DEV_MAILBOX_NETWORK: '11'.repeat(16), DEEP_DEV_MAILBOX_POLICY: '22'.repeat(32),
    DEEP_DEV_CONTACT_NODE1: '33'.repeat(32), DEEP_DEV_CONTACT_NODE2: '44'.repeat(32), DEEP_DEV_CONTACT_NODE3: '55'.repeat(32),
    DEEP_DEV_PHYSICAL_ADDRESS: '192.168.40.20' };
  const c = JSON.parse(execFileSync('docker', args, { encoding: 'utf8', env }));
  assert.equal(Object.keys(c.services).length, 9);
  assert.deepEqual(c.services.registry.ports.map(p => [p.host_ip, Number(p.published), p.target]).sort(),
    [['127.0.0.1', 28543, 443], ['::1', 28543, 443], [env.DEEP_DEV_PHYSICAL_ADDRESS, 28543, 443]].sort());
  for (const [service, port, target] of [['publisher', 28297, 8080], ['registry', 28543, 443],
    ['ingress', 28294, 43001], ['ingress', 28295, 43002], ['ingress', 28296, 43003]]) {
    const p = c.services[service].ports.filter(p => p.host_ip === env.DEEP_DEV_PHYSICAL_ADDRESS && Number(p.published) === port);
    assert.equal(p.length, 1); assert.equal(Number(p[0].published), port); assert.equal(p[0].target, target);
    assert.ok(!c.services[service].volumes.some(v => v.type === 'bind' && /offline-root|[\\/]physical-ingress[\\/]/.test(v.source)));
  }
  for (const n of [1, 2, 3]) {
    const s = c.services[`node-${n}`];
    assert.equal(s.volumes.find(v => v.target === '/var/lib/xnode').source, `node-${n}-state`);
    assert.equal(s.volumes.find(v => v.target === '/var/lib/mailbox-keys').read_only, true);
    assert.ok(s.ports.some(p => p.host_ip === '127.0.0.1' && p.target === 443));
    assert.ok(!s.ports.some(p => p.host_ip === env.DEEP_DEV_PHYSICAL_ADDRESS));
    assert.equal(s.environment.Node__ManagedIngressH2ListenUrl, 'http://0.0.0.0:8082/');
    assert.equal(s.environment.Node__ManagedIngressTrustedProxyAddresses__0, '172.31.241.40');
  }
  const proxy = c.services.ingress;
  assert.equal(proxy.read_only, true);
  assert.deepEqual(proxy.cap_drop, ['ALL']);
  assert.equal(proxy.networks.dev.ipv4_address, '172.31.241.40');
  assert.equal(proxy.volumes.filter(v => /\/server\.(crt|key)$/.test(v.target)).length, 6);
  assert.ok(proxy.volumes.every(v => v.type === 'bind' && v.read_only));
  assert.ok(!proxy.volumes.some(v => /key_ed25519|key_bls|offline-root|operator|state|mailbox-keys/.test(v.source)));
});

test('physical ingress separates authenticated peer and public H2 paths without management exposure', async () => {
  const cfg = await read('../config/deep-dev-physical/haproxy.cfg');
  for (const n of [1, 2, 3]) {
    assert.match(cfg, new RegExp(`bind :4300${n} ssl crt /var/lib/haproxy/node-${n}\\.pem alpn h2`));
    assert.match(cfg, new RegExp(`node-${n}:8082 proto h2 check resolvers docker`));
    assert.match(cfg, new RegExp(`node-${n}:443 ssl verify required ca-file .* crl-file .* verifyhost node-${n} alpn h2`));
  }
  assert.equal((cfg.match(/deny deny_status 404 unless post frame or get capability or post peer/g) || []).length, 3);
  assert.equal((cfg.match(/deny deny_status 404 unless \{ ssl_fc_alpn -m str h2 \}/g) || []).length, 3);
  assert.doesNotMatch(cfg, /verify none|api\/staking|api\/admin|health\/ready|option httplog/);
  assert.deepEqual(cfg.split('\n').filter(line => line.includes('stats socket')).map(line => line.trim()),
    ['stats socket ipv4@127.0.0.1:19999 level user']);
  assert.match(cfg, /http-request del-header X-Forwarded-Proto/);
  assert.match(cfg, /http-request set-header X-Forwarded-Proto https/);
  assert.equal((cfg.match(/http-request set-uri http:\/\/%\[req.hdr\(host\)\]%\[pathq\]/g) || []).length, 3);
  assert.equal((cfg.match(/http-response del-header Date/g) || []).length, 3);
  assert.equal((cfg.match(/http-response del-header Server/g) || []).length, 3);
  assert.equal((cfg.match(/http-response set-header Cache-Control no-store/g) || []).length, 3);
  const entry = await read('../docker/deep-dev-physical-ingress.sh');
  assert.match(entry, /--check/);
  assert.match(entry, /haproxy -c -f/);
  assert.doesNotMatch(entry, /set -x|key_ed25519|key_bls|curl|wget/);
});

test('physical maintenance validates before stop and commits exact publisher bytes before runtime activation', async () => {
  const script = await read('./deep-dev.ps1');
  const flight = script.split("if ($Action -in @('PreparePhysicalIngress','ApplyPhysicalIngress')) {")[1].split("if ($Action -in @('PrepareDevPki'")[0];
  assert.ok(flight.indexOf("'validate-physical-ingress'") < flight.indexOf("@('stop','--timeout','10')"));
  assert.ok(flight.indexOf("'install-physical-ingress'") < flight.indexOf("'publish-physical-ingress'"));
  assert.ok(flight.indexOf("'publish-physical-ingress'") < flight.indexOf("'mark-physical-ingress'"));
  assert.match(flight, /\$candidate\/online:\/run\/deep-physical/);
  assert.doesNotMatch(flight, /\/run\/deep-physical[^\n]*offline-root|key_ed25519|key_bls|provision-floor|--volumes/);
  const publisher = await read('../tools/deep-dev/DevPublisher.cs');
  assert.ok(publisher.indexOf('DevPhysicalIngress.WriteResult(physicalRoot!') < publisher.indexOf('WriteJournal(state,committed,integrity)'));
  assert.match(publisher, /if \(physical is not null\) throw;/);
});

test('deep-dev keeps exactly six scoped native ARM64 services and durable custody', async () => {
  const compose = await read('../docker-compose.deep-dev.yml');
  const services = compose.split('services:\n')[1].split('\nnetworks:')[0];
  assert.deepEqual([...services.matchAll(/^  ([\w-]+):/gm)].map(m => m[1]),
    ['publisher', 'floor', 'registry', 'node-1', 'node-2', 'node-3']);
  assert.match(compose, /platform: linux\/arm64/);
  assert.equal([...compose.matchAll(/restart: always/g)].length, 2);
  assert.doesNotMatch(compose, /restart: unless-stopped/);
  assert.match(compose, /privacyRouting/);
  assert.match(compose, /registry-state:\/var\/lib\/registry/);
  for (const n of [1, 2, 3]) {
    assert.match(compose, new RegExp(`node-${n}-secrets:/run/secrets:ro`));
    assert.match(compose, new RegExp(`node-${n}-state:/var/lib/xnode`));
  }
  assert.doesNotMatch(compose, /offline-root|privileged:|docker\.sock/);
});

test('native public output uses existing publisher and read-only consumers without moving custody', async () => {
  const composePath = fileURLToPath(new URL('../docker-compose.deep-dev.yml', import.meta.url));
  const c = JSON.parse(execFileSync('docker', ['compose', '--project-name', 'deep-dev-current', '-f', composePath,
    'config', '--format', 'json'], {encoding: 'utf8', env: {...process.env,
      DEEP_DEV_ROOT: 'C:/Work/DeepSession/secrets/dev/deep-dev-current', DEEP_DEV_PROJECT: 'deep-dev-current'}}));
  assert.equal(Object.keys(c.services).length, 6);
  const output = c.services.publisher.volumes.find(v => v.target === '/run/deep-public-native');
  assert.equal(output.type, 'volume'); assert.equal(output.source, 'public-runtime'); assert.equal(Boolean(output.read_only), false);
  for (const service of ['registry', 'node-1', 'node-2', 'node-3']) {
    const input = c.services[service].volumes.find(v => v.target === '/run/deep-public');
    assert.equal(input.type, 'volume'); assert.equal(input.source, 'public-runtime'); assert.equal(input.read_only, true);
    assert.equal(c.services[service].depends_on.publisher.condition, 'service_healthy');
  }
  const mirror = await read('../tools/deep-dev/DevPublicArtifactMirror.cs');
  assert.doesNotMatch(mirror, /EnumerateFiles|EnumerateFileSystemEntries|CopyDirectory|\.seed|\.key|SignDetached|Signer\.Load/);
  assert.match(mirror, /RequireNoLinks/); assert.match(mirror, /Read\(file, XPointNetworkClosureWireCodec.MaximumResponseLength\)/);
  assert.match(mirror, /PRIVATE KEY/); assert.match(mirror, /Copy\("network.ncp2", bundle\)/);
  const publisher = await read('../tools/deep-dev/DevPublisher.cs');
  assert.match(publisher, /DevPublicArtifactMirror.Synchronize\(root, journal.Bundle\)/);
});

test('recovery scripts do not reset custody and historical probe receives public inputs only', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /ValidateSet\('deep-dev','deep-dev-current'\)/);
  assert.match(script, /--project-name',\$ProjectName/);
  assert.match(script, /secrets\\dev/);
  assert.doesNotMatch(script, /'down'.*'--volumes'|'volume','rm'|'system','prune'|Remove-Item/);
  const fault = script.split("if ($Action -eq 'HistoryFault')")[1].split("if ($Action -in")[0];
  assert.match(fault, /finally.*start','node-1','node-2','node-3'/s);
  assert.match(fault, /target=\/run\/deep-public,readonly/);
  assert.doesNotMatch(fault, /target=\/run\/(secrets|deep-operator)|target=\/var\/lib/);
  assert.match(fault, /messageDeliveryEvidence=\$false/);
});

test('actual Compose rendering isolates current and retained project state, subnets and ports', () => {
  const composePath = fileURLToPath(new URL('../docker-compose.deep-dev.yml', import.meta.url));
  const configurations = ['deep-dev', 'deep-dev-current'].map((project, index) => {
    const prefix = `172.31.${240 + index}`;
    const document = JSON.parse(execFileSync('docker', ['compose', '--project-name', project, '--file', composePath,
      'config', '--format', 'json'], { encoding: 'utf8', env: { ...process.env,
        DEEP_DEV_ROOT: `C:/Work/DeepSession/secrets/dev/${project}`, DEEP_DEV_PROJECT: project,
        DEEP_DEV_IPV4_PREFIX: prefix, DEEP_DEV_PORT_PREFIX: String(281 + index),
        DEEP_DEV_REGISTRY_PORT: String(28443 + index * 100) } }));
    assert.equal(document.name, project);
    assert.equal(Object.keys(document.services).length, 6);
    assert.equal(document.networks.dev.name, `${project}_dev`);
    assert.equal(document.networks.dev.ipam.config[0].subnet, `${prefix}.0/24`);
    for (const service of ['floor', 'registry', 'node-1', 'node-2', 'node-3'])
      assert.equal(document.volumes[`${service}-secrets`].name, `${project}_${service}-secrets`);
    for (const volume of Object.values(document.volumes)) assert.ok(volume.name.startsWith(`${project}_`));
    const registryPort = 28443 + index * 100;
    assert.deepEqual(document.services.registry.ports.map(p => [p.host_ip, Number(p.published), p.target]).sort(),
      [['127.0.0.1', registryPort, 443], ['::1', registryPort, 443]].sort());
    for (const [name, service] of Object.entries(document.services)) {
      for (const binding of service.ports ?? []) {
        assert.ok(binding.host_ip === '127.0.0.1' || name === 'registry' && binding.host_ip === '::1');
        assert.equal(binding.protocol, 'tcp');
      }
      for (const binding of service.volumes ?? [])
        if (binding.type === 'bind') assert.ok(binding.source.replaceAll('\\', '/').includes(`/secrets/dev/${project}/`));
    }
    return document;
  });
  const ports = document => Object.values(document.services).flatMap(s => (s.ports ?? []).map(p => String(p.published)));
  assert.equal(ports(configurations[0]).filter(p => ports(configurations[1]).includes(p)).length, 0);
  assert.notEqual(configurations[0].networks.dev.ipam.config[0].subnet, configurations[1].networks.dev.ipam.config[0].subnet);
});

test('local builds use reviewed image digests and a prebuilt native asset, not C++ compilation', async () => {
  const dockerfile = await read('../docker/deep-dev.Dockerfile');
  for (const image of ['golang', 'mcr.microsoft.com/dotnet/sdk', 'mcr.microsoft.com/dotnet/aspnet'])
    assert.ok(dockerfile.includes(`${image}@sha256:`));
  assert.match(dockerfile, /GOARCH=arm64/);
  assert.match(dockerfile, /FROM build AS protocol-tests/);
  assert.match(dockerfile, /FROM build AS node-authority-tests/);
  assert.match(dockerfile, /FullyQualifiedName~DeepIdV2NetworkPlacementRuntimeTests\|FullyQualifiedName~FileDeepIdV2DirectoryProtectedHeadStoreTests/);
  assert.match(dockerfile, /FullyQualifiedName~OperationGrammar\|FullyQualifiedName~GrammarMemoBudget/);
  assert.match(dockerfile, /FullyQualifiedName~CompleteOperationScratch/);
  for (const regression of ['MutationGrammar', 'CurrentMailboxAckTargetGrammarTests', 'FreshNativeIdentityJoin', 'RecipientFence_',
    'CurrentHostNativeRecoveryRejectsDamagedReplicaWithoutRepairOrHttp',
    'CurrentPeerColdRecoveryRejectsCoordinatedNativeLossOrAuthenticPreAckRollback',
    'CurrentHostRecoveryUsesOneAuthenticatedSnapshotForClientAndPeerJoin',
    'CurrentStartupReturnsPostJoinTimeOrRejectsChangedAuthority'])
    assert.ok(dockerfile.includes(`FullyQualifiedName~${regression}`));
  assert.doesNotMatch(dockerfile, /cmake|g\+\+|clang|build-essential/);
  const testEnv = await read('./test-env.ps1');
  assert.match(testEnv, /\$BackendMode = .*else \{ "deep-dev" \}/);
});

test('mailbox overlay isolates each seed and socket without adding any public listener', () => {
  const base=fileURLToPath(new URL('../docker-compose.deep-dev.yml',import.meta.url));
  const overlay=fileURLToPath(new URL('../docker-compose.deep-dev.mailbox.yml',import.meta.url));
  const config=JSON.parse(execFileSync('docker',['compose','--project-name','deep-dev-current','-f',base,'-f',overlay,'config','--format','json'],{
    encoding:'utf8',env:{...process.env,DEEP_DEV_PROJECT:'deep-dev-current',DEEP_DEV_ROOT:'C:/Work/DeepSession/secrets/dev/deep-dev-current',
      DEEP_DEV_IPV4_PREFIX:'172.31.241',DEEP_DEV_PORT_PREFIX:'282',DEEP_DEV_REGISTRY_PORT:'28543'}}));
  assert.equal(Object.keys(config.services).length,8);
  for(const role of ['deposit','retrieve']) {
    const s=config.services[`${role}-signer`];
    assert.equal(s.network_mode,'none');assert.equal(s.read_only,true);assert.equal(s.ports,undefined);
    assert.deepEqual(s.entrypoint,['dotnet']);assert.deepEqual(s.command,['Deep.Registry.Api.dll','mailbox-role-signer','run']);
    assert.equal(s.volumes.filter(v=>v.target==='/run/role-secrets'&&v.source===`${role}-secrets`&&v.read_only).length,1);
    assert.equal(s.volumes.length,3);assert.equal(s.restart,'always');
  }
  const secrets=config.services.registry.volumes.filter(v=>v.target==='/run/secrets');
  assert.equal(secrets.length,1);assert.equal(secrets[0].source,'registry-mailbox-secrets');
  assert.equal(config.services.registry.environment.DeepIdV2MailboxGrantAuthority__Enabled,'true');
});

test('mailbox activation explicitly provisions permanent roots and never repairs a retained journal',async()=>{
  const script=await read('./deep-dev.ps1');
  const preparation=await read('../tools/deep-dev/DevMailboxPreparation.cs');
  assert.match(preparation,/MailboxAuthorityV2Verifier.Verify/);assert.match(preparation,/policy.BindsProjection/);
  assert.match(preparation,/signer.Ed25519PublicKey.Span.SequenceEqual/);assert.doesNotMatch(preparation,/Signer.Create|SignDetached|DateTime.UtcNow/);
  assert.match(script,/registry-mailbox-secrets/);assert.match(script,/permanent grant\/MGR roots explicitly committed/);
  assert.match(script,/\$devServiceCount = if \(\$mailboxEnabled\) \{ 8 \} else \{ 6 \}/);
  assert.match(script,/Mailbox-enabled custody requires coordinated role-volume\/journal rollover/);
  const provisioning=script.split("if ($Action -eq 'ProvisionMailbox')")[1].split("if ($Action -eq 'ActivateMailbox')")[0];
  assert.match(provisioning,/BEGIN;/);assert.match(provisioning,/COMMIT;/);
  assert.doesNotMatch(provisioning,/ON CONFLICT|DELETE FROM|TRUNCATE|volume','rm|provision-floor/);
});

test('enrolled node overlay preserves existing identities and isolates read-only key rings from data/custody',()=>{
  const files=['deep-dev','deep-dev.mailbox','deep-dev.mailbox-nodes'].flatMap(name=>['-f',fileURLToPath(new URL(`../docker-compose.${name}.yml`,import.meta.url))]);
  const config=JSON.parse(execFileSync('docker',['compose','--project-name','deep-dev-current',...files,'config','--format','json'],{
    encoding:'utf8',env:{...process.env,DEEP_DEV_PROJECT:'deep-dev-current',DEEP_DEV_ROOT:'C:/Work/DeepSession/secrets/dev/deep-dev-current',
      DEEP_DEV_MAILBOX_NETWORK:'11'.repeat(16),DEEP_DEV_MAILBOX_POLICY:'22'.repeat(32),DEEP_DEV_IPV4_PREFIX:'172.31.241',DEEP_DEV_PORT_PREFIX:'282',DEEP_DEV_REGISTRY_PORT:'28543'}}));
  assert.equal(Object.keys(config.services).length,8);
  for(const i of [1,2,3]) {
    const node=config.services[`node-${i}`];assert.equal(node.environment.Mailbox__Enabled,'true');
    for(const [target,source,readonly] of [['/var/lib/xnode',`node-${i}-state`,false],['/run/secrets',`node-${i}-secrets`,true],
      ['/var/lib/mailbox-custody',`node-${i}-mailbox-custody`,false],['/var/lib/mailbox-keys',`node-${i}-mailbox-keys`,true]]) {
      const mounts=node.volumes.filter(v=>v.target===target);assert.equal(mounts.length,1);assert.equal(mounts[0].source,source);assert.equal(!!mounts[0].read_only,readonly);
    }
  }
});

test('contact overlay composes the current resolver and private issuer with independent custody',async()=>{
  const files=['deep-dev','deep-dev.mailbox','deep-dev.mailbox-nodes','deep-dev.contacts'].flatMap(name=>['-f',fileURLToPath(new URL(`../docker-compose.${name}.yml`,import.meta.url))]);
  const config=JSON.parse(execFileSync('docker',['compose','--project-name','deep-dev-current',...files,'config','--format','json'],{
    encoding:'utf8',env:{...process.env,DEEP_DEV_PROJECT:'deep-dev-current',DEEP_DEV_ROOT:'C:/Work/DeepSession/secrets/dev/deep-dev-current',
      DEEP_DEV_MAILBOX_NETWORK:'11'.repeat(16),DEEP_DEV_MAILBOX_POLICY:'22'.repeat(32),DEEP_DEV_IPV4_PREFIX:'172.31.241',DEEP_DEV_PORT_PREFIX:'282',DEEP_DEV_REGISTRY_PORT:'28543'}}));
  assert.equal(Object.keys(config.services).length,8);
  assert.equal(config.services.registry.cpus,2);
  for(const i of [1,2,3]) {
    const node=config.services[`node-${i}`];
    for(const flag of ['GroupControlService__RuntimeActivation','GroupControlService__MapReplicaEndpoint','RequiredTerminals__GroupControl',
      'ContactService__RuntimeActivation','ContactService__MapReplicaEndpoint','RequiredTerminals__Contact','DeepIdV2ReplicaStage__Enabled',
      'DeepIdV2PreKeyClaim__Enabled','DeepIdV2ContactResolver__Enabled','DeepIdV2ContactResolver__MailboxGrantEnabled'])assert.equal(node.environment[flag],'true');
    assert.equal(node.environment.DeepIdV2ContactResolver__MailboxGrantAuthorityOrigin,'https://registry/');
    for(const [target,source,readonly] of [['/var/lib/contact-custody',`node-${i}-contact-custody`,false],['/var/lib/contact-keys',`node-${i}-contact-keys`,true],
      ['/var/lib/mailbox-keys',`node-${i}-mailbox-keys`,true],['/var/lib/xnode',`node-${i}-state`,false],['/run/secrets',`node-${i}-secrets`,true]]) {
      const mounts=node.volumes.filter(v=>v.target===target);assert.equal(mounts.length,1);assert.equal(mounts[0].source,source);assert.equal(!!mounts[0].read_only,readonly);
    }
  }
  const script=await read('./deep-dev.ps1');
  const actions=script.split("if ($Action -in @('ProvisionNodeContactKeys'")[1].split("if ($Action -eq 'Build')")[0];
  assert.match(actions,/contact-resolver-enroll/);assert.match(actions,/'--network','none'/);
  assert.ok(actions.indexOf("@('stop','--timeout','10',$nodeName)")<actions.indexOf("'contact-resolver-enroll'"));
  assert.doesNotMatch(actions,/provision-floor|Signer.Create|DELETE|TRUNCATE|--volumes|volume','rm/);
});

test('coordination overlay retains eight services and uses explicit current journal roots',async()=>{
  const files=['deep-dev','deep-dev.mailbox','deep-dev.mailbox-nodes','deep-dev.contacts','deep-dev.coordination'].flatMap(name=>['-f',fileURLToPath(new URL(`../docker-compose.${name}.yml`,import.meta.url))]);
  const config=JSON.parse(execFileSync('docker',['compose','--project-name','deep-dev-current',...files,'config','--format','json'],{
    encoding:'utf8',env:{...process.env,DEEP_DEV_PROJECT:'deep-dev-current',DEEP_DEV_ROOT:'C:/Work/DeepSession/secrets/dev/deep-dev-current',
      DEEP_DEV_CONTACT_NODE1:'11'.repeat(32),DEEP_DEV_CONTACT_NODE2:'22'.repeat(32),DEEP_DEV_CONTACT_NODE3:'33'.repeat(32),
      DEEP_DEV_MAILBOX_NETWORK:'11'.repeat(16),DEEP_DEV_MAILBOX_POLICY:'22'.repeat(32),DEEP_DEV_IPV4_PREFIX:'172.31.241',DEEP_DEV_PORT_PREFIX:'282',DEEP_DEV_REGISTRY_PORT:'28543'}}));
  assert.equal(Object.keys(config.services).length,8);
  assert.equal(config.services.registry.environment.ContactRouteAuthority__Enabled,'true');
  assert.equal(config.services.registry.environment.ContactPublicationAuthority__Enabled,'true');
  for(const i of [1,2,3])assert.equal(config.services[`node-${i}`].environment.ContactCoordination__BackendOrigin,'https://registry/');
  const script=await read('./deep-dev.ps1');
  const action=script.split("if ($Action -in @('PrepareContactCoordination','ProvisionContactCoordination','ActivateContactCoordination')) {")[1].split("if ($Action -eq 'Build')")[0];
  assert.match(action,/'BEGIN;'/);assert.match(action,/'COMMIT;'/);
  assert.match(action,/did2-route-threshold-journal.sql/);assert.match(action,/did2-publication-journal.sql/);
  assert.doesNotMatch(action,/IF NOT EXISTS|ON CONFLICT|DELETE FROM|TRUNCATE|provision-floor|--volumes/);
});

test('owned mailbox exercise is public-input-only and calls real account-owned APIs',async()=>{
  const script=await read('./deep-dev.ps1');
  const action=script.split("if ($Action -eq 'ExerciseOwnedMailbox') {")[1].split("if ($Action -eq 'Build')")[0];
  assert.equal((action.match(/'--mount'/g)||[]).length,1);
  assert.match(action,/source=\$custodyPath\/public,target=\/run\/deep-public,readonly/);
  assert.doesNotMatch(action,/role.seed|root.seed|\/run\/secrets|source=.*operator|provision-floor/);
  const probe=await read('../tools/deep-dev/DevOwnedMailboxExercise.cs');
  for(const call of ['AdmitAndVerifyGenesisAsync','VerifyCurrentNetworkAsync','PublishOwnPreKeyInventoryAsync',
    'EnsureOwnPermanentContactPublishedAsync','SynchronizeOwnMailboxAsync'])assert.ok(probe.includes(call));
  assert.doesNotMatch(probe,/EnsureOwnInitialPreKeyInventoryAsync|PublishOwnStagedPreKeyInventoryAsync/);
  assert.match(probe,/samePublication && priorPair is not null/);
  assert.ok(probe.indexOf('PublishOwnPreKeyInventoryAsync') < probe.indexOf('StageAsync("SignedEntryTls"'));
  assert.match(probe,/deviceEvidence=false,messageDeliveryEvidence=false,restartEvidence=false/);
  assert.doesNotMatch(probe,/ServerCertificateValidationCallback|NoCheck|FrozenClock|Signer.Load|SignDetached/);
});

test('Windows owned probe retains DPAPI-protected state and adds no global ROOT trust',async()=>{
  const probe=await read('../tools/deep-dev/DevOwnedMailboxExercise.cs');
  assert.match(probe,/JournaledDeepSecureStorage/);assert.match(probe,/accounts.GetCurrentAsync/);
  assert.match(probe,/WithAppScopedPrivateCertificateAuthority/);
  assert.match(probe,/unavailable.RetryAfter/);assert.match(probe,/await Task.Delay\(delay,ct\)/);
  assert.doesNotMatch(probe,/NoCheck|Ignore.*Revocation|ServerCertificateValidationCallback/);
  const protection=await read('../tools/deep-dev/DevWindowsSecretProtector.cs');assert.match(protection,/ProtectKeysWithDpapi/);
  const pki=await read('../tools/deep-dev/DevPki.cs');assert.match(pki,/new\[\]\{"-user","-addstore","CA",path\}/);
  assert.doesNotMatch(pki,/'-addstore','ROOT'|"-addstore","ROOT"|"-enterprise"/);
});

test('dev PKI serves only signed public CRL inside the existing publisher with no new port mapping',async()=>{
  const files=['deep-dev','deep-dev.mailbox','deep-dev.mailbox-nodes','deep-dev.contacts','deep-dev.coordination','deep-dev.pki'].flatMap(name=>['-f',fileURLToPath(new URL(`../docker-compose.${name}.yml`,import.meta.url))]);
  const config=JSON.parse(execFileSync('docker',['compose','--project-name','deep-dev-current',...files,'config','--format','json'],{
    encoding:'utf8',env:{...process.env,DEEP_DEV_PROJECT:'deep-dev-current',DEEP_DEV_ROOT:'C:/Work/DeepSession/secrets/dev/deep-dev-current',
      DEEP_DEV_CONTACT_NODE1:'11'.repeat(32),DEEP_DEV_CONTACT_NODE2:'22'.repeat(32),DEEP_DEV_CONTACT_NODE3:'33'.repeat(32),
      DEEP_DEV_MAILBOX_NETWORK:'11'.repeat(16),DEEP_DEV_MAILBOX_POLICY:'22'.repeat(32),DEEP_DEV_IPV4_PREFIX:'172.31.241',DEEP_DEV_PORT_PREFIX:'282',DEEP_DEV_REGISTRY_PORT:'28543'}}));
  assert.equal(Object.keys(config.services).length,8);assert.equal(config.services.publisher.command[1],'publish-with-crl');
  assert.equal(config.services.publisher.ports?.length||0,0);
  const host=await read('../tools/deep-dev/DevPkiPublisher.cs');assert.match(host,/ValidateCrl\(bytes,ca\)/);assert.match(host,/ClearProviders/);
  assert.equal((host.match(/MapGet\(/g)||[]).length,1);assert.doesNotMatch(host,/MapPost|\.key|root.seed|SignDetached|NoCheck/);
  const script=await read('./deep-dev.ps1');const ceremony=script.split("if ($Action -in @('PrepareDevPki','ApplyDevPki')) {")[1].split("if ($Action -eq 'ExerciseOwnedMailbox')")[0];
  assert.ok(ceremony.indexOf("'validate-dev-pki'")<ceremony.indexOf("@('stop','--timeout','10')"));
  assert.ok(ceremony.indexOf("@('stop','--timeout','10')")<ceremony.indexOf("'install-dev-pki'"));
  assert.match(ceremony,/stat -c "%u:%g" \/target\/server.key/);
  assert.match(ceremony,/chown "\$owner" \/target\/server.crt.pki-stage/);
  assert.doesNotMatch(ceremony,/provision-floor|--volumes|cp[^;]*server.key|volume','rm/);
});

test('engine fault tests automatic restart with retained custody and refuse a shared engine', async () => {
  const script = await read('./deep-dev.ps1');
  const fault = script.split("if ($Action -in @('StackFault','EngineFault','ExpiryFault'))")[1].split("if ($Action -eq 'Verify')")[0];
  assert.match(script, /\$Action -eq 'EngineFault' -and -not \$ConfirmEngineShutdown/);
  assert.match(fault, /\$wholeEngine = \$Action -eq 'EngineFault'/);
  assert.match(fault, /desktop-linux/);
  assert.match(fault, /\$allRunning.Count -ne \$devServiceCount/);
  assert.match(fault, /\$policy -cne 'always'/);
  assert.match(fault, /Invoke-DesktopOperation 'stop' 60/);
  assert.match(fault, /finally\s*\{\s*if \(\$wholeEngine\) \{[^}]*Invoke-DesktopOperation 'start' 120/s);
  assert.match(fault, /if \(\$wholeEngine\) \{ Invoke-DesktopOperation 'stop' 60 \}\s*else \{ Run-Native docker \(\$compose \+ @\('stop','--timeout','10'\)\) \}/);
  assert.match(fault, /else \{ Run-Native docker \(\$compose \+ @\('start'\)\) \}/);
  assert.match(fault, /post-restart stability window/);
  assert.match(fault, /Online custody changed/);
  assert.match(fault, /unchangedStateMounts=\$true/);
  assert.match(fault, /messageDeliveryEvidence=\$false/);
  assert.match(script, /WaitForExit\(\(\$TimeoutSeconds \+ 10\) \* 1000\)/);
  assert.doesNotMatch(script, /\$process.Kill\(\$true\)/);
  assert.match(fault, /deep-dev-engine-case.v1/);
  assert.match(fault, /deep-dev-stack-case.v1/);
  assert.match(fault, /automaticContainerStart=\$wholeEngine;wholeEngineShutdown=\$wholeEngine/);
});

test('expiry fault authors shorter real signed views without clock or trust changes', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /publish-short-view/);
  assert.match(script, /\$OfflineSeconds = 200/);
  const publisher = await read('../tools/deep-dev/DevPublisher.cs');
  assert.match(publisher, /operationalLifetimeSeconds is < 180 or > 3_600/);
  assert.match(publisher, /AuthorDelegatedAsync/);
  assert.match(publisher, /checked\(observed\+operationalLifetimeSeconds-30\)/);
  assert.match(publisher, /if \(singlePublication\) return/);
  assert.doesNotMatch(script, /Set-Date|hwclock|timedatectl/);
});

test('publisher authenticates terminal paired history and warns without loading root or repairing state', async () => {
  const publisher = await read('../tools/deep-dev/DevPublisher.cs');
  assert.match(publisher, /XPointNetworkAuthorityVerifier\.Verify\(pin,\s*closure\.ExactAuthorityChain,closure\.ExactTimePolicyChain\)/);
  assert.match(publisher, /closure\.ExactTimePolicyChain\[\^1\]/);
  assert.match(publisher, /closure\.ExactMailboxAuthorityChain\[\^1\]/);
  assert.match(publisher, /MailboxAuthorityV2Verifier\.Verify\(authority,pma\.Span,observed,checked\(observed\+1\)\)/);
  assert.match(publisher, /offline policy expiry approaching/);
  assert.match(publisher, /offline policy renewal required/);
  assert.doesNotMatch(publisher, /bootstrap\.Authority|ExactNetworkPolicyChain\.Count != 1|Signer\.Load\([^\n]*root\.seed/);
});

test('offline dev ceremony is explicit and cannot publish root-only renewal as an operational closure', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /\$Action -in @\('PrepareAuthority','PrepareOperational'\)/);
  assert.match(script, /'prepare-authority',\$custodyPath,\$observer/);
  const source = await read('../tools/deep-dev/DevOfflineAuthorityRenewal.cs');
  assert.match(source, /XPointNetworkAuthorityVerifier\.Verify/);
  assert.match(source, /AuthorSameKeyRenewalAsync/);
  assert.match(source, /RequireUnchanged\(\)/);
  assert.match(source, /FileShare\.None/);
  assert.match(source, /FileMode\.CreateNew/);
  assert.doesNotMatch(source, /EncodeResponse|WriteJournal|FileMode\.Create[,)]|genesis reset/);
  const compose = await read('../docker-compose.deep-dev.yml');
  assert.doesNotMatch(compose, /offline-root/);
});

test('new dev bootstrap retains independent mailbox issuer seeds and emits no retired authority section', async () => {
  const source = await read('../tools/deep-dev/Program.cs');
  assert.match(source, /Signer\.Create\(Path.Combine\(registrySecrets, "mailbox-deposit.seed"\)\)/);
  assert.match(source, /Signer\.Create\(Path.Combine\(registrySecrets, "mailbox-retrieve.seed"\)\)/);
  assert.match(source, /depositIssuer.Ed25519PublicKey.Span/);
  assert.match(source, /retrieveIssuer.Ed25519PublicKey.Span/);
  assert.doesNotMatch(source, /\["ContactAuthority"\] =|\["GroupControlAuthority"\] =/);
  assert.match(source, /XPointNetworkClosureWireCodec.DecodeResponse\(bytes\)/);
});

test('observer admission sends the retained exact request over normal TLS without custody mounts or currentness substitution', async () => {
  const script = await read('./deep-dev.ps1');
  const helper = script.split('function Invoke-DevObserverAdmission {')[1].split("if ($Action -eq 'AdmitObserver')")[0];
  assert.match(helper, /observer\/admission.dga2/);
  assert.match(helper, /target=\/run\/deep-public,readonly/);
  assert.match(helper, /target=\/run\/deep-observer\/admission.dga2,readonly/);
  assert.doesNotMatch(helper, /offline-root|target=\/run\/secrets|target=\/run\/deep-operator|target=\/var\/lib/);
  const source = await read('../tools/deep-dev/DevObserverAdmission.cs');
  assert.match(source, /https:\/\/registry\/api\/v2\/account-directory\/genesis-admissions/);
  assert.match(source, /receipt.OperationId.Span.SequenceEqual\(request.OperationId.Span\)/);
  assert.doesNotMatch(source, /ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback|CreateAsync|new SystemClock|EnsureCurrent/);
});

test('offline operational preparation freezes the exact publisher predecessor and never mounts root online', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /if \(\$Action -eq 'PrepareOperational'\)/);
  assert.match(script, /Operator-stopped publisher cannot be resumed/);
  assert.match(script, /if \(-not \$operationalPrepared\) \{\s+Run-Native docker @\('update','--restart',\$publisherPolicy,\$publisherId\)/);
  assert.match(script, /Run-Native docker @\('update','--restart','unless-stopped',\$publisherId\)/);
  const source = await read('../tools/deep-dev/DevOfflineOperationalRenewal.cs');
  assert.match(source, /AuthorPairAsync/);
  assert.match(source, /ComputeNextMailboxGrantFloor/);
  assert.match(source, /XPointNetworkOperationalSuccessorAuthor.AuthorAsync/);
  assert.match(source, /HMACSHA256.HashData\(integrity, payload\)/);
  assert.doesNotMatch(source, /NotImplementedException|FileMode.Create[,)]/);
  const publisher = await read('../tools/deep-dev/DevPublisher.cs');
  assert.match(publisher, /ValidatePreparedImport\(pin,current,candidate\)/);
  assert.match(publisher, /WriteJournal\(state,candidate,key\)/);
  assert.doesNotMatch(publisher, /Signer.LoadRoot|root.seed/);
});

test('operational activation installs a sealed whitelist with all owners stopped before journal import', async () => {
  const script = await read('./deep-dev.ps1');
  const activation = script.split("if ($Action -eq 'ApplyOperational') {")[1].split("if ($Action -in @('StackFault'")[0];
  assert.ok(activation.indexOf("'validate-operational-install'") < activation.indexOf("@('stop','--timeout','10')"));
  assert.ok(activation.indexOf("@('stop','--timeout','10')") < activation.indexOf("'install-operational'"));
  assert.ok(activation.indexOf("'install-operational'") < activation.indexOf("'import-operational'"));
  assert.ok(activation.indexOf("'import-operational'") < activation.indexOf("@('start')"));
  assert.match(activation, /Join-Path \$candidatePath 'operator'/);
  assert.match(activation, /target=\/run\/deep-renewal,readonly/);
  assert.doesNotMatch(activation, /source=\$candidatePath[,}]|Provision|provision-state|provision-floor|down|--volumes|key_ed25519|key_bls/);
  const source = await read('../tools/deep-dev/DevOperationalActivation.cs');
  assert.match(source, /CryptographicOperations.FixedTimeEquals/);
  assert.match(source, /Stale installation candidate/);
  assert.match(source, /CustomRootTrust/);
  assert.match(source, /ResolveIssuer\(domain\)/);
  assert.match(source, /Retained installation target changed/);
  assert.doesNotMatch(source, /ServerCertificateCustomValidationCallback|VerificationFlags|AllowUnknownCertificateAuthority/);
});
