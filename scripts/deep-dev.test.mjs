import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const read = p => readFile(new URL(p, import.meta.url), 'utf8');

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
    for (const service of Object.values(document.services)) {
      for (const binding of service.ports ?? []) assert.equal(binding.host_ip, '127.0.0.1');
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
  assert.doesNotMatch(dockerfile, /cmake|g\+\+|clang|build-essential/);
  const testEnv = await read('./test-env.ps1');
  assert.match(testEnv, /\$BackendMode = .*else \{ "deep-dev" \}/);
});

test('engine fault tests automatic restart with retained custody and refuse a shared engine', async () => {
  const script = await read('./deep-dev.ps1');
  const fault = script.split("if ($Action -in @('StackFault','EngineFault','ExpiryFault'))")[1].split("if ($Action -eq 'Verify')")[0];
  assert.match(script, /\$Action -eq 'EngineFault' -and -not \$ConfirmEngineShutdown/);
  assert.match(fault, /\$wholeEngine = \$Action -eq 'EngineFault'/);
  assert.match(fault, /desktop-linux/);
  assert.match(fault, /\$allRunning.Count -ne 6/);
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
