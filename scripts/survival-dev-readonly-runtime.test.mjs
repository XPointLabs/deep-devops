import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const image = process.env.SURVIVAL_CONTRACTS_IMAGE ?? 'deep-survival/contracts-devnet:dev';
const dockerTimeoutMs = 120_000;

function docker(args) {
  return spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: dockerTimeoutMs,
    windowsHide: true
  });
}

function containedRun(command) {
  return docker([
    'run', '--rm', '--network', 'none', '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
    '--tmpfs', '/workspace/cache:rw,noexec,nosuid,nodev,size=64m,mode=1777',
    '--env', 'HOME=/tmp', '--env', 'COREPACK_HOME=/opt/corepack',
    '--env', 'COREPACK_ENABLE_NETWORK=0', image, 'sh',
    '-ec', command
  ]);
}

function assertSucceeded(result, label) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  assert.equal(result.signal, null, `${label} timed out: ${output}`);
  assert.equal(result.status, 0, `${label} failed: ${output}`);
  assert.doesNotMatch(output, /EROFS|read-only file system|download|fetching package manager|HH502/i);
  return output;
}

test('Hardhat boots with an immutable rootfs, bounded cache, and no runtime network', () => {
  const inspect = docker(['image', 'inspect', image]);
  assert.equal(inspect.status, 0, `missing local image ${image}: ${inspect.stderr}`);

  const result = containedRun('pnpm --version && pnpm exec hardhat help >/tmp/hardhat-help.txt && test -s /tmp/hardhat-help.txt');
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  assert.equal(result.signal, null, `contained Hardhat timed out: ${output}`);
  assert.equal(result.status, 0, output);
  assert.match(output, /(?:^|\r?\n)9\.1\.3(?:\r?\n|$)/);
  assert.doesNotMatch(output, /EROFS|read-only file system|download|fetching package manager/i);
});

test('deploy and smoke complete in an isolated network-none namespace with immutable rootfs', () => {
  const nonce = `${process.pid}-${Date.now()}`;
  const devnetName = `deep-survival-readonly-${nonce}`;
  const initName = `${devnetName}-init`;
  const deployName = `${devnetName}-deploy`;
  const smokeName = `${devnetName}-smoke`;
  const deploymentVolume = `${devnetName}-deployments`;
  const resourceLabel = `com.xpoint.survival.readonly-test=${nonce}`;
  const ephemeralContainerNames = [initName, deployName, smokeName, devnetName];
  const readOnlyRuntimeArgs = [
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
    '--tmpfs', '/workspace/cache:rw,noexec,nosuid,nodev,size=64m,mode=1777',
    '--env', 'HOME=/tmp', '--env', 'COREPACK_HOME=/opt/corepack',
    '--env', 'COREPACK_ENABLE_NETWORK=0'
  ];

  try {
    assertSucceeded(docker(['volume', 'create', '--label', resourceLabel, deploymentVolume]), 'create isolated deployment volume');
    assertSucceeded(docker([
      'run', '--rm', '--name', initName, '--label', resourceLabel,
      '--network', 'none', '--read-only', '--user', '0:0',
      '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--entrypoint', 'sh',
      '--mount', `type=volume,src=${deploymentVolume},dst=/workspace/deployments`,
      image, '-ec', 'chown -R 1000:1000 /workspace/deployments'
    ]), 'initialize isolated deployment volume');

    const start = docker([
      'run', '-d', '--name', devnetName, '--label', resourceLabel,
      '--network', 'none', ...readOnlyRuntimeArgs,
      '--mount', `type=volume,src=${deploymentVolume},dst=/workspace/deployments`,
      image, 'pnpm', 'exec', 'hardhat', 'node', '--hostname', '127.0.0.1'
    ]);
    assertSucceeded(start, 'start isolated Hardhat devnet');

    let ready = false;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const probe = docker([
        'exec', devnetName, 'node', '--eval',
        "fetch('http://127.0.0.1:8545',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]})}).then(r=>r.json()).then(v=>process.exit(v.result==='0x7a69'?0:1)).catch(()=>process.exit(1))"
      ]);
      if (probe.status === 0) {
        ready = true;
        break;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    }
    assert.equal(ready, true, 'isolated Hardhat devnet did not become ready');

    const deployOutput = assertSucceeded(docker([
      'run', '--rm', '--name', deployName, '--label', resourceLabel,
      '--network', `container:${devnetName}`, ...readOnlyRuntimeArgs,
      '--mount', `type=volume,src=${deploymentVolume},dst=/workspace/deployments`,
      image, 'sh', '-ec',
      'rm -f /workspace/deployments/localhost.latest.json && pnpm exec hardhat run --no-compile scripts/deploy-local-devnet.js --network localhost && chmod 0644 /workspace/deployments/localhost.latest.json'
    ]), 'contained contracts-deploy');
    assert.match(deployOutput, /localhost\.latest\.json|deployed|deployment/i);

    const smokeOutput = assertSucceeded(docker([
      'run', '--rm', '--name', smokeName, '--label', resourceLabel,
      '--network', `container:${devnetName}`, ...readOnlyRuntimeArgs,
      '--mount', `type=volume,src=${deploymentVolume},dst=/workspace/deployments,readonly`,
      image, 'pnpm', 'exec', 'hardhat', 'run', '--no-compile',
      'scripts/local-devnet-smoke.js', '--network', 'localhost'
    ]), 'contained contracts-smoke');
    const smokeResult = JSON.parse(smokeOutput.trim());
    assert.equal(smokeResult.ok, true);
    assert.equal(smokeResult.network, 'localhost');
  } finally {
    for (const containerName of ephemeralContainerNames) docker(['rm', '-f', containerName]);
    docker(['volume', 'rm', '-f', deploymentVolume]);
    const leftovers = [];
    for (const containerName of ephemeralContainerNames) {
      if (docker(['container', 'inspect', containerName]).status === 0) leftovers.push(`container:${containerName}`);
    }
    if (docker(['volume', 'inspect', deploymentVolume]).status === 0) leftovers.push(`volume:${deploymentVolume}`);
    assert.deepEqual(leftovers, [], `ephemeral Docker resources leaked: ${leftovers.join(', ')}`);
  }
});
