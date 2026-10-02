'use strict';
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const { prepareCanary, verifyImage, createArguments, sameSource, withCurrentView, withRenewalAndBundle } = require('./start-did2-registry-canary.cjs');
const { writePrivateEnvironment } = require('./prepare-did2-forward-probe-env.cjs');
let phase = 'preflight';

function preparePromotion(source, worker, prepared, expected, port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 ||
      JSON.stringify(source.HostConfig.PortBindings) !== JSON.stringify({
        '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: String(port) }] }) ||
      source.HostConfig.RestartPolicy?.Name !== 'unless-stopped' ||
      source.HostConfig.RestartPolicy.MaximumRetryCount !== 0 ||
      !worker.State?.Running || worker.Image !== expected.image ||
      worker.HostConfig?.NetworkMode !== prepared.network ||
      worker.HostConfig.Privileged || !worker.HostConfig.ReadonlyRootfs ||
      Object.keys(worker.HostConfig.PortBindings || {}).length ||
      !Array.isArray(worker.Config?.Env) || !Array.isArray(worker.Mounts))
    throw new Error('Promotion scope rejected.');
  const mounts = worker.Mounts.map(mount => {
    if (mount.Type !== 'bind' || typeof mount.RW !== 'boolean')
      throw new Error('Promotion custody rejected.');
    return `type=bind,src=${mount.Source},dst=${mount.Destination}${mount.RW ? '' : ',readonly'}`;
  });
  if (JSON.stringify([...worker.Config.Env].sort()) !== JSON.stringify([...prepared.entries].sort()) ||
      JSON.stringify(mounts.sort()) !== JSON.stringify([...prepared.mounts].sort()))
    throw new Error('Promotion worker differs from validated custody.');
  return prepared;
}

function promotionArguments(prepared, image, name, environment, port) {
  const args = createArguments(prepared, image, name, environment);
  args[args.indexOf('--restart') + 1] = 'unless-stopped';
  args.splice(args.indexOf('--entrypoint'), 0, '--publish', `127.0.0.1:${port}:8080/tcp`);
  return args;
}

function docker(args) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('Promotion Docker operation rejected.');
  return result.stdout;
}
function inspect(name) {
  const items = JSON.parse(docker(['inspect', '--type', 'container', name]));
  if (!Array.isArray(items) || items.length !== 1) throw new Error('Promotion cardinality rejected.');
  return items[0];
}
async function requireReady(worker) {
  const networks = Object.values(worker.NetworkSettings.Networks);
  if (networks.length !== 1 || net.isIP(networks[0].IPAddress) !== 4)
    throw new Error('Promotion diagnostic address rejected.');
  // Existing canary HTTP health only, not TLS, proof freshness or device evidence.
  for (const endpoint of ['/health/ready', '/health/did2/ready']) {
    const response = await fetch(`http://${networks[0].IPAddress}:8080${endpoint}`,
      { redirect: 'error', signal: AbortSignal.timeout(10000) });
    const reader = response.body?.getReader();
    if (!reader || response.status !== 200) throw new Error('Promotion health rejected.');
    const parts = []; let length = 0;
    try {
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        length += item.value.length;
        if (length > 4096) throw new Error('Promotion health bound rejected.');
        parts.push(Buffer.from(item.value));
      }
    } finally { await reader.cancel(); }
    if (JSON.parse(Buffer.concat(parts).toString('utf8')).ok !== true)
      throw new Error('Promotion canary is not ready.');
  }
}

async function main(args) {
  const keys = ['--mode', '--container', '--source-image', '--image', '--revision', '--worker', '--replacement',
    '--loopback-port', '--view-file', '--view-sha256', '--bundle-file', '--bundle-sha256', '--retained-ada2-sha256'];
  if (args.length !== keys.length * 2 || keys.some((key, i) => args[i * 2] !== key) ||
      !['preflight', 'promote'].includes(args[1]) || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[3]) ||
      !/^deep-did2-registry-canary-[a-z0-9-]{1,48}$/.test(args[11]) ||
      !/^deep-did2-registry-canary-promoted-[a-z0-9-]{1,32}$/.test(args[13]) ||
      args[11] === args[13] || !/^[1-9][0-9]{3,4}$/.test(args[15]))
    throw new Error('Exact promotion arguments required.');
  const expected = { sourceImage: args[5], image: args[7], revision: args[9] };
  const source = inspect(args[3]); const worker = inspect(args[11]); const port = Number(args[15]);
  const prepare = current => withRenewalAndBundle(
    withCurrentView(prepareCanary(current, expected), args[17], args[19]), current, args[21], args[23], args[25]);
  const prepared = preparePromotion(source, worker, prepare(source), expected, port);
  verifyImage(JSON.parse(docker(['image', 'inspect', expected.image])), expected);
  await requireReady(worker);
  let promoted = false;
  if (args[1] === 'promote') {
    process.umask(0o077);
    const temporary = fs.mkdtempSync('/var/tmp/deep-did2-promotion-');
    const environment = path.join(temporary, 'current.env');
    try {
      writePrivateEnvironment(environment, prepared.entries);
      phase = 'source-cas';
      const current = inspect(args[3]); const currentWorker = inspect(args[11]);
      if (!sameSource(source, current, expected)) throw new Error('Promotion source changed.');
      preparePromotion(current, currentWorker, prepare(current), expected, port);
      await requireReady(currentWorker);
      // Create first: a collision or invalid mount must fail before stopping the
      // source. Docker reserves the exact loopback listener only on start.
      phase = 'create';
      docker(promotionArguments(prepared, expected.image, args[13], environment, port));
      phase = 'stop-worker'; docker(['stop', '--time', '20', args[11]]);
      phase = 'stop-source'; docker(['stop', '--time', '20', args[3]]);
      phase = 'start'; docker(['start', args[13]]);
      promoted = true;
    } finally {
      if (fs.existsSync(environment)) fs.unlinkSync(environment);
      fs.rmdirSync(temporary);
    }
  }
  process.stdout.write(JSON.stringify({ schema: 'deep.registry.retained-canary-promotion.v1', promoted,
    publicProxyConfigurationChanged: false, loopbackListenerReused: true,
    retainedStateReset: false, oldContainersRemoved: false, deviceDeliveryVerified: false }) + '\n');
}
if (require.main === module) main(process.argv.slice(2)).catch(() => {
  process.stderr.write(`DID2 promotion failed closed (${phase}); containers and current protected floors were retained.\n`);
  process.exitCode = 1;
});
module.exports = { preparePromotion, promotionArguments };
