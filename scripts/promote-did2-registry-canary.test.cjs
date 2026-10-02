'use strict';
const test = require('node:test'); const assert = require('node:assert/strict');
const { preparePromotion, promotionArguments } = require('./promote-did2-registry-canary.cjs');
function input() {
  const expected = { image: 'sha256:' + 'a'.repeat(64) };
  const source = { HostConfig: { PortBindings: { '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: '28188' }] },
    RestartPolicy: { Name: 'unless-stopped', MaximumRetryCount: 0 } } };
  const prepared = { network: 'retained', entries: ['PRIVATE=synthetic', 'CURRENT=true'],
    mounts: ['type=bind,src=/retained/state,dst=/state', 'type=bind,src=/public/view,dst=/view,readonly'] };
  const worker = { State: { Running: true }, Image: expected.image, Config: { Env: [...prepared.entries].reverse() },
    HostConfig: { NetworkMode: 'retained', Privileged: false, ReadonlyRootfs: true, PortBindings: {} },
    Mounts: [{ Type: 'bind', Source: '/public/view', Destination: '/view', RW: false },
      { Type: 'bind', Source: '/retained/state', Destination: '/state', RW: true }] };
  return { source, worker, prepared, expected };
}
test('only the exact validated worker custody and retained loopback listener can promote', () => {
  const i = input(); const before = structuredClone(i);
  assert.equal(preparePromotion(i.source, i.worker, i.prepared, i.expected, 28188), i.prepared);
  assert.deepEqual(i, before);
  for (const mutate of [i => i.source.HostConfig.PortBindings['8080/tcp'][0].HostIp = '0.0.0.0',
    i => i.source.HostConfig.PortBindings['8080/tcp'][0].HostPort = '28189',
    i => i.source.HostConfig.PortBindings['443/tcp'] = [],
    i => i.source.HostConfig.RestartPolicy.Name = 'always',
    i => i.worker.State.Running = false, i => i.worker.Image = 'sha256:' + 'b'.repeat(64),
    i => i.worker.HostConfig.NetworkMode = 'other', i => i.worker.HostConfig.Privileged = true,
    i => i.worker.HostConfig.ReadonlyRootfs = false, i => i.worker.HostConfig.PortBindings['8080/tcp'] = [],
    i => i.worker.Config.Env.push('CURRENT=false'), i => i.worker.Mounts[0].RW = true,
    i => i.worker.Mounts[1].Source = '/replaced/state', i => i.worker.Mounts[0].Type = 'volume']) {
    const changed = input(); mutate(changed);
    assert.throws(() => preparePromotion(changed.source, changed.worker, changed.prepared, changed.expected, 28188));
  }
});
test('promotion preserves confinement, mounted state and entrypoint without aliases or public binds', () => {
  const i = input(); const args = promotionArguments(i.prepared, i.expected.image,
    'deep-did2-registry-canary-promoted-test', '/private/current.env', 28188);
  assert.equal(args[args.indexOf('--publish') + 1], '127.0.0.1:28188:8080/tcp');
  assert.equal(args[args.indexOf('--restart') + 1], 'unless-stopped');
  assert.ok(args.includes('--read-only')); assert.ok(args.includes('--cap-drop'));
  assert.ok(!args.includes('--network-alias')); assert.ok(!args.includes('--privileged'));
  for (const mount of i.prepared.mounts) assert.ok(args.includes(mount));
  assert.deepEqual(args.slice(-3), [i.expected.image, '-c', 'umask 077; exec dotnet Deep.Registry.Api.dll']);
});
