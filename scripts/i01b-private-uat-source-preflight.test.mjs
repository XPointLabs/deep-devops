import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  compatBuildContentSha256,
  preflightSource
} from './i01b-private-uat-source-preflight.mjs';

function git(context, args) {
  const result = spawnSync('git', ['-C', context, ...args], {
    encoding: 'utf8',
    windowsHide: true
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test('source preflight accepts only the exact clean commit, context, Dockerfile path, and hash', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i01b-source-preflight-'));
  const xnodeContext = path.join(root, 'xnode');
  const devopsDockerDirectory = path.join(root, 'deep-devops', 'docker');
  const devopsContext = path.join(root, 'deep-devops');
  const dockerfile = path.join(devopsDockerDirectory, 'xnode-xray.Dockerfile');
  await mkdir(xnodeContext);
  await mkdir(devopsDockerDirectory, { recursive: true });
  await writeFile(path.join(xnodeContext, 'XNode.csproj'), '<Project />\n', 'utf8');
  await writeFile(dockerfile, 'FROM scratch\n', 'utf8');
  for (const name of ['file', 'push', 'storage']) {
    await writeFile(
      path.join(devopsDockerDirectory, `${name}-service.Dockerfile`),
      'ARG NODE_IMAGE\nFROM ${NODE_IMAGE}\n',
      'utf8'
    );
    const serviceDirectory = path.join(devopsContext, 'tools', `${name}-service`);
    await mkdir(serviceDirectory, { recursive: true });
    await writeFile(path.join(serviceDirectory, `${name}.mjs`), `export const name = '${name}';\n`, 'utf8');
  }
  const compatDirectory = path.join(devopsContext, 'tools', 'compat-services');
  await mkdir(compatDirectory, { recursive: true });
  await writeFile(path.join(compatDirectory, 'compat.mjs'), 'export const compat = true;\n', 'utf8');
  git(xnodeContext, ['init', '--quiet']);
  git(xnodeContext, ['config', 'user.email', 'synthetic@example.invalid']);
  git(xnodeContext, ['config', 'user.name', 'Synthetic Test']);
  git(xnodeContext, ['add', 'XNode.csproj']);
  git(xnodeContext, ['commit', '--quiet', '-m', 'synthetic source']);
  const expectedCommit = git(xnodeContext, ['rev-parse', 'HEAD']);
  const expectedDockerfileSha256 = createHash('sha256')
    .update(await readFile(dockerfile))
    .digest('hex');
  git(devopsContext, ['init', '--quiet']);
  git(devopsContext, ['config', 'user.email', 'synthetic@example.invalid']);
  git(devopsContext, ['config', 'user.name', 'Synthetic Test']);
  git(devopsContext, ['add', '.']);
  git(devopsContext, ['commit', '--quiet', '-m', 'synthetic devops source']);
  const expectedDevopsCommit = git(devopsContext, ['rev-parse', 'HEAD']);
  const expectedCompatContentSha256 = await compatBuildContentSha256(devopsContext);
  const options = {
    xnodeContext,
    expectedCommit,
    dockerfile,
    expectedDockerfileSha256,
    canonicalDockerfile: dockerfile,
    devopsContext,
    expectedDevopsCommit,
    expectedCompatContentSha256,
    canonicalDevopsRoot: devopsContext
  };

  try {
    const result = await preflightSource(options);
    assert.equal(result.status, 'accepted-clean-pinned-source');
    assert.equal(result.clean, true);
    assert.equal(result.productionReady, false);

    await assert.rejects(
      preflightSource({ ...options, expectedCommit: '0'.repeat(40) }),
      /commit does not match/
    );
    await assert.rejects(
      preflightSource({ ...options, expectedDockerfileSha256: '0'.repeat(64) }),
      /Dockerfile content does not match/
    );
    await assert.rejects(
      preflightSource({ ...options, expectedDevopsCommit: '0'.repeat(40) }),
      /DevOps worktree commit does not match/
    );
    await assert.rejects(
      preflightSource({ ...options, expectedCompatContentSha256: '0'.repeat(64) }),
      /compat build content does not match/
    );

    const alternateDockerfile = path.join(root, 'alternate.Dockerfile');
    await writeFile(alternateDockerfile, 'FROM scratch\n', 'utf8');
    await assert.rejects(
      preflightSource({ ...options, dockerfile: alternateDockerfile }),
      /not the canonical reviewed/
    );

    await writeFile(path.join(xnodeContext, 'untracked.txt'), 'dirty\n', 'utf8');
    await assert.rejects(preflightSource(options), /must be exactly clean/);
    await rm(path.join(xnodeContext, 'untracked.txt'));

    await writeFile(path.join(devopsContext, 'untracked.txt'), 'dirty\n', 'utf8');
    await assert.rejects(preflightSource(options), /DevOps worktree must be exactly clean/);
    await rm(path.join(devopsContext, 'untracked.txt'));

    await assert.rejects(
      preflightSource({ ...options, xnodeContext: `${xnodeContext}${path.sep}.` }),
      /already be normalized/
    );
    await assert.rejects(
      preflightSource({ ...options, xnodeContext: path.dirname(xnodeContext) }),
      /Git worktree root|git rev-parse/
    );

    await writeFile(path.join(xnodeContext, 'XNode.csproj'), '<Project changed=\"true\" />\n', 'utf8');
    await assert.rejects(preflightSource(options), /must be exactly clean/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
