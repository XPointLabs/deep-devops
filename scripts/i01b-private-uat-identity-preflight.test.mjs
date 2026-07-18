import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  deriveEd25519PublicId,
  preflightIdentities
} from './i01b-private-uat-identity-preflight.mjs';

test('identity preflight derives exact public ids from synthetic seeds and fails closed', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'i01b-identity-preflight-'));
  const seeds = ['01'.repeat(32), '02'.repeat(32), '03'.repeat(32)];
  const seedFiles = [];
  for (let index = 0; index < seeds.length; index += 1) {
    const seedFile = path.join(root, `node-${index + 1}.synthetic`);
    await writeFile(seedFile, `${seeds[index]}\n`, 'utf8');
    seedFiles.push(seedFile);
  }
  const nodes = seeds.map((seed, index) => ({
    routerId: deriveEd25519PublicId(seed),
    seedFile: seedFiles[index]
  }));

  try {
    const result = await preflightIdentities({ nodes });
    assert.equal(result.identityCount, 3);
    assert.equal(result.seedValuesPrinted, false);
    assert.deepEqual(result.routerIds, nodes.map(node => node.routerId));

    await assert.rejects(
      preflightIdentities({
        nodes: nodes.map((node, index) => index === 0
          ? { ...node, routerId: nodes[1].routerId }
          : node)
      }),
      /does not match|must be unique/
    );
    await assert.rejects(
      preflightIdentities({
        nodes: nodes.map((node, index) => index === 0
          ? { ...node, routerId: node.routerId.toUpperCase() }
          : node)
      }),
      /exactly lowercase/
    );
    await assert.rejects(
      preflightIdentities({
        nodes: nodes.map((node, index) => index === 2
          ? { ...node, seedFile: seedFiles[0] }
          : node)
      }),
      /does not match|must be unique/
    );

    await writeFile(seedFiles[2], '__NOT_A_SEED__\n', 'utf8');
    await assert.rejects(
      preflightIdentities({ nodes }),
      /seed must be exactly lowercase/
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
