import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
const retiredManifestPath = path.join(
  repositoryRoot,
  'config',
  'retired-uat-public-identities.json'
);
const ed25519Pkcs8SeedPrefix = Buffer.from('302e020100300506032b657004220420', 'hex');

function samePath(left, right) {
  return process.platform === 'win32'
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

export function deriveEd25519PublicId(seedHex) {
  assert.match(
    seedHex,
    /^[0-9a-f]{64}$/,
    'Ed25519 seed must be exactly 32 bytes of lowercase hexadecimal'
  );
  const privateKey = createPrivateKey({
    key: Buffer.concat([ed25519Pkcs8SeedPrefix, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicKeyDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return Buffer.from(publicKeyDer.subarray(-32)).toString('hex');
}

async function readCanonicalSeedFile(seedFile, nodeIndex) {
  assert.equal(typeof seedFile, 'string', `node ${nodeIndex} seed file is required`);
  assert.ok(path.isAbsolute(seedFile), `node ${nodeIndex} seed file path must be absolute`);
  assert.ok(
    samePath(seedFile, path.resolve(seedFile)),
    `node ${nodeIndex} seed file path must already be normalized`
  );
  const info = await lstat(seedFile);
  assert.equal(info.isSymbolicLink(), false, `node ${nodeIndex} seed file must not be a symlink/reparse point`);
  assert.equal(info.isFile(), true, `node ${nodeIndex} seed file must be a regular file`);
  assert.ok(
    samePath(seedFile, await realpath(seedFile)),
    `node ${nodeIndex} seed file must use its exact canonical path`
  );
  assert.ok(info.size <= 256, `node ${nodeIndex} seed file is unexpectedly large`);
  const seedHex = (await readFile(seedFile, 'utf8')).trim();
  assert.match(
    seedHex,
    /^[0-9a-f]{64}$/,
    `node ${nodeIndex} seed must be exactly lowercase 32-byte hexadecimal`
  );
  return seedHex;
}

export async function preflightIdentities(options) {
  assert.equal(options.nodes?.length, 3, 'exactly three private UAT identity bindings are required');
  const retired = JSON.parse(await readFile(retiredManifestPath, 'utf8'));
  const retiredRouterIds = new Set(
    retired.retiredRouterPublicIds.map(value => String(value).toLowerCase())
  );
  const publicIds = [];
  for (let index = 0; index < options.nodes.length; index += 1) {
    const node = options.nodes[index];
    const nodeIndex = index + 1;
    assert.match(
      node.routerId,
      /^[0-9a-f]{64}$/,
      `node ${nodeIndex} RouterId must be exactly lowercase 32-byte hexadecimal`
    );
    assert.ok(
      !retiredRouterIds.has(node.routerId),
      `node ${nodeIndex} RouterId is a retired public identity`
    );
    const seedHex = await readCanonicalSeedFile(node.seedFile, nodeIndex);
    const derivedPublicId = deriveEd25519PublicId(seedHex);
    assert.equal(
      derivedPublicId,
      node.routerId,
      `node ${nodeIndex} RouterId does not match the supplied Ed25519 seed`
    );
    publicIds.push(derivedPublicId);
  }
  assert.equal(new Set(publicIds).size, 3, 'all three derived RouterIds must be unique');

  return {
    schemaVersion: '1.0.0',
    status: 'accepted-fresh-matching-identities',
    identityCount: publicIds.length,
    routerIds: publicIds,
    seedValuesPrinted: false,
    productionReady: false,
    uatRestartAuthorized: false
  };
}

function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!/^--node-[123]-(?:router-id|seed-file)$/.test(name ?? '') ||
        !value ||
        value.startsWith('--') ||
        values.has(name)) {
      throw new Error(`invalid or missing identity preflight argument near ${name ?? '<end>'}`);
    }
    values.set(name, value);
  }
  assert.equal(values.size, 6, 'all six exact identity binding arguments are required');
  return {
    nodes: [1, 2, 3].map(index => ({
      routerId: values.get(`--node-${index}-router-id`),
      seedFile: values.get(`--node-${index}-seed-file`)
    }))
  };
}

export async function main(argv = process.argv.slice(2)) {
  const result = await preflightIdentities(parse(argv));
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01B private UAT identity preflight failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
