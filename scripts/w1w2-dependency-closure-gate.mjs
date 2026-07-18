import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  validateDependencyClosureEvidence,
  validateManifest
} from './pinned-integration-manifest.mjs';

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptRoot, '..');
const manifestPath = path.join(
  repositoryRoot,
  'release',
  'manifests',
  'survival-v2.1.0-w1w2-gate.detached.local.json'
);
const evidencePath = path.join(
  repositoryRoot,
  'release',
  'evidence',
  'w1w2-dependency-closure.json'
);

export async function runW1W2DependencyClosureGate(options = {}) {
  const producerSourceMapPath = options.producerSourceMapPath
    ?? process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP;
  if (!producerSourceMapPath) {
    throw new Error(
      'DEEP_W1W2_PRODUCER_SOURCE_MAP is required for strict producer verification'
    );
  }
  const validated = await validateManifest({
    manifestPath,
    producerSourceMapPath,
    verifyProducerArtifacts: true
  });
  if (validated.verifiedProducerArtifacts.length !== 17) {
    throw new Error('strict producer verification must verify exactly 17 artifacts');
  }
  const counts = Object.fromEntries(['P04', 'P05'].map(id => [
    id,
    validated.verifiedProducerArtifacts.filter(artifact => artifact.workPackage === id).length
  ]));
  if (counts.P04 !== 6 || counts.P05 !== 11) {
    throw new Error('strict producer verification artifact partition is invalid');
  }
  const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
  validateDependencyClosureEvidence(evidence, validated);
  return {
    releaseId: validated.manifest.releaseId,
    producerArtifactsVerified: validated.verifiedProducerArtifacts.length,
    counts
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runW1W2DependencyClosureGate()
    .then(result => {
      console.log(
        `W1/W2 dependency closure gate passed `
        + `(${result.producerArtifactsVerified} immutable producer artifacts).`
      );
    })
    .catch(error => {
      console.error(`W1/W2 dependency closure gate failed closed: ${error.message}`);
      process.exitCode = 1;
    });
}
