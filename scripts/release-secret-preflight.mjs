import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const outputPath = argValue('--summary')
  ? path.resolve(argValue('--summary'))
  : path.join(artifactRoot, 'release', 'release-secret-preflight-summary.json');
const releaseCandidate = String(argValue('--release-candidate') ?? process.env.DEEP_RELEASE_CANDIDATE ?? '').trim();
const releaseLane = String(argValue('--release-lane') ?? process.env.DEEP_RELEASE_LANE ?? 'staging').trim().toLowerCase();
const pushProviderService = String(argValue('--push-provider-service') ?? process.env.DEEP_PUSH_PROVIDER_CANARY_SERVICE ?? 'firebase').trim().toLowerCase();
const requireCiRepoToken = process.argv.includes('--require-ci-repo-token');
const localLanes = new Set(['local', 'dev', 'test', 'smoke']);
const checks = [];

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index >= 0 && index + 1 < process.argv.length) {
    const value = process.argv[index + 1];
    return value.startsWith('--') ? null : value;
  }

  const prefix = `${name}=`;
  const inline = process.argv.find(value => value.startsWith(prefix));
  return inline ? inline.slice(prefix.length) : null;
}

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function hasEnv(name) {
  return typeof process.env[name] === 'string' && process.env[name].trim().length > 0;
}

function firstConfigured(names) {
  const source = names.find(hasEnv) ?? null;
  return {
    configured: Boolean(source),
    source
  };
}

function localOrPlaceholderHost(urlValue) {
  try {
    const parsed = new URL(urlValue);
    const host = parsed.hostname.toLowerCase();
    return host === 'localhost'
      || host === 'host.docker.internal'
      || host === '::1'
      || host.startsWith('127.')
      || host.endsWith('.invalid')
      || ['example.com', 'example.org', 'example.net'].includes(host);
  } catch {
    return true;
  }
}

const serviceKey = pushProviderService.toUpperCase();
const providerUrlNames = [`PUSH_PROVIDER_${serviceKey}_URL`, 'PUSH_PROVIDER_BASE_URL'];
const providerAuthNames = [
  `PUSH_PROVIDER_${serviceKey}_AUTH_HEADER`,
  `PUSH_PROVIDER_${serviceKey}_BEARER_TOKEN`,
  'PUSH_PROVIDER_AUTH_HEADER',
  'PUSH_PROVIDER_BEARER_TOKEN'
];
const canaryTokenNames = ['DEEP_PUSH_PROVIDER_CANARY_TOKEN'];
const ciRepoTokenNames = ['XPOINTLABS_CI_TOKEN'];

addCheck('release-lane:present', releaseLane.length > 0, { observed: releaseLane || null });
addCheck('push-provider-service:supported', ['apns', 'firebase', 'huawei'].includes(pushProviderService), {
  observed: pushProviderService,
  allowed: ['apns', 'firebase', 'huawei']
});

if (requireCiRepoToken) {
  const ciRepoToken = firstConfigured(ciRepoTokenNames);
  addCheck('ci-repo-token:configured', ciRepoToken.configured, {
    requiredEnv: ciRepoTokenNames,
    source: ciRepoToken.source
  });
}

const localLaneBypass = localLanes.has(releaseLane);
addCheck('push-provider:release-lane-classified', releaseLane.length > 0, {
  releaseLane,
  localLaneBypass
});

let providerUrl = { configured: false, source: null };
let providerAuth = { configured: false, source: null };
let canaryToken = { configured: false, source: null };
if (localLaneBypass) {
  addCheck('push-provider:local-lane-provider-config-optional', true, {
    releaseLane,
    note: 'Local/dev/test/smoke lanes may use the provider sink smoke path and do not satisfy release sign-off.'
  });
} else {
  providerUrl = firstConfigured(providerUrlNames);
  providerAuth = firstConfigured(providerAuthNames);
  canaryToken = firstConfigured(canaryTokenNames);

  addCheck('push-provider:url-configured', providerUrl.configured, {
    requiredEnv: providerUrlNames,
    source: providerUrl.source
  });
  addCheck('push-provider:auth-configured', providerAuth.configured, {
    requiredEnv: providerAuthNames,
    source: providerAuth.source
  });
  addCheck('push-provider:canary-token-configured', canaryToken.configured, {
    requiredEnv: canaryTokenNames,
    source: canaryToken.source
  });

  if (providerUrl.source) {
    addCheck('push-provider:url-nonlocal', !localOrPlaceholderHost(process.env[providerUrl.source]), {
      source: providerUrl.source,
      note: 'Release lanes require a non-local, non-placeholder provider URL.'
    });
  }
}

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  releaseCandidate: releaseCandidate || null,
  releaseLane,
  pushProviderService,
  localLaneBypass,
  requireCiRepoToken,
  configuredSources: {
    ciRepoToken: requireCiRepoToken ? firstConfigured(ciRepoTokenNames).source : null,
    providerUrl: providerUrl.source,
    providerAuth: providerAuth.source,
    canaryToken: canaryToken.source
  },
  checks,
  failedChecks: failed.map(check => check.name),
  note: 'Non-secret release preflight: records which required secret/config sources are present without writing secret values.'
};

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Release secret preflight failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Release secret preflight passed (${checks.length} checks). Summary: ${outputPath}`);
