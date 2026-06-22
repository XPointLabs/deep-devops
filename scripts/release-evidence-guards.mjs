import { existsSync } from 'node:fs';
import path from 'node:path';

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function placeholderHost(hostname) {
  const normalized = String(hostname ?? '').toLowerCase();
  return normalized === 'localhost'
    || normalized === '0.0.0.0'
    || normalized.startsWith('127.')
    || normalized.endsWith('.invalid')
    || normalized === 'example.com'
    || normalized.endsWith('.example.com')
    || normalized === 'example.org'
    || normalized.endsWith('.example.org')
    || normalized === 'example.net'
    || normalized.endsWith('.example.net')
    || normalized === 'host.docker.internal';
}

function placeholderUrl(value) {
  if (!hasText(value)) {
    return false;
  }

  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && placeholderHost(url.hostname);
  } catch {
    return false;
  }
}

function collectPlaceholderUrls(value, path = '$', results = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectPlaceholderUrls(entry, `${path}[${index}]`, results));
    return results;
  }

  if (!value || typeof value !== 'object') {
    return results;
  }

  for (const [key, entry] of Object.entries(value)) {
    const entryPath = `${path}.${key}`;
    if (String(key).toLowerCase() === 'url' && placeholderUrl(entry)) {
      results.push({ path: entryPath, url: entry });
      continue;
    }

    collectPlaceholderUrls(entry, entryPath, results);
  }

  return results;
}

function remoteReference(value) {
  if (!hasText(value)) {
    return false;
  }

  try {
    const url = new URL(value);
    return Boolean(url.protocol);
  } catch {
    return false;
  }
}

function resolveEvidencePath(value, baseDir) {
  const trimmed = value.trim();
  return path.isAbsolute(trimmed)
    ? trimmed
    : path.resolve(baseDir ?? process.cwd(), trimmed);
}

function collectLocalEvidencePaths(value, baseDir, objectPath = '$', results = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectLocalEvidencePaths(entry, baseDir, `${objectPath}[${index}]`, results));
    return results;
  }

  if (!value || typeof value !== 'object') {
    return results;
  }

  for (const [key, entry] of Object.entries(value)) {
    const entryPath = `${objectPath}.${key}`;
    if (String(key).toLowerCase() === 'path' && hasText(entry) && !remoteReference(entry)) {
      const resolvedPath = resolveEvidencePath(entry, baseDir);
      results.push({
        path: entryPath,
        value: entry,
        resolvedPath,
        exists: existsSync(resolvedPath)
      });
      continue;
    }

    collectLocalEvidencePaths(entry, baseDir, entryPath, results);
  }

  return results;
}

export function placeholderEvidenceAllowed() {
  return process.env.DEEP_ALLOW_PLACEHOLDER_EVIDENCE === 'true';
}

export function addNoPlaceholderUrlCheck(addCheck, label, manifest) {
  if (!manifest) {
    return;
  }

  const placeholderUrls = collectPlaceholderUrls(manifest);
  const allowPlaceholderEvidence = placeholderEvidenceAllowed();
  addCheck(`${label}:no-placeholder-urls`, allowPlaceholderEvidence || placeholderUrls.length === 0, {
    observed: placeholderUrls,
    allowPlaceholderEvidence
  });
}

export function addLocalEvidencePathCheck(addCheck, label, manifest, options = {}) {
  if (!manifest) {
    return;
  }

  const localPaths = collectLocalEvidencePaths(manifest, options.baseDir);
  const missingPaths = localPaths.filter(entry => !entry.exists);
  const allowPlaceholderEvidence = placeholderEvidenceAllowed();
  addCheck(`${label}:local-paths-exist`, allowPlaceholderEvidence || missingPaths.length === 0, {
    observed: missingPaths,
    checkedPaths: localPaths.length,
    baseDir: options.baseDir ?? process.cwd(),
    allowPlaceholderEvidence
  });
}

function positiveNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function evidenceNow(options = {}) {
  const raw = options.now ?? process.env.DEEP_EVIDENCE_NOW;
  if (hasText(raw)) {
    const parsed = new Date(raw);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }

  return new Date();
}

function maxAgeDays(options = {}) {
  return positiveNumber(options.maxAgeDays)
    ?? positiveNumber(process.env.DEEP_EVIDENCE_MAX_AGE_DAYS)
    ?? 30;
}

export function addGeneratedAtFreshnessCheck(addCheck, label, manifest, options = {}) {
  if (!manifest) {
    return;
  }

  const field = options.field ?? 'generatedAt';
  const generatedAt = manifest[field];
  const observed = hasText(generatedAt) ? generatedAt.trim() : null;
  const timestamp = observed ? new Date(observed) : null;
  const now = evidenceNow(options);
  const maxDays = maxAgeDays(options);
  const futureSkewMinutes = positiveNumber(options.futureSkewMinutes) ?? 10;
  const ageMs = timestamp ? now.getTime() - timestamp.getTime() : Number.NaN;
  const maxAgeMs = maxDays * 24 * 60 * 60 * 1000;
  const futureSkewMs = futureSkewMinutes * 60 * 1000;
  const validTimestamp = Boolean(timestamp) && !Number.isNaN(timestamp.getTime());
  const fresh = validTimestamp && ageMs <= maxAgeMs && ageMs >= -futureSkewMs;

  addCheck(`${label}:generated-at-fresh`, fresh, {
    observed,
    now: now.toISOString(),
    maxAgeDays: maxDays,
    futureSkewMinutes,
    ageDays: validTimestamp ? Number((ageMs / (24 * 60 * 60 * 1000)).toFixed(3)) : null
  });
}
