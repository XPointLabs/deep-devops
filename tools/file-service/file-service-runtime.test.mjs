import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  createAvatarAuthorizationHeaders as avatarAuthorizationHeaders,
  createTestStorageSigningIdentity
} from '../compat-services/storage-signatures.mjs';

const scriptPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'file-service.mjs');
const sessionFileIdFixturePath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'session-file-id.golden.json'
);

async function waitForReady(baseUrl, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(`${baseUrl}/health/ready`);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep retrying until timeout.
    }

    await new Promise(resolve => setTimeout(resolve, 100));
  }

  throw new Error('file-service did not become ready in time');
}

async function startFileService({ port, stateDir, extraEnv = {} }) {
  const child = spawn(process.execPath, [scriptPath], {
    env: {
      ...process.env,
      PORT: String(port),
      MOCK_STATE_DIR: stateDir,
      ...extraEnv
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let stderr = '';
  child.stderr.on('data', chunk => {
    stderr += String(chunk);
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForReady(baseUrl);

  return {
    baseUrl,
    async stop() {
      child.kill('SIGTERM');
      await new Promise(resolve => {
        child.once('exit', () => resolve());
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 1000);
      });

      if (stderr.trim()) {
        assert.fail(`file-service stderr was not empty:\n${stderr}`);
      }
    }
  };
}

function randomPort() {
  return 22000 + Math.floor(Math.random() * 1000);
}

test('health and stats endpoints honor SERVICE_NAME override', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SERVICE_NAME: 'file-runtime-override'
    }
  });

  try {
    const healthResponse = await fetch(`${service.baseUrl}/health/ready`);
    assert.equal(healthResponse.status, 200);
    assert.deepEqual(await healthResponse.json(), { ok: true, service: 'file-runtime-override' });

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.service, 'file-runtime-override');
    assert.equal(statsBody.mode, 'file');
    assert.equal(statsBody.inventory.files, 0);
    assert.equal(typeof statsBody.state.file, 'string');
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime matches the provenance-bound upstream Session BLAKE2b file id', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const service = await startFileService({ port: randomPort(), stateDir });

  try {
    const fixture = JSON.parse(await readFile(sessionFileIdFixturePath, 'utf8'));
    assert.equal(fixture.schema, 'deep.session-file-id-golden/v1');
    assert.equal(fixture.provenance.repository, 'https://github.com/session-foundation/session-file-server');
    assert.equal(fixture.provenance.source_commit, '45534715dc755943527ec5e22778bfb5e67285d0');
    assert.equal(Buffer.from(fixture.input.utf8, 'utf8').toString('hex'), fixture.input.hex);
    assert.equal(Buffer.from(fixture.digest_hex, 'hex').toString('base64url'), fixture.file_id);

    const response = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.from(fixture.input.hex, 'hex')
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).id, fixture.file_id);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime reloads persisted file and legacy state across restart', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  let service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      MAX_FILE_TTL_SECONDS: '7200'
    }
  });

  try {
    const binaryContent = Buffer.from('persisted-file-runtime-content', 'utf8');
    const uploadResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        'x-fs-ttl': '3600'
      },
      body: binaryContent
    });
    assert.equal(uploadResponse.status, 200);
    const firstUpload = await uploadResponse.json();
    assert.match(firstUpload.id, /^[A-Za-z0-9_-]{44}$/);

    const duplicateResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        'x-fs-ttl': '3600'
      },
      body: binaryContent
    });
    assert.equal(duplicateResponse.status, 200);
    const duplicateUpload = await duplicateResponse.json();
    assert.equal(duplicateUpload.id, firstUpload.id);
    assert.ok(duplicateUpload.expires >= firstUpload.expires);

    const infoResponse = await fetch(`${service.baseUrl}/file/${firstUpload.id}/info`);
    assert.equal(infoResponse.status, 200);
    const info = await infoResponse.json();
    assert.equal(info.size, binaryContent.length);

    const legacyContent = Buffer.from('persisted-legacy-file-content', 'utf8').toString('base64');
    const legacyUploadResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ file: legacyContent })
    });
    assert.equal(legacyUploadResponse.status, 200);
    const legacyUpload = await legacyUploadResponse.json();
    assert.equal(legacyUpload.status_code, 200);
    assert.equal(legacyUpload.result, 1);

    await service.stop();
    service = await startFileService({
      port: randomPort(),
      stateDir,
      extraEnv: {
        MAX_FILE_TTL_SECONDS: '7200'
      }
    });

    const reloadedInfoResponse = await fetch(`${service.baseUrl}/file/${firstUpload.id}/info`);
    assert.equal(reloadedInfoResponse.status, 200);
    const reloadedInfo = await reloadedInfoResponse.json();
    assert.deepEqual(reloadedInfo, info);

    const reloadedBytesResponse = await fetch(`${service.baseUrl}/file/${firstUpload.id}`);
    assert.equal(reloadedBytesResponse.status, 200);
    assert.deepEqual(Buffer.from(await reloadedBytesResponse.arrayBuffer()), binaryContent);

    const legacyDownloadResponse = await fetch(`${service.baseUrl}/files/${legacyUpload.result}`);
    assert.equal(legacyDownloadResponse.status, 200);
    const legacyDownloaded = await legacyDownloadResponse.json();
    assert.equal(legacyDownloaded.status_code, 200);
    assert.equal(Buffer.from(legacyDownloaded.result, 'base64').toString('utf8'), 'persisted-legacy-file-content');

    const extendResponse = await fetch(`${service.baseUrl}/file/${firstUpload.id}/extend`, {
      method: 'POST',
      headers: {
        'x-fs-ttl': '3600'
      }
    });
    assert.equal(extendResponse.status, 200);
    const extended = await extendResponse.json();
    assert.equal(extended.size, info.size);
    assert.equal(extended.uploaded, info.uploaded);
    assert.ok(extended.expires >= info.expires);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.files, 2);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime coalesces concurrent duplicate uploads and monotonic extends on the same file id', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const fileStatePath = path.join(stateDir, 'file.json');
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      MAX_FILE_TTL_SECONDS: '7200'
    }
  });

  try {
    const binaryContent = Buffer.from('concurrent-file-runtime-content', 'utf8');
    const uploadTtls = ['30', '45', '60'];
    const uploadResults = await Promise.all(uploadTtls.map(async ttl => {
      const response = await fetch(`${service.baseUrl}/file`, {
        method: 'POST',
        headers: {
          'content-type': 'text/plain',
          'x-fs-ttl': ttl
        },
        body: binaryContent
      });
      assert.equal(response.status, 200);
      return response.json();
    }));

    const uploadedIds = new Set(uploadResults.map(upload => upload.id));
    assert.equal(uploadedIds.size, 1);
    const fileId = uploadResults[0].id;

    const initialInfoResponse = await fetch(`${service.baseUrl}/file/${fileId}/info`);
    assert.equal(initialInfoResponse.status, 200);
    const initialInfo = await initialInfoResponse.json();
    assert.equal(initialInfo.size, binaryContent.length);
    assert.equal(initialInfo.expires, Math.max(...uploadResults.map(upload => upload.expires)));

    const extendTtls = ['90', '120', '150'];
    const extendResults = await Promise.all(extendTtls.map(async ttl => {
      const response = await fetch(`${service.baseUrl}/file/${fileId}/extend`, {
        method: 'POST',
        headers: {
          'x-fs-ttl': ttl
        }
      });
      assert.equal(response.status, 200);
      return response.json();
    }));

    const finalInfoResponse = await fetch(`${service.baseUrl}/file/${fileId}/info`);
    assert.equal(finalInfoResponse.status, 200);
    const finalInfo = await finalInfoResponse.json();
    assert.equal(finalInfo.size, binaryContent.length);
    assert.equal(finalInfo.uploaded, initialInfo.uploaded);
    assert.equal(finalInfo.expires, Math.max(...extendResults.map(result => result.expires)));
    assert.ok(finalInfo.expires >= initialInfo.expires);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.fileUpload, uploadTtls.length);
    assert.equal(statsBody.stats.fileExtend, extendTtls.length);
    assert.equal(statsBody.stats.fileInfo, 2);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.files, 1);

    const persistedState = JSON.parse(await readFile(fileStatePath, 'utf8'));
    assert.equal(persistedState.length, 1);
    assert.equal(persistedState[0].id, fileId);
    assert.equal(persistedState[0].uploaded, finalInfo.uploaded);
    assert.equal(persistedState[0].expires, finalInfo.expires);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime prunes expired file records from reads and persisted state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const fileStatePath = path.join(stateDir, 'file.json');
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      MAX_FILE_TTL_SECONDS: '5'
    }
  });

  try {
    const binaryContent = Buffer.from('expired-file-runtime-content', 'utf8');
    const uploadResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        'x-fs-ttl': '1'
      },
      body: binaryContent
    });
    assert.equal(uploadResponse.status, 200);
    const uploaded = await uploadResponse.json();

    const initialInfoResponse = await fetch(`${service.baseUrl}/file/${uploaded.id}/info`);
    assert.equal(initialInfoResponse.status, 200);
    assert.equal((await initialInfoResponse.json()).size, binaryContent.length);

    await new Promise(resolve => setTimeout(resolve, 2200));

    const expiredInfoResponse = await fetch(`${service.baseUrl}/file/${uploaded.id}/info`);
    assert.equal(expiredInfoResponse.status, 404);
    assert.equal((await expiredInfoResponse.json()).status_code, 404);

    const expiredDownloadResponse = await fetch(`${service.baseUrl}/file/${uploaded.id}`);
    assert.equal(expiredDownloadResponse.status, 404);
    assert.equal((await expiredDownloadResponse.json()).status_code, 404);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.files, 0);

    const persistedStateRaw = await readFile(fileStatePath, 'utf8').catch(error => {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        return '[]';
      }

      throw error;
    });
    const persistedState = JSON.parse(persistedStateRaw);
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime prunes expired legacy file records from legacy download and extend paths', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const fileStatePath = path.join(stateDir, 'file.json');
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      MAX_FILE_TTL_SECONDS: '5'
    }
  });

  try {
    const legacyContent = Buffer.from('expired-legacy-file-runtime-content', 'utf8').toString('base64');
    const legacyUploadResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-fs-ttl': '1'
      },
      body: JSON.stringify({ file: legacyContent })
    });
    assert.equal(legacyUploadResponse.status, 200);
    const legacyUpload = await legacyUploadResponse.json();
    assert.equal(legacyUpload.status_code, 200);

    const initialLegacyDownloadResponse = await fetch(`${service.baseUrl}/files/${legacyUpload.result}`);
    assert.equal(initialLegacyDownloadResponse.status, 200);
    assert.equal((await initialLegacyDownloadResponse.json()).status_code, 200);

    await new Promise(resolve => setTimeout(resolve, 2200));

    const expiredLegacyDownloadResponse = await fetch(`${service.baseUrl}/files/${legacyUpload.result}`);
    assert.equal(expiredLegacyDownloadResponse.status, 404);
    assert.equal((await expiredLegacyDownloadResponse.json()).status_code, 404);

    const expiredLegacyExtendResponse = await fetch(`${service.baseUrl}/file/${legacyUpload.result}/extend`, {
      method: 'POST',
      headers: {
        'x-fs-ttl': '1'
      }
    });
    assert.equal(expiredLegacyExtendResponse.status, 404);
    assert.equal((await expiredLegacyExtendResponse.json()).status_code, 404);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.files, 0);

    const persistedState = JSON.parse(await readFile(fileStatePath, 'utf8'));
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime rejects invalid ttl overrides without mutating persisted state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const fileStatePath = path.join(stateDir, 'file.json');
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      MAX_FILE_TTL_SECONDS: '5'
    }
  });

  try {
    const validContent = Buffer.from('valid-file-runtime-content', 'utf8');
    const validUploadResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        'x-fs-ttl': '2'
      },
      body: validContent
    });
    assert.equal(validUploadResponse.status, 200);
    const validUpload = await validUploadResponse.json();

    const infoResponse = await fetch(`${service.baseUrl}/file/${validUpload.id}/info`);
    assert.equal(infoResponse.status, 200);
    const info = await infoResponse.json();

    const invalidModernUploadResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        'x-fs-ttl': '10'
      },
      body: Buffer.from('invalid-modern-ttl', 'utf8')
    });
    assert.equal(invalidModernUploadResponse.status, 400);
    assert.equal((await invalidModernUploadResponse.json()).status_code, 400);

    const invalidLegacyUploadResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-fs-ttl': 'invalid'
      },
      body: JSON.stringify({ file: Buffer.from('invalid-legacy-ttl', 'utf8').toString('base64') })
    });
    assert.equal(invalidLegacyUploadResponse.status, 400);
    assert.equal((await invalidLegacyUploadResponse.json()).status_code, 400);

    const invalidExtendResponse = await fetch(`${service.baseUrl}/file/${validUpload.id}/extend`, {
      method: 'POST',
      headers: {
        'x-fs-ttl': '10'
      }
    });
    assert.equal(invalidExtendResponse.status, 400);
    assert.equal((await invalidExtendResponse.json()).status_code, 400);

    const infoAfterInvalidExtendResponse = await fetch(`${service.baseUrl}/file/${validUpload.id}/info`);
    assert.equal(infoAfterInvalidExtendResponse.status, 200);
    const infoAfterInvalidExtend = await infoAfterInvalidExtendResponse.json();
    assert.deepEqual(infoAfterInvalidExtend, info);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.files, 1);

    const persistedState = JSON.parse(await readFile(fileStatePath, 'utf8'));
    assert.equal(persistedState.length, 1);
    assert.equal(persistedState[0].id, validUpload.id);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime rejects empty and oversized uploads without mutating state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const fileStatePath = path.join(stateDir, 'file.json');
  const service = await startFileService({
    port: randomPort(),
    stateDir
  });

  try {
    const emptyModernUploadResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain'
      },
      body: Buffer.alloc(0)
    });
    assert.equal(emptyModernUploadResponse.status, 413);
    assert.equal((await emptyModernUploadResponse.json()).status_code, 413);

    const oversizedModernUploadResponse = await fetch(`${service.baseUrl}/file`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain'
      },
      body: Buffer.alloc(6_000_001, 0x61)
    });
    assert.equal(oversizedModernUploadResponse.status, 413);
    assert.equal((await oversizedModernUploadResponse.json()).status_code, 413);

    const emptyLegacyUploadResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({ file: '' })
    });
    assert.equal(emptyLegacyUploadResponse.status, 400);
    assert.equal((await emptyLegacyUploadResponse.json()).status_code, 400);

    const oversizedLegacyUploadResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({ file: 'A'.repeat(8_000_001) })
    });
    assert.equal(oversizedLegacyUploadResponse.status, 413);
    assert.equal((await oversizedLegacyUploadResponse.json()).status_code, 413);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.fileUpload, 4);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.files, 0);

    const persistedStateRaw = await readFile(fileStatePath, 'utf8').catch(error => {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        return '[]';
      }

      throw error;
    });
    const persistedState = JSON.parse(persistedStateRaw);
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime rejects malformed legacy upload payloads without mutating state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const fileStatePath = path.join(stateDir, 'file.json');
  const service = await startFileService({
    port: randomPort(),
    stateDir
  });

  try {
    const malformedJsonResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: '{bad-json'
    });
    assert.equal(malformedJsonResponse.status, 400);
    assert.equal((await malformedJsonResponse.json()).status_code, 400);

    const missingFileResponse = await fetch(`${service.baseUrl}/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({ notFile: 'payload' })
    });
    assert.equal(missingFileResponse.status, 400);
    assert.equal((await missingFileResponse.json()).status_code, 400);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.fileUpload, 2);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.files, 0);

    const persistedStateRaw = await readFile(fileStatePath, 'utf8').catch(error => {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        return '[]';
      }

      throw error;
    });
    const persistedState = JSON.parse(persistedStateRaw);
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime returns 502 for supported metadata paths when env-backed data is unavailable', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      TOKEN_INFO_MAXIMUM_SUPPLY: '240000000',
      TOKEN_INFO_SENT_PER_NODE: '15000',
      TOKEN_INFO_STAKING_REWARD_POOL: '9000000',
      TOKEN_INFO_HISTORY_JSON: '{bad-json'
    }
  });

  try {
    const sessionVersionResponse = await fetch(`${service.baseUrl}/session_version?platform=desktop`);
    assert.equal(sessionVersionResponse.status, 502);
    assert.equal((await sessionVersionResponse.json()).status_code, 502);

    const tokenInfoResponse = await fetch(`${service.baseUrl}/token_info?days=7`);
    assert.equal(tokenInfoResponse.status, 502);
    assert.equal((await tokenInfoResponse.json()).status_code, 502);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.sessionVersion, 1);
    assert.equal(statsBody.stats.tokenInfo, 1);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.files, 0);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime serves env-backed session_version and token_info metadata', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const nowSeconds = Math.floor(Date.now() / 1000);
  const service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SESSION_VERSION_DESKTOP: '1.2.3',
      SESSION_VERSION_DESKTOP_PRERELEASE: '1.2.4-beta1',
      SESSION_VERSION_UPDATED_AT: '1717027200',
      TOKEN_INFO_MAXIMUM_SUPPLY: '240000000',
      TOKEN_INFO_SENT_PER_NODE: '15000',
      TOKEN_INFO_STAKING_REWARD_POOL: '9000000',
      TOKEN_INFO_HISTORY_JSON: JSON.stringify([
        {
          current_value: 0.42,
          circulating_supply: 123456,
          total_nodes: 321,
          updated: nowSeconds - 2 * 24 * 60 * 60
        },
        {
          current_value: 0.41,
          circulating_supply: 120000,
          total_nodes: 300,
          updated: nowSeconds - 12 * 24 * 60 * 60
        }
      ])
    }
  });

  try {
    const sessionVersionResponse = await fetch(`${service.baseUrl}/session_version?platform=desktop`);
    assert.equal(sessionVersionResponse.status, 200);
    const sessionVersion = await sessionVersionResponse.json();
    assert.equal(sessionVersion.status_code, 200);
    assert.equal(sessionVersion.result, '1.2.3');
    assert.equal(sessionVersion.updated, 1717027200);
    assert.equal(sessionVersion.prerelease.result, '1.2.4-beta1');

    const invalidPlatformResponse = await fetch(`${service.baseUrl}/session_version?platform=linux`);
    assert.equal(invalidPlatformResponse.status, 404);
    assert.equal((await invalidPlatformResponse.json()).status_code, 404);

    const tokenInfoResponse = await fetch(`${service.baseUrl}/token_info?days=7`);
    assert.equal(tokenInfoResponse.status, 200);
    const tokenInfo = await tokenInfoResponse.json();
    assert.equal(tokenInfo.status_code, 200);
    assert.equal(tokenInfo.info.maximum_supply, 240000000);
    assert.equal(tokenInfo.info.sent_per_node, 15000);
    assert.equal(tokenInfo.info.staking_reward_pool, 9000000);
    assert.equal(tokenInfo.info.history.length, 1);
    assert.equal(tokenInfo.info.history[0].total_nodes, 321);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime persists avatar upload, update, fetch, and info lifecycle across restart', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const avatarStatePath = path.join(stateDir, 'avatar.json');
  let service = await startFileService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      MAX_FILE_TTL_SECONDS: '7200'
    }
  });

  try {
    const identity = createTestStorageSigningIdentity();
    const sessionId = identity.sessionPubkey;
    const avatarPath = `/avatar/${encodeURIComponent(sessionId)}`;
    const firstAvatar = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
    const firstResponse = await fetch(`${service.baseUrl}${avatarPath}`, {
      method: 'PUT',
      headers: {
        'content-type': 'image/png',
        'x-fs-ttl': '3600',
        ...avatarAuthorizationHeaders(identity, avatarPath, firstAvatar)
      },
      body: firstAvatar
    });
    assert.equal(firstResponse.status, 200);
    const first = await firstResponse.json();
    assert.equal(first.sessionId, sessionId);
    assert.match(first.fileId, /^[A-Za-z0-9_-]{44}$/);
    assert.equal(first.contentType, 'image/png');
    assert.equal(first.size, firstAvatar.length);

    const firstInfoResponse = await fetch(`${service.baseUrl}/avatar/${encodeURIComponent(sessionId)}/info`);
    assert.equal(firstInfoResponse.status, 200);
    assert.deepEqual(await firstInfoResponse.json(), first);

    const firstDownloadResponse = await fetch(`${service.baseUrl}/avatar/${encodeURIComponent(sessionId)}`);
    assert.equal(firstDownloadResponse.status, 200);
    assert.equal(firstDownloadResponse.headers.get('content-type'), 'image/png');
    assert.deepEqual(Buffer.from(await firstDownloadResponse.arrayBuffer()), firstAvatar);

    await service.stop();
    service = await startFileService({
      port: randomPort(),
      stateDir,
      extraEnv: {
        MAX_FILE_TTL_SECONDS: '7200'
      }
    });

    const reloadedResponse = await fetch(`${service.baseUrl}/avatar/${encodeURIComponent(sessionId)}/info`);
    assert.equal(reloadedResponse.status, 200);
    assert.deepEqual(await reloadedResponse.json(), first);

    const secondAvatar = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x02]);
    const secondResponse = await fetch(`${service.baseUrl}${avatarPath}`, {
      method: 'PUT',
      headers: {
        'content-type': 'image/jpeg',
        'x-fs-ttl': '3600',
        ...avatarAuthorizationHeaders(identity, avatarPath, secondAvatar)
      },
      body: secondAvatar
    });
    assert.equal(secondResponse.status, 200);
    const second = await secondResponse.json();
    assert.equal(second.sessionId, sessionId);
    assert.notEqual(second.fileId, first.fileId);
    assert.equal(second.contentType, 'image/jpeg');
    assert.equal(second.size, secondAvatar.length);
    assert.ok(second.updated >= first.updated);

    const secondDownloadResponse = await fetch(`${service.baseUrl}/avatar/${encodeURIComponent(sessionId)}`);
    assert.equal(secondDownloadResponse.status, 200);
    assert.equal(secondDownloadResponse.headers.get('content-type'), 'image/jpeg');
    assert.deepEqual(Buffer.from(await secondDownloadResponse.arrayBuffer()), secondAvatar);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.avatars, 1);
    assert.equal(statsBody.inventory.files, 2);

    const persistedAvatars = JSON.parse(await readFile(avatarStatePath, 'utf8'));
    assert.equal(persistedAvatars.length, 1);
    assert.equal(persistedAvatars[0].sessionId, sessionId);
    assert.equal(persistedAvatars[0].fileId, second.fileId);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file runtime rejects invalid avatar uploads without mutating state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'file-service-runtime-'));
  const service = await startFileService({
    port: randomPort(),
    stateDir
  });

  try {
    const identity = createTestStorageSigningIdentity();
    const attacker = createTestStorageSigningIdentity();
    const avatarPath = `/avatar/${identity.sessionPubkey}`;
    const unsupportedContent = Buffer.from('not-an-image', 'utf8');
    const unsupportedResponse = await fetch(`${service.baseUrl}${avatarPath}`, {
      method: 'PUT',
      headers: {
        'content-type': 'text/plain',
        ...avatarAuthorizationHeaders(identity, avatarPath, unsupportedContent)
      },
      body: unsupportedContent
    });
    assert.equal(unsupportedResponse.status, 415);
    assert.equal((await unsupportedResponse.json()).status_code, 415);

    const emptyContent = Buffer.alloc(0);
    const emptyResponse = await fetch(`${service.baseUrl}${avatarPath}`, {
      method: 'PUT',
      headers: {
        'content-type': 'image/png',
        ...avatarAuthorizationHeaders(identity, avatarPath, emptyContent)
      },
      body: emptyContent
    });
    assert.equal(emptyResponse.status, 413);
    assert.equal((await emptyResponse.json()).status_code, 413);

    const hijackContent = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
    const hijackResponse = await fetch(`${service.baseUrl}${avatarPath}`, {
      method: 'PUT',
      headers: {
        'content-type': 'image/png',
        ...avatarAuthorizationHeaders(attacker, avatarPath, hijackContent, {
          sessionId: identity.sessionPubkey
        })
      },
      body: hijackContent
    });
    assert.equal(hijackResponse.status, 401);

    const missingResponse = await fetch(`${service.baseUrl}${avatarPath}`);
    assert.equal(missingResponse.status, 404);
    assert.equal((await missingResponse.json()).status_code, 404);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.avatarUpload, 3);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.files, 0);
    assert.equal(statsBody.inventory.avatars, 0);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});
