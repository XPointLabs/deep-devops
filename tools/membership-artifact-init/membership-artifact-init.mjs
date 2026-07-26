import { createHash } from 'node:crypto';
import {
  chmodSync,
  chownSync,
  lstatSync,
  readdirSync,
  readFileSync,
  unlinkSync
} from 'node:fs';

const outputDirectory = '/out';
const runtimeUid = 65_532;
const runtimeGid = 65_532;
const privateDirectoryMode = 0o700;
const publicArtifactMode = 0o644;
const artifactName = 'membership-route-catalog.json';
const temporaryArtifactPattern = /^\.membership-route-catalog\.json\.[0-9a-f]{32}\.tmp$/;

function fail(message) {
  throw new Error(`Membership artifact init rejected state: ${message}`);
}

function directoryState() {
  const state = lstatSync(outputDirectory);
  if (!state.isDirectory() || state.isSymbolicLink()) fail('/out is not a real directory');
  return state;
}

function assertRuntimeIdentity() {
  if (process.getuid?.() !== runtimeUid || process.getgid?.() !== runtimeGid) {
    fail('clear/probe process is not the unprivileged runtime identity');
  }
}

function prepareOwnership() {
  if (process.getuid?.() !== 0 || process.getgid?.() !== 0) {
    fail('ownership preparation is not running as root');
  }
  const state = directoryState();
  if (state.uid === runtimeUid && state.gid === runtimeGid) {
    if ((state.mode & 0o777) !== privateDirectoryMode) {
      fail('existing runtime-owned directory mode is not 0700');
    }
    return;
  }
  if (state.uid !== 0 || state.gid !== 0) {
    fail(`unexpected /out owner ${state.uid}:${state.gid}`);
  }
  // A fresh named volume is root-owned. Root still owns it here, so chmod
  // needs no FOWNER capability; CHOWN is the only added container capability.
  chmodSync(outputDirectory, privateDirectoryMode);
  chownSync(outputDirectory, runtimeUid, runtimeGid);
}

function clearPublishedArtifact() {
  assertRuntimeIdentity();
  const state = directoryState();
  if (state.uid !== runtimeUid ||
      state.gid !== runtimeGid ||
      (state.mode & 0o777) !== privateDirectoryMode) {
    fail('runtime-owned /out invariant is not satisfied');
  }
  for (const entry of readdirSync(outputDirectory, { withFileTypes: true })) {
    if (!entry.isFile() ||
        entry.isSymbolicLink() ||
        entry.name !== artifactName && !temporaryArtifactPattern.test(entry.name)) {
      fail(`unexpected entry ${JSON.stringify(entry.name)}`);
    }
    unlinkSync(`${outputDirectory}/${entry.name}`);
  }
}

function probePublishedArtifact(expectedSha256) {
  assertRuntimeIdentity();
  if (!/^[0-9a-f]{64}$/.test(expectedSha256 ?? '')) fail('probe requires an exact lowercase SHA-256');
  const directory = directoryState();
  if (directory.uid !== runtimeUid ||
      directory.gid !== runtimeGid ||
      (directory.mode & 0o777) !== privateDirectoryMode) {
    fail('published directory owner/mode is invalid');
  }
  const artifactPath = `${outputDirectory}/${artifactName}`;
  const artifact = lstatSync(artifactPath);
  if (!artifact.isFile() ||
      artifact.isSymbolicLink() ||
      artifact.uid !== runtimeUid ||
      artifact.gid !== runtimeGid ||
      (artifact.mode & 0o777) !== publicArtifactMode) {
    fail('published artifact owner/mode is invalid');
  }
  const bytes = readFileSync(artifactPath);
  if (bytes.length === 0 || bytes.length > 128 * 1024) fail('published artifact byte bound is invalid');
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expectedSha256) fail('published artifact hash mismatches Sodium-verified fixture output');
  process.stdout.write(`VerifiedPublishedArtifactSha256=${actual}\n`);
}

const [mode, argument] = process.argv.slice(2);
switch (mode) {
  case 'owner':
    prepareOwnership();
    break;
  case 'clear':
    clearPublishedArtifact();
    break;
  case 'probe':
    probePublishedArtifact(argument);
    break;
  default:
    fail('mode must be owner, clear, or probe');
}
