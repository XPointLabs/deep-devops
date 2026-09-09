import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const key = process.argv[index];
  if (key === '--allow-lab-certificate') { values.set(key, true); continue; }
  const value = process.argv[++index];
  if (!key?.startsWith('--') || value === undefined) throw new Error('Invalid ingress preflight arguments.');
  values.set(key, value);
}
const required = ['--profile', '--host', '--current-cert', '--current-key', '--current-pin', '--next-cert', '--next-key', '--next-pin', '--client-timeout-seconds', '--server-timeout-seconds', '--quorum-cidr'];
for (const name of required) if (!values.has(name)) throw new Error(`Missing ${name}.`);
if (!['pinned-self-issued', 'deep-managed', 'operator-managed'].includes(values.get('--profile'))) {
  throw new Error('Invalid ingress certificate profile.');
}

const host = values.get('--host');
const hostIsIp = isIP(host) === 4;
if (!hostIsIp && !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(host)) {
  throw new Error('Ingress host must be one exact DNS name or public IPv4 address.');
}
for (const option of ['--client-timeout-seconds', '--server-timeout-seconds']) {
  const text = values.get(option);
  if (!/^[0-9]+$/.test(text) || Number(text) < 5 || Number(text) > 120) {
    throw new Error('Ingress timeout is outside the approved range.');
  }
}
const quorumCidr = values.get('--quorum-cidr');
const [quorumAddress, quorumPrefix, ...quorumExtra] = quorumCidr.split('/');
if (quorumExtra.length || isIP(quorumAddress) !== 4 || quorumPrefix !== '32') {
  throw new Error('Quorum coordinator CIDR must be one exact public IPv4 /32.');
}
const quorumOctets = quorumAddress.split('.').map(Number);
const quorumIsUnsafe = quorumOctets[0] === 0 || quorumOctets[0] === 10 || quorumOctets[0] === 127 ||
  quorumOctets[0] >= 224 ||
  (quorumOctets[0] === 100 && quorumOctets[1] >= 64 && quorumOctets[1] <= 127) ||
  (quorumOctets[0] === 169 && quorumOctets[1] === 254) ||
  (quorumOctets[0] === 172 && quorumOctets[1] >= 16 && quorumOctets[1] <= 31) ||
  (quorumOctets[0] === 192 && [0, 168].includes(quorumOctets[1])) ||
  (quorumOctets[0] === 198 && (quorumOctets[1] === 18 || quorumOctets[1] === 19 || quorumOctets[1] === 51)) ||
  (quorumOctets[0] === 203 && quorumOctets[1] === 0 && quorumOctets[2] === 113);
if (quorumIsUnsafe) throw new Error('Quorum coordinator address is not an approved public unicast IPv4 address.');

function readPin(file) {
  const pin = fs.readFileSync(file, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new Error('Ingress SPKI pin must be exactly 64 lowercase hexadecimal characters.');
  return pin;
}

function fixedHexEqual(left, right) {
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function inspect(label) {
  const certPem = fs.readFileSync(values.get(`--${label}-cert`));
  const keyPem = fs.readFileSync(values.get(`--${label}-key`));
  const certificate = new crypto.X509Certificate(certPem);
  const privateKey = crypto.createPrivateKey(keyPem);
  const certificateSpki = certificate.publicKey.export({ type: 'spki', format: 'der' });
  const privateSpki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  if (certificateSpki.length !== privateSpki.length || !crypto.timingSafeEqual(certificateSpki, privateSpki)) {
    throw new Error(`${label} certificate does not match its private key.`);
  }
  const sanItems = String(certificate.subjectAltName ?? '').split(', ');
  const exactSan = hostIsIp
    ? sanItems.includes(`IP Address:${host}`) && certificate.checkIP(host) === host
    : sanItems.includes(`DNS:${host}`) && certificate.checkHost(host, { wildcards: false, partialWildcards: false, multiLabelWildcards: false, singleLabelSubdomains: false }) === host;
  if (!exactSan) {
    throw new Error(`${label} certificate SAN does not contain the exact ingress host.`);
  }
  const now = Date.now();
  const minimumRemaining = values.has('--allow-lab-certificate') ? 5 * 60_000 : 14 * 24 * 60 * 60_000;
  if (Date.parse(certificate.validFrom) > now + 5 * 60_000 || Date.parse(certificate.validTo) < now + minimumRemaining) {
    throw new Error(`${label} certificate validity window is not deployable.`);
  }
  const actual = crypto.createHash('sha256').update(certificateSpki).digest('hex');
  if (!fixedHexEqual(actual, readPin(values.get(`--${label}-pin`)))) {
    throw new Error(`${label} certificate SPKI does not match its protected pin input.`);
  }
  return actual;
}

const current = inspect('current');
const next = inspect('next');
if (fixedHexEqual(current, next)) throw new Error('Current and next ingress certificates must use distinct public keys.');
const expectedPriorNext = values.get('--expected-prior-next-spki');
if (expectedPriorNext && (!/^[0-9a-f]{64}$/.test(expectedPriorNext) || !fixedHexEqual(current, expectedPriorNext))) {
  throw new Error('Rotation gate failed: new current SPKI is not the previously approved next SPKI.');
}

const attestationOutput = values.get('--attestation-output');
if (attestationOutput) {
  const fileHash = (name) => crypto.createHash('sha256').update(fs.readFileSync(values.get(name))).digest('hex');
  const attestation = [
    'deep-production-ingress-attestation.v1',
    `profile=${values.get('--profile')}`,
    `host=${host}`,
    `currentCertificateFileSha256=${fileHash('--current-cert')}`,
    `currentPrivateKeyFileSha256=${fileHash('--current-key')}`,
    `currentPinFileSha256=${fileHash('--current-pin')}`,
    `currentSpkiSha256=${current}`,
    `clientTimeoutSeconds=${values.get('--client-timeout-seconds')}`,
    `serverTimeoutSeconds=${values.get('--server-timeout-seconds')}`,
    `quorumCoordinatorCidr=${quorumCidr}`,
    '',
  ].join('\n');
  const temporary = path.join(path.dirname(attestationOutput), `.preflight-${crypto.randomBytes(16).toString('hex')}.tmp`);
  fs.writeFileSync(temporary, attestation, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, attestationOutput);
  fs.chmodSync(attestationOutput, 0o400);
}

process.stdout.write(`${JSON.stringify({
  schema: 'deep-production-ingress-preflight.v1',
  status: 'ok',
  profile: values.get('--profile'),
  host,
  currentSpkiSha256: current,
  nextSpkiSha256: next,
  privateKeysIncluded: false,
  checkedAtUtc: new Date().toISOString(),
}, null, 2)}\n`);
