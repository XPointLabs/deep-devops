import crypto from 'node:crypto';
import fs from 'node:fs';
import tls from 'node:tls';

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined) throw new Error('Invalid TLS probe arguments.');
  args.set(key, value);
}
for (const name of ['--address', '--port', '--host', '--ca', '--expected-pin']) {
  if (!args.has(name)) throw new Error(`Missing ${name}.`);
}
const expected = fs.readFileSync(args.get('--expected-pin'), 'utf8').trim();
if (!/^[0-9a-f]{64}$/.test(expected)) throw new Error('Expected SPKI pin is invalid.');
const port = Number(args.get('--port'));
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('TLS probe port is invalid.');

const result = await new Promise((resolve, reject) => {
  const socket = tls.connect({
    host: args.get('--address'),
    port,
    servername: args.get('--host'),
    ca: fs.readFileSync(args.get('--ca')),
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
  });
  socket.setTimeout(10_000, () => socket.destroy(new Error('TLS probe timed out.')));
  socket.once('error', reject);
  socket.once('secureConnect', () => {
    try {
      if (!socket.authorized) throw new Error('Served certificate is not authorized.');
      const raw = socket.getPeerCertificate(true)?.raw;
      if (!raw) throw new Error('Peer certificate is unavailable.');
      const actual = crypto.createHash('sha256')
        .update(new crypto.X509Certificate(raw).publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex');
      const matches = crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
      if (!matches) throw new Error('Served SPKI does not match the protected current pin.');
      resolve({ schema: 'deep-production-ingress-tls-probe.v1', status: 'ok', host: args.get('--host'), servedSpkiSha256: actual });
    } catch (error) {
      reject(error);
    } finally {
      socket.destroy();
    }
  });
});
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
