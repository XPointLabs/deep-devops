import fs from 'node:fs';
import http from 'node:http';

const action = process.argv[2];
const ttlIndex = process.argv.indexOf('--ttl');
const ttlSeconds = ttlIndex >= 0 ? Number(process.argv[ttlIndex + 1]) : undefined;
if (!['arm', 'disarm', 'status'].includes(action)) throw new Error('Expected arm, disarm, or status.');
if (action === 'arm' && (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 5 || ttlSeconds > 300)) throw new Error('TTL must be 5-300 seconds.');
const token = fs.readFileSync(process.env.DEEP_CHAOS_TOKEN_FILE, 'utf8').trim();
const body = action === 'arm' ? Buffer.from(JSON.stringify({ ttlSeconds })) : Buffer.alloc(0);
const result = await new Promise((resolve, reject) => {
  const request = http.request({
    socketPath: process.env.DEEP_CHAOS_CONTROL_SOCKET,
    path: action === 'status' ? '/status' : `/${action}`,
    method: action === 'status' ? 'GET' : 'POST',
    agent: false,
    headers: { authorization: `Bearer ${token}`, connection: 'close', 'content-length': String(body.length), 'content-type': 'application/json' },
    timeout: 5_000,
  }, (response) => {
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('end', () => response.statusCode === 200 ? resolve(Buffer.concat(chunks).toString('utf8')) : reject(new Error('Chaos control rejected the request.')));
  });
  request.on('timeout', () => request.destroy(new Error('Chaos control timed out.')));
  request.on('error', reject);
  request.end(body);
});
process.stdout.write(`${result}\n`);
