import { createServer } from 'node:http';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const port = Number.parseInt(process.env.PORT ?? '8080', 10);
const stateDirectory = process.env.RELAY_BOOTSTRAP_STATE_DIR ?? '/state';
const statePath = join(stateDirectory, 'relay-contacts.json');
const temporaryPath = join(stateDirectory, 'relay-contacts.tmp.json');

function validContact(value) {
  return value && typeof value === 'object' &&
    /^[0-9a-f]{64}$/.test(value.routerId ?? '') &&
    /^[0-9a-f]{64}$/.test(value.x25519PublicKey ?? '') &&
    /^[0-9a-f]{128}$/.test(value.signature ?? '') &&
    typeof value.rpcEndpoint === 'string' &&
    /^http:\/\/xnode-[1-6]:8081\/api\/peer\/onion$/.test(value.rpcEndpoint);
}

async function readContacts() {
  try {
    const value = JSON.parse(await readFile(statePath, 'utf8'));
    return Array.isArray(value) ? value : [];
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

async function readRequest(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 64 * 1024) throw new Error('request-too-large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function send(response, status, value) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(value));
}

await mkdir(stateDirectory, { recursive: true });
createServer(async (request, response) => {
  try {
    if (request.method === 'GET' && request.url === '/health/ready') return send(response, 200, { status: 'ready' });
    if (request.method === 'GET' && request.url === '/api/relay-contacts') return send(response, 200, await readContacts());
    if (request.method === 'POST' && request.url === '/seed') {
      const contacts = await readRequest(request);
      if (!Array.isArray(contacts) || contacts.length !== 6 || contacts.some(value => !validContact(value)) || new Set(contacts.map(value => value.routerId)).size !== 6) {
        return send(response, 400, { error: 'invalid-relay-contacts' });
      }
      await writeFile(temporaryPath, `${JSON.stringify(contacts)}\n`, { encoding: 'utf8', flag: 'w' });
      await rename(temporaryPath, statePath);
      return send(response, 200, { seeded: contacts.length });
    }
    return send(response, 404, { error: 'not-found' });
  } catch {
    return send(response, 500, { error: 'relay-bootstrap-failed' });
  }
}).listen(port, '0.0.0.0');
