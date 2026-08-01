import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';

const handler = (request, response) => {
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify({
    ok: true,
    port: request.socket.localPort,
    forwardedForPresent: request.headers['x-forwarded-for'] !== undefined,
    forwardedProto: request.headers['x-forwarded-proto'] ?? null,
    forwardedHost: request.headers['x-forwarded-host'] ?? null,
  }));
};

http.createServer(handler).listen(8080, '0.0.0.0');
http.createServer(handler).listen(8081, '0.0.0.0');
if (process.env.LAB_HTTP_ONLY !== 'true') {
  https.createServer({
    cert: fs.readFileSync(process.env.LAB_REALITY_CERT),
    key: fs.readFileSync(process.env.LAB_REALITY_KEY),
  }, handler).listen(443, '0.0.0.0');
}
