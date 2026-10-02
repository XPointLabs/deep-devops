'use strict';
const { main } = require('./add-did2-registry-history-route.cjs');

function addContactRoutes(text, port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || text.length > 16384)
    throw new Error('Contact route input scope rejected.');
  const routes = ['/api/v2/account-directory/genesis-admissions', '/api/v2/account-directory/history',
    '/api/v2/account-directory/proofs', '/api/v2/network/closure', '/health/did2/ready'];
  const block = endpoint => `location = ${endpoint} {\n  proxy_pass http://127.0.0.1:${port};\n  include /etc/nginx/snippets/deep-did2-https-proxy.conf;\n}\n`;
  if (text !== routes.map(block).join('')) throw new Error('Retained contact route closure rejected.');
  // Same listener/security include. These remain DR48 authenticated private
  // coordination terminals, not public contact resolution or a client fallback.
  return text + ['/api/v2/contact-route-authority', '/api/v2/contact-publication-authority'].map(block).join('');
}

if (require.main === module) {
  try { main(process.argv.slice(2), addContactRoutes, 'deep.registry.contact-routes.v1'); }
  catch { console.error('DID2 contact route update failed closed; other services and authority floors were not changed.'); process.exitCode=1; }
}
module.exports = { addContactRoutes };
