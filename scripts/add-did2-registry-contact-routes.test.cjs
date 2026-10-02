'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { addContactRoutes } = require('./add-did2-registry-contact-routes.cjs');
const block = endpoint => `location = ${endpoint} {\n  proxy_pass http://127.0.0.1:28188;\n  include /etc/nginx/snippets/deep-did2-https-proxy.conf;\n}\n`;
const original = ['/api/v2/account-directory/genesis-admissions', '/api/v2/account-directory/history',
  '/api/v2/account-directory/proofs', '/api/v2/network/closure', '/health/did2/ready'].map(block).join('');

test('adds only the two exact DID2 coordination routes with retained upstream and security include', () => {
  const expected = original + ['/api/v2/contact-route-authority', '/api/v2/contact-publication-authority'].map(block).join('');
  assert.equal(addContactRoutes(original, 28188), expected);
  assert.equal(expected.split('location = ').length - 1, 7);
  assert.equal(expected.includes('/api/v1/'), false);
  for (const text of [expected, original + block('/other'), original.replace('28188','28189'),
    original.replace('127.0.0.1','0.0.0.0'), original.replace('include','proxy_set_header'),
    original.replace(block('/api/v2/account-directory/history'),''), original.slice(0,-1)])
    assert.throws(() => addContactRoutes(text, 28188));
  for (const port of [0,80,65536,'28188',28188.1]) assert.throws(() => addContactRoutes(original, port));
});
