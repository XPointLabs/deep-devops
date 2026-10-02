'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {addHistory}=require('./add-did2-registry-history-route.cjs');
const block=endpoint=>`location = ${endpoint} {\n  proxy_pass http://127.0.0.1:28188;\n  include /etc/nginx/snippets/deep-did2-https-proxy.conf;\n}\n`;
const original=['/api/v2/account-directory/genesis-admissions','/api/v2/account-directory/proofs',
  '/api/v2/network/closure','/health/did2/ready'].map(block).join('');
test('adds only exact history with existing backend/security include; refuses ambiguous or foreign snippets',()=>{
  const expected=original.replace(block('/api/v2/account-directory/proofs'),
    block('/api/v2/account-directory/history')+block('/api/v2/account-directory/proofs'));
  assert.equal(addHistory(original,28188),expected);
  for(const text of [expected,original+block('/other'),original.replace('28188','28189'),
    original.replace('127.0.0.1','0.0.0.0'),original.replace('include','proxy_set_header'),original.slice(0,-1)])
    assert.throws(()=>addHistory(text,28188));
  for(const port of [0,80,65536,'28188',28188.1])assert.throws(()=>addHistory(original,port));
});
