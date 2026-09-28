'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {prepare} = require('./prepare-xnode-did2-uat.cjs');
const {fixture} = require('./prepare-xnode-did2-uat.test.cjs');
const {stage} = require('./stage-did2-runtime.cjs');
function scenario(run) { fixture(input=> {
  prepare(input);
  const envFile=path.join(input.seed1,'.env.node.prod');
  fs.appendFileSync(envFile,'DEEP_XPOINT_NETWORK_ID_HEX='+ '11'.repeat(16)+'\n'+
    'DEEP_XPOINT_GENESIS_PIN_HEX='+ '22'.repeat(32)+'\n'+
    'DEEP_REGISTRY_URL=https://registry.example\nDEEP_NODE_PUBLIC_PORT=443\n');
  fs.writeFileSync(path.join(input.seed1,'secrets','key_bls'),'untouched-synthetic-BLS');
  run(input,envFile);
}); }
test('stages closed production inputs, reuses exact rerun and never imports diagnostic state',()=>scenario((input,envFile)=> {
  fs.writeFileSync(path.join(input.output,'state','must-not-import.state'),'synthetic-old-state');
  const originalEd=fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519'));
  const originalEnv=fs.readFileSync(envFile);
  const result=stage(input.output,input.seed1);
  assert.equal(result.records,7);
  assert.equal(result.updates.DEEP_DID2_ORIGIN,'https://8.8.8.1/');
  assert.equal(result.updates.DEEP_NODE_RUNTIME_ENVIRONMENT,'UAT');
  assert.equal(Object.keys(result.updates).length,22);
  assert.deepEqual(fs.readFileSync(envFile),originalEnv,'staging does not select the new bundle');
  const root=path.dirname(path.join(input.seed1,result.updates.DEEP_DID2_CONFIG_FILE));
  assert.deepEqual(fs.readdirSync(root).sort(),['appsettings.Production.json','public','secrets']);
  assert.equal(fs.readFileSync(path.join(input.seed1,'secrets','key_bls'),'utf8'),'untouched-synthetic-BLS');
  assert.deepEqual(fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519')),originalEd);
  const config=JSON.parse(fs.readFileSync(path.join(root,'appsettings.Production.json')));
  assert.deepEqual(Object.keys(config).sort(),['DeepIdV2DirectoryProof','DeepIdV2NetworkPlacement','DeepIdV2ReplicaStage']);
  fs.appendFileSync(envFile,Object.entries(result.updates).map(([k,v])=>k+'='+v).join('\n')+'\n');
  assert.deepEqual(stage(input.output,input.seed1),result);
  assert.equal(fs.readdirSync(path.join(input.seed1,'config','did2-runtime')).length,1);
}));
test('rejects substituted node/protection custody and changed public config before staging',()=>{
  for(const [file,bytes] of [['secrets/key_ed25519',Buffer.from('ab'.repeat(32))],
    ['secrets/onion-state-protection.key',Buffer.alloc(32,9)],['public/xnode.did2.json',Buffer.from('{}')]])
    scenario(input=>{
      fs.writeFileSync(path.join(input.output,file),bytes);
      assert.throws(()=>stage(input.output,input.seed1));
      assert.equal(fs.existsSync(path.join(input.seed1,'config','did2-runtime')),false);
    });
});
test('rejects unexpected network, peer origin, certificate key, and original env duplicates',()=>{
  scenario((input,envFile)=>{
    fs.appendFileSync(envFile,'DEEP_NODE_PUBLIC_PORT=443\n');
    assert.throws(()=>stage(input.output,input.seed1));
  });
  scenario((input,envFile)=>{
    const text=fs.readFileSync(envFile,'utf8').replace('11'.repeat(16),'33'.repeat(16));
    fs.writeFileSync(envFile,text); assert.throws(()=>stage(input.output,input.seed1));
  });
  scenario(input=>{
    const file=path.join(input.output,'appsettings.UAT.json');
    const config=JSON.parse(fs.readFileSync(file)); config.PrivacyRouting.Peers[0].BaseUrl='https://127.0.0.1/';
    fs.writeFileSync(file,JSON.stringify(config)); assert.throws(()=>stage(input.output,input.seed1));
  });
  scenario(input=>{
    fs.copyFileSync(path.join(input.output,'secrets','next-origin.key'),path.join(input.output,'secrets','origin.key'));
    assert.throws(()=>stage(input.output,input.seed1));
  });
});
test('standalone installer asset is byte-identical to canonical DevOps stager',()=>{
  assert.deepEqual(fs.readFileSync(path.join(__dirname,'stage-did2-runtime.cjs')),
    fs.readFileSync(path.join(__dirname,'../../xpoint-node-installer/assets/scripts/stage-did2-runtime.cjs')));
});
test('normalizes one optional Registry origin slash and rejects paths or insecure origins',()=>{
  scenario((input,envFile)=>{
    fs.writeFileSync(envFile,fs.readFileSync(envFile,'utf8').replace('https://registry.example\n','https://registry.example/\n'));
    assert.equal(stage(input.output,input.seed1).records,7);
  });
  for(const origin of ['http://registry.example','https://registry.example/api','https://user@registry.example','https://registry.example/?query=1'])
    scenario((input,envFile)=>{
      fs.writeFileSync(envFile,fs.readFileSync(envFile,'utf8').replace('https://registry.example\n',origin+'\n'));
      assert.throws(()=>stage(input.output,input.seed1));
      assert.equal(fs.existsSync(path.join(input.seed1,'config','did2-runtime')),false);
    });
});
