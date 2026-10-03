'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {prepare} = require('./prepare-xnode-did2-uat.cjs');
const {fixture} = require('./prepare-xnode-did2-uat.test.cjs');
const {stage} = require('./stage-did2-runtime.cjs');
function scenario(run, contactRuntime = false) { fixture(input=> {
  input.contactRuntime = contactRuntime;
  prepare(input);
  const envFile=path.join(input.seed1,'.env.node.prod');
  fs.appendFileSync(envFile,'DEEP_XPOINT_NETWORK_ID_HEX='+ '11'.repeat(16)+'\n'+
    'DEEP_XPOINT_GENESIS_PIN_HEX='+ '22'.repeat(32)+'\n'+
    'DEEP_REGISTRY_URL=https://registry.example\nDEEP_NODE_PUBLIC_PORT=443\n');
  fs.writeFileSync(path.join(input.seed1,'secrets','key_bls'),'untouched-synthetic-BLS');
  run(input,envFile);
}); }

test('explicit DID2 contact profile survives immutable installer staging and exact rerun',()=>scenario((input,envFile)=> {
  const originalEnv=fs.readFileSync(envFile);
  const originalEd=fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519'));
  const originalBls=fs.readFileSync(path.join(input.seed1,'secrets','key_bls'));
  const result=stage(input.output,input.seed1);
  const root=path.dirname(path.join(input.seed1,result.updates.DEEP_DID2_CONFIG_FILE));
  const config=JSON.parse(fs.readFileSync(path.join(root,'appsettings.Production.json')));
  assert.deepEqual(config.ContactCoordination,{Enabled:true,BackendOrigin:'https://registry.example/'});
  assert.deepEqual(config.DeepIdV2ContactResolver,{Enabled:true});
  assert.deepEqual(config.DeepIdV2PreKeyClaim,{Enabled:true});
  assert.deepEqual(Object.keys(config).sort(),['ContactCoordination','DeepIdV2ContactResolver',
    'DeepIdV2DirectoryProof','DeepIdV2NetworkPlacement','DeepIdV2PreKeyClaim','DeepIdV2ReplicaStage']);
  assert.deepEqual(fs.readFileSync(envFile),originalEnv);
  assert.deepEqual(fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519')),originalEd);
  assert.deepEqual(fs.readFileSync(path.join(input.seed1,'secrets','key_bls')),originalBls);
  fs.appendFileSync(envFile,Object.entries(result.updates).map(([k,v])=>k+'='+v).join('\n')+'\n');
  assert.deepEqual(stage(input.output,input.seed1),result);
  assert.equal(fs.readdirSync(path.join(input.seed1,'config','did2-runtime')).length,1);
},true));

test('rejects partial, disabled, substituted or extended contact profiles before staging',()=> {
  const mutations=[
    config=>{delete config.DeepIdV2PreKeyClaim;},
    config=>{config.DeepIdV2ContactResolver.Enabled=false;},
    config=>{config.ContactCoordination.BackendOrigin='https://other.example/';},
    config=>{config.ContactCoordination.SkipAuthentication=true;},
    config=>{config.DeepIdV2ContactResolver.MailboxGrantEnabled=true;},
    config=>{config.DeepIdV2ContactResolver=[];},
    config=>{config.ContactService.RuntimeActivation=true;},
    config=>{config.PrivacyRouting.Enabled=false;}
  ];
  for(const mutate of mutations) scenario((input,envFile)=> {
    const originalEnv=fs.readFileSync(envFile);
    const file=path.join(input.output,'appsettings.UAT.json');
    const config=JSON.parse(fs.readFileSync(file)); mutate(config);
    fs.writeFileSync(file,JSON.stringify(config));
    assert.throws(()=>stage(input.output,input.seed1));
    assert.deepEqual(fs.readFileSync(envFile),originalEnv);
    assert.equal(fs.existsSync(path.join(input.seed1,'config','did2-runtime')),false);
  },true);
});

test('contact activation selects a new immutable bundle without changing the retained prekey-only bundle',()=>scenario((input,envFile)=> {
  const previous=stage(input.output,input.seed1);
  const previousRoot=path.dirname(path.join(input.seed1,previous.updates.DEEP_DID2_CONFIG_FILE));
  const previousConfig=fs.readFileSync(path.join(previousRoot,'appsettings.Production.json'));
  fs.appendFileSync(envFile,Object.entries(previous.updates).map(([k,v])=>k+'='+v).join('\n')+'\n');
  const originalEnv=fs.readFileSync(envFile);
  const file=path.join(input.output,'appsettings.UAT.json');
  const diagnostic=JSON.parse(fs.readFileSync(file));
  diagnostic.ContactCoordination={Enabled:true,BackendOrigin:'https://registry.example/'};
  diagnostic.DeepIdV2ContactResolver={Enabled:true};
  diagnostic.DeepIdV2PreKeyClaim={Enabled:true};
  fs.writeFileSync(file,JSON.stringify(diagnostic));
  const current=stage(input.output,input.seed1);
  assert.notEqual(current.updates.DEEP_DID2_CONFIG_FILE,previous.updates.DEEP_DID2_CONFIG_FILE);
  assert.deepEqual(fs.readFileSync(path.join(previousRoot,'appsettings.Production.json')),previousConfig);
  assert.deepEqual(fs.readFileSync(envFile),originalEnv);
  assert.equal(fs.readdirSync(path.join(input.seed1,'config','did2-runtime')).length,2);
}));
test('binary upgrades reject contact-to-prekey-only profile downgrade before creating another bundle',()=>scenario((input,envFile)=> {
  const previous=stage(input.output,input.seed1);
  fs.appendFileSync(envFile,Object.entries(previous.updates).map(([k,v])=>k+'='+v).join('\n')+'\n');
  const previousRoot=path.dirname(path.join(input.seed1,previous.updates.DEEP_DID2_CONFIG_FILE));
  const previousConfig=fs.readFileSync(path.join(previousRoot,'appsettings.Production.json'));
  const previousEnv=fs.readFileSync(envFile);
  const file=path.join(input.output,'appsettings.UAT.json');
  const diagnostic=JSON.parse(fs.readFileSync(file));
  for(const name of ['ContactCoordination','DeepIdV2ContactResolver','DeepIdV2PreKeyClaim']) delete diagnostic[name];
  fs.writeFileSync(file,JSON.stringify(diagnostic));
  assert.throws(()=>stage(input.output,input.seed1));
  assert.deepEqual(fs.readFileSync(envFile),previousEnv);
  assert.deepEqual(fs.readFileSync(path.join(previousRoot,'appsettings.Production.json')),previousConfig);
  assert.equal(fs.readdirSync(path.join(input.seed1,'config','did2-runtime')).length,1);
},true));

test('stages closed production inputs, reuses exact rerun and never imports diagnostic state',()=>scenario((input,envFile)=> {
  fs.writeFileSync(path.join(input.output,'state','must-not-import.state'),'synthetic-old-state');
  const originalEd=fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519'));
  const originalEnv=fs.readFileSync(envFile);
  const result=stage(input.output,input.seed1);
  assert.equal(result.records,8);
  assert.equal(result.updates.DEEP_DID2_ORIGIN,'https://8.8.8.1/');
  assert.equal(result.updates.DEEP_NODE_RUNTIME_ENVIRONMENT,'UAT');
  assert.equal(Object.keys(result.updates).length,22);
  assert.deepEqual(fs.readFileSync(envFile),originalEnv,'staging does not select the new bundle');
  const root=path.dirname(path.join(input.seed1,result.updates.DEEP_DID2_CONFIG_FILE));
  assert.deepEqual(fs.readdirSync(root).sort(),['appsettings.Production.json','public','secrets']);
  assert.equal(fs.readFileSync(path.join(input.seed1,'secrets','key_bls'),'utf8'),'untouched-synthetic-BLS');
  assert.deepEqual(fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519')),originalEd);
  const config=JSON.parse(fs.readFileSync(path.join(root,'appsettings.Production.json')));
  assert.deepEqual(fs.readFileSync(path.join(root,'public','pma2.0000.bin')),
    fs.readFileSync(path.join(input.assets,'pma2.0000.bin')));
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
test('growing successor history stages a new immutable bundle without demanding new files in its predecessor',()=>scenario((input,envFile)=> {
  const prior=stage(input.output,input.seed1);
  fs.appendFileSync(envFile,Object.entries(prior.updates).map(([k,v])=>k+'='+v).join('\n')+'\n');
  const priorRoot=path.dirname(path.join(input.seed1,prior.updates.DEEP_DID2_CONFIG_FILE));
  const priorConfig=fs.readFileSync(path.join(priorRoot,'appsettings.Production.json'));
  const originalEnv=fs.readFileSync(envFile);
  const originalEd=fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519'));
  const originalBls=fs.readFileSync(path.join(input.seed1,'secrets','key_bls'));
  const publicRoot=path.join(input.output,'public');
  const manifest=JSON.parse(fs.readFileSync(path.join(publicRoot,'public-assets.v2.json')));
  const config=JSON.parse(fs.readFileSync(path.join(publicRoot,'xnode.did2.json')));
  const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
  for(const [role,field] of [['xvp1','ExactPolicyPaths'],['xnv1','ExactViewPaths'],
    ['xnh1','ExactHeadPaths'],['pmt2','ExactMailboxProjectionPaths']]) {
    const name=role+'.0001.bin'; const bytes=Buffer.from(role+'-synthetic-successor');
    fs.writeFileSync(path.join(publicRoot,name),bytes);
    manifest.artifacts.push({Role:role,Ordinal:1,FileName:name,Length:bytes.length,Sha256Hex:sha(bytes)});
    config.DeepIdV2NetworkPlacement[field].push('/run/did2-network/'+name);
    assert.equal(fs.existsSync(path.join(priorRoot,'public',name)),false);
  }
  const configuration=Buffer.from(JSON.stringify(config));
  fs.writeFileSync(path.join(publicRoot,'xnode.did2.json'),configuration);
  manifest.configurationSha256=sha(configuration);
  fs.writeFileSync(path.join(publicRoot,'public-assets.v2.json'),JSON.stringify(manifest));
  const diagnostic=JSON.parse(fs.readFileSync(path.join(input.output,'appsettings.UAT.json')));
  Object.assign(diagnostic,config);
  fs.writeFileSync(path.join(input.output,'appsettings.UAT.json'),JSON.stringify(diagnostic));
  const next=stage(input.output,input.seed1);
  assert.equal(next.records,12);
  assert.notEqual(next.updates.DEEP_DID2_CONFIG_FILE,prior.updates.DEEP_DID2_CONFIG_FILE);
  assert.deepEqual(fs.readFileSync(path.join(priorRoot,'appsettings.Production.json')),priorConfig);
  assert.deepEqual(fs.readFileSync(envFile),originalEnv,'staging must not select or replace the old installation');
  assert.deepEqual(fs.readFileSync(path.join(input.seed1,'secrets','key_ed25519')),originalEd);
  assert.deepEqual(fs.readFileSync(path.join(input.seed1,'secrets','key_bls')),originalBls);
  assert.equal(fs.readdirSync(path.join(input.seed1,'config','did2-runtime')).length,2);
}));
test('an exact-rerun configuration with a missing retained public record still fails closed',()=>scenario((input,envFile)=> {
  const prior=stage(input.output,input.seed1);
  fs.appendFileSync(envFile,Object.entries(prior.updates).map(([k,v])=>k+'='+v).join('\n')+'\n');
  const priorRoot=path.dirname(path.join(input.seed1,prior.updates.DEEP_DID2_CONFIG_FILE));
  fs.unlinkSync(path.join(priorRoot,'public','xnv1.0000.bin'));
  assert.throws(()=>stage(input.output,input.seed1));
  assert.equal(fs.readdirSync(path.join(input.seed1,'config','did2-runtime')).length,1);
}));
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
  assert.deepEqual(fs.readFileSync(path.join(__dirname,'../.env.node.prod.example')),
    fs.readFileSync(path.join(__dirname,'../../xpoint-node-installer/assets/.env.node.prod.example')));
});
test('staging rejects absent or noncontiguous PMA2 before selecting any installation',()=>{
  for(const mode of ['missing','gap','duplicate','placement','missing-path']) scenario((input,envFile)=>{
    const originalEnv=fs.readFileSync(envFile);
    const publicRoot=path.join(input.output,'public');
    const file=path.join(publicRoot,'public-assets.v2.json');
    const manifest=JSON.parse(fs.readFileSync(file));
    const pma=manifest.artifacts.find(item=>item.Role==='pma2');
    if(mode==='missing') manifest.artifacts=manifest.artifacts.filter(item=>item!==pma);
    if(mode==='gap') {
      fs.copyFileSync(path.join(publicRoot,pma.FileName),path.join(publicRoot,'pma2.0001.bin'));
      pma.Ordinal=1; pma.FileName='pma2.0001.bin';
    }
    if(mode==='duplicate') manifest.artifacts.push({...pma});
    if(mode==='placement'||mode==='missing-path') {
      const configFile=path.join(publicRoot,'xnode.did2.json');
      const config=JSON.parse(fs.readFileSync(configFile));
      if(mode==='placement') config.DeepIdV2NetworkPlacement.ExactMailboxProjectionPaths=['/run/did2-network/'+pma.FileName];
      else delete config.DeepIdV2NetworkPlacement.ExactMailboxAuthorityPaths;
      const bytes=Buffer.from(JSON.stringify(config)); fs.writeFileSync(configFile,bytes);
      manifest.configurationSha256=crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
    }
    fs.writeFileSync(file,JSON.stringify(manifest));
    assert.throws(()=>stage(input.output,input.seed1));
    assert.deepEqual(fs.readFileSync(envFile),originalEnv);
    assert.equal(fs.existsSync(path.join(input.seed1,'config','did2-runtime')),false);
  });
});
test('normalizes one optional Registry origin slash and rejects paths or insecure origins',()=>{
  scenario((input,envFile)=>{
    fs.writeFileSync(envFile,fs.readFileSync(envFile,'utf8').replace('https://registry.example\n','https://registry.example/\n'));
    assert.equal(stage(input.output,input.seed1).records,8);
  });
  for(const origin of ['http://registry.example','https://registry.example/api','https://user@registry.example','https://registry.example/?query=1'])
    scenario((input,envFile)=>{
      fs.writeFileSync(envFile,fs.readFileSync(envFile,'utf8').replace('https://registry.example\n',origin+'\n'));
      assert.throws(()=>stage(input.output,input.seed1));
      assert.equal(fs.existsSync(path.join(input.seed1,'config','did2-runtime')),false);
    });
});
