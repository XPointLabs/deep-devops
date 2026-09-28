import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parseWorkflowGraph } from './workflow-upload-contracts.mjs';

const { jobs } = parseWorkflowGraph(readFileSync(new URL('../.github/workflows/unit.yml', import.meta.url), 'utf8'));
test('all unit workflow lanes use the same release specification source as consumers', () => {
  assert.equal(jobs.length, 3);
  for (const job of jobs) {
    const source = job.steps.filter(step => step.uses === 'actions/checkout@v4' &&
      step.with.repository === '${{ github.repository_owner }}/deep-platform');
    assert.equal(source.length, 1);
    assert.equal(source[0].with.ref, '${{ env.RELEASE_SOURCE_REF }}');
    for (const contracts of job.steps.filter(step => step.uses === 'actions/checkout@v4' &&
      step.with.repository === '${{ github.repository_owner }}/xpoint-staking-contracts'))
      assert.equal(contracts.with.ref, '${{ env.RELEASE_SOURCE_REF }}');
  }
});
test('Registry DID2 unit fixtures have Shared source and native test failures stop the lane', () => {
  const unit = jobs.find(job => job.id === 'unit');
  const shared = unit.steps.filter(step => step.uses === 'actions/checkout@v4' &&
    step.with.repository === '${{ github.repository_owner }}/deep-client-shared');
  assert.equal(shared.length, 1);
  assert.equal(shared[0].with.path, 'deep-client-shared');
  assert.equal(shared[0].with.ref, '${{ env.RELEASE_SOURCE_REF }}');
  const execute = unit.steps.find(step => step.name === 'Unit tests');
  assert.match(execute.run, /\$ErrorActionPreference = 'Stop'/);
  assert.match(execute.run, /\$PSNativeCommandUseErrorActionPreference = \$true/);
});
