import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parseWorkflowGraph, validateWorkflows } from './workflow-upload-contracts.mjs';

const valid = `name: test
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Prepare
        id: prepare_upload
        run: >
          node scripts/artifact-upload-manifest.mjs
          --staging "\${{ runner.temp }}/deep-upload/staged"
      - name: Gate
        id: secret_scan
        run: >
          node scripts/artifact-upload-gate.mjs
          --bundle "\${{ runner.temp }}/deep-upload/sealed.json"
      - name: Upload
        id: upload
        if: \${{ steps.prepare_upload.outcome == 'success' && steps.secret_scan.outcome == 'success' }}
        uses: actions/upload-artifact@v4
        with:
          name: evidence
          path: \${{ runner.temp }}/deep-upload/sealed.json
      - name: Download
        uses: actions/download-artifact@v4
        with:
          name: evidence
          path: \${{ runner.temp }}/deep-upload/download
      - name: Verify
        run: >
          node scripts/sealed-evidence-bundle.mjs
          --bundle "\${{ runner.temp }}/deep-upload/download/sealed.json"
          --expected-sha256 "\${{ steps.secret_scan.outputs.bundle_sha256 }}"
          --actions-artifact-id "\${{ steps.upload.outputs.artifact-id }}"
          --actions-artifact-digest "\${{ steps.upload.outputs.artifact-digest }}"
`;

async function fixture(content, extension = 'yml') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-workflow-'));
  await writeFile(path.join(root, `test.${extension}`), content);
  return root;
}

test('parses Actions jobs and steps without treating comments as contracts', () => {
  const graph = parseWorkflowGraph(`# actions/upload-artifact@v4
jobs:
  test:
    steps:
      - run: echo ok
`);
  assert.equal(graph.jobs.length, 1);
  assert.equal(graph.jobs[0].steps.length, 1);
  assert.equal(graph.jobs[0].steps[0].run, 'echo ok');
});

test('accepts a sealed exact-file round trip in .yaml workflows', async () => {
  const root = await fixture(valid, 'yaml');
  try {
    assert.deepEqual(await validateWorkflows({ workflowRoot: root }), { uploadCount: 1, failures: [] });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('comments cannot fake preparation and broad uploads fail closed', async () => {
  const root = await fixture(valid
    .replace('node scripts/artifact-upload-manifest.mjs', 'echo no-prepare # scripts/artifact-upload-manifest.mjs')
    .replace('path: ${{ runner.temp }}/deep-upload/sealed.json', 'path: ${{ runner.temp }}/deep-upload/**'));
  try {
    const result = await validateWorkflows({ workflowRoot: root });
    assert.ok(result.failures.some(item => item.includes('ordered manifest preparation')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('echoed script names cannot fake executable gate steps', async () => {
  const root = await fixture(valid.replace(
    'node scripts/artifact-upload-manifest.mjs',
    'echo node scripts/artifact-upload-manifest.mjs'
  ));
  try {
    const result = await validateWorkflows({ workflowRoot: root });
    assert.ok(result.failures.some(item => item.includes('ordered manifest preparation')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
