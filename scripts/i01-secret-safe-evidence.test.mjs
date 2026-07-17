import assert from 'node:assert/strict';
import test from 'node:test';
import { tapCounters } from './i01-secret-safe-evidence.mjs';

function tap(overrides = {}) {
  const counters = {
    tests: 3,
    pass: 3,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    ...overrides
  };
  return Object.entries(counters).map(([key, value]) => `# ${key} ${value}`).join('\n');
}

test('accepts only complete nonempty TAP output with every test passed', () => {
  assert.deepEqual(tapCounters(tap()), {
    tests: 3,
    passed: 3,
    failed: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0
  });
});

test('rejects empty, partial, skipped, cancelled, todo, and failed TAP output', () => {
  for (const output of [
    tap({ tests: 0, pass: 0 }),
    tap({ tests: 3, pass: 2 }),
    tap({ skipped: 1 }),
    tap({ cancelled: 1 }),
    tap({ todo: 1 }),
    tap({ fail: 1 }),
    '# tests 3\n# pass 3\n# fail 0',
    `${tap()}\n${tap({ skipped: 1 })}`
  ]) {
    assert.throws(() => tapCounters(output), /TAP|complete/);
  }
});
