import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
const read = p => readFile(new URL(p, import.meta.url), 'utf8');

test('retained time-source mode is explicit and does not remove the pre-mailbox guard', async () => {
  const s = await read('./deep-dev.ps1');
  assert.match(s, /\[switch\]\$RetainedMailboxTimeSourceRollover/);
  assert.match(s, /Mailbox-enabled custody requires coordinated role-volume\/journal rollover/);
  assert.match(s, /Invoke-TimeSourceRollover\.ps1/);
  assert.match(s, /\$ProjectName -cne 'deep-dev-current'.*?\$mailboxEnabled/s);
});
test('all writers stop before local, role-volume, SQL or publisher installation', async () => {
  const s = await read('./Invoke-TimeSourceRollover.ps1');
  assert.ok(s.indexOf("'validate-time-sources'") < s.indexOf("$owners=@("));
  assert.ok(s.indexOf("@('stop','--timeout','20')+$owners") < s.indexOf("'install-time-sources'"));
  assert.ok(s.indexOf("'install-time-sources'") < s.indexOf("$copy="));
  assert.ok(s.indexOf("revocation-roots.sql") < s.indexOf("'import-operational'"));
  assert.match(s, /publisher','node-1','node-2','node-3','registry','deposit-signer','retrieve-signer/);
  assert.doesNotMatch(s, /Provision|provision-state|provision-floor|current-mailbox-enroll|--volumes|volume','rm/);
});
test('online mount whitelist excludes offline root and complete private candidate', async () => {
  const s = await read('./Invoke-TimeSourceRollover.ps1');
  assert.match(s, /source=\$candidatePath\/operator,target=\/run\/deep-renewal,readonly/);
  assert.match(s, /source=\$candidatePath\/online\/registry\/mailbox-\$role.seed,target=\/next\/role.seed,readonly/);
  assert.doesNotMatch(s, /source=\$candidatePath,target=|source=.*offline-root.*target=/);
  assert.match(s, /current-mailbox-policy-successor/);
});
test('candidate is sealed, prefix-bound and does not mutate network or native journals in its installer', async () => {
  const s = await read('../tools/deep-dev/DevTimeSourceRollover.cs');
  assert.match(s, /DevOfflineOperationalRenewal.PrepareAsync/);
  assert.match(s, /DevOperationalActivation.Execute/);
  assert.match(s, /FixedTimeEquals/);
  assert.match(s, /Mailbox extension whitelist differs/);
  assert.doesNotMatch(s, /Directory.Delete|provision|File.Delete|MailboxClientLedgerDocument/);
  assert.match(s, /DevMailboxPreparation.RootSql\(next\).Split\('\\n'\).Skip\(1\)/);
});
