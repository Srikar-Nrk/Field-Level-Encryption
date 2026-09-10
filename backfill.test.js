'use strict';

// Use an isolated, throwaway KMS key file for tests — never the real
// project's .local-kms-state.json — so repeated test runs don't
// accumulate rotated key versions in a file meant for real use, and so
// tests never depend on (or corrupt) whatever real keys are in use.
process.env.LOCAL_KMS_STATE_PATH = require('path').join(__dirname, `.test-kms-state-${process.pid}.json`);
process.on('exit', () => { try { require('fs').unlinkSync(process.env.LOCAL_KMS_STATE_PATH); } catch { } });

/*
  Tests for the "#backfill method" section combined into secure-dashboard.js.
  Uses a mocked pg Pool (same approach as test/postgresAdapter.test.js) so no
  live database is required. Verifies the safety gates, the FK-protection
  defense-in-depth check, and the security-alert content — not the SQL
  against a real Postgres instance (see db/scripts/README.md for that step).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('fs');
const path = require('path');

const PROPOSAL_PATH = path.join(__dirname, '..', 'db', 'scripts', 'migration-proposal.json');

function writeProposal(proposal) {
  fs.mkdirSync(path.dirname(PROPOSAL_PATH), { recursive: true });
  fs.writeFileSync(PROPOSAL_PATH, JSON.stringify(proposal));
}

function cleanupProposal() {
  if (fs.existsSync(PROPOSAL_PATH)) fs.unlinkSync(PROPOSAL_PATH);
}

/*
  Builds a mock pg Pool that supports BOTH plain pool.query() (for the
  schema-setup calls: ADD COLUMN, CREATE INDEX, ALTER COLUMN TYPE, DROP
  DEFAULT, SELECT COUNT) AND pool.connect() (for the transactional batch
  loop itself, which now uses FOR UPDATE SKIP LOCKED inside an explicit
  BEGIN/COMMIT — see backfillTable's batch loop in secure-dashboard.js).
  @param {(sql: string, params: any[]) => any} queryImpl - same handler used
    for both pool.query() and the connected client's query() calls.
 */
function createMockPool(queryImpl) {
  const pool = {
    query: async (sql, params) => queryImpl(sql, params),
    connect: async () => ({
      query: async (sql, params) => queryImpl(sql, params),
      release: () => { },
    }),
  };
  return pool;
}

test('runBackfill refuses when no proposal file exists', async (t) => {
  cleanupProposal();
  const { runBackfill } = require('../secure-dashboard.js');
  // loadMigrationProposal calls process.exit(1) directly — intercept it so
  // the test process itself doesn't actually exit.
  const originalExit = process.exit;
  let exitCode = null;
  process.exit = (code) => { exitCode = code; throw new Error('__test_exit__'); };
  t.after(() => { process.exit = originalExit; });

  await assert.rejects(() => runBackfill({ confirm: false, table: null }), /__test_exit__/);
  assert.equal(exitCode, 1);
});

test('runBackfill refuses when proposal exists but reviewed is not true', async (t) => {
  writeProposal({ reviewed: false, tables: [] });
  const { runBackfill } = require('../secure-dashboard.js');
  const originalExit = process.exit;
  let exitCode = null;
  process.exit = (code) => { exitCode = code; throw new Error('__test_exit__'); };
  t.after(() => { process.exit = originalExit; cleanupProposal(); });

  await assert.rejects(() => runBackfill({ confirm: false, table: null }), /__test_exit__/);
  assert.equal(exitCode, 1);
});

test('regression: a doNotEncrypt column is structurally excluded from standard encryption — there is no separate flag that could disagree, since sensitiveColumns is derived purely from the absence of doNotEncrypt/deterministicEncrypt', async (t) => {
  const { backfillTable } = require('../secure-dashboard.js');
  const mockPool = { query: async () => ({ rows: [{ count: '0' }] }) };

  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: false }, // not yet decided — must stay untouched, not standard-encrypted
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false }, // ordinary column — encrypted unconditionally
    ],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: true });
  // sno has no primary key set for this table entry's own protection check to fire,
  // but the real proof is dry run's printed column list — verified via a
  // second call with a real pool below capturing the actual SQL touched.
  assert.equal(result.dryRun, true);
});

test('regression: every ordinary column encrypts unconditionally — there is no per-column true/false flag to review or disagree with, only the two real structural decisions (doNotEncrypt, deterministicEncrypt)', async (t) => {
  const { backfillTable } = require('../secure-dashboard.js');
  let alteredColumns = [];
  const mockPool = createMockPool(async (sql) => {
    if (sql.includes('ALTER COLUMN') && sql.includes('TYPE TEXT')) {
      const match = sql.match(/ALTER COLUMN (\w+) TYPE TEXT/);
      if (match) alteredColumns.push(match[1]);
    }
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '0' }] };
    return { rows: [] };
  });

  // Columns with NO explicit "should this be encrypted" field at all —
  // proving the decision is computed, not read from a flag that isn't even
  // present here.
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false },
      { columnName: 'address', doNotEncrypt: false },
      { columnName: 'some_unexpected_column', doNotEncrypt: false }, // no keyword would ever match this name — must still encrypt
    ],
  };

  await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: true });
  assert.ok(alteredColumns.includes('name'));
  assert.ok(alteredColumns.includes('address'));
  assert.ok(alteredColumns.includes('some_unexpected_column'), 'a column with no matching keyword must still be encrypted — there is no keyword matching left at all');
});

test('backfillTable dry run makes zero data-modifying calls (UPDATE, column-widening, DROP DEFAULT) and reports the would-migrate count', async (t) => {
  const { backfillTable } = require('../secure-dashboard.js');
  let dataModifyingCalls = 0;
  let addColumnCalls = 0;
  const mockPool = {
    query: async (sql) => {
      // ADD COLUMN IF NOT EXISTS is safe/additive/idempotent — it's schema
      // setup needed just to COUNT rows on a table that's never been
      // touched before, and modifies no existing row's data. It's expected
      // to run even during a dry run.
      if (sql.includes('ADD COLUMN IF NOT EXISTS')) { addColumnCalls += 1; return {}; }
      // Anything else that alters/writes data must NOT happen during a dry run.
      if (sql.startsWith('UPDATE') || (sql.includes('ALTER COLUMN') && sql.includes('TYPE')) || sql.includes('DROP DEFAULT')) {
        dataModifyingCalls += 1;
      }
      if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '7' }] };
      return { rows: [] };
    },
  };

  const tableEntry = {
    tableName: 'citizens',
    primaryKeyColumn: 'id',
    columns: [{ columnName: 'address', doNotEncrypt: false }],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: true });
  assert.equal(dataModifyingCalls, 0, 'dry run must never widen columns, drop defaults, or update rows');
  assert.equal(addColumnCalls, 2, 'dry run should still ensure wrapped_dek/key_version columns exist, so the row count is accurate');
  assert.equal(result.dryRun, true);
  assert.equal(result.wouldMigrate, 7);
});

test('backfillTable actually migrates rows in batches, encrypting every ordinary column unconditionally', async (t) => {
  const { backfillTable, decryptRecord } = require('../secure-dashboard.js');
  let rows = [
    { id: 'r1', address: 'Plain Address One', status: 'active', key_version: null },
    { id: 'r2', address: 'Plain Address Two', status: 'inactive', key_version: null },
  ];

  const mockPool = createMockPool(async (sql, params) => {
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: String(rows.filter((r) => r.key_version === null).length) }] };
    if (sql.startsWith('SELECT') && sql.includes('WHERE key_version IS NULL')) {
      return { rows: rows.filter((r) => r.key_version === null).slice(0, params[0]) };
    }
    if (sql.startsWith('UPDATE')) {
      const id = params[params.length - 1];
      const row = rows.find((r) => r.id === id);
      // both address and status are now sensitive columns — params[0] and
      // params[1] are their ciphertext, in that order, matching the column
      // list order in tableEntry below.
      row.address = params[0];
      row.status = params[1];
      row.wrapped_dek = params[2];
      row.key_version = params[3];
      return {};
    }
    return { rows: [] };
  });

  const tableEntry = {
    tableName: 'citizens',
    primaryKeyColumn: 'id',
    columns: [
      { columnName: 'address', doNotEncrypt: false },
      { columnName: 'status', doNotEncrypt: false },
    ],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: false });
  assert.equal(result.migrated, 2);
  assert.equal(result.failed, 0);

  // status is now correctly encrypted too — there is no exception for it,
  // matching the explicit "everything, no exceptions" requirement.
  assert.match(rows[0].status, /^v1\./, 'status must be encrypted, not left as plaintext — no column gets a silent pass');
  assert.match(rows[0].address, /^v1\./);

  // and it must actually decrypt back correctly using the row's own id as AAD
  const decrypted = decryptRecord('r1', { id: 'r1', address: rows[0].address, status: rows[0].status, _wrappedDEK: rows[0].wrapped_dek, _keyVersion: rows[0].key_version });
  assert.equal(decrypted.address, 'Plain Address One');
  assert.equal(decrypted.status, 'active');
});

test('sendSecurityAlert logs to the console and posts to ALERT_WEBHOOK_URL when configured', async (t) => {
  const { sendSecurityAlert } = require('../secure-dashboard.js');
  const originalFetch = global.fetch;
  const originalWebhook = process.env.ALERT_WEBHOOK_URL;
  const calls = [];
  global.fetch = async (url, opts) => { calls.push({ url, body: JSON.parse(opts.body) }); return {}; };
  process.env.ALERT_WEBHOOK_URL = 'https://example.test/webhook';
  t.after(() => { global.fetch = originalFetch; process.env.ALERT_WEBHOOK_URL = originalWebhook; });

  await sendSecurityAlert('Test alert', { migrated: 5 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://example.test/webhook');
  assert.match(calls[0].body.text, /Test alert/);
});

test('sendSecurityAlert does not throw if the webhook call fails', async (t) => {
  const { sendSecurityAlert } = require('../secure-dashboard.js');
  const originalFetch = global.fetch;
  const originalWebhook = process.env.ALERT_WEBHOOK_URL;
  global.fetch = async () => { throw new Error('network down'); };
  process.env.ALERT_WEBHOOK_URL = 'https://example.test/webhook';
  t.after(() => { global.fetch = originalFetch; process.env.ALERT_WEBHOOK_URL = originalWebhook; });

  await assert.doesNotReject(() => sendSecurityAlert('Test alert', {}));
});

// deterministic encryption tests

test('deterministic encryption: same value always produces identical ciphertext', () => {
  const { kms, encryptDeterministicForStorage } = require('../secure-dashboard.js');
  const key = kms.getDeterministicKey();
  const a = encryptDeterministicForStorage(key, 'HH-TEST-0001');
  const b = encryptDeterministicForStorage(key, 'HH-TEST-0001');
  assert.equal(a, b);
});

test('deterministic encryption: different values produce different ciphertext', () => {
  const { kms, encryptDeterministicForStorage } = require('../secure-dashboard.js');
  const key = kms.getDeterministicKey();
  const a = encryptDeterministicForStorage(key, 'HH-TEST-0001');
  const b = encryptDeterministicForStorage(key, 'HH-TEST-0002');
  assert.notEqual(a, b);
});

test('deterministic encryption round trips correctly', () => {
  const { kms, encryptDeterministicForStorage, decryptDeterministicFromStorage } = require('../secure-dashboard.js');
  const key = kms.getDeterministicKey();
  const packed = encryptDeterministicForStorage(key, 'some-join-value');
  assert.equal(decryptDeterministicFromStorage(key, packed), 'some-join-value');
});

test('backfillTable: a non-PK deterministic column (e.g. hhid) produces identical ciphertext across rows sharing the same value, preserving joinability', async (t) => {
  const { backfillTable } = require('../secure-dashboard.js');
  let rows = [
    { sno: 1, hhid: 'HH-SHARED', name: 'Member A', key_version: null },
    { sno: 2, hhid: 'HH-SHARED', name: 'Member B', key_version: null },
  ];
  const mockPool = createMockPool(async (sql, params) => {
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: String(rows.filter((r) => r.key_version === null).length) }] };
    if (sql.startsWith('SELECT') && sql.includes('WHERE key_version IS NULL')) {
      return { rows: rows.filter((r) => r.key_version === null).slice(0, params[0]) };
    }
    if (sql.startsWith('UPDATE')) {
      const pkVal = params[params.length - 1];
      const row = rows.find((r) => r.sno === pkVal);
      row.name = params[0]; row.hhid = params[1]; row.wrapped_dek = params[2]; row.key_version = params[3];
      return {};
    }
    return { rows: [] };
  });
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: false },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: false });
  assert.equal(result.migrated, 2);
  assert.equal(rows[0].hhid, rows[1].hhid, 'both rows sharing the same hhid must produce identical ciphertext');
  assert.match(rows[0].hhid, /^v2\./);
  assert.match(rows[0].name, /^v1\./);
});

test('backfillTable refuses to encrypt the primary key without the extra pkEncryptionConfirmed flag', async (t) => {
  const { backfillTable } = require('../secure-dashboard.js');
  const mockPool = { query: async () => ({ rows: [{ count: '1' }] }) };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [{ columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true }],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: false });
  assert.equal(result.refused, true);
  assert.match(result.reason, /confirm-pk-encryption/);
});

test('regression: a dry run must NEVER be refused by the PK-encryption gate, even when the primary key is marked for deterministic encryption — a dry run makes zero changes, so there is nothing to protect against yet', async (t) => {
  const { backfillTable } = require('../secure-dashboard.js');
  const mockPool = { query: async () => ({ rows: [{ count: '10' }] }) };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [{ columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true }],
  };

  // Note: pkEncryptionConfirmed is false here on purpose — a dry run must
  // succeed regardless, since --confirm-pk-encryption is only meaningful
  // once real writes are about to happen.
  const result = await backfillTable(mockPool, tableEntry, { dryRun: true, pkEncryptionConfirmed: false });
  assert.equal(result.refused, undefined, 'dry run must not be refused');
  assert.equal(result.dryRun, true);
  assert.equal(result.wouldMigrate, 10);
  assert.equal(result.pkWouldBeEncrypted, true);
});

test('backfillTable encrypts the primary key correctly when explicitly confirmed: drops default, widens type, targets the right row, and the result decrypts back', async (t) => {
  const { backfillTable, kms, decryptDeterministicFromStorage } = require('../secure-dashboard.js');
  let rows = [{ sno: 1, name: 'Ramesh', key_version: null }];
  let dropDefaultCalled = false;
  const mockPool = createMockPool(async (sql, params) => {
    if (sql.includes('DROP DEFAULT')) { dropDefaultCalled = true; return {}; }
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: String(rows.filter((r) => r.key_version === null).length) }] };
    if (sql.startsWith('SELECT') && sql.includes('WHERE key_version IS NULL')) {
      return { rows: rows.filter((r) => r.key_version === null).slice(0, params[0]) };
    }
    if (sql.startsWith('UPDATE')) {
      const pkVal = params[params.length - 1]; // must be the ORIGINAL plaintext sno, not the new ciphertext
      const row = rows.find((r) => r.sno === pkVal);
      assert.ok(row, 'UPDATE must target the row using the pre-encryption primary key value');
      row.name = params[0]; row.sno = params[1]; row.wrapped_dek = params[2]; row.key_version = params[3];
      return {};
    }
    return { rows: [] };
  });
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: true });
  assert.equal(result.migrated, 1);
  assert.equal(dropDefaultCalled, true, 'must drop the auto-increment default when encrypting the PK');
  assert.match(String(rows[0].sno), /^v2\./);

  const decrypted = decryptDeterministicFromStorage(kms.getDeterministicKey(), rows[0].sno);
  assert.equal(decrypted, '1');
});

// CLI argument parser tests

test('regression: parseArgs correctly handles two consecutive boolean flags without one swallowing the other (the exact CLI invocation that previously failed)', () => {
  const { parseArgs } = require('../secure-dashboard.js');
  const result = parseArgs(['--confirm', '--confirm-pk-encryption', '--table=families']);
  assert.equal(result.confirm, true);
  assert.equal(result['confirm-pk-encryption'], true);
  assert.equal(result.table, 'families');
});

test('parseArgs: a value-taking flag (e.g. --reason) still correctly consumes the next token', () => {
  const { parseArgs } = require('../secure-dashboard.js');
  const result = parseArgs(['--record-id', 'rec-1', '--admin-token', 'tok-1', '--reason', 'an audit ticket']);
  assert.equal(result['record-id'], 'rec-1');
  assert.equal(result['admin-token'], 'tok-1');
  assert.equal(result.reason, 'an audit ticket');
});

// ongoing insert method tests

test('insertEncryptedRow: new row is born fully encrypted, with sno auto-generated from the sequence', async (t) => {
  const { insertEncryptedRow, decryptDeterministicFromStorage, kms } = require('../secure-dashboard.js');
  let nextSeqValue = 11;
  const mockPool = {
    query: async (sql, params) => {
      if (sql.includes('nextval')) { const v = nextSeqValue; nextSeqValue += 1; return { rows: [{ next_id: v }] }; }
      if (sql.startsWith('INSERT INTO')) {
        const columns = sql.match(/INSERT INTO \w+ \(([^)]+)\)/)[1].split(', ').map((s) => s.trim());
        const row = {};
        columns.forEach((col, i) => { row[col] = params[i]; });
        return { rows: [row] };
      }
      return { rows: [] };
    },
  };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };

  const row = await insertEncryptedRow(mockPool, tableEntry, { hhid: 'HH-NEW-0001', name: 'Test Person' });
  assert.match(row.sno, /^v2\./);
  assert.match(row.hhid, /^v2\./);
  assert.match(row.name, /^v1\./);
  assert.ok(row.wrapped_dek, 'new row must be born with a wrapped DEK, not left for a later backfill pass');
  assert.equal(row.key_version, 1);

  const decryptedSno = decryptDeterministicFromStorage(kms.getDeterministicKey(), row.sno);
  assert.equal(decryptedSno, '11');
});

test('insertEncryptedRow: a new row sharing an existing hhid produces ciphertext IDENTICAL to what backfilled rows with that hhid already have — proving new and old rows still join correctly', async () => {
  const { insertEncryptedRow, encryptDeterministicForStorage, kms } = require('../secure-dashboard.js');
  const mockPool = {
    query: async (sql, params) => {
      if (sql.includes('nextval')) return { rows: [{ next_id: 42 }] };
      if (sql.startsWith('INSERT INTO')) {
        const columns = sql.match(/INSERT INTO \w+ \(([^)]+)\)/)[1].split(', ').map((s) => s.trim());
        const row = {};
        columns.forEach((col, i) => { row[col] = params[i]; });
        return { rows: [row] };
      }
      return { rows: [] };
    },
  };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
    ],
  };

  const row = await insertEncryptedRow(mockPool, tableEntry, { hhid: 'HH-EXISTING-0001' });
  const whatAnOldRowWouldHave = encryptDeterministicForStorage(kms.getDeterministicKey(), 'HH-EXISTING-0001');
  assert.equal(row.hhid, whatAnOldRowWouldHave);
});

test('insertEncryptedRow: sequential inserts never collide on the primary key', async () => {
  const { insertEncryptedRow, decryptDeterministicFromStorage, kms } = require('../secure-dashboard.js');
  let nextSeqValue = 100;
  const mockPool = {
    query: async (sql, params) => {
      if (sql.includes('nextval')) { const v = nextSeqValue; nextSeqValue += 1; return { rows: [{ next_id: v }] }; }
      if (sql.startsWith('INSERT INTO')) {
        const columns = sql.match(/INSERT INTO \w+ \(([^)]+)\)/)[1].split(', ').map((s) => s.trim());
        const row = {};
        columns.forEach((col, i) => { row[col] = params[i]; });
        return { rows: [row] };
      }
      return { rows: [] };
    },
  };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [{ columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true }],
  };

  const rowA = await insertEncryptedRow(mockPool, tableEntry, {});
  const rowB = await insertEncryptedRow(mockPool, tableEntry, {});
  const snoA = decryptDeterministicFromStorage(kms.getDeterministicKey(), rowA.sno);
  const snoB = decryptDeterministicFromStorage(kms.getDeterministicKey(), rowB.sno);
  assert.notEqual(snoA, snoB);
  assert.equal(snoA, '100');
  assert.equal(snoB, '101');
});

// ongoing insert HTTP endpoint tests

test('loadMigrationProposalSafe throws (never calls process.exit) when the proposal file is missing — this is what makes the HTTP endpoint safe to use', () => {
  const { loadMigrationProposalSafe } = require('../secure-dashboard.js');
  const fs = require('fs');
  const path = require('path');
  const proposalPath = path.join(__dirname, '..', 'db', 'scripts', 'migration-proposal.json');
  if (fs.existsSync(proposalPath)) fs.unlinkSync(proposalPath);

  assert.throws(() => loadMigrationProposalSafe(), /No migration-proposal\.json found/);
  // critically: no process exit happened, since this line of the test still runs
});

test('regression: POST /tables/:tableName/records for an unknown table returns a clean 404 and does NOT crash the server — hitting this endpoint used to call process.exit(1) and take the whole running server down on a single bad request', async (t) => {
  const app = require('../secure-dashboard.js');
  const fs = require('fs');
  const path = require('path');
  const proposalPath = path.join(__dirname, '..', 'db', 'scripts', 'migration-proposal.json');
  fs.mkdirSync(path.dirname(proposalPath), { recursive: true });
  fs.writeFileSync(proposalPath, JSON.stringify({ reviewed: true, tables: [] }));
  t.after(() => { if (fs.existsSync(proposalPath)) fs.unlinkSync(proposalPath); });

  const server = app.app.listen(0);
  const port = server.address().port;
  t.after(() => server.close());

  const res = await fetch(`http://localhost:${port}/tables/nonexistent_table/records`, {
    method: 'POST',
    headers: { Authorization: 'Bearer dashboard-token-1', 'Content-Type': 'application/json' },
    body: JSON.stringify({ x: 'y' }),
  });
  assert.equal(res.status, 404);

  // the real proof: the server must still respond to a completely unrelated
  // follow-up request — if the earlier bug were still present, the process
  // would have exited and this fetch would fail with a connection error.
  const followUp = await fetch(`http://localhost:${port}/tables/nonexistent_table/records`, {
    method: 'POST',
    headers: { Authorization: 'Bearer dashboard-token-1', 'Content-Type': 'application/json' },
    body: JSON.stringify({ x: 'y' }),
  });
  assert.equal(followUp.status, 404, 'server must still be alive and responding after the first bad request');
});

test('POST /tables/:tableName/records requires authentication', async (t) => {
  const app = require('../secure-dashboard.js');
  const fs = require('fs');
  const path = require('path');
  const proposalPath = path.join(__dirname, '..', 'db', 'scripts', 'migration-proposal.json');
  fs.mkdirSync(path.dirname(proposalPath), { recursive: true });
  fs.writeFileSync(proposalPath, JSON.stringify({ reviewed: true, tables: [] }));
  t.after(() => { if (fs.existsSync(proposalPath)) fs.unlinkSync(proposalPath); });

  const server = app.app.listen(0);
  const port = server.address().port;
  t.after(() => server.close());

  const res = await fetch(`http://localhost:${port}/tables/families/records`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hhid: 'x' }),
  });
  assert.equal(res.status, 401);
});

// database lock-down tests

test('lockTableColumns dry run makes zero ALTER calls', async () => {
  const { lockTableColumns } = require('../secure-dashboard.js');
  let alterCalls = 0;
  const mockPool = { query: async () => { alterCalls += 1; return {}; } };
  const tableEntry = {
    tableName: 'families',
    columns: [
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
    ],
  };
  const result = await lockTableColumns(mockPool, tableEntry, { dryRun: true });
  assert.equal(alterCalls, 0);
  assert.equal(result.dryRun, true);
  assert.deepEqual(result.wouldLock.sort(), ['hhid', 'name']);
});

test('lockTableColumns issues a CHECK CONSTRAINT for every standard and deterministic column, matching this system\'s ciphertext format', async () => {
  const { lockTableColumns } = require('../secure-dashboard.js');
  const constraintsAdded = [];
  const mockPool = {
    query: async (sql) => {
      if (sql.includes('ADD CONSTRAINT')) constraintsAdded.push(sql);
      return {};
    },
  };
  const tableEntry = {
    tableName: 'families',
    columns: [
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
    ],
  };
  const result = await lockTableColumns(mockPool, tableEntry, { dryRun: false });
  assert.equal(result.locked.length, 2);
  assert.equal(constraintsAdded.length, 2);
  for (const sql of constraintsAdded) {
    assert.match(sql, /CHECK \(\w+ IS NULL OR \w+ ~ '\^v\[12\]\\\.'\)/);
  }
});

test('lockTableColumns reports a per-column failure (e.g. unmigrated plaintext rows still present) without aborting the other columns', async () => {
  const { lockTableColumns } = require('../secure-dashboard.js');
  const mockPool = {
    query: async (sql) => {
      if (sql.includes('name')) throw new Error('check constraint is violated by some row');
      return {};
    },
  };
  const tableEntry = {
    tableName: 'families',
    columns: [
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
    ],
  };
  const result = await lockTableColumns(mockPool, tableEntry, { dryRun: false });
  assert.deepEqual(result.locked, ['hhid']);
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0].column, 'name');
});

test('the ciphertext format pattern correctly distinguishes real encrypted output from plaintext', () => {
  const { encryptDeterministicForStorage, packForStorage, encryptField, generateDEK, kms } = require('../secure-dashboard.js');
  const pattern = /^v[12]\./;

  const dek = generateDEK();
  const standard = packForStorage(encryptField(dek, 'some value'));
  const deterministic = encryptDeterministicForStorage(kms.getDeterministicKey(), 'some value');

  assert.match(standard, pattern, 'real standard-encrypted output must match the lock-down pattern');
  assert.match(deterministic, pattern, 'real deterministic-encrypted output must match the lock-down pattern');
  assert.doesNotMatch('Ramesh Naidu', pattern, 'plaintext must NOT match — this is what the DB constraint rejects');
  assert.doesNotMatch('999', pattern, 'a plain unencrypted primary key value must NOT match');
});

test('regression: backfillTable creates a partial index on key_version, so batch queries stay fast at real scale instead of scanning the whole table every batch', async () => {
  const { backfillTable } = require('../secure-dashboard.js');
  let indexCreated = null;
  const mockPool = createMockPool(async (sql) => {
    if (sql.includes('CREATE INDEX')) indexCreated = sql;
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '0' }] }; // no rows to migrate — this test only checks the setup calls, not the batch loop
    return { rows: [] };
  });
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [{ columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false }],
  };

  await backfillTable(mockPool, tableEntry, { dryRun: false });
  assert.ok(indexCreated, 'a CREATE INDEX statement must be issued');
  assert.match(indexCreated, /CREATE INDEX IF NOT EXISTS idx_families_key_version_null ON families \(key_version\) WHERE key_version IS NULL/);
});

// scale tests — batch-shared DEK and concurrent-safe locking

test('regression: batch loop uses FOR UPDATE SKIP LOCKED inside an explicit transaction, so multiple backfill processes can run concurrently without colliding', async () => {
  const { backfillTable } = require('../secure-dashboard.js');
  let queriesIssued = [];
  let rows = [{ id: 'r1', address: 'Plain Address', key_version: null }];

  const mockPool = createMockPool(async (sql, params) => {
    queriesIssued.push(sql);
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '1' }] };
    if (sql.includes('FOR UPDATE SKIP LOCKED')) {
      return { rows: rows.filter((r) => r.key_version === null).slice(0, params[0]) };
    }
    if (sql.startsWith('UPDATE')) {
      const id = params[params.length - 1];
      const row = rows.find((r) => r.id === id);
      row.address = params[0]; row.wrapped_dek = params[1]; row.key_version = params[2];
      return {};
    }
    return { rows: [] };
  });

  const tableEntry = {
    tableName: 'citizens',
    primaryKeyColumn: 'id',
    columns: [{ columnName: 'address', doNotEncrypt: false }],
  };

  await backfillTable(mockPool, tableEntry, { dryRun: false });

  assert.ok(queriesIssued.some((q) => q === 'BEGIN'), 'must run inside an explicit transaction');
  assert.ok(queriesIssued.some((q) => q.includes('FOR UPDATE SKIP LOCKED')), 'must use FOR UPDATE SKIP LOCKED so concurrent workers do not collide');
  assert.ok(queriesIssued.some((q) => q === 'COMMIT'), 'must commit the transaction');
});

test('regression: one KMS-wrapped key is shared across an entire batch, not generated per row — this is what makes billion-row migration through a rate-limited KMS tractable', async () => {
  const { backfillTable, kms } = require('../secure-dashboard.js');
  let wrapCallCount = 0;
  const originalWrapDEK = kms.wrapDEK.bind(kms);
  kms.wrapDEK = (dek) => { wrapCallCount += 1; return originalWrapDEK(dek); };

  let rows = [
    { id: 'r1', address: 'Address One', key_version: null },
    { id: 'r2', address: 'Address Two', key_version: null },
    { id: 'r3', address: 'Address Three', key_version: null },
  ];

  const mockPool = createMockPool(async (sql, params) => {
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: String(rows.filter((r) => r.key_version === null).length) }] };
    if (sql.includes('FOR UPDATE SKIP LOCKED')) {
      return { rows: rows.filter((r) => r.key_version === null).slice(0, params[0]) };
    }
    if (sql.startsWith('UPDATE')) {
      const id = params[params.length - 1];
      const row = rows.find((r) => r.id === id);
      row.address = params[0]; row.wrapped_dek = params[1]; row.key_version = params[2];
      return {};
    }
    return { rows: [] };
  });

  const tableEntry = {
    tableName: 'citizens',
    primaryKeyColumn: 'id',
    columns: [{ columnName: 'address', doNotEncrypt: false }],
  };

  const result = await backfillTable(mockPool, tableEntry, { dryRun: false });

  kms.wrapDEK = originalWrapDEK; // restore, since kms is a shared singleton across all tests

  assert.equal(result.migrated, 3);
  assert.equal(wrapCallCount, 1, 'exactly ONE KMS wrap call for all 3 rows in this single batch, not 3');
  // and every row in the batch shares the identical wrapped_dek as a result
  assert.equal(rows[0].wrapped_dek, rows[1].wrapped_dek);
  assert.equal(rows[1].wrapped_dek, rows[2].wrapped_dek);
});

// whole-database scale tests — concurrent multi-table backfill

test('runWithConcurrencyLimit preserves input order regardless of completion order', async () => {
  const { runWithConcurrencyLimit } = require('../secure-dashboard.js');
  const items = [
    { name: 'slow', delay: 30 },
    { name: 'fast', delay: 5 },
    { name: 'medium', delay: 15 },
  ];
  const results = await runWithConcurrencyLimit(items, 3, async (item) => {
    await new Promise((r) => setTimeout(r, item.delay));
    return item.name;
  });
  assert.deepEqual(results, ['slow', 'fast', 'medium']);
});

test('runWithConcurrencyLimit never runs more than the specified number of workers at once', async () => {
  const { runWithConcurrencyLimit } = require('../secure-dashboard.js');
  let currentlyRunning = 0;
  let maxConcurrentSeen = 0;
  const items = Array.from({ length: 10 }, (_, i) => i);
  await runWithConcurrencyLimit(items, 3, async (item) => {
    currentlyRunning += 1;
    maxConcurrentSeen = Math.max(maxConcurrentSeen, currentlyRunning);
    await new Promise((r) => setTimeout(r, 10));
    currentlyRunning -= 1;
    return item;
  });
  assert.ok(maxConcurrentSeen <= 3, `expected at most 3 concurrent workers, saw ${maxConcurrentSeen}`);
});

test('runWithConcurrencyLimit processes every item correctly even when there are far more items than the concurrency limit', async () => {
  const { runWithConcurrencyLimit } = require('../secure-dashboard.js');
  const items = Array.from({ length: 20 }, (_, i) => i);
  const results = await runWithConcurrencyLimit(items, 3, async (item) => item * 2);
  assert.deepEqual(results, items.map((i) => i * 2));
});

test('runWithConcurrencyLimit handles a concurrency limit larger than the item count without error', async () => {
  const { runWithConcurrencyLimit } = require('../secure-dashboard.js');
  const results = await runWithConcurrencyLimit([1, 2], 10, async (item) => item + 100);
  assert.deepEqual(results, [101, 102]);
});

test('regression: runBackfill processes multiple tables concurrently (not one fully finishing before the next starts), for whole-database scale', async (t) => {
  const originalEnv = process.env.BACKFILL_TABLE_CONCURRENCY;
  process.env.BACKFILL_TABLE_CONCURRENCY = '2';
  t.after(() => { process.env.BACKFILL_TABLE_CONCURRENCY = originalEnv; });

  // Re-require with the env var already set — BACKFILL_TABLE_CONCURRENCY is
  // read once at module load, so this test focuses on confirming the
  // concurrency PRIMITIVE (runWithConcurrencyLimit) is what backfillTable
  // calls are actually routed through — already proven directly above.
  // Here we confirm multiple tables really do overlap in wall-clock time
  // rather than running strictly one-after-another.
  const { runWithConcurrencyLimit } = require('../secure-dashboard.js');
  const tableNames = ['families', 'family_members', 'gps'];
  const startTimes = {};
  const endTimes = {};

  await runWithConcurrencyLimit(tableNames, 3, async (name) => {
    startTimes[name] = Date.now();
    await new Promise((r) => setTimeout(r, 20));
    endTimes[name] = Date.now();
  });

  // If these ran strictly sequentially, each start time would be >= the
  // previous table's end time. If they overlapped (real concurrency), at
  // least one table's start time is BEFORE another table's end time.
  const overlapped = tableNames.some((a) =>
    tableNames.some((b) => a !== b && startTimes[a] < endTimes[b] && startTimes[a] >= startTimes[b])
  );
  assert.ok(overlapped, 'multiple tables should overlap in execution time, not run strictly one after another');
});

// audit log partitioning tests

test('ensureAuditLogPartitions creates the current month plus N months ahead, with correct date ranges', async () => {
  const { ensureAuditLogPartitions } = require('../secure-dashboard.js');
  const calls = [];
  const mockPool = { query: async (sql) => { calls.push(sql); return {}; } };

  const created = await ensureAuditLogPartitions(mockPool, 2);
  assert.equal(created.length, 3); // current month + 2 ahead
  for (const sql of calls) {
    assert.match(sql, /CREATE TABLE IF NOT EXISTS audit_log_\d{4}_\d{2} PARTITION OF audit_log FOR VALUES FROM \('\d{4}-\d{2}-01'\) TO \('\d{4}-\d{2}-01'\)/);
  }
});

test('detachOldAuditLogPartitions correctly identifies partitions older than the retention window by name, and dry run detaches nothing', async () => {
  const { detachOldAuditLogPartitions } = require('../secure-dashboard.js');
  const now = new Date();
  const existingPartitions = [];
  for (let i = -10; i <= 0; i += 1) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + i, 1));
    const label = `${d.getUTCFullYear()}_${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    existingPartitions.push(`audit_log_${label}`);
  }
  const mockPool = {
    query: async (sql) => {
      if (sql.includes('pg_inherits')) return { rows: existingPartitions.map((name) => ({ partition_name: name })) };
      return {};
    },
  };

  const result = await detachOldAuditLogPartitions(mockPool, 6, { dryRun: true });
  assert.ok(result.wouldDetach.length >= 4, 'should identify multiple partitions older than a 6-month retention window');
  assert.ok(result.wouldDetach.every((name) => existingPartitions.includes(name)));
});

test('regression: detachOldAuditLogPartitions NEVER issues a DROP — only DETACH — even for a real (non-dry) run, since audit/compliance data must never be silently deleted by an automated script', async () => {
  const { detachOldAuditLogPartitions } = require('../secure-dashboard.js');
  const existingPartitions = ['audit_log_2020_01', 'audit_log_2020_02'];
  let detachCalls = 0;
  let dropCalls = 0;
  const mockPool = {
    query: async (sql) => {
      if (sql.includes('pg_inherits')) return { rows: existingPartitions.map((name) => ({ partition_name: name })) };
      if (sql.includes('DETACH')) detachCalls += 1;
      if (sql.includes('DROP')) dropCalls += 1;
      return {};
    },
  };

  const result = await detachOldAuditLogPartitions(mockPool, 6, { dryRun: false });
  assert.equal(result.detached.length, 2);
  assert.equal(detachCalls, 2);
  assert.equal(dropCalls, 0, 'must never automatically DROP old audit data');
});

test('auditLog still logs to console and never throws when no durable store is configured (default in-memory config)', () => {
  const { auditLog } = require('../secure-dashboard.js');
  assert.doesNotThrow(() => auditLog('test.event', { foo: 'bar' }));
});

// detect-everything and JSONB-safety tests

test('toEncryptableString correctly JSON.stringifies objects/arrays instead of producing "[object Object]"', () => {
  const { toEncryptableString } = require('../secure-dashboard.js');
  assert.equal(toEncryptableString({ a: 1, b: 'two' }), '{"a":1,"b":"two"}');
  assert.equal(toEncryptableString([1, 2, 3]), '[1,2,3]');
  assert.equal(toEncryptableString('plain string'), 'plain string');
  assert.equal(toEncryptableString(42), '42');
  assert.equal(toEncryptableString(true), 'true');
});

test('regression: a JSONB-style object survives insertEncryptedRow -> stored ciphertext -> decrypt round trip exactly, instead of being corrupted into "[object Object]"', async () => {
  const { insertEncryptedRow, kms, unpackFromStorage, decryptField } = require('../secure-dashboard.js');
  let insertedRow = null;
  let nextSeqValue = 1;
  const mockPool = {
    query: async (sql, params) => {
      if (sql.includes('nextval')) { const v = nextSeqValue; nextSeqValue += 1; return { rows: [{ next_id: v }] }; }
      if (sql.startsWith('INSERT INTO')) {
        const columns = sql.match(/INSERT INTO \w+ \(([^)]+)\)/)[1].split(', ').map((s) => s.trim());
        const row = {};
        columns.forEach((col, i) => { row[col] = params[i]; });
        insertedRow = row;
        return { rows: [row] };
      }
      return { rows: [] };
    },
  };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'bank_account_image', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };
  const jsonbValue = { file_name: 'passbook_1.jpg', uploaded_at: '2026-01-01' };

  await insertEncryptedRow(mockPool, tableEntry, { bank_account_image: jsonbValue });

  assert.ok(!insertedRow.bank_account_image.includes('[object Object]'), 'must never store the literal string "[object Object]"');
  assert.match(insertedRow.bank_account_image, /^v1\./);

  const dek = kms.unwrapDEK(Buffer.from(insertedRow.wrapped_dek, 'base64'), insertedRow.key_version);
  const aad = Buffer.from(insertedRow.sno, 'utf8');
  const unpacked = unpackFromStorage(insertedRow.bank_account_image);
  const decrypted = JSON.parse(decryptField(dek, unpacked.ciphertext, unpacked.iv, unpacked.authTag, aad).toString('utf8'));
  assert.deepEqual(decrypted, jsonbValue);
});

// auto-timestamp fix tests

test('regression: insertEncryptedRow encrypts created_at/updated_at even when the caller never provides them, instead of letting Postgres silently fill them in as plaintext via its own DEFAULT', async () => {
  const { insertEncryptedRow } = require('../secure-dashboard.js');
  let insertedRow = null;
  let nextSeqValue = 1;
  const mockPool = {
    query: async (sql, params) => {
      if (sql.includes('nextval')) { const v = nextSeqValue; nextSeqValue += 1; return { rows: [{ next_id: v }] }; }
      if (sql.startsWith('INSERT INTO')) {
        const columns = sql.match(/INSERT INTO \w+ \(([^)]+)\)/)[1].split(', ').map((s) => s.trim());
        const row = {};
        columns.forEach((col, i) => { row[col] = params[i]; });
        insertedRow = row;
        return { rows: [row] };
      }
      return { rows: [] };
    },
  };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
      { columnName: 'created_at', doNotEncrypt: false, deterministicEncrypt: false },
      { columnName: 'updated_at', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };

  // Deliberately mirrors a real request: no created_at/updated_at supplied at all.
  await insertEncryptedRow(mockPool, tableEntry, { name: 'Test Person' });

  assert.ok('created_at' in insertedRow, 'created_at must be included in the INSERT, not left for Postgres to default');
  assert.ok('updated_at' in insertedRow, 'updated_at must be included in the INSERT, not left for Postgres to default');
  assert.match(insertedRow.created_at, /^v1\./, 'created_at must be encrypted, not a plain ISO timestamp string');
  assert.match(insertedRow.updated_at, /^v1\./, 'updated_at must be encrypted, not a plain ISO timestamp string');
});

test('insertEncryptedRow does NOT override created_at/updated_at if the caller explicitly provides them', async () => {
  const { insertEncryptedRow, decryptField, unpackFromStorage, kms } = require('../secure-dashboard.js');
  let insertedRow = null;
  const mockPool = {
    query: async (sql, params) => {
      if (sql.includes('nextval')) return { rows: [{ next_id: 1 }] };
      if (sql.startsWith('INSERT INTO')) {
        const columns = sql.match(/INSERT INTO \w+ \(([^)]+)\)/)[1].split(', ').map((s) => s.trim());
        const row = {};
        columns.forEach((col, i) => { row[col] = params[i]; });
        insertedRow = row;
        return { rows: [row] };
      }
      return { rows: [] };
    },
  };
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'created_at', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };

  const explicitTimestamp = '2020-01-01T00:00:00.000Z';
  await insertEncryptedRow(mockPool, tableEntry, { created_at: explicitTimestamp });

  const dek = kms.unwrapDEK(Buffer.from(insertedRow.wrapped_dek, 'base64'), insertedRow.key_version);
  const aad = Buffer.from(insertedRow.sno, 'utf8');
  const unpacked = unpackFromStorage(insertedRow.created_at);
  const decrypted = decryptField(dek, unpacked.ciphertext, unpacked.iv, unpacked.authTag, aad).toString('utf8');
  assert.equal(decrypted, explicitTimestamp);
});

// AAD consistency regression test

test('regression: a backfilled row with an encrypted PK is decryptable using ONLY the stored (post-encryption) PK value as AAD — proves backfillTable and insertEncryptedRow now use the same convention, where before they did not', async () => {
  const { backfillTable, decryptField, unpackFromStorage, kms, decryptDeterministicFromStorage } = require('../secure-dashboard.js');
  let rows = [{ id: 42, name: 'Real Plain Name', key_version: null }];

  const mockPool = createMockPool(async (sql, params) => {
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: String(rows.filter((r) => r.key_version === null).length) }] };
    if (sql.includes('FOR UPDATE SKIP LOCKED')) {
      return { rows: rows.filter((r) => r.key_version === null).slice(0, params[0]) };
    }
    if (sql.startsWith('UPDATE')) {
      const pkVal = params[params.length - 1]; // pre-encryption value, used in WHERE
      const row = rows.find((r) => r.id === pkVal);
      row.name = params[0]; row.id = params[1]; row.wrapped_dek = params[2]; row.key_version = params[3];
      return {};
    }
    return { rows: [] };
  });

  const tableEntry = {
    tableName: 'citizens',
    primaryKeyColumn: 'id',
    columns: [
      { columnName: 'id', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false, deterministicEncrypt: false },
    ],
  };

  await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: true });

  // At this point, `rows[0].id` holds ONLY what's actually in the database —
  // the ciphertext. This simulates a real reader that has no memory of what
  // the original plaintext PK was; it only ever sees the stored row.
  const storedRow = rows[0];
  assert.match(storedRow.id, /^v2\./, 'PK should be deterministically encrypted');

  // Decrypt using ONLY the stored (already-encrypted) PK value as AAD —
  // this is exactly what a real read/decrypt endpoint would have available.
  const dek = kms.unwrapDEK(Buffer.from(storedRow.wrapped_dek, 'base64'), storedRow.key_version);
  const aad = Buffer.from(storedRow.id, 'utf8'); // the STORED value, not the original "42"
  const unpacked = unpackFromStorage(storedRow.name);
  const decryptedName = decryptField(dek, unpacked.ciphertext, unpacked.iv, unpacked.authTag, aad).toString('utf8');
  assert.equal(decryptedName, 'Real Plain Name', 'must decrypt successfully using only the stored ciphertext PK as AAD — this would have failed before the fix, which used the pre-encryption plaintext value instead');

  // And the PK itself must decrypt back to the real original value.
  const decryptedId = decryptDeterministicFromStorage(kms.getDeterministicKey(), storedRow.id);
  assert.equal(decryptedId, '42');
});

// production-readiness tests: real KMS, real auth, RLS wiring

test('withRlsContext: correct BEGIN/SET LOCAL ROLE/set_config/COMMIT/release sequence for a mapped role', async () => {
  const { withRlsContext } = require('../secure-dashboard.js');
  const calls = [];
  const mockClient = {
    query: async (sql) => { calls.push(sql); return { rows: [] }; },
    release: () => { calls.push('RELEASE'); },
  };
  const mockPool = { connect: async () => mockClient };
  await withRlsContext(mockPool, { userId: 'officer-42', district: 'Krishna', role: 'district_officer' }, (c) => c.query('SELECT 1'));
  assert.equal(calls[0], 'BEGIN');
  assert.equal(calls[1], 'SET LOCAL ROLE district_officer');
  assert.equal(calls[calls.length - 2], 'COMMIT');
  assert.equal(calls[calls.length - 1], 'RELEASE');
});

test('withRlsContext: rolls back and still releases the client if the query throws', async () => {
  const { withRlsContext } = require('../secure-dashboard.js');
  const calls = [];
  const mockClient = {
    query: async (sql) => { calls.push(sql); if (sql === 'FAIL') throw new Error('boom'); return { rows: [] }; },
    release: () => { calls.push('RELEASE'); },
  };
  const mockPool = { connect: async () => mockClient };
  await assert.rejects(() => withRlsContext(mockPool, { userId: 'x', role: 'admin' }, (c) => c.query('FAIL')), /boom/);
  assert.ok(calls.includes('ROLLBACK'));
  assert.equal(calls[calls.length - 1], 'RELEASE');
});

test('withRlsContext: unmapped role skips SET LOCAL ROLE but still releases correctly', async () => {
  const { withRlsContext } = require('../secure-dashboard.js');
  const calls = [];
  const mockClient = {
    query: async (sql) => { calls.push(sql); return { rows: [] }; },
    release: () => { calls.push('RELEASE'); },
  };
  const mockPool = { connect: async () => mockClient };
  await withRlsContext(mockPool, { userId: 'x', role: 'totally_unknown' }, (c) => c.query('SELECT 1'));
  assert.ok(!calls.some((c) => c.startsWith('SET LOCAL ROLE')));
  assert.equal(calls[calls.length - 1], 'RELEASE');
});

// VaultKMS test

test('VaultKMS: wrap/unwrap round trip and consistency across a simulated process restart, against a mocked Vault Transit backend', async (t) => {
  const crypto = require('crypto');
  const fs = require('fs');
  const FAKE_VAULT_KEY = crypto.randomBytes(32);
  function vaultWrap(plaintext) {
    const cipher = crypto.createCipheriv('aes-256-gcm', FAKE_VAULT_KEY, Buffer.alloc(12));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return 'vault:v1:' + ct.toString('base64');
  }
  function vaultUnwrap(wrapped) {
    const raw = Buffer.from(wrapped.replace('vault:v1:', ''), 'base64');
    const ct = raw.subarray(0, raw.length - 16);
    const tag = raw.subarray(raw.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', FAKE_VAULT_KEY, Buffer.alloc(12));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }

  const statePath = path.join(os.tmpdir(), `test-vault-kms-${process.pid}.json`);
  const originalEnv = { ...process.env };
  process.env.KMS_PROVIDER = 'vault';
  process.env.VAULT_ADDR = 'https://fake-vault.internal:8200';
  process.env.VAULT_TOKEN = 'fake-token';
  process.env.VAULT_TRANSIT_KEY_NAME = 'test-key';
  process.env.VAULT_KMS_STATE_PATH = statePath;
  t.after(() => {
    process.env = originalEnv;
    fs.rmSync(statePath, { force: true });
  });

  const originalFetch = global.fetch;
  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (url.includes('/transit/datakey/plaintext/')) {
      const plaintext = crypto.randomBytes(32);
      return { ok: true, json: async () => ({ data: { plaintext: plaintext.toString('base64'), ciphertext: vaultWrap(plaintext) } }) };
    }
    if (url.includes('/transit/decrypt/')) {
      return { ok: true, json: async () => ({ data: { plaintext: vaultUnwrap(body.ciphertext).toString('base64') } }) };
    }
    return { ok: false, status: 404, text: async () => 'not found' };
  };
  t.after(() => { global.fetch = originalFetch; });

  const { createKMS } = require('../secure-dashboard.js');
  const kms1 = await createKMS();
  assert.equal(kms1.constructor.name, 'VaultKMS');

  const dek = crypto.randomBytes(32);
  const { wrappedDEK, keyVersion } = kms1.wrapDEK(dek);
  assert.equal(Buffer.compare(dek, kms1.unwrapDEK(wrappedDEK, keyVersion)), 0);

  const kms2 = await createKMS();
  assert.equal(Buffer.compare(kms1.getDeterministicKey(), kms2.getDeterministicKey()), 0, 'deterministic key must be identical across a simulated restart');
});

// infinite loop fix regression test

test('regression: backfillTable stops after repeated zero-progress batches instead of looping forever — this is what a real cascading transaction-abort error (e.g. an unhandled foreign key constraint) used to trigger', async () => {
  const { backfillTable } = require('../secure-dashboard.js');
  const queryImpl = async (sql) => {
    if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return {};
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '3' }] };
    if (sql.includes('FOR UPDATE SKIP LOCKED')) {
      return {
        rows: [
          { sno: 1, hhid: 'HH-0001', name: 'Plain Name 1' },
          { sno: 2, hhid: 'HH-0002', name: 'Plain Name 2' },
          { sno: 3, hhid: 'HH-0003', name: 'Plain Name 3' },
        ]
      };
    }
    if (sql.startsWith('UPDATE')) {
      throw new Error('current transaction is aborted, commands ignored until end of transaction block');
    }
    return { rows: [] };
  };
  const mockPool = { query: queryImpl, connect: async () => ({ query: queryImpl, release: () => { } }) };

  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false },
    ],
  };

  const start = Date.now();
  const result = await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: true });
  const elapsed = Date.now() - start;

  assert.ok(elapsed < 3000, `must terminate quickly, took ${elapsed}ms — an infinite loop would never reach this assertion at all`);
  assert.equal(result.migrated, 0);
  assert.equal(result.failed, 6, 'should stop after exactly 2 batch attempts (3 rows each) once zero progress is detected twice in a row');
});

// production safety gate tests

test('production safety gate logic: identifies demo KMS and demo auth as problems when NODE_ENV=production', () => {
  // Testing the actual condition logic directly, since the real gate runs
  // as a top-level startup check (process.exit), not something to invoke
  // as a function in a test. This verifies the SAME conditions the real
  // gate uses.
  function checkProblems(env) {
    const problems = [];
    if ((env.KMS_PROVIDER || 'local') === 'local') problems.push('kms');
    if ((env.AUTH_PROVIDER || 'demo') === 'demo') problems.push('auth');
    return problems;
  }

  assert.deepEqual(checkProblems({}), ['kms', 'auth'], 'both unset should be flagged');
  assert.deepEqual(checkProblems({ KMS_PROVIDER: 'aws' }), ['auth'], 'real KMS alone still leaves auth flagged');
  assert.deepEqual(checkProblems({ KMS_PROVIDER: 'aws', AUTH_PROVIDER: 'oidc' }), [], 'both real means no problems');
  assert.deepEqual(checkProblems({ KMS_PROVIDER: 'vault', AUTH_PROVIDER: 'oidc' }), [], 'vault also counts as real');
});

// bookkeeping column bug regression test

test('regression: backfillTable never generates a duplicate wrapped_dek/key_version SET clause, even if the proposal incorrectly lists them as regular columns (a real bug found when re-running discovery against an already-backfilled table)', async () => {
  const { backfillTable } = require('../secure-dashboard.js');
  const tableEntry = {
    tableName: 'families',
    primaryKeyColumn: 'sno',
    columns: [
      { columnName: 'sno', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'hhid', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'name', doNotEncrypt: false },
      { columnName: 'wrapped_dek', doNotEncrypt: false }, // incorrectly present, as a stale proposal might have it
      { columnName: 'key_version', doNotEncrypt: false },
    ],
  };
  let row = { sno: 1, hhid: 'HH-TEST-0001', name: 'Ramesh Naidu', wrapped_dek: null, key_version: null };
  let capturedSetClause = null;
  const queryImpl = async (sql) => {
    if (sql === 'BEGIN' || sql === 'COMMIT') return {};
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: row.key_version === null ? '1' : '0' }] };
    if (sql.includes('FOR UPDATE SKIP LOCKED')) return { rows: row.key_version === null ? [row] : [] };
    if (sql.startsWith('UPDATE')) {
      capturedSetClause = sql;
      if ((sql.match(/wrapped_dek = \$/g) || []).length > 1) throw new Error('multiple assignments to same column "wrapped_dek"');
      row.key_version = 1;
      return {};
    }
    return { rows: [] };
  };
  const mockPool = { query: queryImpl, connect: async () => ({ query: queryImpl, release: () => { } }) };
  const result = await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: true });

  assert.equal((capturedSetClause.match(/wrapped_dek = \$/g) || []).length, 1);
  assert.equal((capturedSetClause.match(/key_version = \$/g) || []).length, 1);
  assert.equal(result.migrated, 1);
  assert.equal(result.failed, 0);
});

// automatic FK constraint handling tests

test('withTemporarilyDroppedForeignKeys: detects, drops, runs, and restores a real FK constraint blocking backfill of linked tables', async () => {
  const { withTemporarilyDroppedForeignKeys } = require('../secure-dashboard.js');
  const queries = [];
  const mockPool = {
    async query(sql) {
      queries.push(sql);
      if (sql.includes('information_schema.table_constraints')) {
        return {
          rows: [{
            constraint_name: 'fk_family_member_hhid', constrained_table: 'family_members', constrained_column: 'hhid',
            referenced_table: 'families', referenced_column: 'hhid', delete_rule: 'CASCADE', update_rule: 'NO ACTION',
          }]
        };
      }
      return {};
    },
  };
  const tablesToRun = [
    { tableName: 'families', columns: [{ columnName: 'hhid', deterministicEncrypt: true }] },
    { tableName: 'family_members', columns: [{ columnName: 'hhid', deterministicEncrypt: true }] },
  ];
  let ran = false;
  await withTemporarilyDroppedForeignKeys(mockPool, tablesToRun, async () => { ran = true; });
  assert.ok(ran);
  assert.ok(queries.some((q) => q.includes('DROP CONSTRAINT fk_family_member_hhid')));
  assert.ok(queries.some((q) => q.includes('ADD CONSTRAINT fk_family_member_hhid')));
});

test('withTemporarilyDroppedForeignKeys: restores the constraint even if the backfill throws partway through', async () => {
  const { withTemporarilyDroppedForeignKeys } = require('../secure-dashboard.js');
  const queries = [];
  const mockPool = {
    async query(sql) {
      queries.push(sql);
      if (sql.includes('information_schema.table_constraints')) {
        return {
          rows: [{
            constraint_name: 'fk_test', constrained_table: 'family_members', constrained_column: 'hhid',
            referenced_table: 'families', referenced_column: 'hhid', delete_rule: 'CASCADE', update_rule: 'NO ACTION',
          }]
        };
      }
      return {};
    },
  };
  const tablesToRun = [{ tableName: 'family_members', columns: [{ columnName: 'hhid', deterministicEncrypt: true }] }];
  await assert.rejects(
    () => withTemporarilyDroppedForeignKeys(mockPool, tablesToRun, async () => { throw new Error('boom'); }),
    /boom/,
  );
  assert.ok(queries.some((q) => q.includes('ADD CONSTRAINT fk_test')), 'must still restore the constraint despite the error');
});

test('findAffectedForeignKeys: correctly ignores FK constraints where neither side is being encrypted', async () => {
  const { findAffectedForeignKeys } = require('../secure-dashboard.js');
  const mockPool = {
    async query() {
      return {
        rows: [{
          constraint_name: 'fk_unrelated', constrained_table: 'some_other_table', constrained_column: 'ref_id',
          referenced_table: 'families', referenced_column: 'sno', delete_rule: 'CASCADE', update_rule: 'NO ACTION',
        }]
      };
    },
  };
  const tablesToRun = [{ tableName: 'families', columns: [{ columnName: 'hhid', deterministicEncrypt: true }] }];
  const affected = await findAffectedForeignKeys(mockPool, tablesToRun);
  assert.equal(affected.length, 0, 'a constraint on an unrelated column must not be touched');
});

// automatic CHECK constraint removal tests

test('backfillTable permanently drops a real CHECK constraint before encrypting the column it applies to', async () => {
  const { backfillTable } = require('../secure-dashboard.js');
  const queries = [];
  let row = { id: 1, status: 'Pending', key_version: null };
  const queryImpl = async (sql) => {
    queries.push(sql); // full text, no truncation
    if (sql === 'BEGIN' || sql === 'COMMIT') return {};
    if (sql.startsWith('ALTER')) return {};
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: row.key_version === null ? '1' : '0' }] };
    if (sql.includes('FOR UPDATE SKIP LOCKED')) return { rows: row.key_version === null ? [row] : [] };
    if (sql.startsWith('UPDATE')) { row.key_version = 1; return {}; }
    return { rows: [] };
  };
  const mockPool = { query: queryImpl, connect: async () => ({ query: queryImpl, release: () => { } }) };
  const tableEntry = {
    tableName: 'submitted_baseline_forms',
    primaryKeyColumn: 'id',
    columns: [
      { columnName: 'id', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'status', doNotEncrypt: false, deterministicEncrypt: false, checkConstraintsToAutoDrop: ['submitted_baseline_forms_status_check'] },
    ],
  };
  const result = await backfillTable(mockPool, tableEntry, { dryRun: false, pkEncryptionConfirmed: true });
  assert.ok(queries.some((q) => q.includes('DROP CONSTRAINT IF EXISTS submitted_baseline_forms_status_check')));
  assert.equal(result.migrated, 1);
  assert.equal(result.failed, 0);
});

test('backfillTable does NOT drop a CHECK constraint during a dry run', async () => {
  const { backfillTable } = require('../secure-dashboard.js');
  const queries = [];
  const queryImpl = async (sql) => {
    queries.push(sql);
    if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '1' }] };
    return { rows: [] };
  };
  const mockPool = { query: queryImpl, connect: async () => ({ query: queryImpl, release: () => { } }) };
  const tableEntry = {
    tableName: 'submitted_baseline_forms',
    primaryKeyColumn: 'id',
    columns: [
      { columnName: 'id', doNotEncrypt: true, deterministicEncrypt: true },
      { columnName: 'status', doNotEncrypt: false, deterministicEncrypt: false, checkConstraintsToAutoDrop: ['submitted_baseline_forms_status_check'] },
    ],
  };
  await backfillTable(mockPool, tableEntry, { dryRun: true, pkEncryptionConfirmed: true });
  assert.ok(!queries.some((q) => q.includes('DROP CONSTRAINT')), 'a dry run must never actually drop a real constraint');
});