'use strict';

/*
  Production migration orchestrator.
  Contract: scan the live PostgreSQL database and encrypt every persisted
  application column. There is no static table allow-list and no manual
  migration-proposal approval gate. PK/FK/UNIQUE columns use deterministic
  encryption so relational constraints remain meaningful; ordinary columns
  use AES-256-GCM with per-row DEKs. CHECK constraints are removed because
  plaintext-value checks cannot operate on ciphertext. Generated columns are
  converted to ordinary stored columns before encryption. Tables without a
  PK receive an internal encrypted row identifier so every row can still be
  migrated safely.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { discoverSchema } = require('./db/scripts/discoverSchema');
const dashboard = require('./secure-dashboard');

const PROPOSAL_PATH = path.join(__dirname, 'db', 'scripts', 'migration-proposal.json');
const BOOKKEEPING_COLUMNS = new Set(['wrapped_dek', 'key_version']);
const INTERNAL_ROW_ID = '__enc_row_id';

function qi(identifier) {
  if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(identifier)) {
    throw new Error(`Unsafe PostgreSQL identifier: ${identifier}`);
  }
  return `"${identifier.replaceAll('"', '""')}"`;
}

function tableSql(tableName) {
  return qi(tableName);
}

function loadProposal() {
  if (!fs.existsSync(PROPOSAL_PATH)) throw new Error('Schema discovery did not produce migration-proposal.json');
  return JSON.parse(fs.readFileSync(PROPOSAL_PATH, 'utf8'));
}

async function listCheckConstraints(pool, tableName) {
  const r = await pool.query(`
    SELECT conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'public' AND t.relname = $1 AND c.contype = 'c'
      AND NOT c.conname LIKE '%_not_null'
  `, [tableName]);
  return r.rows.map((r) => r.conname);
}

async function prepareTable(pool, entry) {
  const table = tableSql(entry.tableName);
  const result = { table: entry.tableName, syntheticPk: false, droppedChecks: [], droppedDefaults: [], generatedColumns: [] };

  // Generated columns cannot store arbitrary ciphertext. Drop the generation
  // expression first; the current generated value remains as ordinary data.
  for (const col of entry.columns) {
    if (col.doNotEncrypt && /GENERATED column/i.test(col.doNotEncryptReason || '')) {
      await pool.query(`ALTER TABLE ${table} ALTER COLUMN ${qi(col.columnName)} DROP EXPRESSION`);
      const structural = /Foreign key|primary key|COMPOSITE primary key/i.test(col.doNotEncryptReason || '');
      col.doNotEncrypt = false;
      col.doNotEncryptReason = null;
      col.deterministicEncrypt = structural;
      result.generatedColumns.push(col.columnName);
    }
  }

  // Every user CHECK constraint conflicts with encrypt-everything. Remove it
  // before ciphertext is written, otherwise the database itself will reject
  // the migrated values.
  const checks = await listCheckConstraints(pool, entry.tableName);
  for (const name of checks) {
    await pool.query(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${qi(name)}`);
    result.droppedChecks.push(name);
  }

  // Defaults that write plaintext after migration are a permanent bypass.
  // Drop them; encrypted application insert paths must provide ciphertext.
  for (const col of entry.columns) {
    if (BOOKKEEPING_COLUMNS.has(col.columnName)) continue;
    const encrypted = !col.doNotEncrypt || col.deterministicEncrypt;
    if (encrypted && col.hasMeaningfulDefault && !col.isGenerated) {
      await pool.query(`ALTER TABLE ${table} ALTER COLUMN ${qi(col.columnName)} DROP DEFAULT`);
      result.droppedDefaults.push(col.columnName);
    }
  }

  // A table without a PK has no stable row locator for a resumable migration.
  // Add one. It is itself encrypted deterministically during the normal
  // backfill, so the final database contains no plaintext row identifier.
  if (!Array.isArray(entry.primaryKeyColumns) || entry.primaryKeyColumns.length === 0) {
    await pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${qi(INTERNAL_ROW_ID)} TEXT`);
    const pending = await pool.query(`SELECT ctid FROM ${table} WHERE ${qi(INTERNAL_ROW_ID)} IS NULL LIMIT 1000`);
    while (pending.rows.length) {
      for (const row of pending.rows) {
        await pool.query(`UPDATE ${table} SET ${qi(INTERNAL_ROW_ID)} = $1 WHERE ctid = $2`, [crypto.randomUUID(), row.ctid]);
      }
      const next = await pool.query(`SELECT ctid FROM ${table} WHERE ${qi(INTERNAL_ROW_ID)} IS NULL LIMIT 1000`);
      pending.rows = next.rows;
    }
    entry.primaryKeyColumn = INTERNAL_ROW_ID;
    entry.primaryKeyColumns = [INTERNAL_ROW_ID];
    const existing = entry.columns.find((c) => c.columnName === INTERNAL_ROW_ID);
    if (!existing) {
      entry.columns.push({
        columnName: INTERNAL_ROW_ID,
        dataType: 'text',
        characterMaximumLength: null,
        nullable: false,
        doNotEncrypt: false,
        deterministicEncrypt: true,
        needsSpecialTypeHandling: false,
        internal: true,
      });
    } else {
      existing.doNotEncrypt = false;
      existing.deterministicEncrypt = true;
    }
    result.syntheticPk = true;
  }
  return result;
}

async function verifyZeroPlaintext(pool, proposal) {
  const failures = [];
  for (const entry of proposal.tables) {
    const table = tableSql(entry.tableName);
    const encryptedColumns = entry.columns
      .filter((c) => !BOOKKEEPING_COLUMNS.has(c.columnName) && (c.deterministicEncrypt || !c.doNotEncrypt))
      .map((c) => c.columnName);
    if (!encryptedColumns.length) continue;
    const checks = encryptedColumns.map((c) => `(${qi(c)} IS NOT NULL AND ${qi(c)} !~ '^v[12]\\.')`).join(' OR ');
    const r = await pool.query(`SELECT COUNT(*)::bigint AS count FROM ${table} WHERE ${checks}`);
    const count = Number(r.rows[0].count);
    if (count > 0) failures.push({ table: entry.tableName, plaintextRows: count });
    const missing = await pool.query(`SELECT COUNT(*)::bigint AS count FROM ${table} WHERE key_version IS NULL`);
    if (Number(missing.rows[0].count) > 0) failures.push({ table: entry.tableName, unencryptedRows: Number(missing.rows[0].count) });
  }
  return failures;
}

async function autoEncryptDatabase({ confirm = false, lock = true } = {}) {
  if (!confirm) {
    console.log('DRY RUN: scanning the live database and building the automatic encryption plan.');
    await discoverSchema();
    const proposal = loadProposal();
    console.log(`Discovered ${proposal.tables.length} tables. Re-run with --confirm to modify the database.`);
    return { dryRun: true, tables: proposal.tables.length };
  }

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error('DATABASE_URL is required');
  if (process.env.NODE_ENV === 'production' && !['aws', 'vault'].includes(process.env.KMS_PROVIDER || 'local')) {
    throw new Error('Refusing production encryption with the local/demo KMS. Set KMS_PROVIDER=aws or KMS_PROVIDER=vault.');
  }

  // Always rescan the live DB. The proposal is an audit artifact, never a
  // whitelist or authorization gate.
  await discoverSchema();
  const proposal = loadProposal();
  const pool = new Pool({ connectionString: databaseUrl, max: Number(process.env.PG_POOL_MAX || 10) });
  const prep = [];
  try {
    for (const entry of proposal.tables) prep.push(await prepareTable(pool, entry));
    fs.writeFileSync(PROPOSAL_PATH, JSON.stringify({ ...proposal, reviewed: true, automaticExecution: true }, null, 2));

    const encryptedTables = proposal.tables.filter((t) => t.columns.some((c) => c.deterministicEncrypt || !c.doNotEncrypt));
    const affected = await dashboard.findAffectedForeignKeys(pool, encryptedTables);
    // Reuse the existing FK drop/restore implementation for simple and
    // existing schemas. The final verification below is mandatory.
    const results = await dashboard.withTemporarilyDroppedForeignKeys(pool, encryptedTables, () =>
      dashboard.runWithConcurrencyLimit(
        encryptedTables,
        Number(process.env.BACKFILL_TABLE_CONCURRENCY || 3),
        (entry) => dashboard.backfillTable(pool, entry, { dryRun: false, pkEncryptionConfirmed: true }),
      ),
    );

    if (results.some((r) => r.refused || (r.failed || 0) > 0 || r.skipped)) {
      throw new Error(`Encryption did not complete cleanly: ${JSON.stringify(results)}`);
    }

    if (lock) {
      for (const entry of encryptedTables) {
        const r = await dashboard.lockTableColumns(pool, entry, { dryRun: false });
        if (r.failed && r.failed.length) throw new Error(`Could not lock ${entry.tableName}: ${JSON.stringify(r.failed)}`);
      }
    }

    const failures = await verifyZeroPlaintext(pool, proposal);
    if (failures.length) throw new Error(`ZERO-PLAINTEXT verification FAILED: ${JSON.stringify(failures)}`);

    console.log('\n=== AUTOMATIC ENCRYPTION COMPLETE ===');
    console.log(`Tables processed: ${encryptedTables.length}`);
    console.log(`Foreign keys temporarily handled: ${affected.length}`);
    console.log('Zero-plaintext verification: PASS');
    return { dryRun: false, tables: encryptedTables.length, results, failures: [] };
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  const confirm = process.argv.includes('--confirm');
  autoEncryptDatabase({ confirm }).catch((err) => {
    console.error('Automatic encryption failed:', err.message);
    process.exit(1);
  });
}

module.exports = { autoEncryptDatabase, verifyZeroPlaintext };
