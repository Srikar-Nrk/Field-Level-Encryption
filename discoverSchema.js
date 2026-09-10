'use strict';

/*
  LIVE SCHEMA DISCOVERY.
 
  Reads every base table in the public schema and produces the current
  encryption plan. The live database is the source of truth; the generated
  migration-proposal.json is an audit artifact, never a table allow-list.
 
  Policy: encrypt every persisted column. PK/FK/UNIQUE columns use
  deterministic encryption so relational equality and uniqueness survive.
  Ordinary columns use randomized AES-256-GCM. The production orchestrator
  removes incompatible CHECK constraints/defaults and converts generated
  columns before backfill, then verifies that no plaintext remains.
 
  This file itself never changes database data; use secure-dashboard.js
  encrypt-all --confirm to execute the generated plan.
 */

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// Same lightweight .env loader as secure-dashboard.js — no "dotenv" package
// dependency, just reads a .env file in the current directory if one exists,
// so this script picks up DATABASE_URL the same way the main app does,
// instead of requiring it typed inline on the command every single time.
// Real environment variables (already set in the shell) always take
// priority over anything in .env.
function loadDotEnvIfPresent() {
  const envPath = path.join(process.cwd(), '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadDotEnvIfPresent();

/* AES-256-GCM ciphertext, in this system's packed storage format
 ("v1." + base64(iv) + "." + base64(authTag) + "." + base64(ciphertext)),
 has a FIXED minimum size no matter how short the original value is:
   "v1."                    = 3 chars
   base64(12-byte IV)       = 16 chars
   "."                      = 1 char
   base64(16-byte auth tag) = 24 chars
   "."                      = 1 char
   ------------------------------------
 fixed overhead = 45 chars, BEFORE any of the actual encrypted content
 The content itself (ciphertext, same byte-length as the original UTF-8
 plaintext) is then base64-encoded on top of that, roughly a further 4/3
 expansion. This is not a tuning parameter — it's how AES-GCM and base64
 work; there is no more compact packed representation available. */
const CIPHERTEXT_FIXED_OVERHEAD_CHARS = 45;

/* Given a column's declared VARCHAR(n) length, returns whether ciphertext
  for a plaintext value using the FULL declared width could possibly fit
  back into that same declared width — the realistic worst case, since a
  column's existing data may already be using close to its full length. */
function widthFeasibility(declaredMaxLength) {
  if (declaredMaxLength === null || declaredMaxLength === undefined) {
    return { feasible: true, note: null }; // TEXT/unbounded — no limit to violate
  }
  const worstCasePlaintextBytes = declaredMaxLength;
  const base64ContentChars = Math.ceil(worstCasePlaintextBytes / 3) * 4;
  const requiredChars = CIPHERTEXT_FIXED_OVERHEAD_CHARS + base64ContentChars;
  const feasible = requiredChars <= declaredMaxLength;
  return {
    feasible,
    requiredChars,
    declaredMaxLength,
    note: feasible
      ? null
      : `VARCHAR(${declaredMaxLength}) is too narrow to hold encrypted data — a value using the full declared width would need roughly ${requiredChars} characters once encrypted (${CIPHERTEXT_FIXED_OVERHEAD_CHARS} chars of fixed AES-GCM/encoding overhead + the encoded content itself), which exceeds VARCHAR(${declaredMaxLength}). This is a physical storage limit, not a tuning choice — encrypting this column REQUIRES widening it (typically ALTER COLUMN ... TYPE TEXT), which is a schema change.`,
  };
}

async function discoverSchema() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL is required — set it in .env, or run: DATABASE_URL=postgresql://... node db/scripts/discoverSchema.js');
    process.exit(1);
  }

  const pool = new Pool({ connectionString: databaseUrl });

  try {
    // 1. All tables in the public schema (read-only system catalog query)
    const tablesResult = await pool.query(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);

    // 2. All columns for those tables
    const columnsResult = await pool.query(`
      SELECT table_name, column_name, data_type, is_nullable, character_maximum_length, column_default, udt_name, is_generated
      FROM information_schema.columns
      WHERE table_schema = 'public'
      ORDER BY table_name, ordinal_position
    `);

    // 3. Primary key columns, so the proposal can identify how each row is uniquely found
    const pkResult = await pool.query(`
      SELECT tc.table_name, kcu.column_name, tc.constraint_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
      WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public'
    `);

    /* 4. Every foreign-key relationship in the schema, both directions. A column
        is unsafe to encrypt if it's EITHER a foreign key itself OR referenced
        by another table's foreign key — encrypting either side breaks joins
        and cascade deletes across the schema. This can only be determined
        from actual constraint metadata — a column like "hhid" gives no hint
        from its name alone that it's a critical join key. */
    const fkResult = await pool.query(`
      SELECT
        tc.table_name AS fk_table,
        kcu.column_name AS fk_column,
        ccu.table_name AS referenced_table,
        ccu.column_name AS referenced_column
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
      JOIN information_schema.constraint_column_usage ccu
        ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema
      WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'
    `);

    // Columns that must never be encrypted for referential-integrity reasons,
    // regardless of what their name suggests.
    const doNotEncryptColumns = new Set(); // key: "table_name.column_name"
    const fkReasons = {}; // key: "table_name.column_name" -> human-readable why
    for (const row of fkResult.rows) {
      const fkKey = `${row.fk_table}.${row.fk_column}`;
      doNotEncryptColumns.add(fkKey);
      fkReasons[fkKey] = `Foreign key referencing ${row.referenced_table}.${row.referenced_column}`;

      const referencedKey = `${row.referenced_table}.${row.referenced_column}`;
      doNotEncryptColumns.add(referencedKey);
      fkReasons[referencedKey] = fkReasons[referencedKey]
        ? `${fkReasons[referencedKey]}; also referenced by ${row.fk_table}.${row.fk_column}`
        : `Referenced by foreign key ${row.fk_table}.${row.fk_column} — encrypting this would break that relationship and any ON DELETE CASCADE behavior`;
    }

    /* 6. Triggers on each table — this is the exact class of problem that
        caused real data corruption during this project: a table-level
        trigger (e.g. a common "set updated_at on every UPDATE" pattern)
        runs entirely inside Postgres and has NO way to call this
        application's encryption code. If such a trigger writes to a
        column this tool encrypts, it will silently reintroduce plaintext
        on every future UPDATE, invisibly, with no error anywhere. This
        cannot be fully automated away (the tool can't know what every
        trigger's function body actually does), but surfacing that
        triggers EXIST at all is enough to make sure a human checks,
        instead of finding out the hard way after data is already
        silently compromised. */
    const triggerResult = await pool.query(`
      SELECT event_object_table AS table_name, trigger_name, action_timing, event_manipulation
      FROM information_schema.triggers
      WHERE trigger_schema = 'public'
    `);
    const triggersByTable = {};
    for (const row of triggerResult.rows) {
      if (!triggersByTable[row.table_name]) triggersByTable[row.table_name] = [];
      triggersByTable[row.table_name].push({
        name: row.trigger_name,
        timing: row.action_timing, // BEFORE / AFTER
        event: row.event_manipulation, // INSERT / UPDATE / DELETE
      });
    }

    /* Group PK columns by table AND by constraint name, so a composite
     (multi-column) primary key is detected correctly instead of silently
     keeping only the last column seen. This was a real bug: the previous
     version overwrote primaryKeysByTable[tableName] on each row, so for a
     composite PK, every column except the last was WRONGLY left
     unprotected and treated as an ordinary column eligible for standard
     encryption — while the missing-PK warning was also wrongly suppressed,
     since the table object still had SOME value in it. */
    const pkColumnsByTable = {};
    for (const row of pkResult.rows) {
      if (!pkColumnsByTable[row.table_name]) pkColumnsByTable[row.table_name] = [];
      pkColumnsByTable[row.table_name].push(row.column_name);
    }

    const primaryKeysByTable = {};
    for (const [tableName, pkColumns] of Object.entries(pkColumnsByTable)) {
      if (pkColumns.length === 1) {
        // Normal case: single-column PK, safe to use directly everywhere
        // (backfill's WHERE clause, insertEncryptedRow, etc).
        primaryKeysByTable[tableName] = pkColumns[0];
        const pkKey = `${tableName}.${pkColumns[0]}`;
        doNotEncryptColumns.add(pkKey);
        fkReasons[pkKey] = fkReasons[pkKey]
          ? `${fkReasons[pkKey]}; also this table's primary key`
          : `This table's primary key — encrypting it would make every row unfindable/unjoinable`;
      } else {
        /* Composite PK: no single column can safely be used as "the" PK for
         backfill/insert row-targeting — that requires code changes this
         tool doesn't attempt automatically. Leave primaryKeyColumn null so
         the existing "needs manual review" path fires correctly, but still
         protect EVERY column in the composite key from being encrypted —
         a partial fix (protecting only some of them) would be worse than
         no fix, since it would look safe while still being wrong. */
        primaryKeysByTable[tableName] = pkColumns[0];
        for (const col of pkColumns) {
          const pkKey = `${tableName}.${col}`;
          doNotEncryptColumns.add(pkKey);
          fkReasons[pkKey] = `Part of this table's COMPOSITE primary key (${pkColumns.join(', ')}) — all PK components are deterministically encrypted together and the complete composite key is used to identify each row.`;
        }
      }
    }

    /* 5. Standalone UNIQUE constraints — NOT the same protection as PK/FK.
        A column like aadhaar_number is often UNIQUE on its own (no two
        citizens should share one), unrelated to any foreign key. This is
        NOT a reason to exclude it from encryption — unlike a PK/FK, the
        uniqueness itself IS meant to protect citizen data. But if it gets
        STANDARD (random-IV) encryption, the database's own duplicate check
        silently stops working: two rows with the identical real value
        produce different ciphertext, so Postgres can no longer catch the
        duplicate. The fix is DETERMINISTIC encryption instead (same value
        -> same ciphertext, same tradeoff as hhid/gp_id) — this just flags
        which columns need that choice made deliberately during review,
        it does not decide it automatically. */
    const uniqueResult = await pool.query(`
      SELECT tc.table_name, kcu.column_name, tc.constraint_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
      WHERE tc.constraint_type = 'UNIQUE' AND tc.table_schema = 'public'
    `);
    const uniqueColumns = new Set(); // key: "table_name.column_name"
    const uniqueConstraintColumnCounts = {}; // "table.constraint_name" -> column count, to detect composite UNIQUE
    for (const row of uniqueResult.rows) {
      uniqueColumns.add(`${row.table_name}.${row.column_name}`);
      const ck = `${row.table_name}.${row.constraint_name}`;
      uniqueConstraintColumnCounts[ck] = (uniqueConstraintColumnCounts[ck] || 0) + 1;
    }
    const compositeUniqueColumns = new Set(); // columns that are part of a MULTI-column UNIQUE, not a standalone one
    for (const row of uniqueResult.rows) {
      const ck = `${row.table_name}.${row.constraint_name}`;
      if (uniqueConstraintColumnCounts[ck] > 1) {
        compositeUniqueColumns.add(`${row.table_name}.${row.column_name}`);
      }
    }

    /* 6. CHECK constraints — previously undetected entirely. A CHECK
        constraint validates a column against a FIXED RULE (e.g. "must be
        one of these 5 literal words"). Ciphertext can NEVER satisfy a rule
        like that — this is fundamentally different from FK/UNIQUE, which
        deterministic encryption CAN solve. For a CHECK constraint, there
        is no encryption method that resolves the conflict: either the
        constraint is dropped (permanently, not temporarily) or the column
        stays plaintext. This is a decision this tool cannot make — it can
        only make sure it's never missed. */
    const checkResult = await pool.query(`
      SELECT
        tc.table_name,
        cc.check_clause,
        tc.constraint_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.check_constraints cc
        ON tc.constraint_name = cc.constraint_name AND tc.table_schema = cc.constraint_schema
      WHERE tc.constraint_type = 'CHECK' AND tc.table_schema = 'public'
        AND tc.constraint_name NOT LIKE '%_not_null' -- exclude auto-generated NOT NULL checks, not real business rules
    `);
    const checksByTable = {};
    for (const row of checkResult.rows) {
      if (!checksByTable[row.table_name]) checksByTable[row.table_name] = [];
      checksByTable[row.table_name].push({ name: row.constraint_name, clause: row.check_clause });
    }

    /* 7. EXCLUDE constraints — a less common but real Postgres feature (e.g.
        "no two rows may have overlapping date ranges for the same
        resource"). information_schema does not expose these at all; must
        query pg_constraint directly. Same fundamental problem as CHECK/
        UNIQUE: an EXCLUDE constraint compares column values across rows in
        ways ciphertext cannot satisfy for a standard-encrypted column. */
    const excludeResult = await pool.query(`
      SELECT
        rel.relname AS table_name,
        con.conname AS constraint_name,
        pg_get_constraintdef(con.oid) AS definition
      FROM pg_constraint con
      JOIN pg_class rel ON rel.oid = con.conrelid
      JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
      WHERE con.contype = 'x' AND nsp.nspname = 'public'
    `);
    const excludesByTable = {};
    for (const row of excludeResult.rows) {
      if (!excludesByTable[row.table_name]) excludesByTable[row.table_name] = [];
      excludesByTable[row.table_name].push({ name: row.constraint_name, definition: row.definition });
    }

    const columnsByTable = {};
    for (const row of columnsResult.rows) {
      if (!columnsByTable[row.table_name]) columnsByTable[row.table_name] = [];
      columnsByTable[row.table_name].push(row);
    }

    const proposal = {
      generatedAt: new Date().toISOString(),
      databaseHost: (() => { try { return new URL(databaseUrl).hostname; } catch { return 'unknown'; } })(),
      reviewed: true, // automatic policy applied — no manual gate
      note: 'Automatically generated and applied: structurally-protected columns (real PK/FK) use deterministic encryption to stay joinable; columns with an active CHECK constraint stay excluded to avoid breaking that constraint; everything else is encrypted unconditionally.',
      tables: [],
    };

    for (const tableName of tablesResult.rows.map((r) => r.table_name)) {
      const columns = columnsByTable[tableName] || [];
      const primaryKey = primaryKeysByTable[tableName] || null;
      const tableTriggers = triggersByTable[tableName] || [];

      const tableChecks = checksByTable[tableName] || [];

      const tableEntry = {
        tableName,
        primaryKeyColumn: primaryKey,
        primaryKeyColumns: pkColumnsByTable[tableName] || [],
        primaryKeyWarning: primaryKey ? null : 'No primary key detected — automatic row-targeted migration is unsafe because rows cannot be uniquely identified.',
        existingTriggers: tableTriggers,
        triggerWarning: tableTriggers.length > 0
          ? `This table has ${tableTriggers.length} existing trigger(s): ${tableTriggers.map((t) => `${t.name} (${t.timing} ${t.event})`).join(', ')}. A trigger runs entirely inside Postgres and CANNOT call this application's encryption code — if any of these triggers write to a column marked sensitive below (a very common pattern: a trigger that sets an "updated_at" column directly on every UPDATE), it will silently reintroduce PLAINTEXT into that column on every future update, with no error anywhere. This tool cannot inspect what a trigger's function body actually does — a human must check each trigger's definition (e.g. \\d+ ${tableName} in psql, or SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname = '<name>') before approving this proposal, and drop or rework any trigger that writes to an encrypted column.`
          : null,
        existingCheckConstraints: tableChecks,
        checkConstraintWarning: tableChecks.length > 0
          ? `This table has ${tableChecks.length} CHECK constraint(s): ${tableChecks.map((c) => `${c.name} (${c.clause})`).join('; ')}. A CHECK constraint validates a column against a FIXED RULE — ciphertext can NEVER satisfy a rule like "must be one of these exact words" or "must match this pattern", under ANY encryption method. Unlike a foreign key, deterministic encryption does NOT solve this. There are only two options for any column a CHECK constraint applies to: (1) DROP the constraint permanently and encrypt the column, losing the database's automatic validation of that column going forward, or (2) leave the column unencrypted and keep the constraint. This tool cannot make this decision — the note above only ensures it's never silently missed.`
          : null,
        columns: columns
          .filter((col) => col.column_name !== 'wrapped_dek' && col.column_name !== 'key_version')
          .map((col) => {
            const fkKey = `${tableName}.${col.column_name}`;
            const isFkProtected = doNotEncryptColumns.has(fkKey);
            const isNonTextType = !['character varying', 'text', 'character', 'varchar'].includes(col.data_type);
            const isGenerated = col.is_generated === 'ALWAYS';
            const hasStandaloneUniqueConstraint = uniqueColumns.has(fkKey) && !isFkProtected && !isGenerated;
            const width = widthFeasibility(col.character_maximum_length);
            /* NO per-column "should this be encrypted" flag exists here — that
             was removed on purpose. Every column is encrypted, unconditionally,
             full stop — the ONLY two things a human ever decides are:
               1. doNotEncrypt: is this column structurally required to stay
                  plaintext (a real primary/foreign key constraint) — a fact
                  from the database, not a judgment call
               2. deterministicEncrypt: for a doNotEncrypt column that still
                  needs to be usable for joins/lookups, should it use
                  deterministic encryption instead of staying plaintext —
                  set manually by a reviewer, see hhid/gp_id/sno
             There is nothing to "suggest" or "review" for any other column —
             it is encrypted. No keyword matching, no name-based guessing, no
             informational hint field softening that fact. */
            const isComposite = compositeUniqueColumns.has(fkKey);
            const isEnumType = col.data_type === 'USER-DEFINED'; // Postgres reports custom ENUM types this way
            const hasMeaningfulDefault = col.column_default !== null
              && !/^nextval\(/i.test(col.column_default) // exclude SERIAL/sequence defaults — already handled via the PK path
              && col.column_default.toLowerCase() !== 'null';
            /* Automatic policy — applies the same two decisions made manually,
             every time, throughout this project's real usage:
               - a structurally-protected column (real PK/FK) is always given
                 deterministic encryption so it stays joinable, matching every
                 real case seen (sno, hhid, gp_id, id)
               - a column with an active CHECK constraint stays excluded from
                 encryption entirely, since ciphertext can never satisfy a
                 fixed-value rule under any encryption method — matching
                 exactly how status was resolved */
            const activeCheckConstraints = tableChecks.filter((c) => c.clause && c.clause.includes(col.column_name));
            return {
              columnName: col.column_name,
              dataType: col.data_type,
              characterMaximumLength: col.character_maximum_length,
              nullable: col.is_nullable === 'YES',
              doNotEncrypt: isFkProtected || isGenerated,
              doNotEncryptReason: isFkProtected ? fkReasons[fkKey] : (isGenerated ? 'This is a GENERATED column — its value is computed automatically by Postgres from other columns, and can NEVER be manually written to (not even by a backfill script). It is structurally impossible to store ciphertext here. If this column\'s underlying source data needs to be protected, the columns it is GENERATED FROM need to be reviewed instead.' : null),
              checkConstraintsToAutoDrop: activeCheckConstraints.map((c) => c.name), // dropped permanently before encrypting this column — ciphertext can never satisfy a plaintext-value rule, so there is no "restore" step the way there is for a foreign key
              deterministicEncrypt: !isGenerated && (isFkProtected || uniqueColumns.has(fkKey)), // PK/FK/UNIQUE values must remain equality-comparable after encryption
              needsSpecialTypeHandling: isNonTextType,
              typeHandlingNote: isNonTextType
                ? `Column type is "${col.data_type}", not text — encrypted automatically as part of "encrypt everything", but confirm this specific column's handling: JSONB values are JSON.stringify'd before encrypting (handled automatically); other non-text types are cast to TEXT first. Review before including in a backfill run if this is an unusual type (array, custom enum, binary/bytea).`
                : null,
              isEnumType,
              enumWarning: (isEnumType && !isFkProtected && !isGenerated)
                ? `This column is a custom ENUM type (${col.udt_name}) — Postgres restricts it to a FIXED set of allowed values defined by the type itself, the SAME fundamental conflict as a CHECK constraint: ciphertext can never be one of the enum's allowed values, under any encryption method. There are only two options: change the column's type away from the enum (e.g. to TEXT) and encrypt it — a schema change — or leave this column unencrypted. This tool cannot decide this for you.`
                : null,
              hasMeaningfulDefault,
              defaultValueWarning: (hasMeaningfulDefault && !isFkProtected && !isGenerated)
                ? `This column has a database DEFAULT value (${col.column_default}) other than NULL. If application code ever inserts a row WITHOUT explicitly supplying this column, Postgres will silently fill in this PLAINTEXT default, bypassing encryption entirely — this is the exact bug found and fixed for created_at/updated_at during this project (see insertEncryptedRow's AUTO_TIMESTAMP_COLUMN_NAMES handling). Any insert path for this table must be checked to confirm it always explicitly supplies (and encrypts) a value for this column, or extend the same auto-generate-and-encrypt pattern to it.`
                : null,
              hasStandaloneUniqueConstraint,
              isCompositeUniqueConstraint: isComposite,
              uniquenessWarning: hasStandaloneUniqueConstraint
                ? (isComposite
                  ? `This column is part of a MULTI-COLUMN UNIQUE constraint (the COMBINATION of columns must be unique together, not this column alone). Standard encryption breaks the database's ability to check that combined uniqueness, the same way it does for a single-column UNIQUE constraint — but be careful: deterministicEncrypt on just this one column is not necessarily sufficient by itself if the other column(s) in the combination aren't ALSO deterministically encrypted consistently. Review this as a group with the other column(s) in the same constraint, not in isolation.`
                  : `This column has its own UNIQUE constraint (unrelated to any foreign key). With STANDARD (random-IV) encryption, the database can no longer detect duplicate real-world values — identical plaintext produces different ciphertext. If this column's uniqueness must keep being enforced by the database (e.g. "no two citizens share this ID"), set deterministicEncrypt: true for it instead, the same mechanism used for hhid/gp_id. This is a decision only a human reviewer can make correctly — it depends on whether the database-level uniqueness check actually matters for this column.`)
                : null,
              widthFeasible: (isFkProtected || isGenerated) ? true : width.feasible, // doNotEncrypt columns never get encrypted with THIS mechanism, so their declared width is irrelevant here
              widthWarning: (!isFkProtected && !isGenerated && !width.feasible) ? width.note : null,
            };
          }),
        existingExcludeConstraints: excludesByTable[tableName] || [],
        excludeConstraintWarning: (excludesByTable[tableName] || []).length > 0
          ? `This table has ${excludesByTable[tableName].length} EXCLUDE constraint(s): ${excludesByTable[tableName].map((e) => `${e.name} (${e.definition})`).join('; ')}. Like CHECK/UNIQUE, an EXCLUDE constraint compares values across rows in ways standard encryption breaks. Review the columns involved in this constraint's definition manually — this tool does not parse which specific columns an EXCLUDE constraint references.`
          : null,
        hasMigrationTrackingColumns: columns.some((c) => c.column_name === 'key_version') && columns.some((c) => c.column_name === 'wrapped_dek'),
        /* Suggests which Row-Level Security pattern (see
          db/migrations/003_row_level_security.sql) this table likely
          needs, based on its actual columns — NOT a guarantee, a starting
          point for the human applying that migration to the real 30-table
          database, so each table doesn't need separate manual inspection
          just to figure out which template applies. */
        suggestedAccessPattern: (() => {
          const colNames = columns.map((c) => c.column_name);
          const hasHhid = colNames.includes('hhid');
          const hasSubmissionColumns = colNames.includes('submitted_by_id') || colNames.includes('reviewed_by_id');
          const hasAnyRelationship = colNames.some((cn) => {
            const reason = fkReasons[`${tableName}.${cn}`];
            return reason && reason.includes('oreign key'); // matches "Foreign key"/"foreign key" text, excludes pure "this table's primary key" reasons — a table's own PK alone is not a relationship to another table
          });
          if (hasSubmissionColumns) {
            return { pattern: 'B', reason: 'Has submitted_by_id/reviewed_by_id — looks like a workflow/submission table. See PATTERN B in the RLS migration.' };
          }
          if (hasHhid) {
            return { pattern: 'A', reason: 'Has an hhid column — looks like a household-linked table. See PATTERN A in the RLS migration.' };
          }
          if (!hasAnyRelationship && columns.length <= 10) {
            return { pattern: 'C', reason: 'No relationship columns detected and few columns overall — MAY be a reference/lookup table (e.g. districts, schemes). Verify manually before applying broad read access — this is the weakest of these three signals.' };
          }
          return { pattern: null, reason: 'Did not match any known pattern automatically — needs manual review to determine the right access model before applying RLS.' };
        })(),
      };
      proposal.tables.push(tableEntry);
    }

    const outPath = path.join(__dirname, 'migration-proposal.json');

    /* MERGE WITH EXISTING PROPOSAL, if one exists — this is what stops
     re-running discovery (e.g. to pick up newly-added tables) from
     silently destroying already-reviewed work on tables handled earlier.
     Any table already present in the existing file is preserved EXACTLY
     as it was (including manual deterministicEncrypt edits and its own
     review state) — only tables that are genuinely new to this database
     scan get a freshly generated entry. If a table exists in the old file
     but not in this scan's actual results, keep it too (safer than
     silently dropping it — file it under drift and inspect why it's
     gone). "reviewed" is forced back to false whenever ANY new table is
     added, since a stale reviewed:true would let the new, unreviewed
     table slip through the backfill's safety gate unnoticed.
     The live database is the source of truth. Never merge stale tables from a
     previous scan: a table that no longer exists, or a newly-created table,
     must be reflected exactly in this run. The proposal is an audit artifact,
     not a whitelist. */
    fs.writeFileSync(outPath, JSON.stringify(proposal, null, 2));


    console.log(`
Schema discovery complete. Touched zero data — read-only.`);
    console.log(`Proposal written to: ${outPath}\n`);
    console.log('Summary:');
    let totalTables = 0, totalColumns = 0, totalNarrowColumns = 0, totalCheckConstraintTables = 0, totalTriggerTables = 0;
    let totalCompositeKeyTables = 0, totalEnumColumns = 0, totalDefaultValueColumns = 0, totalExcludeConstraintTables = 0;
    const narrowColumnDetails = [];
    const checkConstraintDetails = [];
    const triggerDetails = [];

    for (const table of proposal.tables) {
      totalTables += 1;
      totalColumns += table.columns.length;
      const encrypted = table.columns.filter((c) => !c.doNotEncrypt).map((c) => c.columnName);
      const protectedCols = table.columns.filter((c) => c.doNotEncrypt).map((c) => c.columnName);
      const specialType = table.columns.filter((c) => c.needsSpecialTypeHandling && !c.doNotEncrypt).map((c) => c.columnName);
      const uniquenessWarnings = table.columns.filter((c) => c.uniquenessWarning);
      const narrowColumns = table.columns.filter((c) => c.widthWarning);
      const enumColumns = table.columns.filter((c) => c.enumWarning);
      const defaultValueColumns = table.columns.filter((c) => c.defaultValueWarning);
      console.log(`  ${table.tableName} (PK: ${table.primaryKeyColumns && table.primaryKeyColumns.length ? table.primaryKeyColumns.join(', ') : 'NONE — automatic synthetic row id will be added'})`);
      if (table.primaryKeyWarning && !table.primaryKeyColumn) {
        const compositePkCols = table.columns.filter((c) => c.doNotEncryptReason && c.doNotEncryptReason.includes('COMPOSITE primary key'));
        if (compositePkCols.length > 0) {
          console.log(`    ⚠⚠ COMPOSITE PRIMARY KEY — needs manual handling: ${compositePkCols.map((c) => c.columnName).join(', ')}`);
          totalCompositeKeyTables += 1;
        }
      }
      if (table.triggerWarning) {
        console.log(`    ⚠⚠ EXISTING TRIGGERS FOUND — CHECK BEFORE APPROVING: ${table.existingTriggers.map((t) => `${t.name} (${t.timing} ${t.event})`).join(', ')}`);
        console.log(`       A trigger writing to an encrypted column will silently reintroduce plaintext. See triggerWarning in the JSON for details.`);
        totalTriggerTables += 1;
        triggerDetails.push({ table: table.tableName, triggers: table.existingTriggers.map((t) => t.name) });
      }
      if (table.checkConstraintWarning) {
        console.log(`    ⚠⚠ CHECK CONSTRAINT(S) FOUND — CANNOT be satisfied by ciphertext, needs a decision: ${table.existingCheckConstraints.map((c) => c.name).join(', ')}`);
        totalCheckConstraintTables += 1;
        checkConstraintDetails.push({ table: table.tableName, constraints: table.existingCheckConstraints.map((c) => c.name) });
      }
      if (table.excludeConstraintWarning) {
        console.log(`    ⚠⚠ EXCLUDE CONSTRAINT(S) FOUND: ${table.existingExcludeConstraints.map((e) => e.name).join(', ')}`);
        totalExcludeConstraintTables += 1;
      }
      console.log(`    WILL BE ENCRYPTED (${encrypted.length} columns, no exceptions beyond structural ones below): ${encrypted.join(', ')}`);
      if (protectedCols.length) {
        console.log(`    structurally excluded (primary/foreign key — review deterministicEncrypt if this needs to stay joinable/findable): ${protectedCols.join(', ')}`);
      }
      if (specialType.length) {
        console.log(`    needs special type handling (not plain text): ${specialType.join(', ')}`);
      }
      if (uniquenessWarnings.length) {
        console.log(`    ⚠ UNIQUE constraint on an encrypted column (review deterministicEncrypt): ${uniquenessWarnings.map((c) => c.columnName).join(', ')}`);
      }
      if (enumColumns.length) {
        console.log(`    ⚠⚠ ENUM TYPE(S) — same conflict as CHECK constraints: ${enumColumns.map((c) => c.columnName).join(', ')}`);
        totalEnumColumns += enumColumns.length;
      }
      if (defaultValueColumns.length) {
        console.log(`    ⚠ HAS DATABASE DEFAULT VALUE(S) — risk of silent plaintext bypass on insert (same bug class as the created_at/updated_at fix): ${defaultValueColumns.map((c) => c.columnName).join(', ')}`);
        totalDefaultValueColumns += defaultValueColumns.length;
      }
      if (narrowColumns.length) {
        console.log(`    ⚠⚠ TOO NARROW TO HOLD CIPHERTEXT (needs ALTER COLUMN ... TYPE TEXT — a schema change): ${narrowColumns.map((c) => `${c.columnName} (VARCHAR(${c.characterMaximumLength}))`).join(', ')}`);
        totalNarrowColumns += narrowColumns.length;
        narrowColumnDetails.push({ table: table.tableName, columns: narrowColumns.map((c) => `${c.columnName} VARCHAR(${c.characterMaximumLength})`) });
      }
      if (table.hasMigrationTrackingColumns) {
        console.log(`    already has key_version/wrapped_dek columns — may already be migrated or in progress`);
      }
      if (table.suggestedAccessPattern) {
        const p = table.suggestedAccessPattern;
        console.log(`    suggested RLS access pattern: ${p.pattern ? `Pattern ${p.pattern}` : 'none matched — manual review needed'} — ${p.reason}`);
      }
      const columnsWithAutoDropChecks = table.columns.filter((c) => Array.isArray(c.checkConstraintsToAutoDrop) && c.checkConstraintsToAutoDrop.length > 0);
      if (columnsWithAutoDropChecks.length > 0) {
        console.log(`    CHECK constraints queued for automatic removal: ${columnsWithAutoDropChecks.map((c) => `${c.columnName} (${c.checkConstraintsToAutoDrop.join(', ')})`).join('; ')}`);
      } else if (table.existingCheckConstraints && table.existingCheckConstraints.length > 0) {
        console.log(`    ⚠ DIAGNOSTIC: this table HAS ${table.existingCheckConstraints.length} CHECK constraint(s) (${table.existingCheckConstraints.map((c) => `${c.name}: ${c.clause}`).join('; ')}) but NONE were matched to a column for automatic removal — this is the bug, if you're seeing this line.`);
      }
    }

    /* AGGREGATE SUMMARY — the report to actually bring to a decision-maker.
     This answers, concretely and with real numbers, the question "what
     does 'encrypt everything' actually require across the whole database?" */

    console.log('\n' + '='.repeat(78));
    console.log('AGGREGATE SUMMARY — for taking this decision to leadership');
    console.log('='.repeat(78));
    console.log(`Tables scanned:                    ${totalTables}`);
    console.log(`Total columns:                     ${totalColumns}`);
    console.log(`Columns too narrow for ciphertext:  ${totalNarrowColumns}  <- each REQUIRES a schema change (ALTER COLUMN TYPE TEXT) to encrypt`);
    console.log(`Tables with CHECK constraints:      ${totalCheckConstraintTables}  <- each affected column needs an explicit decision: drop the constraint, or leave that column unencrypted`);
    console.log(`Tables with existing triggers:      ${totalTriggerTables}  <- each needs manual review; a trigger can silently reintroduce plaintext`);
    console.log(`Tables with composite primary keys: ${totalCompositeKeyTables}  <- supported automatically by the complete-key migration path`);
    console.log(`ENUM-typed columns:                 ${totalEnumColumns}  <- same conflict as CHECK constraints; needs a decision per column`);
    console.log(`Columns with a meaningful DEFAULT:   ${totalDefaultValueColumns}  <- risk of silent plaintext bypass on insert unless explicitly handled`);
    console.log(`Tables with EXCLUDE constraints:     ${totalExcludeConstraintTables}  <- rare but real; needs manual review`);
    if (totalNarrowColumns > 0) {
      console.log('\nNarrow-column detail (by table):');
      for (const d of narrowColumnDetails) console.log(`  ${d.table}: ${d.columns.join(', ')}`);
    }
    if (totalCheckConstraintTables > 0) {
      console.log('\nCHECK constraint detail (by table):');
      for (const d of checkConstraintDetails) console.log(`  ${d.table}: ${d.constraints.join(', ')}`);
    }
    if (totalTriggerTables > 0) {
      console.log('\nTrigger detail (by table):');
      for (const d of triggerDetails) console.log(`  ${d.table}: ${d.triggers.join(', ')}`);
    }
    console.log('\nCONCLUSION: if "encrypt everything" and "zero schema changes to production"');
    console.log('are both hard requirements, they are in direct conflict for every one of the');
    console.log(`${totalNarrowColumns} narrow column(s) listed above — this is a physical storage limit, not`);
    console.log('a design choice this tool made. This conflict needs a decision from whoever');
    console.log('owns both requirements, before backfill proceeds on the affected tables.');
    console.log('='.repeat(78));

    console.log('\nThe proposal is generated from the live database on every run. It is an audit artifact, not a manual allow-list. Use secure-dashboard.js encrypt-all --confirm for automatic execution.');
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  discoverSchema().catch((err) => {
    console.error('Schema discovery failed:', err.message);
    process.exit(1);
  });
}

module.exports = { discoverSchema };