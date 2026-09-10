# Automatic PostgreSQL Field-Level Encryption

This revision changes the migration model from a manually approved table allow-list to a live-database-driven encryption run.

## Required behavior

- Every base table in the `public` schema is discovered on every run.
- Every persisted application column is encrypted.
- Primary-key, foreign-key, and UNIQUE columns use deterministic encryption so equality, joins, PKs, FKs, and uniqueness remain usable.
- Ordinary columns use AES-256-GCM randomized encryption with per-row DEKs.
- Composite primary keys are supported.
- Tables without a primary key receive an internal `__enc_row_id`, which is itself encrypted.
- Existing CHECK constraints are removed because plaintext-value checks cannot be evaluated against ciphertext.
- Generated columns are converted to ordinary columns before encryption.
- Plaintext-producing defaults are removed from encrypted columns.
- Encrypted columns can be locked with database CHECK constraints so future plaintext writes fail instead of silently bypassing the encryption layer.
- The final run performs a zero-plaintext verification and fails if any encrypted column still contains a non-ciphertext value or any row has no encryption key version.
- `migration-proposal.json` is an audit artifact, not an authorization/allow-list.

## Commands

```bash
npm install
npm run scan
npm run encrypt-all                 # dry run
npm run encrypt-all -- --confirm    # execute
```

The production command refuses to execute with the local/demo KMS when `NODE_ENV=production`. Use a real KMS (`KMS_PROVIDER=aws` or `KMS_PROVIDER=vault`).

## Production procedure

1. Take and verify a database backup/snapshot.
2. Test the exact migration against a restored production-like copy.
3. Configure the real KMS and credentials.
4. Run `npm run encrypt-all` first and inspect the plan/output.
5. Run `npm run encrypt-all -- --confirm` during a controlled maintenance window.
6. Do not terminate the process while foreign keys are temporarily dropped.
7. Confirm the final `Zero-plaintext verification: PASS`.
8. Exercise all application read/write paths after migration.
9. Re-run the encryption command whenever new tables/columns are introduced, or integrate it into the schema-change deployment pipeline.

## Important scope

The current discovery implementation targets PostgreSQL base tables in the `public` schema, matching the existing project. If a deployment uses multiple application schemas, schema qualification should be added before that deployment; do not treat a multi-schema database as fully covered by a public-only scan.

This tool protects data stored in PostgreSQL. It does not by itself encrypt WAL files, physical database files, backups, logs, query text, application memory, client-side caches, or data exported outside PostgreSQL. Those require separate infrastructure controls.
