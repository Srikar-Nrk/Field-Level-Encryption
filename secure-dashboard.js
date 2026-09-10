'use strict';

/*
 secure-dashboard.js — field-level encryption for a Postgres-backed dashboard.
 AES-256-GCM envelope encryption; deterministic encryption for join/PK columns
 (sno, hhid, gp_id) so real FOREIGN KEY constraints keep working.
 
 Run:
   npm install
   node secure-dashboard.js                # starts the API server
   KMS: KMS_PROVIDER=local (default, demo) | aws | vault — see .env.example
  Auth: AUTH_PROVIDER=demo (default) | oidc — see .env.example
 
  CLI commands:
    node secure-dashboard.js encrypt-all [--confirm]           # live-scan and encrypt every table
    node secure-dashboard.js backfill [--confirm] [--table=<name>] [--confirm-pk-encryption]
    node secure-dashboard.js insert-row --table=<name> --data='{"col":"value"}'
    node secure-dashboard.js lock-columns --table=<name> [--confirm]
    node secure-dashboard.js audit-maintenance [--confirm]
    node secure-dashboard.js compute-lookup --value="..."   (deterministic ciphertext for a plaintext value)
    node secure-dashboard.js verify                          (checks KMS/RLS/concurrent-backfill against a real DB)
    node secure-dashboard.js rotate
    node secure-dashboard.js admin-decrypt --id=<id> --reason="..."
 
  API:
    POST /records, GET /records/:id                          (built-in table)
    POST /tables/:tableName/records, GET /tables/:tableName/records   (external tables, e.g. families)
    GET /demo-ui                                              (browser verification page)
 
  db/scripts/discoverSchema.js generates migration-proposal.json as an audit artifact.
  encrypt-all always rescans the live database and never uses that file as a whitelist.
  See db/migrations/003_row_level_security.sql for the RLS policies withRlsContext applies.
 */


const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

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
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

loadDotEnvIfPresent();

// Config, from env vars / .env. Demo defaults unless KMS_PROVIDER/
// AUTH_PROVIDER are set to a real provider (see below).
const CONFIG = {
  PORT: parseInt(process.env.PORT, 10) || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  DB_PROVIDER: process.env.DB_PROVIDER || 'in-memory',
  DATABASE_URL: process.env.DATABASE_URL || '',
  DASHBOARD_TOKENS: (process.env.DASHBOARD_TOKENS || 'dashboard-token-1,dashboard-token-2')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean),
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || 'dbadmin-token-1',
};

if (CONFIG.NODE_ENV === 'production' && CONFIG.DB_PROVIDER === 'in-memory') {
  console.error(
    'FATAL: NODE_ENV=production but DB_PROVIDER is still "in-memory". ' +
    'Refusing to start — this would silently run production traffic against ' +
    'a database that loses all data on restart. Set DB_PROVIDER=postgres and ' +
    'DATABASE_URL in your environment/.env before starting in production.',
  );
  process.exit(1);
}

const ALGORITHM = 'aes-256-gcm';

const IV_LENGTH_BYTES = 12;

const AUTH_TAG_LENGTH_BYTES = 16;

const DEK_LENGTH_BYTES = 32;

function generateDEK() {
  return crypto.randomBytes(DEK_LENGTH_BYTES);
}

function encryptField(dek, plaintext, aad = null) {
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  if (aad)
    cipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(plaintext),
    });
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(String(plaintext), 'utf8')),
    cipher.final(),
  ]);
  return {
    ciphertext: ciphertext,
    iv: iv,
    authTag: cipher.getAuthTag(),
  };
}

function decryptField(dek, ciphertext, iv, authTag, aad = null) {
  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  decipher.setAuthTag(authTag);
  if (aad) decipher.setAAD(aad);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function toEncryptableString(value) {
  if (Buffer.isBuffer(value)) return `base64:${value.toString('base64')}`;
  if (value !== null && typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function fromDecryptedString(plainStr, dataType) {
  if (!dataType) return plainStr;
  if (dataType === 'jsonb' || dataType === 'json' || dataType.endsWith('[]')) {
    try { return JSON.parse(plainStr); } catch { return plainStr; }
  }
  if (dataType === 'bytea' && plainStr.startsWith('base64:')) return Buffer.from(plainStr.slice(7), 'base64');
  return plainStr;
}

function packForStorage({ ciphertext: ciphertext, iv: iv, authTag: authTag }) {
  return `v1.${iv.toString('base64')}.${authTag.toString('base64')}.${ciphertext.toString('base64')}`;
}

function unpackFromStorage(packed) {
  const [version, ivB64, tagB64, ctB64] = packed.split('.');
  if (version !== 'v1') throw new Error('unpackFromStorage: unrecognized envelope format');
  return {
    iv: Buffer.from(ivB64, 'base64'),
    authTag: Buffer.from(tagB64, 'base64'),
    ciphertext: Buffer.from(ctB64, 'base64'),
  };
}

function wipe(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0);
}

const DETERMINISTIC_IV_LENGTH_BYTES = 12;

function encryptFieldDeterministic(key, plaintext) {
  const plaintextBuf = Buffer.from(String(plaintext), 'utf8');
  const iv = crypto
    .createHmac('sha256', key)
    .update(plaintextBuf)
    .digest()
    .subarray(0, DETERMINISTIC_IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  return {
    ciphertext: ciphertext,
    iv: iv,
    authTag: cipher.getAuthTag(),
  };
}

function decryptFieldDeterministic(key, ciphertext, iv, authTag) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encryptDeterministicForStorage(key, plaintext) {
  const {
    ciphertext: ciphertext,
    iv: iv,
    authTag: authTag,
  } = encryptFieldDeterministic(key, plaintext);
  return `v2.${iv.toString('base64')}.${authTag.toString('base64')}.${ciphertext.toString('base64')}`;
}

function decryptDeterministicFromStorage(key, packed) {
  const [version, ivB64, tagB64, ctB64] = packed.split('.');
  if (version !== 'v2')
    throw new Error('decryptDeterministicFromStorage: unrecognized format (expected v2.*)');
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const ciphertext = Buffer.from(ctB64, 'base64');
  return decryptFieldDeterministic(key, ciphertext, iv, authTag).toString('utf8');
}


// ===== KMS =====
// LocalKMS: demo only, key in a local file. AwsKMS/VaultKMS below are real.
class LocalKMS {
  constructor() {
    this.kekStore = new Map();
    this.currentKeyVersion = 0;
    this.deterministicKey = null;
    this._statePath =
      process.env.LOCAL_KMS_STATE_PATH || path.join(__dirname, '.local-kms-state.json');
    this._loadOrInitState();
  }
  _loadOrInitState() {
    if (fs.existsSync(this._statePath)) {
      try {
        const saved = JSON.parse(fs.readFileSync(this._statePath, 'utf8'));
        this.currentKeyVersion = saved.currentKeyVersion;
        this.deterministicKey = Buffer.from(saved.deterministicKey, 'base64');
        for (const [version, entry] of Object.entries(saved.kekStore)) {
          this.kekStore.set(parseInt(version, 10), {
            kek: Buffer.from(entry.kek, 'base64'),
            createdAt: new Date(entry.createdAt),
            retiredAt: entry.retiredAt ? new Date(entry.retiredAt) : null,
          });
        }
        return;
      } catch (err) {
        console.error(
          '[LocalKMS] failed to load persisted demo keys, generating fresh ones (any data encrypted under the old keys will no longer decrypt):',
          err.message,
        );
      }
    }
    this.deterministicKey = crypto.randomBytes(32);
    this.currentKeyVersion = 1;
    this.kekStore.set(1, {
      kek: crypto.randomBytes(32),
      createdAt: new Date(),
      retiredAt: null,
    });
    this._saveState();
  }
  _saveState() {
    const serialized = {
      currentKeyVersion: this.currentKeyVersion,
      deterministicKey: this.deterministicKey.toString('base64'),
      kekStore: Object.fromEntries(
        [...this.kekStore.entries()].map(([version, entry]) => [
          version,
          {
            kek: entry.kek.toString('base64'),
            createdAt: entry.createdAt.toISOString(),
            retiredAt: entry.retiredAt ? entry.retiredAt.toISOString() : null,
          },
        ]),
      ),
    };
    try {
      fs.writeFileSync(this._statePath, JSON.stringify(serialized, null, 2), {
        mode: 384,
      });
    } catch (err) {
      console.error('[LocalKMS] failed to persist demo keys to disk:', err.message);
    }
  }
  getCurrentKeyVersion() {
    return this.currentKeyVersion;
  }
  getDeterministicKey() {
    return this.deterministicKey;
  }
  wrapDEK(dek) {
    const entry = this.kekStore.get(this.currentKeyVersion);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', entry.kek, iv);
    const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
    const wrappedDEK = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
    return {
      wrappedDEK: wrappedDEK,
      keyVersion: this.currentKeyVersion,
    };
  }
  unwrapDEK(wrappedDEK, keyVersion) {
    const entry = this.kekStore.get(keyVersion);
    if (!entry) throw new Error(`unwrapDEK: unknown or destroyed key version ${keyVersion}`);
    const iv = wrappedDEK.subarray(0, 12);
    const authTag = wrappedDEK.subarray(12, 28);
    const ciphertext = wrappedDEK.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', entry.kek, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
  rotateKEK() {
    const previous = this.kekStore.get(this.currentKeyVersion);
    if (previous) previous.retiredAt = new Date();
    this.currentKeyVersion += 1;
    this.kekStore.set(this.currentKeyVersion, {
      kek: crypto.randomBytes(32),
      createdAt: new Date(),
      retiredAt: null,
    });
    this._saveState();
    return this.currentKeyVersion;
  }
  rewrapDEK(wrappedDEK, oldKeyVersion) {
    const plaintextDEK = this.unwrapDEK(wrappedDEK, oldKeyVersion);
    const result = this.wrapDEK(plaintextDEK);
    plaintextDEK.fill(0);
    return result;
  }
  destroyKeyVersion(keyVersion) {
    if (keyVersion === this.currentKeyVersion)
      throw new Error('refusing to destroy the current active key version');
    const entry = this.kekStore.get(keyVersion);
    if (entry) entry.kek.fill(0);
    this.kekStore.delete(keyVersion);
    this._saveState();
  }
  listKeyVersions() {
    return [...this.kekStore.entries()].map(([version, e]) => ({
      version: version,
      createdAt: e.createdAt,
      retiredAt: e.retiredAt,
      isCurrent: version === this.currentKeyVersion,
    }));
  }
}

function deriveKeysFromRootKey(rootKey, currentKeyVersion) {
  const deterministicKey = crypto
    .createHmac('sha256', rootKey)
    .update('deterministic-key-v1')
    .digest();
  const kekStore = new Map();
  for (let v = 1; v <= currentKeyVersion; v += 1) {
    kekStore.set(v, {
      kek: crypto.createHmac('sha256', rootKey).update(`kek-v${v}`).digest(),
      createdAt: new Date(),
      retiredAt: v === currentKeyVersion ? null : new Date(),
    });
  }
  return {
    deterministicKey: deterministicKey,
    kekStore: kekStore,
  };
}


// Shared base for any "root key wrapped by an external KMS" provider.
class WrappedRootKeyKMS extends LocalKMS {
  static async _createWithStatePath(statePath) {
    const instance = Object.create(this.prototype);
    instance.kekStore = new Map();
    instance.currentKeyVersion = 0;
    instance.deterministicKey = null;
    instance._statePath = statePath;
    await instance._loadOrInitState_wrappedRoot();
    return instance;
  }
  async _loadOrInitState_wrappedRoot() {
    if (fs.existsSync(this._statePath)) {
      const saved = JSON.parse(fs.readFileSync(this._statePath, 'utf8'));
      const rootKey = await this._unwrapRootKey(saved.wrappedRootKey);
      const { deterministicKey: deterministicKey, kekStore: kekStore } = deriveKeysFromRootKey(
        rootKey,
        saved.currentKeyVersion,
      );
      this.currentKeyVersion = saved.currentKeyVersion;
      this.deterministicKey = deterministicKey;
      this.kekStore = kekStore;
      rootKey.fill(0);
      console.log(`[${this.constructor.name}] loaded existing keys, unwrapped via external KMS.`);
      return;
    }
    const { rootKey: rootKey, wrappedRootKey: wrappedRootKey } =
      await this._generateAndWrapRootKey();
    this.currentKeyVersion = 1;
    const { deterministicKey: deterministicKey, kekStore: kekStore } = deriveKeysFromRootKey(
      rootKey,
      1,
    );
    this.deterministicKey = deterministicKey;
    this.kekStore = kekStore;
    fs.writeFileSync(
      this._statePath,
      JSON.stringify(
        {
          wrappedRootKey: wrappedRootKey,
          currentKeyVersion: 1,
        },
        null,
        2,
      ),
      {
        mode: 384,
      },
    );
    rootKey.fill(0);
    console.log(
      `[${this.constructor.name}] generated new root key, wrapped copy persisted (safe — useless without external KMS access).`,
    );
  }
  _saveState() {
    const existing = JSON.parse(fs.readFileSync(this._statePath, 'utf8'));
    existing.currentKeyVersion = this.currentKeyVersion;
    fs.writeFileSync(this._statePath, JSON.stringify(existing, null, 2), {
      mode: 384,
    });
  }
  rotateKEK() {
    throw new Error(
      `${this.constructor.name}.rotateKEK: not implemented as a simple call — rotating the root key requires re-deriving and re-persisting KEK history correctly. Use your KMS provider's own key rotation for the underlying key, or implement explicit root-key rotation deliberately if your policy requires more frequent rotation.`,
    );
  }
}


// Real KMS: AWS. Needs AWS_KMS_KEY_ID, AWS_REGION, real AWS credentials.
class AwsKMS extends WrappedRootKeyKMS {
  static async create() {
    return WrappedRootKeyKMS._createWithStatePath.call(
      AwsKMS,
      process.env.AWS_KMS_STATE_PATH || path.join(__dirname, '.aws-kms-wrapped-root.json'),
    );
  }
  _client() {
    const { KMSClient: KMSClient } = require('@aws-sdk/client-kms');
    return new KMSClient({
      region: process.env.AWS_REGION,
    });
  }
  async _generateAndWrapRootKey() {
    const { GenerateDataKeyCommand: GenerateDataKeyCommand } = require('@aws-sdk/client-kms');
    const keyId = process.env.AWS_KMS_KEY_ID;
    if (!keyId) throw new Error('AWS_KMS_KEY_ID is required when KMS_PROVIDER=aws');
    const generated = await this._client().send(
      new GenerateDataKeyCommand({
        KeyId: keyId,
        KeySpec: 'AES_256',
      }),
    );
    return {
      rootKey: Buffer.from(generated.Plaintext),
      wrappedRootKey: Buffer.from(generated.CiphertextBlob).toString('base64'),
    };
  }
  async _unwrapRootKey(wrappedRootKeyB64) {
    const { DecryptCommand: DecryptCommand } = require('@aws-sdk/client-kms');
    const decrypted = await this._client().send(
      new DecryptCommand({
        CiphertextBlob: Buffer.from(wrappedRootKeyB64, 'base64'),
      }),
    );
    return Buffer.from(decrypted.Plaintext);
  }
}


// Real KMS: HashiCorp Vault Transit. Cloud-agnostic. Needs VAULT_ADDR/VAULT_TOKEN.
class VaultKMS extends WrappedRootKeyKMS {
  static async create() {
    return WrappedRootKeyKMS._createWithStatePath.call(
      VaultKMS,
      process.env.VAULT_KMS_STATE_PATH || path.join(__dirname, '.vault-kms-wrapped-root.json'),
    );
  }
  async _vaultRequest(urlPath, body) {
    const vaultAddr = process.env.VAULT_ADDR;
    const vaultToken = process.env.VAULT_TOKEN;
    if (!vaultAddr) throw new Error('VAULT_ADDR is required when KMS_PROVIDER=vault');
    if (!vaultToken) throw new Error('VAULT_TOKEN is required when KMS_PROVIDER=vault');
    const res = await fetch(`${vaultAddr.replace(/\/$/, '')}/v1/${urlPath}`, {
      method: 'POST',
      headers: {
        'X-Vault-Token': vaultToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Vault request to ${urlPath} failed (${res.status}): ${text}`);
    }
    return res.json();
  }
  _keyName() {
    return process.env.VAULT_TRANSIT_KEY_NAME || 'secure-dashboard-root';
  }
  async _generateAndWrapRootKey() {
    const result = await this._vaultRequest(`transit/datakey/plaintext/${this._keyName()}`, {
      bits: 256,
    });
    return {
      rootKey: Buffer.from(result.data.plaintext, 'base64'),
      wrappedRootKey: result.data.ciphertext,
    };
  }
  async _unwrapRootKey(wrappedRootKey) {
    const result = await this._vaultRequest(`transit/decrypt/${this._keyName()}`, {
      ciphertext: wrappedRootKey,
    });
    return Buffer.from(result.data.plaintext, 'base64');
  }
}

async function createKMS() {
  const provider = process.env.KMS_PROVIDER || 'local';
  if (provider === 'aws') return AwsKMS.create();
  if (provider === 'vault') return VaultKMS.create();
  return new LocalKMS();
}

let kms = new LocalKMS();

const NOT_ENCRYPTED_FIELDS = new Set(['id', '_wrappedDEK', '_keyVersion']);

function encryptRecord(recordId, record) {
  if (!recordId) throw new Error('encryptRecord: recordId is required (used as AAD binding)');
  const dek = generateDEK();
  const aad = Buffer.from(String(recordId), 'utf8');
  const outputRow = {};
  for (const field of Object.keys(record)) {
    if (NOT_ENCRYPTED_FIELDS.has(field)) {
      outputRow[field] = record[field];
      continue;
    }
    if (record[field] === undefined || record[field] === null) continue;
    const {
      ciphertext: ciphertext,
      iv: iv,
      authTag: authTag,
    } = encryptField(dek, String(record[field]), aad);
    outputRow[field] = packForStorage({
      ciphertext: ciphertext,
      iv: iv,
      authTag: authTag,
    });
  }
  const { wrappedDEK: wrappedDEK, keyVersion: keyVersion } = kms.wrapDEK(dek);
  wipe(dek);
  outputRow._wrappedDEK = wrappedDEK.toString('base64');
  outputRow._keyVersion = keyVersion;
  return outputRow;
}

function decryptRecord(recordId, row) {
  const wrappedDEK = Buffer.from(row._wrappedDEK, 'base64');
  const dek = kms.unwrapDEK(wrappedDEK, row._keyVersion);
  const aad = Buffer.from(String(recordId), 'utf8');
  const output = {};
  const INTERNAL_ONLY = new Set(['_wrappedDEK', '_keyVersion']);
  try {
    for (const field of Object.keys(row)) {
      if (INTERNAL_ONLY.has(field)) continue;
      if (NOT_ENCRYPTED_FIELDS.has(field)) {
        output[field] = row[field];
        continue;
      }
      if (row[field] === undefined || row[field] === null) continue;
      const { ciphertext: ciphertext, iv: iv, authTag: authTag } = unpackFromStorage(row[field]);
      output[field] = decryptField(dek, ciphertext, iv, authTag, aad).toString('utf8');
    }
  } finally {
    wipe(dek);
  }
  return output;
}

function rewrapRecordKey(row) {
  const wrappedDEK = Buffer.from(row._wrappedDEK, 'base64');
  const { wrappedDEK: newWrapped, keyVersion: keyVersion } = kms.rewrapDEK(
    wrappedDEK,
    row._keyVersion,
  );
  return {
    _wrappedDEK: newWrapped.toString('base64'),
    _keyVersion: keyVersion,
  };
}

let _auditLogPool = null;

function getAuditLogPool() {
  if (CONFIG.DB_PROVIDER !== 'postgres' || !CONFIG.DATABASE_URL) return null;
  if (!_auditLogPool) {
    _auditLogPool = new Pool({
      connectionString: CONFIG.DATABASE_URL,
    });
  }
  return _auditLogPool;
}

function auditLog(event, details) {
  const entry = {
    ts: new Date().toISOString(),
    event: event,
    ...details,
  };
  console.log(JSON.stringify(entry));
  const pool = getAuditLogPool();
  if (!pool) return;
  pool
    .query('INSERT INTO audit_log (occurred_at, event, details) VALUES ($1, $2, $3)', [
      entry.ts,
      event,
      JSON.stringify(details || {}),
    ])
    .catch((err) => {
      console.error(
        '[audit_log] failed to persist durably (console record above is unaffected):',
        err.message,
      );
    });
}

const AUDIT_LOG_MONTHS_AHEAD = parseInt(process.env.AUDIT_LOG_MONTHS_AHEAD, 10) || 3;

const AUDIT_LOG_RETENTION_MONTHS = parseInt(process.env.AUDIT_LOG_RETENTION_MONTHS, 10) || 6;

function formatPartitionMonth(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  return `${year}_${month}`;
}

function monthBoundary(date, monthOffset) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + monthOffset, 1));
}

async function ensureAuditLogPartitions(pool, monthsAhead = AUDIT_LOG_MONTHS_AHEAD) {
  const now = new Date();
  const created = [];
  for (let i = 0; i <= monthsAhead; i += 1) {
    const start = monthBoundary(now, i);
    const end = monthBoundary(now, i + 1);
    const partitionName = `audit_log_${formatPartitionMonth(start)}`;
    const startStr = start.toISOString().slice(0, 10);
    const endStr = end.toISOString().slice(0, 10);
    await pool.query(
      `CREATE TABLE IF NOT EXISTS ${partitionName} PARTITION OF audit_log FOR VALUES FROM ('${startStr}') TO ('${endStr}')`,
    );
    created.push(partitionName);
  }
  return created;
}

async function detachOldAuditLogPartitions(
  pool,
  retentionMonths = AUDIT_LOG_RETENTION_MONTHS,
  { dryRun: dryRun } = {},
) {
  const cutoff = monthBoundary(new Date(), -retentionMonths);
  const cutoffLabel = formatPartitionMonth(cutoff);
  const existingResult = await pool.query(
    `\n    SELECT child.relname AS partition_name\n    FROM pg_inherits\n    JOIN pg_class parent ON pg_inherits.inhparent = parent.oid\n    JOIN pg_class child ON pg_inherits.inhrelid = child.oid\n    WHERE parent.relname = 'audit_log'\n    ORDER BY child.relname\n  `,
  );
  const toDetach = existingResult.rows
    .map((r) => r.partition_name)
    .filter((name) => {
      const match = name.match(/^audit_log_(\d{4}_\d{2})$/);
      return match && match[1] < cutoffLabel;
    });
  if (dryRun) {
    return {
      wouldDetach: toDetach,
      cutoff: cutoffLabel,
    };
  }
  const detached = [];
  for (const partitionName of toDetach) {
    await pool.query(`ALTER TABLE audit_log DETACH PARTITION ${partitionName}`);
    detached.push(partitionName);
    console.log(
      `  Detached ${partitionName} — still exists as a standalone table, not deleted. Export and drop it per your retention policy when ready.`,
    );
  }
  return {
    detached: detached,
    cutoff: cutoffLabel,
  };
}

async function runAuditMaintenance({ confirm: confirm }) {
  const databaseUrl = CONFIG.DATABASE_URL || process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL is required for audit log maintenance.');
    process.exit(1);
  }
  const pool = new Pool({
    connectionString: databaseUrl,
  });
  try {
    console.log(
      confirm
        ? '=== Ensuring future partitions exist and detaching old ones ==='
        : '=== DRY RUN — pass --confirm to actually create/detach partitions ===',
    );
    if (confirm) {
      const created = await ensureAuditLogPartitions(pool);
      console.log('Partitions ensured:', created);
      const result = await detachOldAuditLogPartitions(pool);
      console.log('Detach result:', JSON.stringify(result, null, 2));
    } else {
      const result = await detachOldAuditLogPartitions(pool, AUDIT_LOG_RETENTION_MONTHS, {
        dryRun: true,
      });
      console.log(
        `[DRY RUN] Would ensure ${AUDIT_LOG_MONTHS_AHEAD + 1} months of future partitions exist.`,
      );
      console.log(
        '[DRY RUN] Would detach:',
        result.wouldDetach.length
          ? result.wouldDetach
          : '(none — nothing older than the retention cutoff yet)',
      );
    }
  } finally {
    await pool.end();
  }
}

function createInMemoryAdapter() {
  const store = new Map();
  return {
    async getRecord(id) {
      return store.has(id) ? store.get(id) : null;
    },
    async setRecord(id, row) {
      store.set(id, {
        ...row,
        id: id,
      });
    },
    async listRecords() {
      return [...store.values()];
    },
    async getRecordsByKeyVersion(keyVersion) {
      return [...store.values()].filter((row) => row._keyVersion === keyVersion);
    },
    async updateKeyMetadata(id, { _wrappedDEK: _wrappedDEK, _keyVersion: _keyVersion }) {
      const row = store.get(id);
      if (!row) throw new Error(`updateKeyMetadata: record ${id} not found`);
      row._wrappedDEK = _wrappedDEK;
      row._keyVersion = _keyVersion;
    },
    async close() { },
    _debugClear() {
      store.clear();
    },
  };
}

function createPostgresAdapter(options = {}) {
  const pool =
    options.pool ||
    new Pool({
      connectionString: options.connectionString || process.env.DATABASE_URL,
      max: parseInt(process.env.PG_POOL_MAX, 10) || 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
  function rowFromDb(dbRow) {
    if (!dbRow) return null;
    return {
      id: dbRow.id,
      _wrappedDEK: dbRow.wrapped_dek,
      _keyVersion: dbRow.key_version,
      ...dbRow.encrypted_data,
    };
  }
  function splitRowForDb(row) {
    const { id: id, _wrappedDEK: _wrappedDEK, _keyVersion: _keyVersion, ...encryptedFields } = row;
    return {
      id: id,
      wrappedDEK: _wrappedDEK,
      keyVersion: _keyVersion,
      encryptedFields: encryptedFields,
    };
  }
  return {
    async getRecord(id) {
      const result = await pool.query(
        'SELECT id, encrypted_data, wrapped_dek, key_version FROM sensitive_records WHERE id = $1',
        [id],
      );
      return rowFromDb(result.rows[0]);
    },
    async setRecord(id, row) {
      const {
        wrappedDEK: wrappedDEK,
        keyVersion: keyVersion,
        encryptedFields: encryptedFields,
      } = splitRowForDb({
        ...row,
        id: id,
      });
      await pool.query(
        `INSERT INTO sensitive_records (id, encrypted_data, wrapped_dek, key_version)\n         VALUES ($1, $2, $3, $4)\n         ON CONFLICT (id) DO UPDATE\n           SET encrypted_data = EXCLUDED.encrypted_data,\n               wrapped_dek = EXCLUDED.wrapped_dek,\n               key_version = EXCLUDED.key_version`,
        [id, JSON.stringify(encryptedFields), wrappedDEK, keyVersion],
      );
    },
    async listRecords() {
      const result = await pool.query(
        'SELECT id, encrypted_data, wrapped_dek, key_version FROM sensitive_records ORDER BY created_at_meta',
      );
      return result.rows.map(rowFromDb);
    },
    async getRecordsByKeyVersion(keyVersion) {
      const result = await pool.query(
        'SELECT id, encrypted_data, wrapped_dek, key_version FROM sensitive_records WHERE key_version = $1',
        [keyVersion],
      );
      return result.rows.map(rowFromDb);
    },
    async updateKeyMetadata(id, { _wrappedDEK: _wrappedDEK, _keyVersion: _keyVersion }) {
      const result = await pool.query(
        'UPDATE sensitive_records SET wrapped_dek = $1, key_version = $2 WHERE id = $3',
        [_wrappedDEK, _keyVersion, id],
      );
      if (result.rowCount === 0) {
        throw new Error(`updateKeyMetadata: record ${id} not found`);
      }
    },
    async close() {
      await pool.end();
    },
    _pool: pool,
  };
}

function createDbAdapter() {
  if (CONFIG.DB_PROVIDER === 'postgres') {
    if (!CONFIG.DATABASE_URL) {
      console.error(
        'FATAL: DB_PROVIDER=postgres requires DATABASE_URL to be set (in .env or a real environment variable).',
      );
      process.exit(1);
    }
    return createPostgresAdapter({
      connectionString: CONFIG.DATABASE_URL,
    });
  }
  return createInMemoryAdapter();
}

const db = createDbAdapter();

let jwksClient = null;

function getJwksClient() {
  if (!jwksClient) {
    const jwksRsa = require('jwks-rsa');
    jwksClient = jwksRsa({
      jwksUri: process.env.OIDC_JWKS_URI,
      cache: true,
      cacheMaxAge: 600000,
      rateLimit: true,
    });
  }
  return jwksClient;
}

function getSigningKey(kid) {
  return new Promise((resolve, reject) => {
    getJwksClient().getSigningKey(kid, (err, key) => {
      if (err) return reject(err);
      resolve(key.getPublicKey ? key.getPublicKey() : key.publicKey || key.rsaPublicKey);
    });
  });
}

async function verifyOidcToken(token) {
  const jwt = require('jsonwebtoken');
  const decoded = jwt.decode(token, {
    complete: true,
  });
  if (!decoded) throw new Error('malformed token');
  const publicKey = await getSigningKey(decoded.header.kid);
  const verifyOptions = {
    issuer: process.env.OIDC_ISSUER,
    algorithms: ['RS256'],
  };
  if (process.env.OIDC_AUDIENCE) verifyOptions.audience = process.env.OIDC_AUDIENCE;
  const claims = jwt.verify(token, publicKey, verifyOptions);
  return {
    userId: claims.sub,
    district: claims[process.env.OIDC_DISTRICT_CLAIM || 'district'] || null,
    role: claims[process.env.OIDC_ROLE_CLAIM || 'role'] || null,
  };
}


// Auth: real OIDC/JWT, verified against your actual identity provider
async function authenticateDashboardUserOidc(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token)
    return res.status(401).json({
      error: 'unauthenticated',
    });
  try {
    req.user = await verifyOidcToken(token);
    next();
  } catch (err) {
    auditLog('auth.token_rejected', {
      error: err.message,
    });
    res.status(401).json({
      error: 'unauthenticated',
    });
  }
}

const DASHBOARD_USERS = Object.fromEntries(
  CONFIG.DASHBOARD_TOKENS.map((token, i) => [
    token,
    {
      userId: `dashboard-user-${i + 1}`,
    },
  ]),
);

function authenticateDashboardUserDemo(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const user = DASHBOARD_USERS[token];
  if (!user)
    return res.status(401).json({
      error: 'unauthenticated',
    });
  req.user = user;
  next();
}


// Dispatches to OIDC or demo tokens based on AUTH_PROVIDER — every route uses this.
function authenticateDashboardUser(req, res, next) {
  if ((process.env.AUTH_PROVIDER || 'demo') === 'oidc') {
    return authenticateDashboardUserOidc(req, res, next);
  }
  return authenticateDashboardUserDemo(req, res, next);
}


// HTTP API
const app = express();

app.use(express.json());

app.get('/demo-ui', (req, res) => {
  res
    .type('html')
    .send(
      `<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n<title>Encryption Verification — Demo UI (not production)</title>\n<style>\n  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #222; }\n  h1 { font-size: 20px; }\n  .banner { background: #fff3cd; border: 1px solid #ffe69c; padding: 12px 16px; border-radius: 6px; margin-bottom: 24px; font-size: 14px; }\n  input, select { padding: 8px; margin: 4px 0; width: 100%; box-sizing: border-box; }\n  label { font-size: 13px; color: #555; margin-top: 10px; display: block; }\n  button { padding: 8px 16px; margin-top: 12px; cursor: pointer; }\n  table { border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }\n  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n  th { background: #f5f5f5; }\n  #error { color: #b91c1c; margin-top: 10px; }\n  .section { border: 1px solid #eee; padding: 16px; border-radius: 8px; margin-bottom: 24px; }\n</style>\n</head>\n<body>\n<h1>Encryption Verification — Demo UI</h1>\n<div class="banner">This is a minimal verification page, not the real production dashboard. It calls the same API a real UI would, so what renders here is real proof of what an end user would actually see — not a mock.</div>\n\n<div class="section">\n  <label>Dashboard token</label>\n  <input id="token" value="dashboard-token-1">\n  <label>Table name</label>\n  <input id="tableName" value="families">\n  <button onclick="loadRows()">Load and decrypt rows</button>\n  <div id="error"></div>\n  <div id="tableOutput"></div>\n</div>\n\n<script>\nasync function loadRows() {\n  const token = document.getElementById('token').value;\n  const tableName = document.getElementById('tableName').value;\n  const errorEl = document.getElementById('error');\n  const outputEl = document.getElementById('tableOutput');\n  errorEl.textContent = '';\n  outputEl.innerHTML = 'Loading...';\n  try {\n    const res = await fetch('/tables/' + encodeURIComponent(tableName) + '/records?limit=20', {\n      headers: { Authorization: 'Bearer ' + token },\n    });\n    const body = await res.json();\n    if (!res.ok) { errorEl.textContent = 'Error: ' + (body.error || res.status); outputEl.innerHTML = ''; return; }\n    if (!body.rows.length) { outputEl.innerHTML = '<p>No rows found.</p>'; return; }\n    const columns = Object.keys(body.rows[0]);\n    let html = '<table><tr>' + columns.map(c => '<th>' + c + '</th>').join('') + '</tr>';\n    for (const row of body.rows) {\n      html += '<tr>' + columns.map(c => '<td>' + (row[c] === null ? '' : String(row[c])) + '</td>').join('') + '</tr>';\n    }\n    html += '</table>';\n    outputEl.innerHTML = html;\n  } catch (err) {\n    errorEl.textContent = 'Request failed: ' + err.message;\n    outputEl.innerHTML = '';\n  }\n}\n<\/script>\n</body>\n</html>`,
    );
});

app.post('/records', authenticateDashboardUser, async (req, res) => {
  try {
    const id = crypto.randomUUID();
    const encryptedRow = encryptRecord(id, req.body);
    encryptedRow.id = id;
    await db.setRecord(id, encryptedRow);
    auditLog('record.created', {
      recordId: id,
      userId: req.user.userId,
    });
    res.status(201).json({
      id: id,
    });
  } catch (err) {
    auditLog('record.create_error', {
      userId: req.user.userId,
      error: err.message,
    });
    res.status(500).json({
      error: 'failed to create record',
    });
  }
});

app.get('/records', authenticateDashboardUser, async (req, res) => {
  const rows = await db.listRecords();
  try {
    const decrypted = rows.map((row) => decryptRecord(row.id, row));
    auditLog('records.listed', {
      userId: req.user.userId,
      count: decrypted.length,
    });
    res.json({
      count: decrypted.length,
      records: decrypted,
    });
  } catch (err) {
    auditLog('records.list_error', {
      userId: req.user.userId,
      error: err.message,
    });
    res.status(500).json({
      error: 'decryption failed',
    });
  }
});

app.get('/records/:id', authenticateDashboardUser, async (req, res) => {
  const row = await db.getRecord(req.params.id);
  if (!row)
    return res.status(404).json({
      error: 'not found',
    });
  try {
    const decrypted = decryptRecord(req.params.id, row);
    auditLog('record.viewed', {
      recordId: req.params.id,
      userId: req.user.userId,
      fields: Object.keys(decrypted),
    });
    res.json(decrypted);
  } catch (err) {
    auditLog('record.view_error', {
      recordId: req.params.id,
      userId: req.user.userId,
      error: err.message,
    });
    res.status(500).json({
      error: 'decryption failed',
    });
  }
});

app.post('/records/:id/reveal', authenticateDashboardUser, async (req, res) => {
  const row = await db.getRecord(req.params.id);
  if (!row)
    return res.status(404).json({
      error: 'not found',
    });
  try {
    const decrypted = decryptRecord(req.params.id, row);
    auditLog('record.viewed', {
      recordId: req.params.id,
      userId: req.user.userId,
      fields: Object.keys(decrypted),
      via: 'reveal-alias',
    });
    res.json(decrypted);
  } catch (err) {
    auditLog('record.view_error', {
      recordId: req.params.id,
      userId: req.user.userId,
      error: err.message,
    });
    res.status(500).json({
      error: 'decryption failed',
    });
  }
});

let _tablesPool = null;

function getTablesPool() {
  if (!_tablesPool) {
    const databaseUrl = CONFIG.DATABASE_URL || process.env.DATABASE_URL;
    if (!databaseUrl) throw new Error('DATABASE_URL is required for this endpoint');
    _tablesPool = new Pool({
      connectionString: databaseUrl,
    });
  }
  return _tablesPool;
}

const ROLE_CLAIM_TO_PG_ROLE = {
  district_officer: 'district_officer',
  crp: 'crp_role',
  supervisor: 'supervisor_role',
  admin: 'state_admin_role',
  analyst: 'analyst_role',
};

async function withRlsContext(pool, user, queryFn) {
  const pgRole = ROLE_CLAIM_TO_PG_ROLE[user.role];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (pgRole) {
      await client.query(`SET LOCAL ROLE ${pgRole}`);
    }
    if (user.district) {
      await client.query('SELECT set_config($1, $2, true)', [
        'app.current_district',
        String(user.district),
      ]);
    }
    if (user.userId) {
      await client.query('SELECT set_config($1, $2, true)', [
        'app.current_user_id',
        String(user.userId),
      ]);
    }
    const result = await queryFn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => { });
    throw err;
  } finally {
    client.release();
  }
}

app.post('/tables/:tableName/records', authenticateDashboardUser, async (req, res) => {
  let proposal;
  try {
    proposal = loadMigrationProposalSafe();
  } catch (err) {
    return res.status(500).json({
      error: 'could not load the reviewed migration proposal',
      detail: err.message,
    });
  }
  const tableEntry = proposal.tables.find((t) => t.tableName === req.params.tableName);
  if (!tableEntry) {
    return res.status(404).json({
      error: `table "${req.params.tableName}" is not in the reviewed proposal — run discoverSchema.js and review it first`,
    });
  }
  try {
    const pool = getTablesPool();
    const insertedRow = await insertEncryptedRow(pool, tableEntry, req.body);
    auditLog('table_row.created', {
      table: req.params.tableName,
      userId: req.user.userId,
    });
    res.status(201).json({
      success: true,
      table: req.params.tableName,
    });
  } catch (err) {
    auditLog('table_row.create_error', {
      table: req.params.tableName,
      userId: req.user.userId,
      error: err.message,
    });
    res.status(500).json({
      error: 'failed to insert row',
      detail: err.message,
    });
  }
});


function getPrimaryKeyColumns(tableEntry) {
  if (Array.isArray(tableEntry.primaryKeyColumns) && tableEntry.primaryKeyColumns.length) return tableEntry.primaryKeyColumns;
  return tableEntry.primaryKeyColumn ? [tableEntry.primaryKeyColumn] : [];
}

// AAD binds encrypted fields to the row identity. For composite keys we bind
// to the ordered set of encrypted PK values, not just the first component.
function buildRowAad(tableEntry, row) {
  const pkColumns = getPrimaryKeyColumns(tableEntry);
  return Buffer.from(pkColumns.map((c) => String(row[c] ?? '')).join('\x1f'), 'utf8');
}

// Decrypts a row from an EXTERNAL table, reversing insertEncryptedRow/
// backfillTable's encryption using the same AAD convention.
function decryptTableRow(row, tableEntry) {
  const primaryKeyColumn = tableEntry.primaryKeyColumn;
  const BOOKKEEPING_COLUMNS = new Set(['wrapped_dek', 'key_version']); // never real data — see backfillTable for why this filter exists
  const sensitiveColumns = tableEntry.columns
    .filter((c) => !c.doNotEncrypt && !c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  const deterministicColumns = tableEntry.columns
    .filter((c) => c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  const deterministicKey = kms.getDeterministicKey();
  const decrypted = {
    ...row,
  };
  for (const col of tableEntry.columns.filter((c) => c.internal)) delete decrypted[col.columnName];
  for (const col of deterministicColumns) {
    if (row[col] === null || row[col] === undefined) continue;
    decrypted[col] = decryptDeterministicFromStorage(deterministicKey, row[col]);
  }
  if (!row.wrapped_dek || row.key_version === null || row.key_version === undefined) {
    return decrypted;
  }
  const dek = kms.unwrapDEK(Buffer.from(row.wrapped_dek, 'base64'), row.key_version);
  const aad = buildRowAad(tableEntry, row);
  try {
    for (const col of sensitiveColumns) {
      if (row[col] === null || row[col] === undefined) continue;
      const unpacked = unpackFromStorage(row[col]);
      const plainBuf = decryptField(dek, unpacked.ciphertext, unpacked.iv, unpacked.authTag, aad);
      const plainStr = plainBuf.toString('utf8');
      const colDef = tableEntry.columns.find((c) => c.columnName === col);
      decrypted[col] = fromDecryptedString(plainStr, colDef && colDef.dataType);
    }
  } finally {
    wipe(dek);
  }
  return decrypted;
}

app.get('/tables/:tableName/records', authenticateDashboardUser, async (req, res) => {
  let proposal;
  try {
    proposal = loadMigrationProposalSafe();
  } catch (err) {
    return res.status(500).json({
      error: 'could not load the reviewed migration proposal',
      detail: err.message,
    });
  }
  const tableEntry = proposal.tables.find((t) => t.tableName === req.params.tableName);
  if (!tableEntry) {
    return res.status(404).json({
      error: `table "${req.params.tableName}" is not in the reviewed proposal`,
    });
  }
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const offset = parseInt(req.query.offset, 10) || 0;
  try {
    const pool = getTablesPool();
    const columnNames = tableEntry.columns
      .map((c) => c.columnName)
      .concat(['wrapped_dek', 'key_version']);
    const result = await withRlsContext(pool, req.user, (client) =>
      client.query(
        `SELECT ${columnNames.join(', ')} FROM ${req.params.tableName} ORDER BY ${tableEntry.primaryKeyColumn} LIMIT $1 OFFSET $2`,
        [limit, offset],
      ),
    );
    const decryptedRows = result.rows.map((row) => {
      const {
        wrapped_dek: wrapped_dek,
        key_version: key_version,
        ...visibleFields
      } = decryptTableRow(row, tableEntry);
      return visibleFields;
    });
    auditLog('table_rows.viewed', {
      table: req.params.tableName,
      userId: req.user.userId,
      count: decryptedRows.length,
    });
    res.json({
      table: req.params.tableName,
      rows: decryptedRows,
      limit: limit,
      offset: offset,
    });
  } catch (err) {
    auditLog('table_rows.view_error', {
      table: req.params.tableName,
      userId: req.user.userId,
      error: err.message,
    });
    res.status(500).json({
      error: 'failed to fetch/decrypt rows',
      detail: err.message,
    });
  }
});

async function runKeyRotation() {
  const oldVersion = kms.getCurrentKeyVersion();
  auditLog('key_rotation.start', {
    oldVersion: oldVersion,
  });
  const newVersion = kms.rotateKEK();
  auditLog('key_rotation.kek_rotated', {
    oldVersion: oldVersion,
    newVersion: newVersion,
  });
  const rowsToMigrate = await db.getRecordsByKeyVersion(oldVersion);
  let migrated = 0,
    failed = 0;
  for (const row of rowsToMigrate) {
    try {
      const newKeyFields = rewrapRecordKey(row);
      await db.updateKeyMetadata(row.id, newKeyFields);
      migrated += 1;
    } catch (err) {
      failed += 1;
      auditLog('key_rotation.record_failed', {
        recordId: row.id,
        error: err.message,
      });
    }
  }
  auditLog('key_rotation.complete', {
    newVersion: newVersion,
    migrated: migrated,
    failed: failed,
  });
  if (failed === 0) {
    auditLog('key_rotation.old_key_ready_for_destruction', {
      oldVersion: oldVersion,
      note: 'Destroy only after your compliance-mandated grace period.',
    });
  }
  return {
    oldVersion: oldVersion,
    newVersion: newVersion,
    migrated: migrated,
    failed: failed,
  };
}

const ADMIN_USERS = {
  [CONFIG.ADMIN_TOKEN]: {
    userId: 'dba-1',
    role: 'db_admin',
    team: 'database-operations',
  },
};

async function adminDecryptRecord({
  adminToken: adminToken,
  recordId: recordId,
  reason: reason,
  fields: fields,
}) {
  if (!reason || !reason.trim()) {
    throw new Error('a reason (ticket/justification) is required for every admin decrypt');
  }
  const admin = ADMIN_USERS[adminToken];
  if (!admin) {
    auditLog('admin.decrypt.denied', {
      recordId: recordId,
      reason: reason,
    });
    throw new Error('unauthenticated: invalid or unrecognized admin credential');
  }
  const row = await db.getRecord(recordId);
  if (!row) {
    auditLog('admin.decrypt.not_found', {
      adminUserId: admin.userId,
      recordId: recordId,
      reason: reason,
    });
    throw new Error(`record ${recordId} not found`);
  }
  let decrypted;
  try {
    decrypted = decryptRecord(recordId, row);
  } catch (err) {
    auditLog('admin.decrypt.error', {
      adminUserId: admin.userId,
      recordId: recordId,
      reason: reason,
      error: err.message,
    });
    throw err;
  }
  const returned =
    fields && fields.length ? Object.fromEntries(fields.map((f) => [f, decrypted[f]])) : decrypted;
  auditLog('admin.decrypt.success', {
    adminUserId: admin.userId,
    adminTeam: admin.team,
    recordId: recordId,
    reason: reason,
    fieldsRevealed: Object.keys(returned),
  });
  return returned;
}

async function sendSecurityAlert(subject, details) {
  const payload = {
    subject: subject,
    details: details,
    ts: new Date().toISOString(),
  };
  console.log(`\n[SECURITY/BACKEND ALERT] ${subject}`);
  console.log(JSON.stringify(details, null, 2));
  const webhookUrl = process.env.ALERT_WEBHOOK_URL;
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        text: `*${subject}*\n\`\`\`${JSON.stringify(details, null, 2)}\`\`\``,
      }),
    });
  } catch (err) {
    console.error(
      '[SECURITY/BACKEND ALERT] webhook delivery failed (alert was still logged above):',
      err.message,
    );
  }
}

const BACKFILL_BATCH_SIZE = parseInt(process.env.BACKFILL_BATCH_SIZE, 10) || 500;

const BACKFILL_PAUSE_MS = parseInt(process.env.BACKFILL_PAUSE_MS, 10) || 250;

function loadMigrationProposalSafe() {
  const proposalPath = path.join(__dirname, 'db', 'scripts', 'migration-proposal.json');
  if (!fs.existsSync(proposalPath)) {
    throw new Error(
      'No migration-proposal.json found. Run discoverSchema.js first, then review and approve the resulting proposal.',
    );
  }
  const proposal = JSON.parse(fs.readFileSync(proposalPath, 'utf8'));
  if (proposal.reviewed !== true) {
    throw new Error(
      'migration-proposal.json exists but "reviewed" is not set to true — a human must review it first.',
    );
  }
  return proposal;
}

function loadMigrationProposal() {
  try {
    return loadMigrationProposalSafe();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

function encryptRowForBackfill(recordId, plainValues) {
  const dek = generateDEK();
  const aad = Buffer.from(String(recordId), 'utf8');
  const encryptedValues = {};
  for (const [column, value] of Object.entries(plainValues)) {
    if (value === null || value === undefined) continue;
    const {
      ciphertext: ciphertext,
      iv: iv,
      authTag: authTag,
    } = encryptField(dek, toEncryptableString(value), aad);
    encryptedValues[column] = packForStorage({
      ciphertext: ciphertext,
      iv: iv,
      authTag: authTag,
    });
  }
  const { wrappedDEK: wrappedDEK, keyVersion: keyVersion } = kms.wrapDEK(dek);
  wipe(dek);
  return {
    encryptedValues: encryptedValues,
    wrappedDEK: wrappedDEK.toString('base64'),
    keyVersion: keyVersion,
  };
}


// Backfill: encrypt existing plaintext data in an external table
async function backfillTable(
  pool,
  tableEntry,
  { dryRun: dryRun, pkEncryptionConfirmed: pkEncryptionConfirmed },
) {
  const { tableName: tableName } = tableEntry;
  const primaryKeyColumns = getPrimaryKeyColumns(tableEntry);
  const primaryKeyColumn = primaryKeyColumns[0] || null;
  // Defense in depth: wrapped_dek/key_version are internal encryption
  // bookkeeping columns, added by a PREVIOUS backfill run — never real
  // data, and must never be treated as columns to encrypt, even if a
  // stale or hand-edited proposal file incorrectly lists them (this
  // happened for real: re-running discovery against an already-backfilled
  // table, before this filter existed, produced exactly this bug).
  const BOOKKEEPING_COLUMNS = new Set(['wrapped_dek', 'key_version']);
  const deterministicColumns = tableEntry.columns
    .filter((c) => c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  const pkIsBeingEncrypted = primaryKeyColumns.every((c) => deterministicColumns.includes(c));
  const sensitiveColumns = tableEntry.columns
    .filter((c) => !c.doNotEncrypt && !c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  if (primaryKeyColumns.length === 0) {
    console.log(`  SKIPPING ${tableName}: no primary key detected. A row cannot be safely targeted for migration.`);
    return { table: tableName, skipped: true, reason: 'no primary key' };
  }
  if (sensitiveColumns.length === 0 && deterministicColumns.length === 0) {
    console.log(`  SKIPPING ${tableName}: no columns marked sensitive in the reviewed proposal.`);
    return {
      table: tableName,
      skipped: true,
      reason: 'no sensitive columns',
    };
  }
  console.log(
    `\n  Table: ${tableName} (PK: ${primaryKeyColumn}${pkIsBeingEncrypted ? ' — WILL BE ENCRYPTED' : ''})`,
  );
  if (sensitiveColumns.length)
    console.log(`  Standard encryption (random IV): ${sensitiveColumns.join(', ')}`);
  if (deterministicColumns.length)
    console.log(`  Deterministic encryption (joinable): ${deterministicColumns.join(', ')}`);
  if (!dryRun) {
    const allEncryptedColumns = new Set([...sensitiveColumns, ...deterministicColumns]);
    const constraintsToDrop = new Set();
    for (const col of tableEntry.columns) {
      if (allEncryptedColumns.has(col.columnName) && Array.isArray(col.checkConstraintsToAutoDrop)) {
        for (const name of col.checkConstraintsToAutoDrop) constraintsToDrop.add(name);
      }
    }
    for (const constraintName of constraintsToDrop) {
      console.log(`  Permanently dropping CHECK constraint "${constraintName}" on ${tableName} — ciphertext can never satisfy a plaintext-value rule, so this cannot be restored afterward the way a foreign key can.`);
      await pool.query(`ALTER TABLE ${tableName} DROP CONSTRAINT IF EXISTS ${constraintName}`);
    }
  }
  await pool.query(`ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS wrapped_dek TEXT`);
  await pool.query(`ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS key_version INTEGER`);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_${tableName}_key_version_null ON ${tableName} (key_version) WHERE key_version IS NULL`,
  );
  const countResult = await pool.query(
    `SELECT COUNT(*) FROM ${tableName} WHERE key_version IS NULL`,
  );
  const totalRemaining = parseInt(countResult.rows[0].count, 10);
  console.log(`  Rows still unencrypted: ${totalRemaining}`);
  if (dryRun) {
    console.log(
      `  [DRY RUN] Would encrypt ${totalRemaining} rows in batches of ${BACKFILL_BATCH_SIZE}. No changes made.`,
    );
    if (pkIsBeingEncrypted) {
      console.log(
        `  [DRY RUN] NOTE: this table's primary key ("${primaryKeyColumn}") is marked for encryption too.`,
      );
      console.log(
        `  [DRY RUN] Running for real will additionally require the --confirm-pk-encryption flag.`,
      );
    }
    return {
      table: tableName,
      dryRun: true,
      wouldMigrate: totalRemaining,
      pkWouldBeEncrypted: pkIsBeingEncrypted,
    };
  }
  if (pkIsBeingEncrypted && !pkEncryptionConfirmed) {
    console.error(
      `  REFUSING to encrypt primary key "${primaryKeyColumn}" on ${tableName} without explicit confirmation.\n` +
      `  Encrypting a primary key is structurally different from other columns: it changes the column's\n` +
      `  type, removes its auto-increment default, and requires updating every OTHER place in your live\n` +
      `  system that inserts into this table — this script cannot see or fix those other insert paths.\n` +
      `  Re-run with --confirm-pk-encryption to proceed anyway, once that's understood and planned for.`,
    );
    return {
      table: tableName,
      refused: true,
      reason: 'primary key encryption requires --confirm-pk-encryption',
    };
  }
  for (const col of [...sensitiveColumns, ...deterministicColumns]) {
    try {
      await pool.query(`ALTER TABLE ${tableName} ALTER COLUMN ${col} TYPE TEXT USING ${col}::TEXT`);
    } catch (err) {
      console.error(`  FAILED to widen column ${col} to TEXT: ${err.message}`);
      return {
        table: tableName,
        refused: true,
        reason: `could not widen column ${col}: ${err.message}`,
      };
    }
  }
  if (pkIsBeingEncrypted) {
    try {
      await pool.query(`ALTER TABLE ${tableName} ALTER COLUMN ${primaryKeyColumn} DROP DEFAULT`);
      console.log(
        `  Removed the plaintext DB default on ${primaryKeyColumn}, but preserved the owned sequence.`,
      );
      console.log(
        `  Auto-increment remains available through the encryption-aware insert path, which obtains the`,
      );
      console.log(
        `  next sequence value and deterministically encrypts it before storage. Direct SQL INSERTs that`,
      );
      console.log(
        `  omit this encrypted PK are intentionally rejected rather than storing a plaintext key.`,
      );
    } catch (err) {
      console.error(`  FAILED to drop default on ${primaryKeyColumn}: ${err.message}`);
      return {
        table: tableName,
        refused: true,
        reason: `could not drop PK default: ${err.message}`,
      };
    }
  }
  const deterministicKey = kms.getDeterministicKey();
  let migrated = 0;
  let failed = 0;
  let consecutiveZeroProgressBatches = 0;
  for (; ;) {
    const migratedBeforeThisBatch = migrated;
    const client = await pool.connect();
    let shouldBreak = false;
    try {
      await client.query('BEGIN');
      const readColumns = [
        ...new Set([...primaryKeyColumns, ...sensitiveColumns, ...deterministicColumns]),
      ];
      const batchResult = await client.query(
        `SELECT ${readColumns.join(', ')} FROM ${tableName} WHERE key_version IS NULL LIMIT $1 FOR UPDATE SKIP LOCKED`,
        [BACKFILL_BATCH_SIZE],
      );
      const batchRows = batchResult.rows;
      if (batchRows.length === 0) {
        await client.query('COMMIT');
        shouldBreak = true;
      } else {
        const dek = generateDEK();
        const { wrappedDEK: wrappedDEK, keyVersion: keyVersion } = kms.wrapDEK(dek);
        const wrappedDEKStr = wrappedDEK.toString('base64');
        for (const row of batchRows) {
          const originalPkValues = Object.fromEntries(primaryKeyColumns.map((c) => [c, row[c]]));
          const finalPkValues = {};
          for (const pkCol of primaryKeyColumns) {
            finalPkValues[pkCol] = deterministicColumns.includes(pkCol)
              ? encryptDeterministicForStorage(deterministicKey, String(row[pkCol]))
              : row[pkCol];
          }
          const finalPkRow = { ...row, ...finalPkValues };
          const rowAad = buildRowAad(tableEntry, finalPkRow);
          try {
            const setClauses = [];
            const params = [];
            let i = 1;
            for (const col of sensitiveColumns) {
              const value = row[col];
              setClauses.push(`${col} = $${i}`);
              if (value === null || value === undefined) {
                params.push(null);
              } else {
                const aad = rowAad;
                const {
                  ciphertext: ciphertext,
                  iv: iv,
                  authTag: authTag,
                } = encryptField(dek, toEncryptableString(value), aad);
                params.push(
                  packForStorage({
                    ciphertext: ciphertext,
                    iv: iv,
                    authTag: authTag,
                  }),
                );
              }
              i += 1;
            }
            for (const col of deterministicColumns) {
              const value = row[col];
              setClauses.push(`${col} = $${i}`);
              params.push(
                value === null || value === undefined
                  ? null
                  : primaryKeyColumns.includes(col)
                    ? finalPkValues[col]
                    : encryptDeterministicForStorage(deterministicKey, String(value)),
              );
              i += 1;
            }
            setClauses.push(`wrapped_dek = $${i}`);
            params.push(wrappedDEKStr);
            i += 1;
            setClauses.push(`key_version = $${i}`);
            params.push(keyVersion);
            i += 1;
            const whereClauses = [];
            for (const pkCol of primaryKeyColumns) {
              whereClauses.push(`${pkCol} = $${i}`);
              params.push(originalPkValues[pkCol]);
              i += 1;
            }
            await client.query(
              `UPDATE ${tableName} SET ${setClauses.join(', ')} WHERE ${whereClauses.join(' AND ')}`,
              params,
            );
            migrated += 1;
          } catch (err) {
            failed += 1;
            console.error(
              `  FAILED to migrate ${tableName} PK=${JSON.stringify(originalPkValues)}: ${err.message}`,
            );
          }
        }
        wipe(dek);
        await client.query('COMMIT');
      }
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { });
      console.error(`  Batch failed entirely, rolled back: ${err.message}`);
      shouldBreak = true;
    } finally {
      client.release();
    }
    if (shouldBreak) break;

    if (migrated === migratedBeforeThisBatch) {
      // The batch had rows (we only reach here when shouldBreak was false,
      // meaning batchRows.length > 0), but NONE of them actually succeeded.
      // This is the exact signature of a transaction-abort cascade: one
      // row's real error poisons the whole transaction, every other row in
      // the batch fails with the generic "current transaction is aborted"
      // message, the batch effectively rolls back, and nothing about the
      // next iteration's SELECT would differ — so without this check, the
      // loop would retry the identical failing batch forever. A couple of
      // retries are allowed first, in case this was a genuinely transient
      // issue (a connection blip), but sustained zero progress means
      // something structural is wrong and needs a human to look at the
      // FAILED messages above, not an infinite retry loop.
      consecutiveZeroProgressBatches += 1;
      if (consecutiveZeroProgressBatches >= 2) {
        console.error(
          `  STOPPING: an entire batch made zero progress ${consecutiveZeroProgressBatches} times in a row for ${tableName}. This usually means the FIRST "FAILED to migrate" error above is the real cause — every row after it failed only because that first error aborted the whole transaction, not because those rows have their own separate problems. Fix the root cause (often a foreign key constraint blocking the update — see earlier in this conversation for the drop-before-backfill / restore-after pattern) and re-run.`,
        );
        break;
      }
    } else {
      consecutiveZeroProgressBatches = 0;
    }

    console.log(`  Progress: ${migrated} migrated, ${failed} failed (this table, so far)`);
    await new Promise((resolve) => setTimeout(resolve, BACKFILL_PAUSE_MS));
  }
  return {
    table: tableName,
    migrated: migrated,
    failed: failed,
  };
}

const BACKFILL_TABLE_CONCURRENCY = parseInt(process.env.BACKFILL_TABLE_CONCURRENCY, 10) || 3;

async function runWithConcurrencyLimit(items, concurrency, worker) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function runNext() {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      results[currentIndex] = await worker(items[currentIndex], currentIndex);
    }
  }
  const workers = Array.from(
    {
      length: Math.min(concurrency, items.length),
    },
    () => runNext(),
  );
  await Promise.all(workers);
  return results;
}

// Finds every real FOREIGN KEY constraint where either the constrained
// column or the referenced column belongs to a table/column being
// deterministically encrypted in this run. Encrypting such a column changes
// its stored value, which a live FK constraint will correctly refuse (the
// old and new values can't both satisfy the relationship mid-migration) —
// this is why the constraint must be dropped before backfill and restored
// after, not something a script should skip past.
async function findAffectedForeignKeys(pool, tablesToRun) {
  const encryptedColumnsByTable = {};
  for (const t of tablesToRun) {
    encryptedColumnsByTable[t.tableName] = new Set(
      t.columns.filter((c) => c.deterministicEncrypt).map((c) => c.columnName),
    );
  }
  const result = await pool.query(`
    SELECT
      con.oid,
      con.conname AS constraint_name,
      child.relname AS constrained_table,
      parent.relname AS referenced_table,
      ARRAY(
        SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
        ORDER BY k.ord
      ) AS constrained_columns,
      ARRAY(
        SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum
        ORDER BY k.ord
      ) AS referenced_columns,
      pg_get_constraintdef(con.oid) AS definition
    FROM pg_constraint con
    JOIN pg_class child ON child.oid = con.conrelid
    JOIN pg_class parent ON parent.oid = con.confrelid
    JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
    WHERE con.contype = 'f' AND child_ns.nspname = 'public'
  `);
  // node-postgres normally parses PostgreSQL text[] as a JavaScript array,
  // but custom type parsers can return an array-literal string. Normalize
  // both forms before using Array.prototype.some().
  const normalizePgTextArray = (value) => {
    if (Array.isArray(value)) return value;
    if (value == null) return [];
    if (typeof value !== 'string') return [];
    const trimmed = value.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        return Array.isArray(parsed) ? parsed : [];
      } catch (_) {
        return [];
      }
    }
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      return trimmed.slice(1, -1)
        .split(',')
        .map((v) => v.replace(/^\"|\"$/g, '').replace(/\\\"/g, '\"'))
        .filter(Boolean);
    }
    return [trimmed];
  };

  return result.rows
    .map((row) => ({
      ...row,
      constrained_columns: normalizePgTextArray(row.constrained_columns),
      referenced_columns: normalizePgTextArray(row.referenced_columns),
    }))
    .filter((row) => {
      const childSet = encryptedColumnsByTable[row.constrained_table] || new Set();
      const parentSet = encryptedColumnsByTable[row.referenced_table] || new Set();
      return row.constrained_columns.some((c) => childSet.has(c)) ||
        row.referenced_columns.some((c) => parentSet.has(c));
    });
}

async function withTemporarilyDroppedForeignKeys(pool, tablesToRun, fn) {
  const affected = await findAffectedForeignKeys(pool, tablesToRun);
  if (affected.length === 0) return fn();

  console.log(`\nAutomatically dropping ${affected.length} foreign key constraint(s) that would otherwise block this backfill (will be restored after):`);
  const quoteIdent = (name) => `\"${String(name).replaceAll('\"', '\"\"')}\"`;
  for (const fk of affected) {
    console.log(`  ${fk.constrained_table}(${fk.constrained_columns.join(', ')}) -> ${fk.referenced_table}(${fk.referenced_columns.join(', ')})`);
    await pool.query(`ALTER TABLE ${fk.constrained_table} DROP CONSTRAINT ${quoteIdent(fk.constraint_name)}`);
  }

  try {
    return await fn();
  } finally {
    console.log(`\nRestoring ${affected.length} foreign key constraint(s):`);
    for (const fk of affected) {
      try {
        const constraintName = fk.constraint_name;
        await pool.query(`ALTER TABLE ${fk.constrained_table} ADD CONSTRAINT ${quoteIdent(constraintName)} ${fk.definition}`);
        console.log(`  Restored ${constraintName}.`);
      } catch (err) {
        console.error(`  FAILED to restore ${fk.constraint_name}: ${err.message}`);
      }
    }
  }
}

async function runBackfill({
  confirm: confirm,
  table: table,
  pkEncryptionConfirmed: pkEncryptionConfirmed,
}) {
  const proposal = loadMigrationProposal();
  const databaseUrl = CONFIG.DATABASE_URL || process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error(
      'DATABASE_URL is required for the backfill (set it even if the main app is using DB_PROVIDER=in-memory — the backfill targets your existing live table directly).',
    );
    process.exit(1);
  }
  const pool = new Pool({
    connectionString: databaseUrl,
    max: parseInt(process.env.PG_POOL_MAX, 10) || 10,
  });
  let tablesToRun = proposal.tables;
  if (table) {
    tablesToRun = proposal.tables.filter((t) => t.tableName === table);
    if (tablesToRun.length === 0) {
      console.error(`Table "${table}" not found in the reviewed proposal.`);
      await pool.end();
      process.exit(1);
    }
  }
  console.log(
    confirm
      ? '=== RUNNING BACKFILL (writes will happen) ==='
      : '=== DRY RUN (no changes will be made — pass --confirm to actually run) ===',
  );
  if (tablesToRun.length > 1) {
    console.log(
      `Processing ${tablesToRun.length} tables, up to ${Math.min(BACKFILL_TABLE_CONCURRENCY, tablesToRun.length)} concurrently.`,
    );
  }
  let results;
  try {
    const runAll = () =>
      runWithConcurrencyLimit(tablesToRun, BACKFILL_TABLE_CONCURRENCY, (tableEntry) =>
        backfillTable(pool, tableEntry, {
          dryRun: !confirm,
          pkEncryptionConfirmed: pkEncryptionConfirmed,
        }),
      );
    // Only drop/restore real constraints for an actual run — a dry run
    // makes no changes at all, so there's nothing to protect against yet.
    results = confirm
      ? await withTemporarilyDroppedForeignKeys(pool, tablesToRun, runAll)
      : await runAll();
  } finally {
    await pool.end();
  }
  console.log('\n=== Summary ===');
  console.log(JSON.stringify(results, null, 2));
  if (!confirm) {
    console.log('\nThis was a dry run. Re-run with --confirm to actually perform the backfill.');
    return results;
  }
  const totalMigrated = results.reduce((sum, r) => sum + (r.migrated || 0), 0);
  const totalFailed = results.reduce((sum, r) => sum + (r.failed || 0), 0);
  const tablesWithFailures = results.filter((r) => (r.failed || 0) > 0).map((r) => r.table);
  const tablesRefused = results
    .filter((r) => r.refused)
    .map((r) => ({
      table: r.table,
      reason: r.reason,
    }));
  let subject = 'Backfill encryption completed successfully';
  if (tablesRefused.length > 0)
    subject = 'Backfill encryption BLOCKED for one or more tables — review needed';
  else if (totalFailed > 0) subject = 'Backfill encryption completed WITH FAILURES — review needed';
  await sendSecurityAlert(subject, {
    tablesProcessed: results.map((r) => r.table),
    totalRowsMigrated: totalMigrated,
    totalRowsFailed: totalFailed,
    tablesWithFailures: tablesWithFailures,
    tablesRefused: tablesRefused,
    perTableResults: results,
  });
  return results;
}


// Ongoing inserts: encrypt NEW rows in an external table
async function getSequenceForEncryptedPrimaryKey(pool, tableName, columnName) {
  // pg_get_serial_sequence normally finds SERIAL/IDENTITY sequences. The
  // encryption migration removes the plaintext DEFAULT because a DB default
  // cannot safely call the external KMS, but the underlying sequence ownership
  // is preserved. Fall back to pg_depend so auto-increment semantics remain
  // available to the encryption-aware insert path even after the DEFAULT is gone.
  const direct = await pool.query(`SELECT pg_get_serial_sequence($1, $2) AS seq`, [tableName, columnName]);
  if (direct.rows[0]?.seq) return direct.rows[0].seq;

  const fallback = await pool.query(`
    SELECT format('%I.%I', ns.nspname, seq.relname) AS seq
    FROM pg_class seq
    JOIN pg_namespace ns ON ns.oid = seq.relnamespace
    JOIN pg_depend dep ON dep.objid = seq.oid
    JOIN pg_class tbl ON tbl.oid = dep.refobjid
    JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = dep.refobjsubid
    WHERE seq.relkind = 'S'
      AND tbl.relname = $1
      AND attr.attname = $2
      AND dep.deptype IN ('a', 'i')
    LIMIT 1
  `, [tableName, columnName]);
  return fallback.rows[0]?.seq || null;
}

async function insertEncryptedRow(pool, tableEntry, plainRow) {
  const tableName = tableEntry.tableName;
  const primaryKeyColumns = getPrimaryKeyColumns(tableEntry);
  const BOOKKEEPING_COLUMNS = new Set(['wrapped_dek', 'key_version']);
  const sensitiveColumns = tableEntry.columns
    .filter((c) => !c.doNotEncrypt && !c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  const deterministicColumns = tableEntry.columns
    .filter((c) => c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);

  const finalValues = { ...plainRow };
  const deterministicKey = kms.getDeterministicKey();

  // Generate a value for the internal row identifier used by tables that had
  // no primary key at discovery time. It is immediately stored as deterministic
  // ciphertext, never as plaintext.
  if (primaryKeyColumns.length === 1 && primaryKeyColumns[0] === '__enc_row_id' && finalValues.__enc_row_id == null) {
    finalValues.__enc_row_id = crypto.randomUUID();
  }

  // Preserve the existing SERIAL/identity convenience for a single PK. For
  // composite keys, callers must provide the complete key explicitly.
  for (const pkCol of primaryKeyColumns) {
    if (finalValues[pkCol] === undefined || finalValues[pkCol] === null) {
      if (primaryKeyColumns.length !== 1) {
        throw new Error(`Missing composite primary-key value: ${pkCol}`);
      }
      const seq = await getSequenceForEncryptedPrimaryKey(pool, tableName, pkCol);
      if (!seq) throw new Error(`Missing primary-key value ${pkCol} and no owned sequence is available. The table must retain its SERIAL/IDENTITY sequence for encryption-aware auto-generation.`);
      const nextValResult = await pool.query(`SELECT nextval($1) AS next_id`, [seq]);
      finalValues[pkCol] = nextValResult.rows[0].next_id;
    }
  }

  for (const col of deterministicColumns) {
    if (finalValues[col] === undefined || finalValues[col] === null) continue;
    finalValues[col] = encryptDeterministicForStorage(deterministicKey, String(finalValues[col]));
  }

  const AUTO_TIMESTAMP_COLUMN_NAMES = new Set(['created_at', 'updated_at']);
  const nowIso = new Date().toISOString();
  for (const col of sensitiveColumns) {
    if (AUTO_TIMESTAMP_COLUMN_NAMES.has(col) && (finalValues[col] === undefined || finalValues[col] === null)) {
      finalValues[col] = nowIso;
    }
  }

  const plainValuesForDek = {};
  for (const col of sensitiveColumns) {
    if (finalValues[col] !== undefined && finalValues[col] !== null) plainValuesForDek[col] = finalValues[col];
  }
  const dek = generateDEK();
  const aad = buildRowAad(tableEntry, finalValues);
  for (const [col, value] of Object.entries(plainValuesForDek)) {
    const { ciphertext, iv, authTag } = encryptField(dek, toEncryptableString(value), aad);
    finalValues[col] = packForStorage({ ciphertext, iv, authTag });
  }
  const { wrappedDEK, keyVersion } = kms.wrapDEK(dek);
  wipe(dek);
  finalValues.wrapped_dek = wrappedDEK.toString('base64');
  finalValues.key_version = keyVersion;

  const columns = Object.keys(finalValues);
  const placeholders = columns.map((_, i) => `$${i + 1}`);
  const values = columns.map((c) => finalValues[c]);
  const result = await pool.query(
    `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING *`,
    values,
  );
  return result.rows[0];
}

const CIPHERTEXT_FORMAT_PATTERN = '^v[12]\\.';

async function lockTableColumns(pool, tableEntry, { dryRun: dryRun } = {}) {
  const { tableName: tableName } = tableEntry;
  const BOOKKEEPING_COLUMNS = new Set(['wrapped_dek', 'key_version']); // never real data — see backfillTable for why this filter exists
  const sensitiveColumns = tableEntry.columns
    .filter((c) => !c.doNotEncrypt && !c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  const deterministicColumns = tableEntry.columns
    .filter((c) => c.deterministicEncrypt && !BOOKKEEPING_COLUMNS.has(c.columnName))
    .map((c) => c.columnName);
  const columnsToLock = [...sensitiveColumns, ...deterministicColumns];
  if (columnsToLock.length === 0) {
    return {
      table: tableName,
      skipped: true,
      reason: 'no encrypted columns to lock',
    };
  }
  if (dryRun) {
    console.log(
      `  [DRY RUN] Would add a CHECK CONSTRAINT to ${columnsToLock.length} columns on ${tableName}: ${columnsToLock.join(', ')}`,
    );
    return {
      table: tableName,
      dryRun: true,
      wouldLock: columnsToLock,
    };
  }
  const locked = [];
  const failed = [];
  for (const col of columnsToLock) {
    const constraintName = `chk_${tableName}_${col}_encrypted`;
    try {
      await pool.query(
        `ALTER TABLE ${tableName} ADD CONSTRAINT ${constraintName} CHECK (${col} IS NULL OR ${col} ~ '${CIPHERTEXT_FORMAT_PATTERN}')`,
      );
      locked.push(col);
    } catch (err) {
      failed.push({
        column: col,
        error: err.message,
      });
      console.error(`  FAILED to lock ${tableName}.${col}: ${err.message}`);
      if (err.message.includes('violates check constraint')) {
        console.error(
          `  This usually means ${col} still has unmigrated (plaintext) rows — run the backfill for this table first.`,
        );
      }
    }
  }
  console.log(`  Locked ${locked.length}/${columnsToLock.length} columns on ${tableName}.`);
  return {
    table: tableName,
    locked: locked,
    failed: failed,
  };
}

const BOOLEAN_ONLY_FLAGS = new Set(['confirm', 'confirm-pk-encryption']);

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const eqIndex = argv[i].indexOf('=');
      if (eqIndex !== -1) {
        args[argv[i].slice(2, eqIndex)] = argv[i].slice(eqIndex + 1);
      } else {
        const key = argv[i].slice(2);
        if (BOOLEAN_ONLY_FLAGS.has(key)) {
          args[key] = true;
        } else {
          args[key] = argv[i + 1];
          i += 1;
        }
      }
    }
  }
  return args;
}


// Verification: checks KMS/RLS/concurrent-backfill against a real DB
async function runProductionReadinessVerification() {
  const results = [];
  function record(name, passed, detail) {
    results.push({
      name: name,
      passed: passed,
      detail: detail,
    });
    console.log(`${passed ? '✅ PASS' : '❌ FAIL'} — ${name}`);
    if (detail) console.log(`    ${detail}`);
  }
  const databaseUrl = CONFIG.DATABASE_URL || process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL is required.');
    return false;
  }
  const pool = new Pool({
    connectionString: databaseUrl,
  });
  console.log('\n=== CHECK 1: KMS is real, not the demo fallback ===');
  const provider = process.env.KMS_PROVIDER || 'local';
  if (provider === 'local') {
    record(
      'KMS provider',
      false,
      'KMS_PROVIDER is unset or "local" — still using the demo file-based key. Set KMS_PROVIDER=aws or KMS_PROVIDER=vault with real credentials before this can pass.',
    );
  } else {
    try {
      const realKms = await createKMS();
      const dek = generateDEK();
      const { wrappedDEK: wrappedDEK, keyVersion: keyVersion } = realKms.wrapDEK(dek);
      const unwrapped = realKms.unwrapDEK(wrappedDEK, keyVersion);
      const roundTripOk = Buffer.compare(dek, unwrapped) === 0;
      record(
        `KMS provider (${provider})`,
        roundTripOk,
        roundTripOk
          ? `Connected to real ${provider.toUpperCase()} KMS, wrap/unwrap round trip verified.`
          : 'Connected, but the round trip did not return the original value — investigate before trusting this KMS.',
      );
    } catch (err) {
      record(`KMS provider (${provider})`, false, `Could not connect: ${err.message}`);
    }
  }
  console.log('\n=== CHECK 2: Row-Level Security is actually applied and enforcing ===');
  try {
    const rlsResult = await pool.query(
      `\n      SELECT relname, relrowsecurity FROM pg_class\n      WHERE relname IN ('families', 'family_members', 'submitted_baseline_forms')\n    `,
    );
    if (rlsResult.rows.length === 0) {
      record(
        'RLS enabled on tables',
        false,
        'None of families/family_members/submitted_baseline_forms exist in this database yet.',
      );
    } else {
      const missing = rlsResult.rows.filter((r) => !r.relrowsecurity);
      if (missing.length > 0) {
        record(
          'RLS enabled on tables',
          false,
          `RLS is NOT enabled on: ${missing.map((r) => r.relname).join(', ')}. Run db/migrations/003_row_level_security.sql against this database.`,
        );
      } else {
        record(
          'RLS enabled on tables',
          true,
          `Confirmed enabled on: ${rlsResult.rows.map((r) => r.relname).join(', ')}`,
        );
        const policyResult = await pool.query(
          `\n          SELECT tablename, COUNT(*) AS policy_count FROM pg_policies\n          WHERE tablename IN ('families', 'family_members', 'submitted_baseline_forms')\n          GROUP BY tablename\n        `,
        );
        const hasPolicies = policyResult.rows.every((r) => parseInt(r.policy_count, 10) > 0);
        record(
          'RLS policies exist',
          hasPolicies && policyResult.rows.length > 0,
          JSON.stringify(policyResult.rows),
        );
      }
    }
  } catch (err) {
    record('RLS check', false, `Query failed: ${err.message}`);
  }
  console.log(
    '\n=== CHECK 3: concurrent multi-table backfill actually works against real tables ===',
  );
  try {
    const proposal = loadMigrationProposalSafe();
    const testableTables = proposal.tables.filter((t) =>
      ['families', 'family_members'].includes(t.tableName),
    );
    if (testableTables.length < 2) {
      record(
        'Concurrent backfill',
        false,
        'Need both families and family_members in the reviewed proposal — found: ' +
        testableTables.map((t) => t.tableName).join(', '),
      );
    } else {
      const before = await Promise.all(
        testableTables.map((t) =>
          pool.query(`SELECT COUNT(*) FROM ${t.tableName} WHERE key_version IS NULL`),
        ),
      );
      const unmigratedBefore = before.reduce((sum, r) => sum + parseInt(r.rows[0].count, 10), 0);
      const startTimes = {};
      const endTimes = {};
      const runResults = await runWithConcurrencyLimit(testableTables, 2, async (tableEntry) => {
        startTimes[tableEntry.tableName] = Date.now();
        const r = await backfillTable(pool, tableEntry, {
          dryRun: true,
        });
        endTimes[tableEntry.tableName] = Date.now();
        return r;
      });
      const overlapped = testableTables.some((a) =>
        testableTables.some(
          (b) =>
            a.tableName !== b.tableName &&
            startTimes[a.tableName] < endTimes[b.tableName] &&
            startTimes[a.tableName] >= startTimes[b.tableName],
        ),
      );
      record(
        'Concurrent backfill ran across tables',
        runResults.length === testableTables.length,
        `Processed ${runResults.length} tables. Genuine overlap in execution time: ${overlapped}.`,
      );
      record(
        'Backfill correctly reports table state',
        true,
        `Rows still unmigrated (dry run only, nothing written): ${unmigratedBefore}`,
      );
    }
  } catch (err) {
    record('Concurrent backfill', false, `Failed: ${err.message}`);
  }
  await pool.end();
  console.log('\n' + '='.repeat(60));
  console.log('SUMMARY');
  console.log('='.repeat(60));
  const passedCount = results.filter((r) => r.passed).length;
  console.log(`${passedCount}/${results.length} checks passed.`);
  for (const r of results) console.log(`  ${r.passed ? '✅' : '❌'} ${r.name}`);
  console.log(
    passedCount < results.length
      ? '\nNOT all checks passed — do not treat this environment as production-ready.'
      : '\nAll checks passed against this database.',
  );
  return passedCount === results.length;
}

if (require.main === module) {
  const [, , command, ...rest] = process.argv;
  (async () => {
    // PRODUCTION SAFETY GATE — refuses to start at all if NODE_ENV=production
    // but demo-only settings are still active. This is deliberate and not
    // bypassable via a flag: a demo key stored in a plaintext file, or
    // static bearer tokens standing in for real login, must never silently
    // run against real citizen data just because someone forgot to update
    // .env when promoting to production. Fail loudly at startup, not
    // silently at 2am when someone notices the wrong thing happened.
    if ((process.env.NODE_ENV || CONFIG.NODE_ENV) === 'production') {
      const problems = [];
      if ((process.env.KMS_PROVIDER || 'local') === 'local') {
        problems.push('KMS_PROVIDER is "local" (or unset) — this stores the encryption key in a plaintext file. Set KMS_PROVIDER=aws or KMS_PROVIDER=vault with real credentials.');
      }
      if ((process.env.AUTH_PROVIDER || 'demo') === 'demo') {
        problems.push('AUTH_PROVIDER is "demo" (or unset) — this uses static bearer tokens instead of real login. Set AUTH_PROVIDER=oidc with your real identity provider configured.');
      }
      if (problems.length > 0) {
        console.error('\n' + '='.repeat(70));
        console.error('REFUSING TO START: NODE_ENV=production but demo settings are active.');
        console.error('='.repeat(70));
        for (const p of problems) console.error('  - ' + p);
        console.error('\nThis check exists specifically to prevent demo-only security settings');
        console.error('from ever silently running against real production data. Fix the');
        console.error('env vars above, or set NODE_ENV to something other than "production"');
        console.error('if this genuinely is not a production environment.');
        console.error('='.repeat(70) + '\n');
        process.exit(1);
      }
    }

    kms = await createKMS();
    if (command === 'rotate') {
      const result = await runKeyRotation();
      console.log('\nRotation result:', result);
      console.log('Key versions:', kms.listKeyVersions());
      await db.close();
    } else if (command === 'admin-decrypt') {
      const args = parseArgs(rest);
      if (!args['record-id'] || !args['admin-token']) {
        console.error(
          'Usage: node secure-dashboard.js admin-decrypt --record-id <id> --admin-token <token> --reason "<why>" [--fields a,b,c]',
        );
        process.exit(1);
      }
      try {
        const result = await adminDecryptRecord({
          adminToken: args['admin-token'],
          recordId: args['record-id'],
          reason: args.reason,
          fields: args.fields ? args.fields.split(',') : null,
        });
        console.log('\nDecrypted record:', JSON.stringify(result, null, 2));
      } catch (err) {
        console.error('\nDenied:', err.message);
        process.exitCode = 1;
      } finally {
        await db.close();
      }
    } else if (command === 'encrypt-all') {
      const args = parseArgs(rest);
      const { autoEncryptDatabase } = require('./auto-encrypt-all');
      await autoEncryptDatabase({
        confirm: args.confirm === true || 'confirm' in args,
        lock: args.lock !== false,
      });
    } else if (command === 'backfill') {
      const args = parseArgs(rest);
      await runBackfill({
        confirm: args.confirm === true || 'confirm' in args,
        table: args.table || null,
        pkEncryptionConfirmed:
          args['confirm-pk-encryption'] === true || 'confirm-pk-encryption' in args,
      });
    } else if (command === 'insert-row') {
      const args = parseArgs(rest);
      if (!args.table || !args.data) {
        console.error(
          'Usage: node secure-dashboard.js insert-row --table=<name> --data=\'{"col":"value", ...}\'',
        );
        process.exit(1);
      }
      const proposal = loadMigrationProposal();
      const tableEntry = proposal.tables.find((t) => t.tableName === args.table);
      if (!tableEntry) {
        console.error(`Table "${args.table}" not found in the reviewed proposal.`);
        process.exit(1);
      }
      let plainRow;
      try {
        plainRow = JSON.parse(args.data);
      } catch (err) {
        console.error('Could not parse --data as JSON:', err.message);
        process.exit(1);
      }
      const databaseUrl = CONFIG.DATABASE_URL || process.env.DATABASE_URL;
      if (!databaseUrl) {
        console.error('DATABASE_URL is required.');
        process.exit(1);
      }
      const pool = new Pool({
        connectionString: databaseUrl,
      });
      try {
        const insertedRow = await insertEncryptedRow(pool, tableEntry, plainRow);
        console.log('Row inserted, fully encrypted:', JSON.stringify(insertedRow, null, 2));
      } finally {
        await pool.end();
      }
    } else if (command === 'lock-columns') {
      const args = parseArgs(rest);
      if (!args.table) {
        console.error('Usage: node secure-dashboard.js lock-columns --table=<name> [--confirm]');
        process.exit(1);
      }
      const proposal = loadMigrationProposal();
      const tableEntry = proposal.tables.find((t) => t.tableName === args.table);
      if (!tableEntry) {
        console.error(`Table "${args.table}" not found in the reviewed proposal.`);
        process.exit(1);
      }
      const databaseUrl = CONFIG.DATABASE_URL || process.env.DATABASE_URL;
      if (!databaseUrl) {
        console.error('DATABASE_URL is required.');
        process.exit(1);
      }
      const pool = new Pool({
        connectionString: databaseUrl,
      });
      const confirm = args.confirm === true || 'confirm' in args;
      try {
        const result = await lockTableColumns(pool, tableEntry, {
          dryRun: !confirm,
        });
        console.log(JSON.stringify(result, null, 2));
        if (!confirm)
          console.log(
            '\nThis was a dry run. Re-run with --confirm to actually apply the constraints.',
          );
      } finally {
        await pool.end();
      }
    } else if (command === 'audit-maintenance') {
      const args = parseArgs(rest);
      await runAuditMaintenance({
        confirm: args.confirm === true || 'confirm' in args,
      });
    } else if (command === 'compute-lookup') {
      const args = parseArgs(rest);
      if (!args.value) {
        console.error('Usage: node secure-dashboard.js compute-lookup --value="HH-DYNAMIC-0001"');
        console.error(
          'Prints the exact ciphertext a deterministically-encrypted column (hhid, sno, gp_id) would',
        );
        console.error(
          'store for this plaintext value — paste the output into a raw SQL WHERE clause to find it,',
        );
        console.error("e.g.: SELECT * FROM families WHERE hhid = '<output>';");
        process.exit(1);
      }
      const lookupValue = encryptDeterministicForStorage(kms.getDeterministicKey(), args.value);
      console.log(lookupValue);
    } else if (command === 'verify') {
      const passed = await runProductionReadinessVerification();
      process.exit(passed ? 0 : 1);
    } else {
      const PORT = CONFIG.PORT;
      app.listen(PORT, () =>
        console.log(`Secure dashboard API listening on http://localhost:${PORT}`),
      );
    }
  })().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}

module.exports = {
  CONFIG: CONFIG,
  createKMS: createKMS,
  AwsKMS: AwsKMS,
  VaultKMS: VaultKMS,
  verifyOidcToken: verifyOidcToken,
  authenticateDashboardUser: authenticateDashboardUser,
  withRlsContext: withRlsContext,
  runProductionReadinessVerification: runProductionReadinessVerification,
  findAffectedForeignKeys: findAffectedForeignKeys,
  withTemporarilyDroppedForeignKeys: withTemporarilyDroppedForeignKeys,
  LocalKMS: LocalKMS,
  generateDEK: generateDEK,
  encryptField: encryptField,
  decryptField: decryptField,
  packForStorage: packForStorage,
  unpackFromStorage: unpackFromStorage,
  wipe: wipe,
  toEncryptableString: toEncryptableString,
  encryptFieldDeterministic: encryptFieldDeterministic,
  decryptFieldDeterministic: decryptFieldDeterministic,
  encryptDeterministicForStorage: encryptDeterministicForStorage,
  decryptDeterministicFromStorage: decryptDeterministicFromStorage,
  LocalKMS: LocalKMS,
  kms: kms,
  encryptRecord: encryptRecord,
  decryptRecord: decryptRecord,
  rewrapRecordKey: rewrapRecordKey,
  NOT_ENCRYPTED_FIELDS: NOT_ENCRYPTED_FIELDS,
  app: app,
  db: db,
  runKeyRotation: runKeyRotation,
  adminDecryptRecord: adminDecryptRecord,
  auditLog: auditLog,
  runBackfill: runBackfill,
  backfillTable: backfillTable,
  getPrimaryKeyColumns: getPrimaryKeyColumns,
  buildRowAad: buildRowAad,
  encryptRowForBackfill: encryptRowForBackfill,
  sendSecurityAlert: sendSecurityAlert,
  loadMigrationProposal: loadMigrationProposal,
  loadMigrationProposalSafe: loadMigrationProposalSafe,
  parseArgs: parseArgs,
  runWithConcurrencyLimit: runWithConcurrencyLimit,
  insertEncryptedRow: insertEncryptedRow,
  getSequenceForEncryptedPrimaryKey: getSequenceForEncryptedPrimaryKey,
  decryptTableRow: decryptTableRow,
  lockTableColumns: lockTableColumns,
  ensureAuditLogPartitions: ensureAuditLogPartitions,
  detachOldAuditLogPartitions: detachOldAuditLogPartitions,
  runAuditMaintenance: runAuditMaintenance,
};