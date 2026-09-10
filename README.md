# PostgreSQL Field-Level Encryption Tool — Initial Implementation (v1)

Built a PostgreSQL field-level encryption tool designed to encrypt existing database data while preserving relational integrity between encrypted keys and values.

The current implementation uses **AES-256-GCM envelope encryption** and has been tested against a PostgreSQL database containing multiple related tables.

## Prerequisites

- Node.js
- PostgreSQL
- PostgreSQL database connection configuration
- KMS configuration for production deployments

## Current Implementation

### Encryption

* AES-256-GCM authenticated encryption
* Envelope encryption architecture
* Versioned encrypted values
* Per-table/data-encryption-key handling
* Key-version tracking
* Deterministic encryption for relational/structural fields where equality matching is required
* Standard randomized encryption for other fields
* Authentication data (AAD) binding encrypted values to their row/primary-key context

### Database Structure & Key Handling

* Primary Key encryption
* Foreign Key encryption
* Composite Primary Key support
* Composite Foreign Key support
* UNIQUE constraint/column encryption
* Deterministic encryption for PK/FK/UNIQUE fields to preserve relational integrity
* Auto-increment/sequence handling for encrypted Primary Keys
* Tables without Primary Keys are handled using an internal encrypted-row identifier
* Foreign Keys are temporarily handled during migration and restored afterward
* Existing relational constraints are preserved where supported by the migration process

### Automatic Schema Discovery

* Automatically scans the live PostgreSQL database
* Detects tables and columns
* Detects Primary Keys
* Detects Foreign Keys
* Detects UNIQUE constraints
* Detects CHECK constraints
* Detects generated columns
* Detects triggers
* Detects column data types
* Detects defaults
* Detects composite keys
* Identifies structural columns that require deterministic encryption
* Generates a migration proposal/audit artifact

The migration proposal is treated as an **audit/review artifact rather than a permanent allow-list**, allowing the live database schema to be rescanned before encryption.

### Automatic Encryption / Migration

* Automatically processes all discovered PostgreSQL base tables within the current supported schema scope
* Supports large numbers of tables without manually specifying each table
* Existing plaintext data can be backfilled into encrypted form
* Migration temporarily handles affected Foreign Keys
* Encrypted columns can be locked against future plaintext database writes
* Performs zero-plaintext verification after migration
* Verifies encrypted values and key-version metadata
* Reports failed/refused/skipped migrations
* Supports encryption-aware insertion of new records
* Preserves encrypted relational behavior when inserting new data

### Data Types

The implementation includes handling for different PostgreSQL value representations, including:

* Text/string values
* Numeric values
* Boolean values
* Dates/timestamps
* JSON/JSON-like values
* PostgreSQL arrays
* Binary/Buffer/bytea values
* Special data types encountered during schema discovery

### Constraints & Special Cases

The migration identifies database features that require special handling, including:

* CHECK constraints
* Generated columns
* Database defaults
* Auto-increment sequences
* Triggers
* Composite keys
* Tables without Primary Keys
* Narrow VARCHAR columns
* EXCLUDE constraints

Some database-side expressions/constraints may require application-level handling after encryption because their original logic may not operate correctly against ciphertext.

### Key Management

The architecture is designed to support external key-management systems.

Current development/testing includes local KMS state, while production-oriented handling is designed around external systems such as:

* AWS KMS
* HashiCorp Vault
* Azure Key Vault — future integration/evaluation

Production mode is intended to reject local/demo KMS usage.

### Testing Performed

The implementation has been tested against PostgreSQL with:

* Multiple related tables
* Existing encrypted data migration
* Existing-data backfill
* Primary/Foreign Key relationships
* Deterministic encrypted PK/FK values
* Auto-generated encrypted Primary Keys
* New encrypted row insertion
* Foreign Key validation after encryption
* Multiple Foreign Keys referencing encrypted values
* Newly added table discovery and migration
* Zero-plaintext verification
* Encrypted-column locking

The current test database has been successfully migrated from **4 tables to 5 tables**, including the addition and encryption of a new `children` table.

## Current Scope

The current implementation is **PostgreSQL-specific**.

Potential future database support/testing includes:

* PostgreSQL — current implementation
* MySQL — future evaluation
* MariaDB — future evaluation
* Microsoft SQL Server — future evaluation
* Oracle Database — future evaluation
* SQLite — future evaluation
* Other relational database systems where practical

Database-specific adapters may be required because different database engines implement constraints, types, sequences, generated columns, indexes, triggers, and metadata differently.

# TODO

## PostgreSQL Testing & Hardening

* Test against different PostgreSQL databases and schemas
* Test databases with 30, 300, 1000+ tables
* Test very large datasets
* Test all relevant PostgreSQL data types
* Test composite Primary Keys
* Test composite Foreign Keys
* Test UNIQUE constraints and indexes
* Test tables without Primary Keys
* Test generated columns
* Test database defaults
* Test triggers
* Test CHECK constraints
* Test EXCLUDE constraints
* Test existing-data backfills
* Test updates to already-encrypted data
* Test insertion of new encrypted data
* Test new tables created after the initial encryption process
* Test concurrent reads/writes during migration
* Test migration failure recovery
* Improve rollback/recovery mechanisms
* Improve performance for large databases
* Improve zero-plaintext verification coverage
* Investigate PostgreSQL WAL, logs, temporary data and backup considerations

## Database Support

* Evaluate MySQL support
* Evaluate MariaDB support
* Evaluate Microsoft SQL Server support
* Evaluate Oracle Database support
* Evaluate SQLite support
* Identify database-specific encryption and constraint challenges
* Create database-specific adapters where required
* Test relational integrity across supported database engines
* Test database-specific data types and metadata discovery

## Key Management

* Test AWS KMS integration
* Test HashiCorp Vault integration
* Evaluate Azure Key Vault integration
* Improve key rotation
* Improve key-version management
* Test recovery from key-management failures
* Ensure production deployments never depend on local/demo key storage
* Improve secure key lifecycle management

## Security

* Perform a comprehensive security review
* Review deterministic encryption leakage and equality-pattern exposure
* Review AAD design and ciphertext binding
* Review key storage and key-access controls
* Review plaintext exposure through application logs/errors
* Review temporary migration data
* Review database WAL and backup exposure
* Review operational security during migration
* Conduct penetration/security testing
* Evaluate compliance requirements for production deployments

## Application / Lifecycle Support

* Add a proper encryption-aware UPDATE workflow
* Ensure modified existing values are automatically encrypted
* Handle new tables created after the initial migration
* Provide automated onboarding for newly created tables
* Improve detection of schema changes
* Handle schema migrations after encryption
* Improve application integration
* Prevent plaintext bypasses through unsupported database access paths
* Provide clearer migration and verification reports

## Usability & Deployment

* Reduce manual configuration requirements
* Improve automatic schema discovery
* Improve automatic identification of structural columns
* Improve CLI experience
* Add configuration validation
* Improve error messages
* Improve migration progress reporting
* Improve documentation
* Add production deployment documentation
* Add automated test suites
* Add integration tests against multiple PostgreSQL versions
* Add CI/CD testing
* Containerize the tool where useful
* Eventually package this as an easy-to-use reusable database encryption tool

  ## Usage

### 1. Discover the database schema

npm run scan

### 2. Preview the encryption migration

node auto-encrypt-all.js

### 3. Execute the encryption migration

node auto-encrypt-all.js --confirm

### 4. Insert encrypted data

node secure-dashboard.js insert-row --table=<table_name> --data='<json_data>'

Example:

node secure-dashboard.js insert-row --table=children --data='{"hhid":"EXISTING-HHID","name":"Test Child","relation":"Son","gender":"Male","age":"10"}'

### 5. Run tests

npm test

## Long-Term Goal

The long-term goal is to turn this prototype into a **reusable, production-grade database encryption tool** that can be pointed at an existing database, automatically understand its structure, safely migrate its data to encrypted form, preserve required relational behavior, and continue handling future data and schema changes with minimal manual configuration.

The project should eventually be usable through a simple workflow such as cloning/installing the repository or using a packaged CLI, rather than requiring users to manually modify encryption logic for every database.

