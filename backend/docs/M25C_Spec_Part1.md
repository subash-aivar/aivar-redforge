# M25C Implementation Specification — Part 1
## Enterprise Credential Vault: Infrastructure & API Layer
### Version 1.0 FROZEN | Authority: M25 Architecture v1.0 FINAL + M25B Spec v1.1

---

## §1. Goals

M25C wires the M25A domain and M25B application layers to real infrastructure. It delivers:

1. **Persistence** — Six SQLAlchemy repository implementations and one `IUnitOfWork` implementation backed by PostgreSQL via `asyncpg`.
2. **Encryption adapters** — `AesGcmEncryptionAdapter` (AES-256-GCM) and two `IKeyManagementPort` implementations: `LocalAesKwKmsAdapter` for development/test and `AwsKmsAdapter` for production.
3. **Platform adapters** — `RbacPermissionAdapter` (bridges the existing RBAC bounded context) and `ApprovalWorkflowAdapter` (queries the approval table or in-process stub).
4. **Event publication** — `StructlogEventPublisher` logs events; `InProcessEventPublisher` dispatches to registered handlers for integration wiring.
5. **Alembic migration** — `0044_credential_vault_foundation.py` creates all seven tables.
6. **FastAPI API layer** — Fourteen REST endpoints under `/api/v1/credentials/`, six under `/api/v1/credential-policies/`, four under `/api/v1/vault-backends/`, and one under `/api/v1/audit-logs/`, all wired through `Depends`.
7. **Dependency injection** — `CredentialVaultContainer` wires all application services with concrete implementations, registered with the FastAPI app at startup.
8. **Observability** — OpenTelemetry spans on every repository call; Prometheus counters for credential operations and encryption latency; structured logging on every security event.
9. **Health check** — Credential vault readiness probe added to `/health/ready`.
10. **Integration tests** — Full PostgreSQL integration tests for repositories, UoW, and encryption.

---

## §2. Scope

| In Scope | Out of Scope |
|---|---|
| `credential_vault/infrastructure/` package | Any modification to `credential_vault/domain/` |
| `credential_vault/api/` package | Any modification to `credential_vault/application/` |
| `redforge/infrastructure/database/migrations/versions/0044_*.py` | Business logic in any adapter |
| Seven ORM model classes | Credential Vault event bus / outbox (post-M25) |
| Six repository implementations | Rotation scheduler / expiration scanner (M25D) |
| `CredentialVaultUnitOfWork` | DEK rewrap orchestration (M25D) |
| Four port adapter implementations | Non-credential API changes |
| FastAPI router and Pydantic schemas | AWS KMS unit test mocking (boto3 mock is M25D) |
| DI container class | Multi-region KMS failover |
| OpenTelemetry instrumentation | |
| Prometheus metrics | |
| Startup validator extension | |

---

## §3. Architecture Constraints

**Dependency rule** (inviolable):
```
credential_vault/infrastructure/ → credential_vault/application/ → credential_vault/domain/
credential_vault/api/            → credential_vault/application/
credential_vault/infrastructure/ → redforge/infrastructure/database/ (Base, engine)
credential_vault/infrastructure/ → stdlib, sqlalchemy, cryptography, boto3
```

No file in `credential_vault/infrastructure/` or `credential_vault/api/` may import from `credential_vault/domain/` directly unless the import is an ABC, VO, or event type used for type annotation only. All concrete domain objects are accessed through repository ABCs.

**ORM models are not domain objects.** No domain logic in ORM models. No aggregate methods. ORM models carry only column definitions and constraints.

**Repositories never commit.** `AsyncSession.commit()` is called exclusively by `CredentialVaultUnitOfWork.commit()`.

**Adapters never open UoW.** Port adapters (`RbacPermissionAdapter`, `ApprovalWorkflowAdapter`) receive their own `AsyncSession` or a read-only session factory for cross-bounded-context queries. They are not part of the credential vault UoW transaction.

**Repository mapper functions are pure.** Each repository has private `_to_domain(row: OrmModel) -> DomainObject` and `_from_domain(obj: DomainObject) -> OrmModel` functions. These are pure functions: no I/O, no session access.

**`cryptography` library for encryption.** `hazmat.primitives.ciphers.aead.AESGCM` for AES-256-GCM. No other encryption library for the vault.

**AWS KMS via `boto3`.** Async wrapper: `asyncio.get_event_loop().run_in_executor(None, sync_boto3_call)`. Production adapter only.

---

## §4. Repository Structure

```
backend/src/credential_vault/
├── infrastructure/
│   ├── __init__.py
│   ├── container.py                  # DI container — CredentialVaultContainer
│   ├── encryption/
│   │   ├── __init__.py
│   │   ├── aes_gcm_encryption_adapter.py
│   │   └── local_kms_adapter.py
│   ├── kms/
│   │   ├── __init__.py
│   │   └── aws_kms_adapter.py
│   ├── persistence/
│   │   ├── __init__.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── credential_model.py
│   │   │   ├── credential_version_model.py
│   │   │   ├── rotation_policy_model.py
│   │   │   ├── expiration_policy_model.py
│   │   │   ├── vault_backend_model.py
│   │   │   ├── audit_log_model.py
│   │   │   └── audit_entry_model.py
│   │   ├── repositories/
│   │   │   ├── __init__.py
│   │   │   ├── pg_credential_repository.py
│   │   │   ├── pg_credential_version_repository.py
│   │   │   ├── pg_rotation_policy_repository.py
│   │   │   ├── pg_expiration_policy_repository.py
│   │   │   ├── pg_vault_backend_repository.py
│   │   │   └── pg_audit_log_repository.py
│   │   └── unit_of_work.py           # CredentialVaultUnitOfWork
│   ├── platform_adapters/
│   │   ├── __init__.py
│   │   ├── rbac_permission_adapter.py
│   │   └── approval_workflow_adapter.py
│   └── events/
│       ├── __init__.py
│       └── structlog_event_publisher.py
├── api/
│   ├── __init__.py
│   ├── dependencies.py               # FastAPI Depends functions
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── credential_schemas.py
│   │   ├── policy_schemas.py
│   │   ├── backend_schemas.py
│   │   └── audit_schemas.py
│   └── v1/
│       ├── __init__.py
│       ├── credentials.py            # /api/v1/credentials router
│       ├── credential_policies.py    # /api/v1/credential-policies router
│       ├── vault_backends.py         # /api/v1/vault-backends router
│       └── audit_logs.py             # /api/v1/audit-logs router
```

**Migration** (in existing redforge migration tree):
```
backend/src/redforge/infrastructure/database/migrations/versions/
└── 0044_credential_vault_foundation.py
```

**Tests:**
```
backend/tests/credential_vault/
├── infrastructure/
│   ├── conftest.py                   # pg_session, pg_uow fixtures
│   ├── test_pg_credential_repository.py
│   ├── test_pg_credential_version_repository.py
│   ├── test_pg_rotation_policy_repository.py
│   ├── test_pg_expiration_policy_repository.py
│   ├── test_pg_vault_backend_repository.py
│   ├── test_pg_audit_log_repository.py
│   ├── test_credential_vault_uow.py
│   ├── test_aes_gcm_encryption_adapter.py
│   ├── test_local_kms_adapter.py
│   └── test_aws_kms_adapter.py
└── api/
    ├── conftest.py                   # TestClient, overrides
    ├── test_credentials_api.py
    ├── test_credential_policies_api.py
    ├── test_vault_backends_api.py
    └── test_audit_logs_api.py
```

Total new files: **45** (27 source + 14 test + 2 conftest + 1 migration + 1 router registration patch).

---

## §5. Database Schema

### Migration number
`0044` — next after `0043_evidence_recommendations.py`.

### `credential_vault_credentials`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `tenant_id` | `UUID` | `NOT NULL, INDEX` |
| `name` | `VARCHAR(256)` | `NOT NULL` |
| `cred_category` | `VARCHAR(64)` | `NOT NULL` |
| `cred_subtype` | `VARCHAR(64)` | `NOT NULL` |
| `schema_id` | `UUID` | `NULLABLE` |
| `state` | `VARCHAR(32)` | `NOT NULL` |
| `owner_principal_id` | `UUID` | `NOT NULL` |
| `active_version_id` | `UUID` | `NULLABLE, FK → credential_vault_versions(id)` |
| `rotation_policy_id` | `UUID` | `NULLABLE, FK → credential_vault_rotation_policies(id)` |
| `expiration_policy_id` | `UUID` | `NULLABLE, FK → credential_vault_expiration_policies(id)` |
| `vault_backend_id` | `UUID` | `NOT NULL, FK → credential_vault_vault_backends(id)` |
| `description` | `TEXT` | `NULLABLE` |
| `tags_json` | `JSONB` | `NOT NULL, DEFAULT '{}'` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `row_version` | `INTEGER` | `NOT NULL, DEFAULT 1` |

Unique constraint: `(tenant_id, name)` — enforces `CredentialAlreadyExists`.
Index: `(tenant_id, state)` for `list_by_tenant` with state filter.
Index: `(tenant_id, rotation_policy_id)` for `list_with_rotation_policy`.
Index: `(tenant_id, expiration_policy_id)` for `list_with_expiration_policy`.

### `credential_vault_versions`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `credential_id` | `UUID` | `NOT NULL, FK → credential_vault_credentials(id), INDEX` |
| `tenant_id` | `UUID` | `NOT NULL` |
| `version_number` | `INTEGER` | `NOT NULL` |
| `version_state` | `VARCHAR(32)` | `NOT NULL` |
| `created_by` | `UUID` | `NOT NULL` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `expires_at` | `TIMESTAMPTZ` | `NULLABLE` |
| `ciphertext` | `BYTEA` | `NOT NULL` |
| `cipher_algorithm` | `VARCHAR(64)` | `NOT NULL` |
| `iv` | `BYTEA` | `NOT NULL` |
| `tag` | `BYTEA` | `NOT NULL` |
| `payload_size` | `INTEGER` | `NOT NULL` |
| `wrapped_dek` | `BYTEA` | `NOT NULL` |
| `master_key_id` | `VARCHAR(256)` | `NOT NULL` |
| `wrapping_algorithm` | `VARCHAR(64)` | `NOT NULL` |
| `key_created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `rotation_trigger` | `VARCHAR(64)` | `NULLABLE` |
| `rotation_prev_version_id` | `UUID` | `NULLABLE` |
| `rotation_policy_id` | `UUID` | `NULLABLE` |
| `rotation_notes` | `TEXT` | `NULLABLE` |
| `row_version` | `INTEGER` | `NOT NULL, DEFAULT 1` |

Index: `(credential_id, tenant_id, version_state)` for state-filtered list queries.
Index: `(credential_id, tenant_id, version_number DESC)` for max version_number lookup.

### `credential_vault_rotation_policies`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `tenant_id` | `UUID` | `NOT NULL, INDEX` |
| `name` | `VARCHAR(256)` | `NOT NULL` |
| `interval_days` | `INTEGER` | `NULLABLE` |
| `max_versions_kept` | `INTEGER` | `NOT NULL` |
| `notify_days_before` | `INTEGER` | `NOT NULL` |
| `auto_rotate` | `BOOLEAN` | `NOT NULL` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `row_version` | `INTEGER` | `NOT NULL, DEFAULT 1` |

Unique constraint: `(tenant_id, name)`.

### `credential_vault_expiration_policies`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `tenant_id` | `UUID` | `NOT NULL, INDEX` |
| `name` | `VARCHAR(256)` | `NOT NULL` |
| `ttl_days` | `INTEGER` | `NOT NULL` |
| `warn_days_before` | `INTEGER` | `NOT NULL` |
| `hard_expire` | `BOOLEAN` | `NOT NULL` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `row_version` | `INTEGER` | `NOT NULL, DEFAULT 1` |

Unique constraint: `(tenant_id, name)`.

### `credential_vault_vault_backends`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `tenant_id` | `UUID` | `NOT NULL, INDEX` |
| `name` | `VARCHAR(256)` | `NOT NULL` |
| `backend_type` | `VARCHAR(64)` | `NOT NULL` |
| `is_default` | `BOOLEAN` | `NOT NULL, DEFAULT FALSE` |
| `config_encrypted` | `BYTEA` | `NOT NULL` |
| `config_key_envelope` | `JSONB` | `NOT NULL` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `row_version` | `INTEGER` | `NOT NULL, DEFAULT 1` |

Unique constraint: `(tenant_id, name)`.

**Security note:** `config_encrypted` stores the backend configuration blob encrypted with AES-256-GCM via `IEncryptionPort`. The key envelope is stored separately as JSONB. The plaintext config never appears in the database.

### `credential_vault_audit_logs`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `credential_id` | `UUID` | `NOT NULL, UNIQUE, FK → credential_vault_credentials(id)` |
| `tenant_id` | `UUID` | `NOT NULL` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |

One-to-one with credentials: each credential has exactly one `AuditLog`.

### `credential_vault_audit_entries`

| Column | Type | Constraints |
|---|---|---|
| `id` | `UUID` | `PK` |
| `audit_log_id` | `UUID` | `NOT NULL, FK → credential_vault_audit_logs(id), INDEX` |
| `credential_id` | `UUID` | `NOT NULL` |
| `tenant_id` | `UUID` | `NOT NULL` |
| `operation` | `VARCHAR(64)` | `NOT NULL` |
| `outcome` | `VARCHAR(32)` | `NOT NULL` |
| `principal_id` | `UUID` | `NOT NULL` |
| `occurred_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `detail` | `TEXT` | `NOT NULL` |
| `client_ip` | `VARCHAR(45)` | `NULLABLE` |
| `request_id` | `VARCHAR(128)` | `NULLABLE` |

Index: `(audit_log_id, occurred_at DESC)` for paginated listing.
Index: `(credential_id, tenant_id)` for direct lookup without join.

---

## §6. ORM Models

### Design rules

- All ORM models inherit from `redforge.infrastructure.database.base.Base`.
- SQLAlchemy 2.x `Mapped[T]` + `mapped_column()` syntax everywhere.
- `UUID` columns use `from sqlalchemy.dialects.postgresql import UUID as PgUUID` with `as_uuid=True`. Column declared as `Mapped[uuid.UUID]`.
- `BYTEA` columns: `Mapped[bytes] = mapped_column(LargeBinary)`.
- `JSONB` columns: `Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)`.
- `TIMESTAMPTZ` columns: `Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)`.
- No relationship declarations — repositories use explicit joins via SQL statements.
- `row_version` (optimistic lock counter) is `Mapped[int] = mapped_column(Integer, nullable=False, default=1)`.
- Table names are prefixed with `credential_vault_` to avoid collisions with the existing `redforge` schema.

### `CredentialModel`

```python
class CredentialModel(Base):
    __tablename__ = "credential_vault_credentials"

    id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    cred_category: Mapped[str] = mapped_column(String(64), nullable=False)
    cred_subtype: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_principal_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    active_version_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    rotation_policy_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    expiration_policy_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    vault_backend_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_credential_vault_credentials_tenant_name"),
        Index("ix_cv_credentials_tenant_state", "tenant_id", "state"),
        Index("ix_cv_credentials_rotation_policy", "tenant_id", "rotation_policy_id"),
        Index("ix_cv_credentials_expiration_policy", "tenant_id", "expiration_policy_id"),
    )
```

### Optimistic concurrency

Every table has `row_version: int` initialized to 1. Repository `save()` / `update()` methods include:
```sql
UPDATE credential_vault_credentials
SET ..., row_version = row_version + 1
WHERE id = :id AND row_version = :expected_version
```
If `rowcount == 0`, the repository raises `OptimisticLockConflict(entity_id=str(credential_id), current_version=aggregate._version)`. The `_version` field on domain aggregates maps to `row_version` in the ORM model. On load, `row_version` is copied into `aggregate._version`.

---

## §7. Repository Implementations

### Common constructor pattern

All six repository classes follow the same constructor:
```python
class PgCredentialRepository(ICredentialRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
```

The session is provided by `CredentialVaultUnitOfWork`. Repositories never create sessions.

### `PgCredentialRepository`

**`save(credential)`**

Upsert pattern using `INSERT ... ON CONFLICT (id) DO UPDATE`. Include `row_version = row_version + 1` on the UPDATE path. On insert, pass the ORM model's `row_version = 1`. Check `rowcount` for the conflict guard (INSERT inserts row_version=1 naturally; UPDATE increments). After both paths, sync `credential._version` to the resulting `row_version` by re-reading it from the returning clause.

Actually, use a cleaner pattern: load-then-update. On `save()`:
1. Attempt `SELECT ... FOR UPDATE SKIP LOCKED` is too aggressive. Use optimistic retry:
2. Check if a row exists: `SELECT row_version FROM ... WHERE id = :id`.
3. If not exists: `INSERT INTO ... VALUES (...)` with `row_version = 1`.
4. If exists: `UPDATE ... SET ..., row_version = row_version + 1 WHERE id = :id AND row_version = :expected`. If `rowcount == 0` → raise `OptimisticLockConflict`.

`_expected_version` is `credential._version`.

**`get_by_id(credential_id, tenant_id)`**

```sql
SELECT * FROM credential_vault_credentials
WHERE id = :id AND tenant_id = :tenant_id
```
If no row → raise `CredentialNotFound(str(credential_id), str(tenant_id))`.
Map via `_to_domain(row) -> Credential`.

**`get_by_name(name, tenant_id)`**

```sql
SELECT * FROM credential_vault_credentials
WHERE name = :name AND tenant_id = :tenant_id
```

**`exists_by_name(name, tenant_id)`**

```sql
SELECT 1 FROM credential_vault_credentials
WHERE name = :name AND tenant_id = :tenant_id LIMIT 1
```
Returns `True` if row exists.

**`list_by_tenant(tenant_id, states, limit, offset)`**

```sql
SELECT * FROM credential_vault_credentials
WHERE tenant_id = :tenant_id
  [AND state = ANY(:states)]
ORDER BY created_at DESC
LIMIT :limit OFFSET :offset
```

**`list_with_rotation_policy(policy_id, tenant_id)`** / **`list_with_expiration_policy(...)`**

Returns list of `CredentialId` only (no full hydration):
```sql
SELECT id FROM credential_vault_credentials
WHERE rotation_policy_id = :policy_id AND tenant_id = :tenant_id
  AND state != 'DELETED'
```

### `PgCredentialVersionRepository`

**`save(version)`**

INSERT only (versions are never updated via `save()`). Raises `IntegrityError` on duplicate PK (internal error — indicates programming fault).

**`get_by_id(version_id, tenant_id)`**

SELECT by PK + tenant guard.

**`get_active_version(credential_id, tenant_id)`**

```sql
SELECT * FROM credential_vault_versions
WHERE credential_id = :cred_id AND tenant_id = :tid AND version_state = 'ACTIVE'
LIMIT 1
```
If no row → raise `ActiveVersionNotFound(str(credential_id))`.

**`list_by_credential(credential_id, tenant_id, states)`**

```sql
SELECT * FROM credential_vault_versions
WHERE credential_id = :cred_id AND tenant_id = :tid
  [AND version_state = ANY(:states)]
ORDER BY version_number ASC
```

**`atomic_promote(new_version, supersede_version_id, tenant_id)`**

Two SQL statements in the same session (atomic at the session transaction level):
1. UPDATE `credential_vault_versions SET version_state = 'SUPERSEDED', row_version = row_version + 1 WHERE id = :supersede_id AND tenant_id = :tid AND version_state = 'ACTIVE'`. If `rowcount == 0` → raise `OptimisticLockConflict(...)`.
2. UPDATE `credential_vault_versions SET version_state = 'ACTIVE', row_version = row_version + 1 WHERE id = :new_id AND tenant_id = :tid AND version_state = 'PENDING'`. If `rowcount == 0` → raise `OptimisticLockConflict(...)`.

If `supersede_version_id is None` (first version, no prior active), skip statement 1.

**`update(version)`**

```sql
UPDATE credential_vault_versions
SET version_state = :state, ..., row_version = row_version + 1
WHERE id = :id AND tenant_id = :tid AND row_version = :expected
```
`OptimisticLockConflict` if `rowcount == 0`.

**`count_superseded(credential_id, tenant_id)`**

```sql
SELECT COUNT(*) FROM credential_vault_versions
WHERE credential_id = :cid AND tenant_id = :tid AND version_state = 'SUPERSEDED'
```

### `PgAuditLogRepository`

**`save(audit_log)`**

INSERT only. Audit logs are never updated.

**`get_by_credential(credential_id, tenant_id)`**

```sql
SELECT * FROM credential_vault_audit_logs
WHERE credential_id = :cid AND tenant_id = :tid
```

**`append_entry(audit_log_id, entry, tenant_id)`**

INSERT into `credential_vault_audit_entries`. No SELECT. If INSERT fails (FK violation, constraint) → exception propagates; the `ApplicationAuditFailure` wrapper in the application service catches it.

**`list_entries(audit_log_id, tenant_id, since, operations, limit, offset)`**

```sql
SELECT * FROM credential_vault_audit_entries
WHERE audit_log_id = :alid
  [AND occurred_at >= :since]
  [AND operation = ANY(:operations)]
ORDER BY occurred_at DESC
LIMIT :limit OFFSET :offset
```

### `PgRotationPolicyRepository`, `PgExpirationPolicyRepository`, `PgVaultBackendRepository`

Standard CRUD pattern identical to `PgCredentialRepository` minus the state filter. Each raises the appropriate domain exception on not-found (`RotationPolicyNotFound`, `ExpirationPolicyNotFound`, `VaultBackendNotFound`).

`delete(policy_id, tenant_id)`:
```sql
DELETE FROM credential_vault_rotation_policies WHERE id = :id AND tenant_id = :tid
```
`PolicyInUse` is raised by the application service before calling `delete()` (after checking `list_with_rotation_policy()`). The repository delete does not need to re-check.

`VaultBackendInUse`: same pattern — application service checks `list_with_rotation_policy` against the backend. Actually: `ICredentialRepository.list_by_backend_id(backend_id, tenant_id)` — add this as a query:
```sql
SELECT id FROM credential_vault_credentials
WHERE vault_backend_id = :bid AND tenant_id = :tid AND state != 'DELETED'
```
If count > 0 → `VaultBackendInUse`. Note: this method is not in the domain repository ABC but is needed by the application service during `delete_vault_backend`. Add it to `ICredentialRepository` — this is an M25C addition to the domain layer's repository ABC that was omitted from M25B. See §15 Risks.

---

## §8. `CredentialVaultUnitOfWork`

`CredentialVaultUnitOfWork` implements `IUnitOfWork` from `credential_vault.application.ports.i_unit_of_work`.

```python
class CredentialVaultUnitOfWork(IUnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None
        self._committed: bool = False  # inherited invariant from IUnitOfWork

    async def __aenter__(self) -> CredentialVaultUnitOfWork:
        self._session = self._session_factory()
        # Instantiate all six repositories sharing the single session
        self.credentials = PgCredentialRepository(self._session)
        self.versions = PgCredentialVersionRepository(self._session)
        self.rotation_policies = PgRotationPolicyRepository(self._session)
        self.expiration_policies = PgExpirationPolicyRepository(self._session)
        self.vault_backends = PgVaultBackendRepository(self._session)
        self.audit_logs = PgAuditLogRepository(self._session)
        return self

    async def commit(self) -> None:
        assert self._session is not None
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        if self._session is not None:
            await self._session.rollback()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._committed and self._session is not None:
            await self._session.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None
```

**UoW factory** (provided to all application services):
```python
def make_credential_vault_uow_factory(
    session_factory: async_sessionmaker[AsyncSession]
) -> Callable[[], CredentialVaultUnitOfWork]:
    def factory() -> CredentialVaultUnitOfWork:
        return CredentialVaultUnitOfWork(session_factory)
    return factory
```

---

## §9. Encryption Adapters

### `AesGcmEncryptionAdapter`

Implements `IEncryptionPort`. Uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.

**`encrypt(plaintext, dek)`**

1. Validate `len(dek) == 32` (256-bit). Raise `InvalidArgument` if not.
2. `iv = os.urandom(12)` — 96-bit IV for GCM.
3. `aesgcm = AESGCM(dek)`.
4. `ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)` — produces ciphertext + 16-byte authentication tag appended.
5. Split: `ciphertext = ciphertext_with_tag[:-16]`, `tag = ciphertext_with_tag[-16:]`.
6. `payload_size = len(plaintext)`.
7. Zero dek bytes: `for i in range(len(dek)): dek[i] = 0` — note: this requires `dek` to be mutable `bytearray`, not `bytes`. Document that `IKeyManagementPort.generate_dek()` returns `bytearray` for the plaintext DEK, and implementations must accept `bytes | bytearray`.
8. Return `EncryptedPayload(ciphertext, "AES-256-GCM", iv, tag, payload_size)`.

**`decrypt(payload, dek)`**

1. Validate `len(dek) == 32`.
2. `aesgcm = AESGCM(dek)`.
3. Reconstruct `ciphertext_with_tag = payload.ciphertext + payload.tag`.
4. `plaintext = aesgcm.decrypt(payload.iv, ciphertext_with_tag, None)` — raises `InvalidTag` on AEAD failure; catch and raise `EncryptionAuthTagFailure` (new domain exception).
5. Zero dek bytes.
6. Return `plaintext`.

**`EncryptionAuthTagFailure`** — add to `credential_vault.domain.exceptions.domain_exceptions`. This is a new domain exception required by M25C (M25A did not anticipate AEAD failure). See §15 Risks.

### `LocalAesKwKmsAdapter`

Implements `IKeyManagementPort`. For development and test environments only. Uses AES key-wrapping (RFC 3394) via `cryptography.hazmat.primitives.keywrap.aes_key_wrap`.

**Constructor:** `__init__(master_key: bytes, master_key_id: str)` — master key is a 256-bit AES key loaded from environment variable `CREDENTIAL_VAULT_LOCAL_MASTER_KEY` (base64-encoded). Do not hardcode.

**`generate_dek()`**

1. `dek = bytearray(os.urandom(32))`.
2. `wrapped = aes_key_wrap(wrapping_key=self._master_key, key_to_wrap=bytes(dek), backend=default_backend())`.
3. Return `(bytes(dek), KeyEnvelope(wrapped, self._master_key_id, "AES-KW-256", datetime.now(UTC)))`.

**`unwrap_dek(envelope)`**

1. Validate `envelope.master_key_id == self._master_key_id`. If mismatch → raise `KmsKeyNotFound(envelope.master_key_id)`.
2. `dek = aes_key_unwrap(wrapping_key=self._master_key, wrapped_key=envelope.wrapped_dek, backend=default_backend())`.
3. Return `bytearray(dek)`.

**`rewrap_dek(old_envelope, new_master_key_id)`**

Not supported in local adapter. Raise `NotImplementedError("rewrap not supported in LocalAesKwKmsAdapter")`.

### `AwsKmsAdapter`

Implements `IKeyManagementPort`. Uses `boto3` with `KMS` service. All boto3 calls are wrapped in `asyncio.get_event_loop().run_in_executor(None, ...)` to avoid blocking the event loop.

**Constructor:** `__init__(kms_client, master_key_arn: str)` — `kms_client` is a boto3 KMS client injected (not created inside the adapter).

**`generate_dek()`**

1. `response = kms_client.generate_data_key(KeyId=master_key_arn, KeySpec="AES_256")`.
2. `dek = bytearray(response["Plaintext"])`.
3. `wrapped = response["CiphertextBlob"]`.
4. Return `(bytes(dek), KeyEnvelope(wrapped, master_key_arn, "AWS_KMS_AES_256", datetime.now(UTC)))`.

**`unwrap_dek(envelope)`**

1. `response = kms_client.decrypt(CiphertextBlob=envelope.wrapped_dek, KeyId=master_key_arn)`.
2. Return `bytearray(response["Plaintext"])`.

**`rewrap_dek(old_envelope, new_master_key_id)`**

1. `dek = await self.unwrap_dek(old_envelope)`.
2. `new_response = kms_client.encrypt(KeyId=new_master_key_id, Plaintext=bytes(dek))`.
3. Zero `dek`.
4. Return `KeyEnvelope(new_response["CiphertextBlob"], new_master_key_id, "AWS_KMS_AES_256", datetime.now(UTC))`.

---

## §10. Platform Adapters

### `RbacPermissionAdapter`

Implements `IPermissionPort`. Bridges to the existing RBAC bounded context (`redforge.application.rbac`).

**Constructor:** `__init__(effective_access_svc: EffectiveAccessService)` — the existing `EffectiveAccessService` from `redforge.application.rbac` is injected.

**`has_permission(principal_id, credential_id, permission, tenant_id)`**

Translates credential vault permission constants to the existing RBAC system's permission check:
```python
result = await self._effective_access_svc.has_permission(
    subject_id=str(principal_id),
    resource_type="credential",
    resource_id=str(credential_id),
    permission=permission,
    organization_id=str(tenant_id),
)
return result
```

This assumes the existing RBAC system accepts `resource_type="credential"`. If the RBAC system does not yet have a `credential` resource type registered, the adapter returns `True` in development mode and raises `ApplicationPortError` in production. **This must be validated in the startup validator.**

### `ApprovalWorkflowAdapter`

Implements `IApprovalPort`. Queries the `credential_vault_approval_requests` table (a lightweight approval table introduced in migration `0044`) OR defers to an in-process stub for development.

**`is_approved(credential_id, principal_id, operation, tenant_id)`**

```sql
SELECT COUNT(*) FROM credential_vault_approval_requests
WHERE credential_id = :cid
  AND operation = :op
  AND tenant_id = :tid
  AND approved_at IS NOT NULL
  AND expires_at > NOW()
```
Returns `True` if count >= required quorum (fetched from a config table or environment).

**`get_approver_count(credential_id, operation, tenant_id)`**

Returns `(actual, required)`:
- `actual`: COUNT of approved rows.
- `required`: from environment variable `CREDENTIAL_VAULT_APPROVAL_QUORUM` (default: 2).

`credential_vault_approval_requests` table is also created in migration `0044`:

| Column | Type |
|---|---|
| `id` | `UUID PK` |
| `credential_id` | `UUID NOT NULL` |
| `tenant_id` | `UUID NOT NULL` |
| `operation` | `VARCHAR(64) NOT NULL` |
| `requester_id` | `UUID NOT NULL` |
| `approver_id` | `UUID NOT NULL` |
| `approved_at` | `TIMESTAMPTZ NULLABLE` |
| `expires_at` | `TIMESTAMPTZ NOT NULL` |

---

## §11. Event Publisher

### `StructlogEventPublisher`

Implements `IEventPublisher` from `credential_vault.application.ports.i_event_publisher`.

**Constructor:** `__init__(logger: structlog.BoundLogger, handlers: list[Callable[[BaseDomainEvent], Awaitable[None]]] | None = None)`.

**`publish_batch(events)`**

1. For each event: log at INFO with `event_type`, `aggregate_id`, `tenant_id`, `occurred_at`.
2. If `handlers` provided: call each handler concurrently via `asyncio.gather(*[h(e) for e in events for h in handlers], return_exceptions=True)`. Log any exceptions at WARNING; never raise.

The `NullEventPublisher` pattern from `redforge.infrastructure.events` serves as reference: publish_batch silently discards in development.

---

## §12. Security Constraints

### DEK lifecycle

- Plaintext DEKs live in memory only. They are `bytearray` objects that are zeroed after encryption/decryption. Never persisted. Never logged.
- Encrypted payloads (ciphertext + IV + tag) and key envelopes (wrapped DEK + master key ID) are persisted to `credential_vault_versions`.
- The `ResolvedSecret` VO must have `.zero()` called by the application service in a `finally` block. This is an M25B responsibility — M25C confirms the call chain.
- If `resolve_credential` raises before `ResolvedSecret` is constructed, no zeroing is needed. If after construction, the `finally` block must zero regardless of outcome.

### Column-level encryption for `config_encrypted`

Backend config (connection strings, API keys) is encrypted before storage. `VaultBackendRegistered` event carries no config. `CredentialVaultContainer` provides the encryption adapter to the `VaultBackendApplicationService`. On `register_vault_backend`, the service encrypts `config` bytes before passing to `uow.vault_backends.save()`. The ORM model stores `config_encrypted: bytes` and `config_key_envelope: dict`.

### TLS / transport

All connections between the API and PostgreSQL use TLS. Enforced via `?ssl=require` in the database URL. Enforced in the startup validator.

### Audit tamper-detection

Audit entries are append-only. No `UPDATE` or `DELETE` SQL is ever issued against `credential_vault_audit_entries`. The `PgAuditLogRepository.append_entry` method issues only `INSERT`. This is enforced by not implementing any mutation method on the ORM model for audit entries.

### Fail-closed on `append_entry` failure

M25C repositories may raise `SQLAlchemyError` (connection lost, deadlock) from `append_entry`. These exceptions propagate to the application service which wraps them in `ApplicationAuditFailure`. The UoW then rollbacks. This is the intended fail-closed behavior — the operation does not complete without a committed audit record.
