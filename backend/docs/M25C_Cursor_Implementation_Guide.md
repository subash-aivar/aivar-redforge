# M25C Cursor Implementation Guide
## Enterprise Credential Vault — Infrastructure & API Layer
### Execution Authority: M25C Specification v1.0 FROZEN

---

## Document Purpose

This guide converts the frozen M25C specification into a sequential execution plan for Cursor. All architectural decisions are made. Cursor implements; it does not design.

**Frozen inputs:**
- `M25C_Spec_Part1.md` — Sections 1–12
- `M25C_Spec_Part2.md` — Sections 13–24
- `M25A` / `M25B` — frozen, zero modifications permitted
- Migration head entering M25C: `0043`

**New root directories:**
- `backend/src/credential_vault/infrastructure/`
- `backend/src/credential_vault/api/`
- `backend/tests/credential_vault/infrastructure/`
- `backend/tests/credential_vault/api/`

---

# 1. Overall Strategy

## 1.1 Layering contract

```
credential_vault/infrastructure/  →  credential_vault/application/   (allowed)
credential_vault/infrastructure/  →  credential_vault/domain/         (ABC types, VOs in TYPE_CHECKING only)
credential_vault/infrastructure/  →  redforge.infrastructure.database.base (allowed)
credential_vault/api/             →  credential_vault/application/   (allowed)
credential_vault/api/             →  credential_vault/infrastructure/ (FORBIDDEN — container via app.state)
credential_vault/infrastructure/  →  fastapi / pydantic / uvicorn     (FORBIDDEN except container.py)
```

## 1.2 What Cursor must never do

- Modify any file under `credential_vault/domain/` **except**: add `EncryptionAuthTagFailure`, `KmsKeyNotFound` to `domain_exceptions.py`, and add `list_with_vault_backend` to `i_credential_repository.py` (see R1, R2, R3 in spec §23).
- Modify any file under `credential_vault/application/`.
- Write plaintext secrets or DEK bytes to any log statement.
- Commit in a repository method — only `CredentialVaultUnitOfWork.commit()` may commit.
- Add `config` to `VaultBackendResponse`.
- Add `encrypted_payload` or `key_envelope` to `VersionResponse`.
- Use `asyncio.run()` or create nested event loops in adapters.

---

# 2. Pre-Implementation: Domain Additive Extensions

Before writing any infrastructure, apply three additive changes to domain files. These are the only permitted domain modifications.

### Step 1 — Add domain exceptions

In `credential_vault/domain/exceptions/domain_exceptions.py`, add at the end of the file:

```python
class EncryptionAuthTagFailure(DomainException):
    """AES-GCM authentication tag verification failed. Ciphertext is corrupted or tampered."""
    def __init__(self) -> None:
        super().__init__("Encryption authentication tag verification failed")

class KmsKeyNotFound(DomainException):
    """KMS master key ID not found or inaccessible."""
    def __init__(self, master_key_id: str) -> None:
        super().__init__(f"KMS master key not found: {master_key_id}")
        self.master_key_id = master_key_id
```

### Step 2 — Add `list_with_vault_backend` to `ICredentialRepository`

In `credential_vault/domain/repositories/i_credential_repository.py`, add:

```python
@abstractmethod
async def list_with_vault_backend(
    self,
    backend_id: VaultBackendId,
    tenant_id: TenantId,
) -> list[CredentialId]:
    """Used to enforce VaultBackendInUse on backend delete."""
```

Add `VaultBackendId` to the `TYPE_CHECKING` imports in that file.

### Step 3 — Validate domain integrity

```bash
mypy src/credential_vault/domain/ --strict
ruff check src/credential_vault/domain/
pytest tests/credential_vault/domain/ -x
```

All must pass. Then commit the three domain changes as a single commit: "add EncryptionAuthTagFailure, KmsKeyNotFound domain exceptions; add list_with_vault_backend to ICredentialRepository".

---

# 3. Sequential Implementation Phases

---

## Phase 1: ORM Models

### Objective
Create seven ORM model files. No business logic. No repository code.

### Files to create (8)

| # | File |
|---|---|
| 1 | `infrastructure/__init__.py` |
| 2 | `infrastructure/persistence/__init__.py` |
| 3 | `infrastructure/persistence/models/__init__.py` |
| 4 | `infrastructure/persistence/models/credential_model.py` |
| 5 | `infrastructure/persistence/models/credential_version_model.py` |
| 6 | `infrastructure/persistence/models/rotation_policy_model.py` |
| 7 | `infrastructure/persistence/models/expiration_policy_model.py` |
| 8 | `infrastructure/persistence/models/vault_backend_model.py` |
| 9 | `infrastructure/persistence/models/audit_log_model.py` |
| 10 | `infrastructure/persistence/models/audit_entry_model.py` |

### Imports for every model file

```python
from __future__ import annotations
import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import Boolean, DateTime, Index, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from redforge.infrastructure.database.base import Base
```

### Column type mapping reference

| Domain concept | Python type | SQLAlchemy column |
|---|---|---|
| All ID fields (UUID7) | `uuid.UUID` | `mapped_column(PgUUID(as_uuid=True), ...)` |
| State/type strings | `str` | `mapped_column(String(N), nullable=False)` |
| `bytes` (ciphertext, wrapped_dek) | `bytes` | `mapped_column(LargeBinary, nullable=False)` |
| `dict` (tags, config_key_envelope) | `dict[str, Any]` | `mapped_column(JSONB, nullable=False, default=dict)` |
| `datetime` | `datetime` | `mapped_column(DateTime(timezone=True), nullable=False)` |
| Optimistic lock | `int` | `mapped_column(Integer, nullable=False, default=1, name="row_version")` |
| Nullable UUID FK | `uuid.UUID \| None` | `mapped_column(PgUUID(as_uuid=True), nullable=True)` |

### `CredentialModel` — `__table_args__`

```python
__table_args__ = (
    UniqueConstraint("tenant_id", "name", name="uq_cv_credentials_tenant_name"),
    Index("ix_cv_credentials_tenant_state", "tenant_id", "state"),
    Index("ix_cv_credentials_rotation_policy", "tenant_id", "rotation_policy_id"),
    Index("ix_cv_credentials_expiration_policy", "tenant_id", "expiration_policy_id"),
)
```

### `CredentialVersionModel` — `__table_args__`

```python
__table_args__ = (
    Index("ix_cv_versions_cred_state", "credential_id", "tenant_id", "version_state"),
    Index("ix_cv_versions_cred_number", "credential_id", "tenant_id", "version_number"),
)
```

### Internal checkpoints

- Each model imports from `redforge.infrastructure.database.base` only.
- No domain object imports.
- `Base.metadata.tables` contains all seven table names after importing all models.

### Validation checklist

```bash
ruff check src/credential_vault/infrastructure/persistence/models/
mypy src/credential_vault/infrastructure/persistence/models/ --strict
python -c "
from credential_vault.infrastructure.persistence.models.credential_model import CredentialModel
from credential_vault.infrastructure.persistence.models.credential_version_model import CredentialVersionModel
print('ORM models import OK')
"
```

### Exit criteria
Zero mypy errors. Zero ruff violations. All seven models importable.

### Common mistakes
- Importing domain `CredentialState` to validate column values — ORM models use `str` only.
- Using `relationship()` between models — not permitted (spec §6).
- Naming columns without the `name=` kwarg then getting Alembic autogenerate surprises.
- Missing `nullable=False` on `row_version` — must have a default but also be non-nullable.

---

## Phase 2: Alembic Migration

### Objective
Write `0044_credential_vault_foundation.py`. Verify upgrade and downgrade on a real PostgreSQL test database.

### File to create (1)

`backend/src/redforge/infrastructure/database/migrations/versions/0044_credential_vault_foundation.py`

### Implementation rules

- Import all seven `*Model` classes from `credential_vault.infrastructure.persistence.models.*` at the top of the migration file — Alembic needs them in metadata.
- Write `upgrade()` creating tables in FK-dependency order: vault_backends → rotation_policies → expiration_policies → credentials → versions → audit_logs → audit_entries → approval_requests.
- Write `downgrade()` in reverse.
- Use `op.create_table()` not `Base.metadata.create_all()`.
- Use `sa.ForeignKeyConstraint([...], [...], deferrable=True, initially="DEFERRED")` for the `credentials.active_version_id → versions.id` foreign key.
- All `VARCHAR` lengths must match ORM model declarations exactly.
- Index creation: use `op.create_index()` after `op.create_table()`.

### Validation checklist

```bash
# Requires TEST_DATABASE_URL environment variable
alembic -c backend/alembic.ini upgrade 0044
alembic -c backend/alembic.ini downgrade 0043
alembic -c backend/alembic.ini upgrade 0044
echo "Migration round-trip OK"
pytest tests/credential_vault/infrastructure/test_migration.py -x -m integration
```

### Exit criteria
Up/down/up triple-run produces no errors. All eight tables created with correct columns verified by `pg_catalog` inspection.

---

## Phase 3: Repository Implementations

### Objective
Implement all six repository classes. No API code. No encryption code.

### Files to create (8)

| # | File |
|---|---|
| 1 | `infrastructure/persistence/repositories/__init__.py` |
| 2 | `infrastructure/persistence/repositories/pg_credential_repository.py` |
| 3 | `infrastructure/persistence/repositories/pg_credential_version_repository.py` |
| 4 | `infrastructure/persistence/repositories/pg_rotation_policy_repository.py` |
| 5 | `infrastructure/persistence/repositories/pg_expiration_policy_repository.py` |
| 6 | `infrastructure/persistence/repositories/pg_vault_backend_repository.py` |
| 7 | `infrastructure/persistence/repositories/pg_audit_log_repository.py` |
| 8 | `infrastructure/persistence/unit_of_work.py` |

### Repository method structure

Every repository method follows:
1. Build the SQL statement.
2. Execute via `await self._session.execute(stmt)`.
3. Map results to domain objects using pure `_to_domain()` functions.
4. For mutations: check `rowcount` for optimistic lock.

### `_to_domain` / `_from_domain` patterns

**`_to_domain(row: CredentialModel) -> Credential`**

Construct domain aggregate from ORM row. Copy `row.row_version` to `credential._version`. Reconstruct all VOs from raw values.

Example VO reconstructions:
```python
CredentialId(row.id)                          # row.id is uuid.UUID
TenantId(row.tenant_id)
CredentialName(row.name)                       # CredentialName wraps str
CredentialType(CredentialCategory(row.cred_category), row.cred_subtype, row.schema_id)
CredentialState(row.state)
PrincipalId(row.owner_principal_id)
VaultBackendId(row.vault_backend_id)
VersionId(row.active_version_id) if row.active_version_id else None
RotationPolicyId(row.rotation_policy_id) if row.rotation_policy_id else None
ExpirationPolicyId(row.expiration_policy_id) if row.expiration_policy_id else None
dict(row.tags_json)                            # copy of JSONB dict
```

Aggregate construction must call `Credential(...)` constructor directly (not `Credential.create()`) to reconstruct without raising domain events.

**`_from_domain(credential: Credential) -> CredentialModel`**

Inverse: unwrap VOs to primitives via `.value` or `str()`.

### Optimistic lock pattern (critical)

```python
async def save(self, credential: Credential) -> None:
    expected_version = credential._version  # read the current version
    # ... build update statement ...
    result = await self._session.execute(
        update(CredentialModel)
        .where(
            CredentialModel.id == credential.credential_id.value,
            CredentialModel.row_version == expected_version,
        )
        .values(..., row_version=expected_version + 1)
        .returning(CredentialModel.row_version)
    )
    row = result.fetchone()
    if row is None:
        raise OptimisticLockConflict(
            entity_id=str(credential.credential_id),
            current_version=expected_version,
        )
    credential._version = row.row_version  # sync the new version back
```

For INSERT (new credential), `row_version=1` and sync `credential._version = 1` after.

**`OptimisticLockConflict`** — verify this exception exists in `credential_vault.domain.exceptions.domain_exceptions`. If it does not, add it (additive).

### `PgCredentialVersionRepository.atomic_promote` — critical

```python
async def atomic_promote(
    self,
    new_version: CredentialVersion,
    supersede_version_id: VersionId | None,
    tenant_id: TenantId,
) -> None:
    if supersede_version_id is not None:
        result = await self._session.execute(
            update(CredentialVersionModel)
            .where(
                CredentialVersionModel.id == supersede_version_id.value,
                CredentialVersionModel.tenant_id == tenant_id.value,
                CredentialVersionModel.version_state == "ACTIVE",
            )
            .values(version_state="SUPERSEDED", row_version=CredentialVersionModel.row_version + 1)
        )
        if result.rowcount == 0:
            raise OptimisticLockConflict(
                entity_id=str(supersede_version_id), current_version=-1
            )
    result2 = await self._session.execute(
        update(CredentialVersionModel)
        .where(
            CredentialVersionModel.id == new_version.version_id.value,
            CredentialVersionModel.tenant_id == tenant_id.value,
            CredentialVersionModel.version_state == "PENDING",
        )
        .values(version_state="ACTIVE", row_version=CredentialVersionModel.row_version + 1)
    )
    if result2.rowcount == 0:
        raise OptimisticLockConflict(
            entity_id=str(new_version.version_id), current_version=-1
        )
```

Both updates execute in the same transaction (same session). They are atomic at the PostgreSQL transaction level.

### `CredentialVaultUnitOfWork` — in `unit_of_work.py`

See spec §8. The session is created from the `async_sessionmaker` factory. Implement `__aenter__`, `__aexit__`, `commit`, `rollback`. Set all six repos on `self` in `__aenter__`.

### Integration test conftest

```python
# tests/credential_vault/infrastructure/conftest.py

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/cv_test")

@pytest_asyncio.fixture(scope="session")
async def pg_engine():
    engine = create_async_engine(TEST_DATABASE_URL)
    yield engine
    await engine.dispose()

@pytest_asyncio.fixture(scope="session", autouse=True)
async def apply_migrations(pg_engine):
    from alembic.config import Config
    from alembic import command
    cfg = Config("backend/alembic.ini")
    command.upgrade(cfg, "0044")
    yield
    # Do NOT downgrade after tests — leave schema in place for speed

@pytest_asyncio.fixture
async def pg_session(pg_engine):
    session_factory = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()

@pytest_asyncio.fixture
async def pg_uow(pg_engine):
    from credential_vault.infrastructure.persistence.unit_of_work import CredentialVaultUnitOfWork
    session_factory = async_sessionmaker(pg_engine, expire_on_commit=False)
    uow = CredentialVaultUnitOfWork(session_factory)
    async with uow as active_uow:
        yield active_uow
        await active_uow.rollback()  # always rollback test data
```

### Validation checklist

```bash
ruff check src/credential_vault/infrastructure/persistence/
mypy src/credential_vault/infrastructure/persistence/ --strict
pytest tests/credential_vault/infrastructure/ -x -m integration --tb=short
```

### Exit criteria
All repository integration tests pass. mypy zero errors. Optimistic lock conflict tests pass.

### Common mistakes in Phase 3
- Using `self._session.add(orm_model)` + `flush()` for updates — use explicit `UPDATE` statements for optimistic lock enforcement.
- Calling `self._session.commit()` inside a repository method.
- Mapping `CredentialState` as domain type in the `_to_domain` function signature — the function returns a domain type but receives an ORM model; mypy must be satisfied.
- Forgetting to sync `aggregate._version = new_row_version` after a successful save.
- Not importing the ORM model `__init__.py` before Alembic metadata is populated — migration file must import all models.

---

## Phase 4: Encryption Adapters

### Objective
Implement `AesGcmEncryptionAdapter`, `LocalAesKwKmsAdapter`, and `AwsKmsAdapter`.

### Files to create (5)

| # | File |
|---|---|
| 1 | `infrastructure/encryption/__init__.py` |
| 2 | `infrastructure/encryption/aes_gcm_encryption_adapter.py` |
| 3 | `infrastructure/encryption/local_kms_adapter.py` |
| 4 | `infrastructure/kms/__init__.py` |
| 5 | `infrastructure/kms/aws_kms_adapter.py` |

### `aes_gcm_encryption_adapter.py`

Imports: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`, `import os`.

**DEK type**: The `dek` parameter in both methods is typed as `bytes`. Document that callers must pass a `bytearray` that this method will zero — but since `bytes` is immutable, zeroization requires a `bytearray`. Accept `bytes | bytearray` in the implementation but type the ABC as `bytes`. In practice: `dek_array = bytearray(dek)` → use → zero `dek_array`. The original `bytes` object is not zeroed (immutable). This is a known limitation of the interface typing; document it.

Actually — the correct approach: the `IEncryptionPort` protocol accepts `bytes`. The caller (application service) passes the `bytearray` returned by `generate_dek()`. When the adapter receives it as `bytes` (due to the type signature), it can still zero via: since `bytearray` is a subtype of `bytes` in terms of Python runtime, the adapter can check `isinstance(dek, bytearray)` and zero if so. Document this.

**`encrypt`**:
```python
async def encrypt(self, plaintext: bytes, dek: bytes) -> EncryptedPayload:
    if len(dek) != 32:
        raise ApplicationValidationError("dek", "must be 32 bytes (AES-256)")
    iv = os.urandom(12)
    aesgcm = AESGCM(dek)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    if isinstance(dek, bytearray):
        for i in range(len(dek)):
            dek[i] = 0
    return EncryptedPayload(
        ciphertext=ciphertext,
        algorithm="AES-256-GCM",
        iv=iv,
        tag=tag,
        payload_size=len(plaintext),
    )
```

**`decrypt`**:
```python
async def decrypt(self, payload: EncryptedPayload, dek: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(payload.iv, payload.ciphertext + payload.tag, None)
    except InvalidTag:
        raise EncryptionAuthTagFailure() from None
    finally:
        if isinstance(dek, bytearray):
            for i in range(len(dek)):
                dek[i] = 0
    return plaintext
```

### `local_kms_adapter.py`

```python
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.backends import default_backend
```

Load master key from environment: `base64.b64decode(os.environ["CREDENTIAL_VAULT_LOCAL_MASTER_KEY"])`. Validate length == 32 in `__init__`.

### `aws_kms_adapter.py`

All boto3 calls wrapped:
```python
import asyncio
loop = asyncio.get_event_loop()
response = await loop.run_in_executor(None, lambda: self._client.generate_data_key(...))
```

Use `functools.partial` or `lambda` to pass kwargs to boto3. Never `await` boto3 directly.

### Validation checklist

```bash
mypy src/credential_vault/infrastructure/encryption/ src/credential_vault/infrastructure/kms/ --strict
pytest tests/credential_vault/infrastructure/test_aes_gcm_encryption_adapter.py -x
pytest tests/credential_vault/infrastructure/test_local_kms_adapter.py -x
```

### Exit criteria
Encrypt-decrypt round trip test passes. Tag failure test passes. DEK zeroization verified.

---

## Phase 5: Platform Adapters + Event Publisher

### Files to create (4)

| # | File |
|---|---|
| 1 | `infrastructure/platform_adapters/__init__.py` |
| 2 | `infrastructure/platform_adapters/rbac_permission_adapter.py` |
| 3 | `infrastructure/platform_adapters/approval_workflow_adapter.py` |
| 4 | `infrastructure/events/__init__.py` |
| 5 | `infrastructure/events/structlog_event_publisher.py` |

### `RbacPermissionAdapter`

```python
class RbacPermissionAdapter(IPermissionPort):
    def __init__(self, effective_access_svc: EffectiveAccessService) -> None:
        self._svc = effective_access_svc

    async def has_permission(
        self, principal_id: PrincipalId, credential_id: CredentialId,
        permission: str, tenant_id: TenantId,
    ) -> bool:
        try:
            return await self._svc.has_permission(
                subject_id=str(principal_id),
                resource_type="credential",
                resource_id=str(credential_id),
                permission=permission,
                organization_id=str(tenant_id),
            )
        except Exception as exc:
            logger.warning("permission_check_failed", error=str(exc))
            return False  # fail-open in permission check; fail-closed in audit
```

### `ApprovalWorkflowAdapter`

```python
class ApprovalWorkflowAdapter(IApprovalPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], required_quorum: int = 2):
        self._session_factory = session_factory
        self._required = required_quorum

    async def is_approved(self, credential_id, principal_id, operation, tenant_id) -> bool:
        actual, required = await self.get_approver_count(credential_id, operation, tenant_id)
        return actual >= required

    async def get_approver_count(self, credential_id, operation, tenant_id) -> tuple[int, int]:
        async with self._session_factory() as session:
            result = await session.execute(
                text("""
                    SELECT COUNT(*) FROM credential_vault_approval_requests
                    WHERE credential_id = :cid AND operation = :op
                      AND tenant_id = :tid AND approved_at IS NOT NULL
                      AND expires_at > NOW()
                """),
                {"cid": credential_id.value, "op": operation, "tid": tenant_id.value},
            )
            actual = result.scalar_one()
        return (actual, self._required)
```

### `StructlogEventPublisher`

```python
class StructlogEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self._logger = structlog.get_logger("credential_vault.events")

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        for event in events:
            self._logger.info(
                "domain_event_published",
                event_type=type(event).__name__,
                occurred_at=event.occurred_at.isoformat(),
            )
```

Never raises. Never re-raises. Swallows all exceptions with a WARNING.

### Validation checklist

```bash
mypy src/credential_vault/infrastructure/ --strict
ruff check src/credential_vault/infrastructure/
```

---

## Phase 6: DI Container

### Objective
Wire all components into `CredentialVaultContainer`.

### Files to create (1)

`credential_vault/infrastructure/container.py`

### Container implementation

```python
class CredentialVaultContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        encryption_adapter: IEncryptionPort,
        kms_adapter: IKeyManagementPort,
        permission_adapter: IPermissionPort,
        approval_adapter: IApprovalPort,
        event_publisher: IEventPublisher,
    ) -> None:
        self._session_factory = session_factory
        self.encryption_adapter = encryption_adapter
        self.kms_adapter = kms_adapter
        self.permission_adapter = permission_adapter
        self.approval_adapter = approval_adapter

        self._uow_factory = make_credential_vault_uow_factory(session_factory)

        # Domain services (pure or port-injected)
        access_control = AccessControlPolicyService()
        break_glass = BreakGlassService(approval_adapter)  # verify constructor
        recovery = RecoveryService(approval_adapter)       # verify constructor
        resolver = CredentialResolverService(
            kms_adapter, encryption_adapter, access_control, break_glass, recovery
        )

        # Application services
        self.credential_service = CredentialApplicationService(
            self._uow_factory, event_publisher, kms_adapter, encryption_adapter,
            permission_adapter, approval_adapter, access_control, break_glass, recovery, resolver
        )
        self.rotation_policy_service = RotationPolicyApplicationService(
            self._uow_factory, event_publisher, permission_adapter
        )
        self.expiration_policy_service = ExpirationPolicyApplicationService(
            self._uow_factory, event_publisher, permission_adapter
        )
        self.vault_backend_service = VaultBackendApplicationService(
            self._uow_factory, event_publisher, permission_adapter
        )

        # Query services (constructed per-request via Depends; stored here as factories)
        self._query_session_factory = session_factory

    def make_credential_query_service(self, session: AsyncSession) -> CredentialQueryService:
        return CredentialQueryService(
            PgCredentialRepository(session),
            PgCredentialVersionRepository(session),
            self.permission_adapter,
        )

    def make_audit_query_service(self, session: AsyncSession) -> AuditQueryService:
        return AuditQueryService(
            PgAuditLogRepository(session),
            PgCredentialRepository(session),
            self.permission_adapter,
        )
```

**Verify before implementing:** Check `BreakGlassService.__init__` and `RecoveryService.__init__` signatures in `credential_vault/domain/services/`. Update container wiring accordingly.

### Validation checklist

```bash
mypy src/credential_vault/infrastructure/container.py --strict
python -c "
import os
os.environ['CREDENTIAL_VAULT_LOCAL_MASTER_KEY'] = __import__('base64').b64encode(b'A'*32).decode()
from credential_vault.infrastructure.container import CredentialVaultContainer
print('Container imports OK')
"
```

---

## Phase 7: API Layer

### Objective
Implement Pydantic schemas and FastAPI routers.

### Files to create (9)

| # | File |
|---|---|
| 1 | `credential_vault/api/__init__.py` |
| 2 | `credential_vault/api/dependencies.py` |
| 3 | `credential_vault/api/schemas/__init__.py` |
| 4 | `credential_vault/api/schemas/credential_schemas.py` |
| 5 | `credential_vault/api/schemas/policy_schemas.py` |
| 6 | `credential_vault/api/schemas/backend_schemas.py` |
| 7 | `credential_vault/api/schemas/audit_schemas.py` |
| 8 | `credential_vault/api/v1/__init__.py` |
| 9 | `credential_vault/api/v1/credentials.py` |
| 10 | `credential_vault/api/v1/credential_policies.py` |
| 11 | `credential_vault/api/v1/vault_backends.py` |
| 12 | `credential_vault/api/v1/audit_logs.py` |

### Schema rules

**Request schemas** contain raw primitives matching command fields.

**Response schemas** match DTO fields. Computed from DTOs in handlers:
```python
@router.post("/credentials", status_code=201, response_model=CredentialResponse)
async def create_credential(
    body: CreateCredentialRequest,
    request: Request,
    svc: Annotated[CredentialApplicationService, Depends(get_credential_service)],
) -> CredentialResponse:
    tenant_id = extract_tenant_id(request)
    principal_id = extract_principal_id(request)
    cmd = CreateCredentialCommand(
        tenant_id=tenant_id,
        principal_id=principal_id,
        owner_principal_id=principal_id,
        name=body.name,
        category=body.category,
        subtype=body.subtype,
        schema_id=body.schema_id,
        vault_backend_id=body.vault_backend_id,
        plaintext_secret=body.plaintext_secret.encode("utf-8"),
        description=body.description,
        tags=body.tags,
        expires_at=body.expires_at,
    )
    dto = await svc.create_credential(cmd)
    return CredentialResponse(**dto.to_dict())
```

### Exception handlers

Register once on the app (or sub-app) — not in each router:
```python
from fastapi import Request
from fastapi.responses import JSONResponse
from credential_vault.domain.exceptions.domain_exceptions import CredentialNotFound, ...
from credential_vault.application.exceptions import ApplicationAuditFailure, ...

def register_credential_vault_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(CredentialNotFound)
    async def handle_not_found(request: Request, exc: CredentialNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})
    # ... one per exception type per §13 mapping table
```

### `resolve_credential` endpoint — critical zeroization

```python
@router.post("/credentials/{credential_id}/resolve", response_model=ResolveCredentialResponse)
async def resolve_credential(...) -> ResolveCredentialResponse:
    ...
    dto = await svc.resolve_credential(cmd)
    try:
        # dto.plaintext_secret is bytes
        return ResolveCredentialResponse(
            credential_id=dto.credential_id,
            version_id=dto.version_id,
            secret_b64=base64.b64encode(dto.plaintext_secret).decode(),
            resolved_at=dto.resolved_at,
        )
    finally:
        # Zero the plaintext_secret bytes if possible
        # Note: bytes is immutable; if the application service passed bytearray through,
        # this is a no-op at the API layer. The zeroization is done in the application service.
        pass
```

The application service is responsible for zeroization (M25B). The API layer does not need to zero.

### Router registration

In `credential_vault/api/v1/__init__.py`:
```python
from fastapi import APIRouter
from .credentials import router as credentials_router
from .credential_policies import router as policies_router
from .vault_backends import router as backends_router
from .audit_logs import router as audit_logs_router

router = APIRouter()
router.include_router(credentials_router)
router.include_router(policies_router)
router.include_router(backends_router)
router.include_router(audit_logs_router)
```

In `redforge/api/v1/__init__.py` (existing file), add:
```python
from credential_vault.api.v1 import router as credential_vault_router
# then:
router.include_router(credential_vault_router, tags=["credential-vault"])
```

### `dependencies.py`

```python
from fastapi import Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession

async def get_async_cv_session(request: Request) -> AsyncSession:
    container = request.app.state.cv_container
    session = container._query_session_factory()
    try:
        yield session
    finally:
        await session.close()

async def get_credential_service(request: Request) -> CredentialApplicationService:
    return request.app.state.cv_container.credential_service

async def get_credential_query_service(
    request: Request,
    session: AsyncSession = Depends(get_async_cv_session),
) -> CredentialQueryService:
    return request.app.state.cv_container.make_credential_query_service(session)
```

### JWT extraction helpers

```python
def extract_tenant_id(request: Request) -> uuid.UUID:
    payload = request.state.jwt_payload  # set by auth middleware
    return uuid.UUID(payload["organization_id"])

def extract_principal_id(request: Request) -> uuid.UUID:
    payload = request.state.jwt_payload
    return uuid.UUID(payload["sub"])
```

Verify `request.state.jwt_payload` structure matches existing auth middleware in `redforge/api/security.py`.

### Validation checklist

```bash
mypy src/credential_vault/api/ --strict
ruff check src/credential_vault/api/
pytest tests/credential_vault/api/ -x -v
```

### Exit criteria
All API tests pass. All response models exclude `config`, `encrypted_payload`, `key_envelope`.

### Common mistakes in Phase 7
- Constructing application service inside route handler — use `Depends`.
- Passing `request` body's `tenant_id` to the command — extract from JWT only.
- Returning `VersionDTO.to_dict()` that includes encryption fields — DTOs do not have those fields.
- Using `JSONResponse` for all responses instead of typed Pydantic models.
- Forgetting `status_code=201` on POST create endpoints.
- Forgetting `status_code=204` on DELETE endpoints (return `None`, not `""`).

---

## Phase 8: Observability and Startup

### Files to create (3)

| # | File |
|---|---|
| 1 | `infrastructure/metrics.py` |
| 2 | `infrastructure/metrics_wrapper.py` |
| 3 | `infrastructure/startup_validator.py` |

### Startup validator

```python
async def validate_credential_vault(container: CredentialVaultContainer) -> None:
    errors: list[str] = []

    # 1. DB connectivity
    try:
        async with container._query_session_factory() as s:
            await s.execute(text("SELECT 1"))
    except Exception as e:
        errors.append(f"credential_vault db unreachable: {e}")

    # 2. Migration head
    # 3. KMS round-trip (non-blocking in non-production)
    # 4. Encryption round-trip

    if errors:
        raise RuntimeError(f"Credential Vault startup validation failed: {errors}")
```

Call from the existing `redforge` startup sequence.

### Validation checklist (Phase 8)

```bash
mypy src/credential_vault/infrastructure/metrics.py src/credential_vault/infrastructure/startup_validator.py --strict
```

---

## Phase 9: Final Integration

### Full validation suite

```bash
# 1. Format
ruff format --check src/credential_vault/

# 2. Lint
ruff check src/credential_vault/

# 3. Type check — full bounded context
mypy src/credential_vault/ --strict

# 4. Domain integrity
git diff --exit-code src/credential_vault/domain/ src/credential_vault/application/
# Expected: ONLY the three additive domain changes from Pre-Implementation

# 5. No infrastructure in application
grep -rn "sqlalchemy\|asyncpg\|cryptography\|boto3" src/credential_vault/application/ && exit 1 || echo "OK"

# 6. No FastAPI/Pydantic in infrastructure (except container.py)
grep -rn "fastapi\|pydantic" src/credential_vault/infrastructure/ | grep -v container.py && exit 1 || echo "OK"

# 7. Unit tests
pytest tests/credential_vault/ -x --ignore=tests/credential_vault/infrastructure/ -v

# 8. Integration tests
pytest tests/credential_vault/infrastructure/ -x -m integration -v

# 9. API tests
pytest tests/credential_vault/api/ -x -v

# 10. Migration up/down
alembic upgrade 0044
alembic downgrade 0043
alembic upgrade 0044
echo "Migration OK"
```

### Exit criteria
All nine checks pass. Zero domain/application modifications (except the three pre-approved additive extensions). Total new files: 45.

---

# 4. Final Completion Checklist

## Domain additive extensions
- [ ] `EncryptionAuthTagFailure` added to `domain_exceptions.py`
- [ ] `KmsKeyNotFound` added to `domain_exceptions.py`
- [ ] `list_with_vault_backend` added to `i_credential_repository.py`
- [ ] All three domain additions pass mypy --strict

## ORM models
- [ ] 7 ORM models created; all inherit from `redforge.infrastructure.database.base.Base`
- [ ] All ID columns use `PgUUID(as_uuid=True)`
- [ ] `row_version` on all aggregate tables
- [ ] `config` NOT a readable column on `VaultBackendModel` (encrypted as `config_encrypted`)

## Migration
- [ ] Migration `0044` creates all 8 tables in correct FK order
- [ ] `downgrade()` drops in reverse order
- [ ] Up/down/up triple-run passes on test DB
- [ ] All indexes created

## Repositories
- [ ] 6 `Pg*Repository` classes implement their respective ABCs
- [ ] `list_with_vault_backend` implemented on `PgCredentialRepository`
- [ ] Optimistic lock conflict raised on `rowcount == 0` in save/update
- [ ] `atomic_promote` uses two UPDATE statements; never two `save()` calls
- [ ] No `session.commit()` in any repository method
- [ ] `_to_domain` and `_from_domain` are pure functions

## UnitOfWork
- [ ] `CredentialVaultUnitOfWork` implements `IUnitOfWork`
- [ ] `__aexit__` calls `rollback()` only when `_committed == False`
- [ ] Session closed in `__aexit__` regardless of outcome
- [ ] `make_credential_vault_uow_factory` returns a callable

## Encryption
- [ ] `AesGcmEncryptionAdapter.encrypt` uses `os.urandom(12)` for IV
- [ ] `AesGcmEncryptionAdapter.decrypt` raises `EncryptionAuthTagFailure` on tag mismatch
- [ ] DEK bytes zeroed after use in both encrypt and decrypt
- [ ] `LocalAesKwKmsAdapter` loads master key from environment, not hardcoded
- [ ] `AwsKmsAdapter` wraps all boto3 calls in `run_in_executor`

## Platform adapters
- [ ] `RbacPermissionAdapter.has_permission` returns `bool`, never raises
- [ ] `ApprovalWorkflowAdapter` queries `credential_vault_approval_requests` table
- [ ] `StructlogEventPublisher.publish_batch` never raises

## DI Container
- [ ] `CredentialVaultContainer` wires all 4 application services
- [ ] `make_credential_query_service` and `make_audit_query_service` factory methods exist
- [ ] Container registered as `app.state.cv_container` at startup

## API Layer
- [ ] 21 endpoints across 4 routers
- [ ] `CreateCredentialRequest.plaintext_secret` is `str`; handler encodes to `bytes`
- [ ] `ResolveCredentialResponse.secret_b64` is base64-encoded, not raw bytes
- [ ] Exception handlers registered for all 23 exception types per §13 mapping
- [ ] No `config` in `VaultBackendResponse`
- [ ] No `encrypted_payload` / `key_envelope` in `VersionResponse`
- [ ] 201 on POST create, 204 on DELETE
- [ ] JWT extraction from `request.state.jwt_payload`
- [ ] Router registered in `redforge/api/v1/__init__.py`

## Observability
- [ ] Prometheus counters defined in `metrics.py`
- [ ] Structlog security events defined (no plaintext secrets logged)
- [ ] Startup validator calls DB, KMS, and encryption checks

## Tests
- [ ] All repository integration tests pass against real PostgreSQL
- [ ] Optimistic lock conflict tests pass
- [ ] `atomic_promote` tests pass
- [ ] Encryption round-trip tests pass
- [ ] DEK zeroization tests pass
- [ ] All API endpoint tests pass

## Final static analysis
- [ ] `mypy src/credential_vault/ --strict` → 0 errors
- [ ] `ruff check src/credential_vault/` → 0 violations
- [ ] `ruff format --check src/credential_vault/` → 0 violations
- [ ] Domain + application diff clean (only the 3 approved additions)
