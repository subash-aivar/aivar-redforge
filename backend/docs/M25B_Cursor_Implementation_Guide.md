# M25B Cursor Implementation Guide
## Enterprise Credential Vault — Application Layer
### Execution Authority: M25B Specification v1.1 | M25 Architecture v1.0 FINAL

---

## Document Purpose

This guide converts the frozen M25B specification into a step-by-step execution plan for Cursor. Every decision has already been made. Cursor implements; it does not design.

**Frozen inputs:**
- `M25B_Spec_Part1.md` — Sections 1–12
- `M25B_Spec_Part2.md` — Sections 13–23
- `credential_vault/domain/` — M25A, zero modifications permitted

**Target directory:** `backend/src/credential_vault/application/`
**Test directory:** `backend/tests/credential_vault/application/`

---

# 1. Overall Implementation Strategy

## 1.1 Layering contract

The application layer depends on the domain layer. It never depends on infrastructure. This is enforced structurally: no import from `credential_vault/application/` may reach `infrastructure/`, `api/`, or any ORM model.

```
credential_vault/application/  →  credential_vault/domain/  (allowed)
credential_vault/application/  →  stdlib, typing             (allowed)
credential_vault/application/  →  infrastructure/            (FORBIDDEN)
credential_vault/application/  →  api/                       (FORBIDDEN)
```

mypy and an import-cycle check enforce this after each phase.

## 1.2 Execution model

All 27 files are implemented in strict dependency order across eight phases. No phase begins until the previous phase passes all validation checks. Files within a phase that have no inter-dependencies may be implemented in any order, but all must be complete before phase validation runs.

## 1.3 What Cursor must never do

- Modify any file under `credential_vault/domain/`.
- Access `credential._pending_new_version_id` or `credential._pending_rotation_context` (private slots).
- Use `version.promote()` for SUPERSEDED→ACTIVE transitions (no such domain method exists; direct public-attribute assignment is the spec-defined mechanism).
- Call `has_permission` with a sentinel or fabricated credential ID.
- Define any HTTP response models, FastAPI routes, or Pydantic schemas.
- Write to a database directly (no SQLAlchemy, no psycopg2 imports).
- Implement `IUnitOfWork`, `IEventPublisher`, or any port ABC (those are M25C).
- Add business logic to commands, queries, or DTOs (they are pure data containers).
- Catch `OptimisticLockConflict` — it propagates to the caller unmodified.
- Commit before writing the audit entry (fail-closed invariant).

## 1.4 Quality standard

- `mypy --strict` — zero errors across all 27 files.
- `ruff check` — zero violations.
- `ruff format` — applied before each phase validation.
- `pytest tests/credential_vault/application/ -x` — zero failures.
- No circular imports anywhere in `credential_vault/`.

---

# 2. Sequential Implementation Phases

---

## Phase 1: Foundation

### Objective
Establish the five foundational files that all other application-layer files depend on: the package init, application exceptions, validation helpers, and the two application port ABCs.

### Scope
`application/__init__.py`, `application/exceptions.py`, `application/_validation.py`, `application/ports/__init__.py`, `application/ports/i_unit_of_work.py`, `application/ports/i_event_publisher.py`

### Files to create (6)

| # | File | Purpose |
|---|---|---|
| 1 | `application/__init__.py` | Empty package marker |
| 2 | `application/exceptions.py` | `ApplicationException` hierarchy |
| 3 | `application/_validation.py` | Shared primitive validators |
| 4 | `application/ports/__init__.py` | Empty package marker |
| 5 | `application/ports/i_unit_of_work.py` | `IUnitOfWork` ABC |
| 6 | `application/ports/i_event_publisher.py` | `IEventPublisher` ABC |

### Files to modify
None.

### Exact implementation order
1 → 4 → 2 → 3 → 5 → 6 (init files first, then dependents)

### Dependencies
Phase 1 has no application-layer dependencies. It imports from `credential_vault/domain/` only (inside `TYPE_CHECKING` blocks).

### `application/exceptions.py` — implementation details

Define exactly four classes:

- `ApplicationException(Exception)` — base; no additional fields.
- `ApplicationAuditFailure(ApplicationException)` — raised when `IAuditLogRepository.append_entry` raises. Causes transaction rollback via `__aexit__`. Constructor: `__init__(self, message: str) -> None`.
- `ApplicationPortError(ApplicationException)` — raised when an external port call (KMS, permission port) fails with an unexpected exception. Constructor: `__init__(self, port_name: str, cause: Exception) -> None`. Store both as attributes; format message as `f"{port_name} port failure: {cause}"`.
- `ApplicationValidationError(ApplicationException)` — raised by `_validation.py` helpers and by service methods when command/query primitives fail pre-UoW validation. Constructor: `__init__(self, field: str, reason: str) -> None`. Store both; format as `f"Invalid {field}: {reason}"`.

No other exception classes. Do not subclass domain exceptions.

### `application/_validation.py` — implementation details

Four module-private helper functions. This module imports only from `stdlib`. No domain imports.

- `validate_uuid(value: UUID, field: str) -> None` — raises `ApplicationValidationError(field, "must be a valid non-nil UUID")` if `value.int == 0`.
- `validate_str(value: str, field: str, max_len: int, allow_empty: bool = False) -> None` — raises `ApplicationValidationError` if empty (unless `allow_empty=True`) or `len(value) > max_len`.
- `validate_limit(value: int) -> int` — clamps to `max(1, min(value, 1000))` and returns the clamped value; raises `ApplicationValidationError("limit", "must be 1–1000")` if `value < 1`.
- `validate_offset(value: int) -> None` — raises `ApplicationValidationError("offset", "must be >= 0")` if `value < 0`.

All four are imported with `from credential_vault.application._validation import ...` inside service methods. They are NOT re-exported from `application/__init__.py`.

### `application/ports/i_unit_of_work.py` — implementation details

`IUnitOfWork` is an `abc.ABC`. It carries six typed repository attributes, two abstract async methods, and implements the async context manager protocol.

**Six repository attributes** (declared as abstract class-level annotations, not properties):
```
credentials: ICredentialRepository
versions: ICredentialVersionRepository
rotation_policies: IRotationPolicyRepository
expiration_policies: IExpirationPolicyRepository
vault_backends: IVaultBackendRepository
audit_logs: IAuditLogRepository
```

All six types are imported inside `TYPE_CHECKING` only.

**Two abstract methods:**
- `async def commit(self) -> None`
- `async def rollback(self) -> None`

**Context manager protocol** (concrete, not abstract):
- `async def __aenter__(self) -> IUnitOfWork` — returns `self`.
- `async def __aexit__(self, exc_type, exc_val, exc_tb) -> None` — calls `await self.rollback()` if `exc_type is not None` AND `commit()` was not yet called. Use an internal `_committed: bool` flag initialized to `False`; set to `True` inside `commit()`. `__aexit__` calls `rollback()` only when `not self._committed`.

**Important:** `_committed` is a concrete instance attribute initialized in a concrete `__init__`. Subclasses must call `super().__init__()` or replicate this flag.

Do not define `SENTINEL_CREDENTIAL_ID`. Do not define any constant in this file.

### `application/ports/i_event_publisher.py` — implementation details

`IEventPublisher` is an `abc.ABC` with a single abstract method:

- `async def publish_batch(self, events: list[BaseDomainEvent]) -> None`

`BaseDomainEvent` is imported inside `TYPE_CHECKING` only from `credential_vault.domain.events.base`.

An empty `events` list is a valid input. The method must be a no-op in that case (enforced by implementations; the interface does not specify it).

### Internal checkpoints
- `application/__init__.py` exists and is importable.
- `exceptions.py` imports cleanly with no domain imports at module top level.
- `_validation.py` imports cleanly with stdlib only.
- `IUnitOfWork.__abstractmethods__` includes `commit` and `rollback` only.
- `IEventPublisher.__abstractmethods__` includes `publish_batch` only.

### Expected outputs
Six files, all importable, all mypy-clean, no test failures (no tests yet for this phase).

### Validation checklist

```
ruff check src/credential_vault/application/
ruff format --check src/credential_vault/application/
mypy src/credential_vault/application/ --strict
python -c "from credential_vault.application.exceptions import ApplicationException"
python -c "from credential_vault.application.ports.i_unit_of_work import IUnitOfWork"
python -c "from credential_vault.application.ports.i_event_publisher import IEventPublisher"
python -c "import credential_vault.application._validation"
```

### Exit criteria
All six checks pass. Zero mypy errors. Zero ruff violations.

### Common mistakes in Phase 1
- Importing domain repository ABCs at module top level in `i_unit_of_work.py` — triggers import cycles. All domain imports go inside `TYPE_CHECKING`.
- Implementing `__aenter__`/`__aexit__` as abstract — they must be concrete on `IUnitOfWork` so the `_committed` flag pattern works.
- Forgetting `from __future__ import annotations` at the top of every file — required for deferred annotation evaluation under `python_version = "3.14"`.
- Placing `_validation.py` helpers in `__init__.py` — they belong in their own module.

### Architectural pitfalls
- Do not inherit `IUnitOfWork` from any database session class. It is a pure ABC.
- Do not add a `collect_events()` method to `IUnitOfWork`. Event draining is done by the application service calling `aggregate.pop_events()` directly after commit.

---

## Phase 2: Commands

### Objective
Implement all 26 command dataclasses across three files. Commands are pure data containers — no methods, no business logic, no imports from the domain.

### Scope
`application/commands/__init__.py`, `application/commands/credential_commands.py`, `application/commands/policy_commands.py`, `application/commands/backend_commands.py`

### Files to create (4)

| # | File | Commands |
|---|---|---|
| 1 | `commands/__init__.py` | Empty |
| 2 | `commands/credential_commands.py` | 18 commands |
| 3 | `commands/policy_commands.py` | 6 commands |
| 4 | `commands/backend_commands.py` | 2 commands |

### Files to modify
None.

### Dependencies
Phase 1 must be complete. Commands have zero application-layer dependencies. Commands depend only on stdlib (`uuid.UUID`, `datetime.datetime`).

### Implementation rules for all commands

- Every command is `@dataclass(frozen=True, slots=True)`.
- `from __future__ import annotations` at top of each file.
- `from uuid import UUID` and `from datetime import datetime` at module level (not in `TYPE_CHECKING`) — these are runtime types needed for frozen dataclass fields.
- All ID fields are `UUID`, not `CredentialId`, `TenantId`, etc. VO construction happens in the application service.
- All state/type/trigger fields are `str`. Enum construction happens in the application service.
- `bytes` fields (plaintext secrets) have no default values and are not optional unless the spec explicitly marks them so.
- No `to_dict()`, no `from_dict()`, no validators inside commands. Commands carry data only.

### Field specification — `credential_commands.py`

Implement exactly the 18 commands from M25B Spec §5.1. Critical details:

**`CreateCredentialCommand`**: `plaintext_secret: bytes` is required. `expires_at: datetime | None` defaults to `None`.

**`ResolveCredentialCommand`**: `break_glass: bool = False`. `justification: str | None = None`. `client_ip: str | None = None`. `request_id: str | None = None`.

**`RotateCredentialCommand`**: `new_plaintext_secret: bytes` required. `policy_id: UUID | None = None`. `notes: str | None = None`.

**`CommitRotationCommand`**: Three fields only — `tenant_id`, `credential_id`, `principal_id`.

**`AbortRotationCommand`**: `reason: str` required (no default).

**`EmergencyRevokeCommand`**: `justification: str` required (no default).

**`RecoverCredentialCommand`**: `target_version_id: UUID` required. `justification: str` required.

**`HardDeleteCredentialCommand`**: Three fields only — `tenant_id`, `credential_id`, `principal_id`.

**`EnableCredentialCommand`**: Three fields only — `tenant_id`, `credential_id`, `principal_id`.

**`AttachRotationPolicyCommand`** and **`AttachExpirationPolicyCommand`**: Four fields — `tenant_id`, `credential_id`, `policy_id`, `principal_id`.

**`DetachRotationPolicyCommand`** and **`DetachExpirationPolicyCommand`**: Three fields — `tenant_id`, `credential_id`, `principal_id`.

### Field specification — `policy_commands.py`

**`CreateRotationPolicyCommand`**: `interval_days: int | None = None`. `auto_rotate: bool` required.

**`CreateExpirationPolicyCommand`**: `hard_expire: bool` required.

All update commands mirror the create commands minus the `name` field (name is immutable after creation).

### Field specification — `backend_commands.py`

**`RegisterVaultBackendCommand`**: `config: dict[str, str]` required. `is_default: bool` required.

**`DeleteVaultBackendCommand`**: Three fields — `tenant_id`, `backend_id`, `principal_id`.

### Internal checkpoints
- `dataclasses.fields(CreateCredentialCommand)` returns exactly 11 fields.
- `CreateCredentialCommand(...)` is immutable: assigning to a field raises `FrozenInstanceError`.
- `CreateCredentialCommand.__slots__` exists and is non-empty.

### Validation checklist

```
ruff check src/credential_vault/application/commands/
mypy src/credential_vault/application/commands/ --strict
python -c "from credential_vault.application.commands.credential_commands import CreateCredentialCommand"
python -c "from credential_vault.application.commands.policy_commands import CreateRotationPolicyCommand"
python -c "from credential_vault.application.commands.backend_commands import RegisterVaultBackendCommand"
pytest tests/credential_vault/application/commands/ -x
```

### Exit criteria
All commands importable. All frozen. mypy zero errors. All command tests pass.

### Common mistakes in Phase 2
- Using domain types (`CredentialId`, `TenantId`) as field types — commands use stdlib `UUID` only.
- Using `StrEnum` values as field types for `category`, `trigger`, `backend_type` — they must be `str`.
- Setting `frozen=False` accidentally — all commands must be `frozen=True`.
- Importing from `credential_vault.domain` in command files — forbidden. Commands are dependency-free.
- Adding default values to required fields like `plaintext_secret` or `reason`.

---

## Phase 3: Queries

### Objective
Implement all 11 query dataclasses across four files.

### Scope
`application/queries/__init__.py`, `application/queries/credential_queries.py`, `application/queries/policy_queries.py`, `application/queries/backend_queries.py`, `application/queries/audit_queries.py`

### Files to create (5)

| # | File | Queries |
|---|---|---|
| 1 | `queries/__init__.py` | Empty |
| 2 | `queries/credential_queries.py` | 4 queries |
| 3 | `queries/policy_queries.py` | 4 queries |
| 4 | `queries/backend_queries.py` | 2 queries |
| 5 | `queries/audit_queries.py` | 1 query |

### Implementation rules

Same rules as commands: `@dataclass(frozen=True, slots=True)`, stdlib types only, no logic.

### Field specification

**`ListCredentialsQuery`**: `states: list[str] | None = None`. `limit: int = 100`. `offset: int = 0`.

**`ListVersionsQuery`**: `states: list[str] | None = None`.

**`ListAuditEntriesQuery`**: `since: datetime | None = None`. `operations: list[str] | None = None`. `limit: int = 100`. `offset: int = 0`.

**`ListRotationPoliciesQuery`**, **`ListExpirationPoliciesQuery`**, **`ListVaultBackendsQuery`**: Two fields each — `tenant_id: UUID`, `principal_id: UUID`.

All `Get*Query` types: Three fields — `tenant_id`, target ID (`credential_id` / `policy_id` / `backend_id`), `principal_id`.

### Validation checklist

```
ruff check src/credential_vault/application/queries/
mypy src/credential_vault/application/queries/ --strict
pytest tests/credential_vault/application/queries/ -x
```

### Exit criteria
All queries importable, frozen, mypy clean, query tests pass.

---

## Phase 4: DTOs

### Objective
Implement seven DTO classes. DTOs convert domain aggregates and entities to serializable output objects. They carry no business logic beyond the `from_aggregate` / `from_entity` factory classmethods and `to_dict()`.

### Scope
`application/dtos/__init__.py`, `application/dtos/credential_dtos.py`, `application/dtos/policy_dtos.py`, `application/dtos/backend_dtos.py`, `application/dtos/audit_dtos.py`

### Files to create (5)

| # | File | DTOs |
|---|---|---|
| 1 | `dtos/__init__.py` | Empty |
| 2 | `dtos/credential_dtos.py` | `CredentialDTO`, `VersionDTO`, `ResolvedSecretDTO` |
| 3 | `dtos/policy_dtos.py` | `RotationPolicyDTO`, `ExpirationPolicyDTO` |
| 4 | `dtos/backend_dtos.py` | `VaultBackendDTO` |
| 5 | `dtos/audit_dtos.py` | `AuditEntryDTO` |

### Dependencies
Phases 1–3 complete. DTOs depend on domain aggregates/entities only inside `TYPE_CHECKING`.

### Implementation rules for all DTOs

- All DTOs are `@dataclass(frozen=True, slots=True)`.
- All ID fields are `str` (not `UUID`). Serialized via `str(vo_instance)` in the factory classmethod (VO `__str__` returns `str(self.value)`).
- All `datetime` fields are `str`. Serialized via `.isoformat()`. UTC datetimes include timezone info; result ends with `+00:00`.
- `from_aggregate` / `from_entity` are `@classmethod` methods with return type annotation `-> Self` (use `from typing import Self`). Domain types referenced in these signatures are inside `TYPE_CHECKING`.
- `to_dict(self) -> dict[str, object]` is a concrete instance method. Return a shallow dict mapping field names to their values. For `list` fields, return a copy (`list(self.tags.items())` is wrong — return `dict(self.tags)`).

### `CredentialDTO` — critical details

Fields: `credential_id`, `tenant_id`, `name`, `category`, `subtype`, `schema_id: str | None`, `state`, `owner_principal_id`, `active_version_id: str | None`, `rotation_policy_id: str | None`, `expiration_policy_id: str | None`, `vault_backend_id`, `description: str | None`, `tags: dict[str, str]`, `created_at`, `updated_at`, `version: int`.

`from_aggregate(credential: Credential) -> CredentialDTO`:
- `category = credential.credential_type.category.value`
- `subtype = credential.credential_type.subtype`
- `schema_id = str(credential.credential_type.schema_id) if credential.credential_type.schema_id is not None else None`
- `owner_principal_id = str(credential.owner_principal)`
- `active_version_id = str(credential.active_version_id) if credential.active_version_id is not None else None`
- `rotation_policy_id = str(credential.rotation_policy_id) if credential.rotation_policy_id is not None else None`
- `expiration_policy_id = str(credential.expiration_policy_id) if credential.expiration_policy_id is not None else None`
- `state = credential.state.value`
- `tags = dict(credential.tags)`
- `version = credential.version` (the `@property` on Credential returns `_version`)

### `VersionDTO` — critical details

Fields: `version_id`, `credential_id`, `tenant_id`, `version_number: int`, `version_state`, `created_by`, `created_at`, `expires_at: str | None`, `rotation_trigger: str | None`, `rotation_policy_id: str | None`.

`from_entity(version: CredentialVersion) -> VersionDTO`:
- `version_state = version.version_state.value`
- `rotation_trigger = version.rotation_context.trigger.value if version.rotation_context is not None else None`
- `rotation_policy_id = str(version.rotation_context.policy_id) if version.rotation_context is not None and version.rotation_context.policy_id is not None else None`
- `expires_at = version.expires_at.isoformat() if version.expires_at is not None else None`

**`VersionDTO` must not expose `encrypted_payload` or `key_envelope`**. These fields do not appear in `VersionDTO` at all.

### `ResolvedSecretDTO` — critical details

Fields: `credential_id: str`, `version_id: str`, `plaintext_secret: bytes`, `resolved_at: str`.

**No `from_aggregate` classmethod.** Constructed directly in the service.
**No `to_dict()` method.** `ResolvedSecretDTO` is never serialized to JSON by the application layer.
The `frozen=True` constraint means `plaintext_secret` is a `bytes` reference; the bytes object itself is mutable-equivalent if using `bytearray` but the spec uses `bytes` from `IEncryptionPort.decrypt()`. Do not zero the bytes in the DTO. The caller (presentation layer) is responsible for zeroization.

### `VaultBackendDTO` — critical details

Fields: `backend_id`, `tenant_id`, `name`, `backend_type`, `is_default: bool`, `created_at`, `updated_at`, `version: int`.

**`config` is NOT a field.** It must not appear anywhere in `VaultBackendDTO`. Not in the constructor, not in `to_dict()`, not in `from_aggregate`.

`from_aggregate(backend: VaultBackend) -> VaultBackendDTO`:
- `backend_type = backend.backend_type.value`

### `AuditEntryDTO` — critical details

Fields: `entry_id`, `audit_log_id`, `credential_id`, `tenant_id`, `operation`, `outcome`, `principal_id`, `occurred_at`, `detail`, `client_ip: str | None`, `request_id: str | None`.

`from_entity(entry: AuditEntry) -> AuditEntryDTO`:
- `operation = entry.operation.value`
- `outcome = entry.outcome.value`
- `principal_id = str(entry.principal_id)`
- `client_ip = entry.client_ip`
- `request_id = entry.request_id`

### Internal checkpoints
- `VersionDTO` has no `encrypted_payload` or `key_envelope` fields.
- `VaultBackendDTO` has no `config` field.
- `ResolvedSecretDTO` has no `to_dict` method.
- `CredentialDTO.to_dict()` returns a `dict` where all values are JSON-serializable primitives.
- `CredentialDTO.tags` is a `dict[str, str]` copy (not a reference to the aggregate's `tags`).

### Validation checklist

```
ruff check src/credential_vault/application/dtos/
mypy src/credential_vault/application/dtos/ --strict
pytest tests/credential_vault/application/dtos/ -x
```

### Exit criteria
All DTOs importable, frozen, mypy clean, DTO tests pass. `config` not present in `VaultBackendDTO`. `encrypted_payload` not present in `VersionDTO`.

### Common mistakes in Phase 4
- Serializing UUIDs with `uuid.UUID.__str__` on the VO wrapper — use `str(vo_instance)` which calls `VO.__str__` returning `str(self.value)`.
- Returning a reference to `credential.tags` instead of a copy — DTOs must be self-contained.
- Forgetting `version: int` on aggregate DTOs — it comes from `aggregate.version` (property returning `_version`).
- Adding `encrypted_payload` or `key_envelope` fields "for completeness" — forbidden.
- Making `VersionDTO.rotation_trigger` return a `RotationTrigger` enum — it must return `str` (`.value`).

---

## Phase 5: Application Services — Command Side

### Objective
Implement five command-side application services: `CredentialApplicationService`, `RotationPolicyApplicationService`, `ExpirationPolicyApplicationService`, `VaultBackendApplicationService`, and the shared `services/__init__.py`.

### Scope
`application/services/__init__.py`, `application/services/credential_application_service.py`, `application/services/rotation_policy_application_service.py`, `application/services/expiration_policy_application_service.py`, `application/services/vault_backend_application_service.py`

### Files to create (5)

| # | File |
|---|---|
| 1 | `services/__init__.py` |
| 2 | `services/credential_application_service.py` |
| 3 | `services/rotation_policy_application_service.py` |
| 4 | `services/expiration_policy_application_service.py` |
| 5 | `services/vault_backend_application_service.py` |

### Dependencies
All Phases 1–4 complete.

---

### 5A. `CredentialApplicationService` — implementation details

#### Constructor

```
__init__(
    uow_factory: Callable[[], IUnitOfWork],
    event_publisher: IEventPublisher,
    key_mgmt_port: IKeyManagementPort,
    encryption_port: IEncryptionPort,
    permission_port: IPermissionPort,
    approval_port: IApprovalPort,
    access_control: AccessControlPolicyService,
    break_glass_svc: BreakGlassService,
    recovery_svc: RecoveryService,
    resolver_svc: CredentialResolverService,
)
```

All ten parameters are stored as private attributes (`self._uow_factory`, etc.). All domain types are imported inside `TYPE_CHECKING`.

#### Private helpers (implement these first, before any public method)

**`_build_access_context(principal_id: UUID, purpose: str, client_ip: str | None, request_id: str | None, break_glass: bool, justification: str | None) -> AccessContext`**
- Constructs `AccessContext` from primitives.
- Raises `ApplicationValidationError` on validation failure from `AccessContext.__post_init__`.

**`_get_audit_log(uow: IUnitOfWork, credential_id: CredentialId, tenant_id: TenantId) -> AuditLog`**
- Calls `await uow.audit_logs.get_by_credential(credential_id, tenant_id)`.
- Does not catch exceptions; propagates `CredentialNotFound`.

**`_make_audit_entry(audit_log_id: AuditLogId, credential_id: CredentialId, tenant_id: TenantId, operation: AuditOperation, principal_id: PrincipalId, detail: str, client_ip: str | None = None, request_id: str | None = None) -> AuditEntry`**
- Constructs an `AuditEntry` with `entry_id=AuditEntryId(uuid7())`, `outcome=AuditOutcome.SUCCESS`, `occurred_at=datetime.now(UTC)`.

**`async def _write_audit_and_commit(uow: IUnitOfWork, audit_log_id: AuditLogId, entry: AuditEntry, tenant_id: TenantId) -> None`**
- Calls `await uow.audit_logs.append_entry(audit_log_id, entry, tenant_id)`.
- If `append_entry` raises: raises `ApplicationAuditFailure(str(exc))`. The UoW `__aexit__` will call `rollback()`.
- If `append_entry` succeeds: calls `await uow.commit()`.

**`async def _publish(aggregates: list[Any]) -> None`** (where `Any` bounds to aggregates with `pop_events()`)
- Collects `events: list[BaseDomainEvent] = []`.
- Calls `aggregate.pop_events()` for each aggregate in order; extends `events`.
- Calls `await self._event_publisher.publish_batch(events)`.
- Wraps the `publish_batch` call in a `try/except Exception`: on failure, logs a WARNING only. Never re-raises.

#### Transaction lifecycle (applies to every mutating method)

```
1. Validate command primitives (pre-UoW)
2. Authorization check via permission_port (pre-UoW)
3. async with self._uow_factory() as uow:
       a. Load aggregate(s) via uow repositories
       b. Load audit_log via _get_audit_log()
       c. Perform domain mutations
       d. Save aggregate(s) via uow repositories
       e. Construct AuditEntry
       f. _write_audit_and_commit(uow, ...) — writes audit THEN commits
   # UoW.__aexit__ calls rollback() if commit was not reached
4. await _publish([mutated_aggregate, ...])
5. return DTO
```

Step 3e–3f ordering is invariant: **audit write precedes commit, always**. Never call `uow.commit()` before `uow.audit_logs.append_entry()`.

#### Method-by-method implementation guide

**`create_credential(cmd)`**

Pre-UoW:
1. Call `validate_uuid(cmd.tenant_id, "tenant_id")`, etc. for all UUIDs.
2. Validate `cmd.name` (non-empty, ≤256 chars, pattern `[\w\-\./ ]+`).
3. Validate `cmd.category` is a valid `CredentialCategory` value — use `CredentialCategory(cmd.category)` in a try/except `ValueError`, raise `ApplicationValidationError`.
4. Validate `cmd.subtype` (≤64 chars, `[A-Z0-9_-]+`).
5. If `cmd.category == "CUSTOM"` and `cmd.schema_id is None` → raise `ApplicationValidationError("schema_id", "required for CUSTOM category")`.
6. Validate `cmd.plaintext_secret` is non-empty bytes.
7. Generate `credential_id = CredentialId(uuid7())`.
8. Call `await self._permission_port.has_permission(PrincipalId(cmd.owner_principal_id), credential_id, IPermissionPort.PERMISSION_WRITE, TenantId(cmd.tenant_id))`. If `False` → raise `AccessDenied(...)`.

KMS/encryption (pre-UoW, failures prevent UoW from opening):
9. `dek_bytes, key_envelope = await self._key_mgmt_port.generate_dek()` — wrap in try/except, raise `ApplicationPortError("key_management", exc)` on failure.
10. `encrypted_payload = await self._encryption_port.encrypt(cmd.plaintext_secret, dek_bytes)` — wrap, raise `ApplicationPortError("encryption", exc)` on failure.

UoW block:
11. `version_id = VersionId(uuid7())`.
12. `audit_log_id = AuditLogId(uuid7())`.
13. Check name uniqueness: `exists = await uow.credentials.exists_by_name(CredentialName(cmd.name), TenantId(cmd.tenant_id))`. If `True` → raise `CredentialAlreadyExists(CredentialName(cmd.name), TenantId(cmd.tenant_id))`.
14. Verify backend: `await uow.vault_backends.get_by_id(VaultBackendId(cmd.vault_backend_id), TenantId(cmd.tenant_id))`.
15. Construct `CredentialVersion(version_id, credential_id, TenantId(cmd.tenant_id), version_number=1, encrypted_payload, key_envelope, VersionState.PENDING, None, now, PrincipalId(cmd.owner_principal_id), cmd.expires_at)`.
16. Construct `CredentialType(CredentialCategory(cmd.category), cmd.subtype, cmd.schema_id)`.
17. `credential = Credential.create(credential_id, TenantId(cmd.tenant_id), CredentialName(cmd.name), cred_type, PrincipalId(cmd.owner_principal_id), VaultBackendId(cmd.vault_backend_id), cmd.description, cmd.tags, now)`.
18. `credential.activate(TenantId(cmd.tenant_id), version_id, now)`.
19. `version.promote()`.
20. `audit_log = AuditLog.create(audit_log_id, credential_id, TenantId(cmd.tenant_id), now)`.
21. `await uow.versions.save(version)`.
22. `await uow.credentials.save(credential)`.
23. `await uow.audit_logs.save(audit_log)`.
24. `entry = _make_audit_entry(audit_log_id, credential_id, TenantId(cmd.tenant_id), AuditOperation.CREATED, PrincipalId(cmd.owner_principal_id), f"credential created by {cmd.owner_principal_id}")`.
25. `await _write_audit_and_commit(uow, audit_log_id, entry, TenantId(cmd.tenant_id))`.

Post-UoW:
26. `await _publish([credential])`.
27. Return `CredentialDTO.from_aggregate(credential)`.

---

**`resolve_credential(cmd)`**

Pre-UoW:
1. Validate command UUIDs and `purpose` (non-empty, ≤512).
2. Validate `client_ip` if present via `ipaddress.ip_address(cmd.client_ip)`.
3. If `cmd.break_glass` and not `cmd.justification` → raise `ApplicationValidationError("justification", "required for break-glass access")`.
4. Construct `access_context = _build_access_context(...)`.

UoW block:
5. `credential = await uow.credentials.get_by_id(CredentialId(cmd.credential_id), TenantId(cmd.tenant_id))`.
6. `active_version = await uow.versions.get_active_version(CredentialId(cmd.credential_id), TenantId(cmd.tenant_id))`.
7. `resolved_secret = await self._resolver_svc.resolve(credential, active_version, access_context)`. This may raise `AccessDenied`, `CredentialIsRevoked`, `CredentialIsExpired`, `CredentialIsDeleted`, `ActiveVersionNotFound`, `InsufficientApprovers`, `BreakGlassJustificationRequired`. All propagate.
8. `audit_log = await _get_audit_log(uow, CredentialId(cmd.credential_id), TenantId(cmd.tenant_id))`.
9. Determine operation: `AuditOperation.BREAK_GLASS if cmd.break_glass else AuditOperation.ACCESSED`.
10. `detail = f"purpose={cmd.purpose}; ip={cmd.client_ip}; request_id={cmd.request_id}"`.
11. `entry = _make_audit_entry(..., client_ip=cmd.client_ip, request_id=cmd.request_id)`.
12. `await uow.credentials.save(credential)` — persists the `CredentialAccessed`/`BreakGlassAccessed` event that `resolver_svc.resolve()` attached to `credential._pending_events`.
13. `await _write_audit_and_commit(uow, audit_log.audit_log_id, entry, TenantId(cmd.tenant_id))`.

Post-UoW:
14. `await _publish([credential])`.
15. Return `ResolvedSecretDTO(str(credential.credential_id), str(active_version.version_id), resolved_secret.get_plaintext(), resolved_secret.resolved_at.isoformat())`.

**Fail-closed enforcement:** If step 13 raises `ApplicationAuditFailure`, the UoW rolls back (no `save` is committed). `resolved_secret` already exists in memory but is not returned. The exception propagates. The secret is never delivered without a committed audit record.

---

**`rotate_credential(cmd)` (begin rotation)**

Pre-UoW:
1. Validate UUIDs, `trigger` as valid `RotationTrigger`, `notes` ≤1024.
2. Validate `cmd.new_plaintext_secret` non-empty.

Pre-UoW (outside UoW because failures prevent opening):
3. `dek_bytes, key_envelope = await self._key_mgmt_port.generate_dek()`.
4. `encrypted_payload = await self._encryption_port.encrypt(cmd.new_plaintext_secret, dek_bytes)`.

UoW block:
5. Load credential.
6. Assert `PERMISSION_ROTATE` via `await self._access_control.assert_can_rotate(credential, AccessContext(PrincipalId(cmd.principal_id), "rotation"))`.
7. Get max version_number: `versions = await uow.versions.list_by_credential(CredentialId(cmd.credential_id), TenantId(cmd.tenant_id))`. `next_version_number = max(v.version_number for v in versions) + 1`.
8. `new_version_id = VersionId(uuid7())`.
9. `rotation_context = RotationContext(RotationTrigger(cmd.trigger), PrincipalId(cmd.principal_id), credential.active_version_id, RotationPolicyId(cmd.policy_id) if cmd.policy_id else None, cmd.notes)`.
10. Construct `CredentialVersion(new_version_id, ..., version_number=next_version_number, VersionState.PENDING, rotation_context, ...)`.
11. `credential.begin_rotation(TenantId(cmd.tenant_id), new_version_id, rotation_context, now)`.
12. `await uow.versions.save(new_version)`.
13. `await uow.credentials.save(credential)`.
14. Audit: `AuditOperation.ROTATION_STARTED`, detail `f"trigger={cmd.trigger}; new_version_id={new_version_id}"`.
15. `await _write_audit_and_commit(...)`.

Post-UoW:
16. `await _publish([credential])`.
17. Return `CredentialDTO.from_aggregate(credential)`.

---

**`commit_rotation(cmd)`**

UoW block:
1. Load credential. Must be ROTATING (domain enforces via `commit_rotation` method).
2. `pending = await uow.versions.list_by_credential(CredentialId(cmd.credential_id), TenantId(cmd.tenant_id), states=[VersionState.PENDING])`.
3. If `len(pending) != 1` → raise `InvalidStateTransition(current=credential.state.value, attempted="commit_rotation")`.
4. `new_version = pending[0]`.
5. Load `old_version = await uow.versions.get_by_id(credential.active_version_id, TenantId(cmd.tenant_id))`.
6. `new_version.promote()`.
7. `old_version.supersede()`.
8. `credential.commit_rotation(TenantId(cmd.tenant_id), new_version.version_id, old_version.version_id, now)`.
9. `await uow.versions.atomic_promote(new_version, supersede_version_id=old_version.version_id, TenantId(cmd.tenant_id))`.
10. `await uow.credentials.save(credential)`.
11. Audit: `AuditOperation.ROTATION_COMMITTED`, detail `f"new_version_id={new_version.version_id}; superseded={old_version.version_id}"`.
12. `await _write_audit_and_commit(...)`.

**Never call `uow.versions.save(new_version)` and `uow.versions.save(old_version)` separately for this operation.** Always use `atomic_promote`. This is the only repository operation that simultaneously promotes and supersedes.

---

**`abort_rotation(cmd)`**

UoW block:
1. Load credential. Must be ROTATING.
2. `pending = await uow.versions.list_by_credential(..., states=[VersionState.PENDING])`.
3. If `len(pending) != 1` → raise `InvalidStateTransition(...)`.
4. `aborted_version = pending[0]`.
5. `aborted_version.revoke()` — domain method transitions any state → REVOKED.
6. `credential.abort_rotation(TenantId(cmd.tenant_id), cmd.reason, PrincipalId(cmd.principal_id), now)`.
7. `await uow.versions.update(aborted_version)`.
8. `await uow.credentials.save(credential)`.
9. Audit: `AuditOperation.ROTATION_ABORTED`, detail `f"reason={cmd.reason}; aborted_version_id={aborted_version.version_id}"`.
10. `await _write_audit_and_commit(...)`.

---

**`disable_credential(cmd)`, `enable_credential(cmd)`, `revoke_credential(cmd)`**

Standard pattern:
1. Validate UUIDs.
2. Check permission via `permission_port.has_permission(...)`.
3. UoW: load credential.
4. Call aggregate method.
5. `uow.credentials.save(credential)`.
6. Audit write + commit.
7. Publish + return DTO.

Permission constants: disable/enable → `PERMISSION_WRITE`; revoke → `PERMISSION_REVOKE` via `self._access_control.assert_can_revoke`.

---

**`emergency_revoke(cmd)`**

1. Validate `justification` non-empty, ≤2048.
2. Check `PERMISSION_EMERGENCY_REVOKE` via `self._access_control.assert_can_emergency_revoke(credential_placeholder, context)`.
3. UoW: load credential.
4. `credential.emergency_revoke(TenantId(cmd.tenant_id), PrincipalId(cmd.principal_id), cmd.justification, now)`.
5. Save, audit (`AuditOperation.EMERGENCY_REVOKED`), commit, publish.

**`emergency_revoke` may be called from any state except DELETED** (the aggregate enforces this via `_assert_not_deleted`). Do not add state guards in the application service.

---

**`expire_credential(cmd)`**

No permission check — this is a system-initiated operation. The system principal (`cmd.principal_id`) is the scheduler's service account.
1. UoW: load credential.
2. `credential.expire(TenantId(cmd.tenant_id), now)`.
3. Save, audit (`AuditOperation.EXPIRED`, detail `"system-initiated expiration"`), commit, publish.

---

**`recover_credential(cmd)`**

1. Check `PERMISSION_WRITE`.
2. UoW:
   a. Load credential. Must be REVOKED.
   b. Load `target_version = await uow.versions.get_by_id(VersionId(cmd.target_version_id), TenantId(cmd.tenant_id))`.
   c. Build `access_context` with `justification=cmd.justification`.
   d. `await self._recovery_svc.validate_recovery(credential, target_version, access_context)` — raises on invalid state, mismatched tenant, non-restorable version state, or insufficient approvers.
   e. `credential.recover(TenantId(cmd.tenant_id), PrincipalId(cmd.principal_id), target_version.version_id, now)`.
   f. `target_version.version_state = VersionState.ACTIVE` — **direct assignment to public attribute** (see architecture note in spec §9.1 UC-07).
   g. `await uow.versions.update(target_version)`.
   h. `await uow.credentials.save(credential)`.
   i. Audit (`AuditOperation.RECOVERED`), commit, publish.

---

**`hard_delete_credential(cmd)`**

1. Check `PERMISSION_DELETE` via `self._access_control.assert_can_delete(credential, context)`.
2. UoW: load credential.
3. `credential.hard_delete(TenantId(cmd.tenant_id), PrincipalId(cmd.principal_id), now)`.
4. `await uow.credentials.save(credential)`.
5. Audit (`AuditOperation.DELETED`), commit, publish.
6. Return `None`.

Credential aggregate moves to state DELETED. No physical row deletion.

---

**`rollback_version(cmd)`**

1. Check `PERMISSION_WRITE`.
2. UoW:
   a. Load credential. Must be ACTIVE.
   b. Load `target_version`. Verify `target_version.version_state == VersionState.SUPERSEDED`. If not → raise `InvalidStateTransition(current=target_version.version_state.value, attempted="rollback")`.
   c. Load `current_active = await uow.versions.get_by_id(credential.active_version_id, TenantId(cmd.tenant_id))`.
   d. `current_active.supersede()`.
   e. `target_version.version_state = VersionState.ACTIVE` — same public-attribute pattern as recovery.
   f. `credential.rollback_version(TenantId(cmd.tenant_id), target_version.version_id, PrincipalId(cmd.principal_id), now)`.
   g. `await uow.versions.update(current_active)`.
   h. `await uow.versions.update(target_version)`.
   i. `await uow.credentials.save(credential)`.
   j. Audit (`AuditOperation.VERSION_ROLLED_BACK`), commit, publish.

---

**`update_metadata(cmd)`**

1. Check `PERMISSION_WRITE`.
2. UoW: load credential.
3. `credential.update_metadata(TenantId(cmd.tenant_id), cmd.description, cmd.tags, PrincipalId(cmd.principal_id), now)`.
4. Save, audit (`AuditOperation.METADATA_UPDATED`, detail showing `changed_fields` from the event), commit, publish.

**Note on changed_fields:** The `CredentialMetadataUpdated` event contains `changed_fields: list[str]`. Drain this from `credential.pop_events()` only AFTER commit. For the audit detail string, read the fields from the command comparison directly: compare `cmd.description` vs current aggregate state before mutation, or use a hardcoded summary.

---

**Attach/Detach policy methods (4 methods)**

Pattern for `attach_rotation_policy(cmd)`:
1. Check `PERMISSION_MANAGE_POLICY`.
2. UoW:
   a. Load credential.
   b. Verify policy exists: `await uow.rotation_policies.get_by_id(RotationPolicyId(cmd.policy_id), TenantId(cmd.tenant_id))`.
   c. `credential.attach_rotation_policy(TenantId(cmd.tenant_id), RotationPolicyId(cmd.policy_id), PrincipalId(cmd.principal_id), now)`.
   d. `await uow.credentials.save(credential)`.
   e. Audit (`AuditOperation.POLICY_ATTACHED`), commit, publish.

`detach_rotation_policy`: same but skip policy existence check, call `credential.detach_rotation_policy(...)`, audit `POLICY_DETACHED`.

Mirror for expiration policy variants.

---

### 5B. `RotationPolicyApplicationService` — implementation details

#### Constructor

```
__init__(
    uow_factory: Callable[[], IUnitOfWork],
    event_publisher: IEventPublisher,
    permission_port: IPermissionPort,
)
```

No domain service dependencies. This service uses `IPermissionPort` directly for `PERMISSION_MANAGE_POLICY` checks.

#### `create_rotation_policy(cmd)`

1. Validate: `name` non-empty ≤256, `interval_days` None or 1–3650, `max_versions_kept` 1–100, `notify_days_before` 0–90.
2. Check `PERMISSION_MANAGE_POLICY` (use `cmd.principal_id` and generate a policy-level UUID7 as the resource ID — or skip per-resource check and rely on tenant enforcement; the permission port handles this).
3. UoW:
   a. `policy = RotationPolicy.create(RotationPolicyId(uuid7()), TenantId(cmd.tenant_id), cmd.name, cmd.interval_days, cmd.max_versions_kept, cmd.notify_days_before, cmd.auto_rotate, now)`.
   b. `await uow.rotation_policies.save(policy)` — raises `DuplicatePolicyName` if name taken.
   c. `await uow.commit()`.
4. `await _publish([policy])`.
5. Return `RotationPolicyDTO.from_aggregate(policy)`.

**No audit log for policies.** `RotationPolicy` has no associated `AuditLog`. Do not call `uow.audit_logs` in any policy method.

#### `update_rotation_policy(cmd)`

1. Validate fields.
2. Check `PERMISSION_MANAGE_POLICY`.
3. UoW: load policy, call `policy.update(...)`, save, commit.
4. Publish, return DTO.

#### `delete_rotation_policy(cmd)`

1. Check `PERMISSION_MANAGE_POLICY`.
2. UoW: load policy, call `policy.delete(...)`, call `uow.rotation_policies.delete(policy_id, tenant_id)` — raises `PolicyInUse` if referenced by credentials, commit.
3. Publish, return `None`.

#### Query methods on `RotationPolicyApplicationService`

`get_rotation_policy(qry)` and `list_rotation_policies(qry)` are synchronous-equivalent reads: no UoW, direct repository access. Load via `uow` or inject repository directly. These are read operations: load, map to DTO, return. No mutation, no events, no audit.

---

### 5C. `ExpirationPolicyApplicationService`

Identical pattern to `RotationPolicyApplicationService`. Replace:
- `RotationPolicy` → `ExpirationPolicy`
- `IRotationPolicyRepository` → `IExpirationPolicyRepository`
- `RotationPolicyId` → `ExpirationPolicyId`
- `RotationPolicyDTO` → `ExpirationPolicyDTO`
- Validation: `ttl_days` 1–3650, `warn_days_before` 1–90 and `warn_days_before < ttl_days`.

---

### 5D. `VaultBackendApplicationService`

#### Constructor

```
__init__(
    uow_factory: Callable[[], IUnitOfWork],
    event_publisher: IEventPublisher,
    permission_port: IPermissionPort,
)
```

#### `register_vault_backend(cmd)`

1. Validate: `name` non-empty ≤256, `backend_type` valid `VaultBackendType`, `config` ≤100 keys with values ≤2048 chars.
2. Check `PERMISSION_ADMIN`.
3. UoW:
   a. `backend = VaultBackend.create(VaultBackendId(uuid7()), TenantId(cmd.tenant_id), cmd.name, VaultBackendType(cmd.backend_type), cmd.config, cmd.is_default, now)`.
   b. `await uow.vault_backends.save(backend)`.
   c. `await uow.commit()`.
4. Publish, return `VaultBackendDTO.from_aggregate(backend)`.

#### `delete_vault_backend(cmd)`

1. Check `PERMISSION_ADMIN`.
2. UoW: load backend, call `backend.delete(...)`, call `uow.vault_backends.delete(backend_id, tenant_id)` — raises `VaultBackendInUse` if credentials reference it, commit.
3. Publish, return `None`.

---

### Phase 5 validation checklist

```
ruff check src/credential_vault/application/services/
mypy src/credential_vault/application/services/ --strict
pytest tests/credential_vault/application/services/test_credential_application_service.py -x
pytest tests/credential_vault/application/services/test_rotation_policy_application_service.py -x
pytest tests/credential_vault/application/services/test_expiration_policy_application_service.py -x
pytest tests/credential_vault/application/services/test_vault_backend_application_service.py -x
```

### Exit criteria
All command service methods implemented. mypy zero errors. All command-side service tests pass.

### Common mistakes in Phase 5
- Opening UoW before KMS/encryption calls — if `generate_dek()` fails after the UoW opens, you must rollback. Move all port calls that can fail before `async with uow`.
- Calling `aggregate.pop_events()` inside the UoW block — call it only AFTER `uow.commit()` returns.
- Calling `uow.commit()` before `uow.audit_logs.append_entry()` — inverts the fail-closed invariant.
- Calling `uow.versions.save(new_version)` and `uow.versions.update(old_version)` instead of `atomic_promote` during CommitRotation.
- Using `credential._pending_new_version_id` — instead query `list_by_credential(states=[PENDING])`.
- Setting `target_version.version_state = VersionState.ACTIVE` via a domain method that doesn't exist — direct public-attribute assignment is correct.
- Publishing events before commit — events must be drained and published AFTER `uow.commit()`.

### Architectural pitfalls in Phase 5
- `CredentialResolverService.resolve()` attaches `CredentialAccessed` or `BreakGlassAccessed` to `credential._pending_events` via `credential.record_domain_event()`. This means the credential must be saved (`uow.credentials.save(credential)`) inside the UoW block after `resolve()` returns, so the event is associated with the persisted state. Never skip this save.
- `_publish([credential])` is called ONCE per method, AFTER the UoW exits. Do not call `publish_batch` inside the UoW block.
- `_write_audit_and_commit` is a helper that combines audit write and commit atomically in sequence. It must never be called outside an open UoW context.

---

## Phase 6: Query Services

### Objective
Implement two query-side services: `CredentialQueryService` and `AuditQueryService`.

### Scope
`application/services/credential_query_service.py`, `application/services/audit_query_service.py`

### Files to create (2)

| # | File |
|---|---|
| 1 | `services/credential_query_service.py` |
| 2 | `services/audit_query_service.py` |

### Dependencies
Phase 5 complete.

### Query service design rules

- Query services receive repository references directly in their constructors — no `uow_factory`.
- No UoW, no `commit()`, no `rollback()`.
- No domain mutations.
- No events published.
- No audit entries written.
- Permission checks via injected `IPermissionPort`.

### `CredentialQueryService` — constructor

```
__init__(
    credential_repo: ICredentialRepository,
    version_repo: ICredentialVersionRepository,
    permission_port: IPermissionPort,
)
```

#### `get_credential(qry)`

1. Check `PERMISSION_READ`: `await self._permission_port.has_permission(PrincipalId(qry.principal_id), CredentialId(qry.credential_id), IPermissionPort.PERMISSION_READ, TenantId(qry.tenant_id))`. If False → raise `AccessDenied`.
2. `credential = await self._credential_repo.get_by_id(CredentialId(qry.credential_id), TenantId(qry.tenant_id))`.
3. Return `CredentialDTO.from_aggregate(credential)`.

#### `list_credentials(qry)`

No `has_permission` call. See spec §14.4 and UC-21.
1. Validate `limit` and `offset`.
2. Parse `qry.states` → `list[CredentialState]` if provided (each element must be a valid `CredentialState` value; invalid strings raise `ApplicationValidationError`).
3. `credentials = await self._credential_repo.list_by_tenant(TenantId(qry.tenant_id), parsed_states, validated_limit, validated_offset)`.
4. Return `[CredentialDTO.from_aggregate(c) for c in credentials]`.

#### `get_version(qry)`

1. Check `PERMISSION_READ` on the parent credential (use `qry.credential_id` as the resource).
2. `version = await self._version_repo.get_by_id(VersionId(qry.version_id), TenantId(qry.tenant_id))`.
3. Return `VersionDTO.from_entity(version)`.

#### `list_versions(qry)`

1. Check `PERMISSION_READ`.
2. Parse `qry.states`.
3. `versions = await self._version_repo.list_by_credential(CredentialId(qry.credential_id), TenantId(qry.tenant_id), parsed_states)`.
4. Return `[VersionDTO.from_entity(v) for v in versions]`.

### `AuditQueryService` — constructor

```
__init__(
    audit_log_repo: IAuditLogRepository,
    credential_repo: ICredentialRepository,
    permission_port: IPermissionPort,
)
```

#### `list_audit_entries(qry)`

1. Check `PERMISSION_READ` on the credential.
2. `audit_log = await self._audit_log_repo.get_by_credential(CredentialId(qry.credential_id), TenantId(qry.tenant_id))`.
3. Parse `qry.operations` → `list[AuditOperation]` if provided.
4. Validate `limit` (1–1000) and `offset` (≥0).
5. `entries = await self._audit_log_repo.list_entries(audit_log.audit_log_id, TenantId(qry.tenant_id), qry.since, parsed_operations, validated_limit, validated_offset)`.
6. Return `[AuditEntryDTO.from_entity(e) for e in entries]`.

### Phase 6 validation checklist

```
ruff check src/credential_vault/application/services/
mypy src/credential_vault/application/services/ --strict
pytest tests/credential_vault/application/services/test_credential_query_service.py -x
pytest tests/credential_vault/application/services/test_audit_query_service.py -x
```

### Exit criteria
All query service methods implemented, mypy clean, query service tests pass.

### Common mistakes in Phase 6
- Using `uow_factory` in query services — query services hold direct repository references.
- Writing audit entries in query service methods — forbidden.
- Publishing events in query service methods — forbidden.
- Mutating any aggregate attribute in a query service — forbidden.

---

## Phase 7: Tests

### Objective
Write all application-layer tests. No implementation is changed in this phase.

### Test file locations

```
tests/credential_vault/application/
├── conftest.py
├── commands/
│   ├── test_credential_commands.py
│   └── test_policy_commands.py
├── queries/
│   └── test_credential_queries.py
├── dtos/
│   └── test_credential_dtos.py
├── services/
│   ├── test_credential_application_service.py
│   ├── test_credential_query_service.py
│   ├── test_rotation_policy_application_service.py
│   ├── test_expiration_policy_application_service.py
│   ├── test_vault_backend_application_service.py
│   └── test_audit_query_service.py
```

### `conftest.py` — required fixtures

All fixtures are session- or function-scoped using `pytest.fixture`. All async collaborators use `unittest.mock.AsyncMock`. All sync collaborators use `MagicMock`.

**`mock_uow` fixture:**
- `AsyncMock` that implements context manager: `__aenter__` returns itself, `__aexit__` does nothing by default.
- Six repository attributes, each an `AsyncMock`:
  - `mock_uow.credentials = AsyncMock(spec=ICredentialRepository)`
  - `mock_uow.versions = AsyncMock(spec=ICredentialVersionRepository)`
  - `mock_uow.rotation_policies = AsyncMock(spec=IRotationPolicyRepository)`
  - `mock_uow.expiration_policies = AsyncMock(spec=IExpirationPolicyRepository)`
  - `mock_uow.vault_backends = AsyncMock(spec=IVaultBackendRepository)`
  - `mock_uow.audit_logs = AsyncMock(spec=IAuditLogRepository)`
- `mock_uow.commit = AsyncMock()`, `mock_uow.rollback = AsyncMock()`.

**`mock_uow_factory` fixture:** `MagicMock(return_value=mock_uow)` that supports `async with mock_uow_factory()`.

**`mock_event_publisher` fixture:** `AsyncMock(spec=IEventPublisher)`. `publish_batch` returns None by default.

**`mock_key_mgmt_port` fixture:** `AsyncMock(spec=IKeyManagementPort)`. `generate_dek` returns `(b"fake-dek-32bytes-padding-here-x", fake_key_envelope)` where `fake_key_envelope` is a constructed `KeyEnvelope` with valid non-empty fields.

**`mock_encryption_port` fixture:** `AsyncMock(spec=IEncryptionPort)`. `encrypt` returns a constructed `EncryptedPayload` with valid non-empty fields. `decrypt` returns `b"decrypted-plaintext"`.

**`mock_permission_port` fixture:** `AsyncMock(spec=IPermissionPort)`. `has_permission` returns `True` by default.

**`mock_approval_port` fixture:** `AsyncMock(spec=IApprovalPort)`. `is_approved` returns `True` by default. `get_approver_count` returns `(2, 2)`.

**`make_credential(state=CredentialState.ACTIVE, ...)` factory:** Returns a real `Credential` aggregate with valid state. Use `Credential.create(...)` followed by `credential.activate(...)` for ACTIVE state. For other states, call the appropriate aggregate method.

**`make_version(state=VersionState.ACTIVE, ...)` factory:** Returns a real `CredentialVersion` entity with valid `EncryptedPayload` and `KeyEnvelope`.

**`make_audit_log(credential_id, tenant_id)` factory:** Returns a real `AuditLog` from `AuditLog.create(...)`.

**`credential_service` fixture:** Constructs `CredentialApplicationService` with all mock ports and real domain services wired through mocks.

### Required test cases per service method (minimum coverage)

Every method must have:

| Test | Description |
|---|---|
| `test_<method>_success` | Happy path; verifies DTO fields, UoW called, commit called, events published |
| `test_<method>_access_denied` | `has_permission` returns False → `AccessDenied` raised, UoW not opened |
| `test_<method>_not_found` | Repository raises `CredentialNotFound` → propagates unchanged |
| `test_<method>_invalid_state` | Domain raises `InvalidStateTransition` → propagates, rollback called |
| `test_<method>_audit_fail_closed` | `append_entry` raises → `ApplicationAuditFailure`, commit not called |
| `test_<method>_optimistic_lock` | `save()` raises `OptimisticLockConflict` → propagates unchanged |
| `test_<method>_validation_failure` | Invalid command field → `ApplicationValidationError` before UoW opens |
| `test_<method>_events_published` | `publish_batch` called with correct event type after commit |
| `test_<method>_publish_failure_nonfatal` | `publish_batch` raises → no exception propagates, commit succeeded |

### Critical test cases for specific methods

**`create_credential`:**
- `test_create_credential_success_dto_fields_populated` — verify all 17 `CredentialDTO` fields are non-None and correctly typed.
- `test_create_credential_name_already_exists` — `exists_by_name` returns True → `CredentialAlreadyExists`.
- `test_create_credential_backend_not_found` — backend repo raises `VaultBackendNotFound`.
- `test_create_credential_kms_failure_no_uow_opened` — `generate_dek` raises → `ApplicationPortError`, UoW `__aenter__` never called.
- `test_create_credential_audit_log_saved_in_same_transaction` — verify `uow.audit_logs.save` and `uow.credentials.save` both called before `uow.commit`.
- `test_create_custom_without_schema_id` → `ApplicationValidationError`.
- `test_create_with_non_custom_with_schema_id` → `ApplicationValidationError`.

**`resolve_credential`:**
- `test_resolve_returns_plaintext_bytes` — `ResolvedSecretDTO.plaintext_secret` is `bytes`.
- `test_resolve_no_secret_returned_on_audit_failure` — `append_entry` raises → `ApplicationAuditFailure`, no `ResolvedSecretDTO` returned.
- `test_resolve_credential_saved_after_resolve` — `uow.credentials.save(credential)` is called after `resolver_svc.resolve()` to persist the access event.
- `test_resolve_break_glass_emits_break_glass_event` — `BreakGlassAccessed` in published events, not `CredentialAccessed`.
- `test_resolve_revoked_credential` — `CredentialIsRevoked` raised.
- `test_resolve_insufficient_approvers_for_break_glass` — `InsufficientApprovers` raised.

**`commit_rotation`:**
- `test_commit_rotation_uses_list_by_credential_not_private_field` — verify `uow.versions.list_by_credential` is called with `states=[VersionState.PENDING]`; `atomic_promote` is called once.
- `test_commit_rotation_no_pending_version_raises` — `list_by_credential` returns empty list → `InvalidStateTransition`.
- `test_commit_rotation_no_separate_version_save_calls` — verify `uow.versions.save` is NOT called; only `atomic_promote`.

**`recover_credential`:**
- `test_recover_sets_version_state_directly` — verify `target_version.version_state == VersionState.ACTIVE` after service call.
- `test_recover_not_approved` — `is_approved` returns False → `InsufficientApprovers`.

**DTO tests:**
- `test_version_dto_no_encrypted_payload_field` — `hasattr(VersionDTO(...), "encrypted_payload")` is False.
- `test_vault_backend_dto_no_config_field` — `hasattr(VaultBackendDTO(...), "config")` is False.
- `test_resolved_secret_dto_no_to_dict` — `hasattr(ResolvedSecretDTO(...), "to_dict")` is False.
- `test_credential_dto_tags_is_copy` — modifying the returned dict does not affect the original aggregate.

### Phase 7 validation checklist

```
pytest tests/credential_vault/application/ -x --tb=short
pytest tests/credential_vault/application/ --cov=src/credential_vault/application --cov-report=term-missing
```

Every public service method must appear in the coverage report with line coverage.

### Exit criteria
All tests pass. No test accesses `credential._pending_new_version_id` or `credential._pending_rotation_context`. No test calls `uow.versions.save()` in CommitRotation assertions.

---

## Phase 8: Final Integration

### Objective
Run repository-wide validation across the entire `credential_vault/` package to confirm zero cross-layer contamination and full spec compliance.

### Files to modify
None. This is a read-only validation phase.

### Full validation suite

```bash
# 1. Format check
ruff format --check src/credential_vault/

# 2. Lint
ruff check src/credential_vault/

# 3. Type check — application layer only
mypy src/credential_vault/application/ --strict

# 4. Type check — full bounded context
mypy src/credential_vault/ --strict

# 5. Import cycle detection
python -c "
import sys, importlib
mods = [
    'credential_vault.application.services.credential_application_service',
    'credential_vault.application.services.credential_query_service',
    'credential_vault.application.dtos.credential_dtos',
    'credential_vault.application.ports.i_unit_of_work',
]
for m in mods:
    importlib.import_module(m)
    print(f'OK: {m}')
"

# 6. Dependency rule: application must not import infrastructure
grep -r "from.*infrastructure" src/credential_vault/application/ && echo "VIOLATION" || echo "OK"
grep -r "import.*infrastructure" src/credential_vault/application/ && echo "VIOLATION" || echo "OK"
grep -r "sqlalchemy\|psycopg\|asyncpg\|motor\|redis" src/credential_vault/application/ && echo "VIOLATION" || echo "OK"
grep -r "fastapi\|pydantic\|starlette" src/credential_vault/application/ && echo "VIOLATION" || echo "OK"

# 7. Domain not modified
git diff src/credential_vault/domain/ && echo "DOMAIN MODIFIED — STOP" || echo "Domain clean"

# 8. Run all tests
pytest tests/credential_vault/ -x --tb=short

# 9. Run application tests in isolation
pytest tests/credential_vault/application/ -x -v
```

### Exit criteria
All nine checks pass. Zero mypy errors. Zero ruff violations. Zero domain modifications.

---

# 3. Cross-Cutting Implementation Details

## 3.1 UnitOfWork Lifecycle

The UoW is obtained by calling `self._uow_factory()`. The factory returns a new UoW instance on every call. Never reuse a UoW instance across method calls.

```
async with self._uow_factory() as uow:
    # ... all repository interactions here
    await _write_audit_and_commit(uow, ...)
    # commit was called inside _write_audit_and_commit
# At this point: if commit was called, __aexit__ does nothing
# If commit was NOT called (exception), __aexit__ calls rollback()
```

The `_committed` flag on `IUnitOfWork` (set inside `commit()`) determines whether `__aexit__` rolls back. The application service never calls `rollback()` directly.

## 3.2 Async Patterns

- Every application service method is `async def`.
- Every port call is `await`.
- Every repository call is `await`.
- The `async with uow` pattern is mandatory — never call `uow.__aenter__()` directly.
- Never use `asyncio.gather` to parallelize repository calls within a single UoW — order is defined by the spec and must be preserved.
- Do not create background tasks with `asyncio.create_task` in application services.

## 3.3 Repository Save Ordering

Within `create_credential`:
1. `uow.versions.save(version)` — before credential, because credential's `active_version_id` references this version.
2. `uow.credentials.save(credential)`.
3. `uow.audit_logs.save(audit_log)`.
4. `uow.audit_logs.append_entry(...)`.
5. `uow.commit()`.

Within `commit_rotation`:
1. `uow.versions.atomic_promote(new_version, supersede_version_id=old_version_id, tenant_id)` — single atomic operation.
2. `uow.credentials.save(credential)`.
3. `uow.audit_logs.append_entry(...)`.
4. `uow.commit()`.

For all other mutations: save aggregate first, then audit entry, then commit.

## 3.4 Commit Ordering

**Invariant:** `append_entry` is always called before `commit`. This is encoded in `_write_audit_and_commit`. Do not inline this logic in service methods — always use the helper.

```
append_entry → [if raises: ApplicationAuditFailure, __aexit__ rollbacks] → commit
```

## 3.5 Audit Fail-Closed Behavior

```
try:
    await uow.audit_logs.append_entry(audit_log_id, entry, tenant_id)
except Exception as exc:
    raise ApplicationAuditFailure(str(exc)) from exc
await uow.commit()
```

If `append_entry` raises:
- `ApplicationAuditFailure` is raised.
- The `async with uow` block catches the exception in `__aexit__`.
- `__aexit__` calls `rollback()` because `_committed` is still `False`.
- No data is persisted.
- The caller receives `ApplicationAuditFailure`.
- For `resolve_credential`: the `ResolvedSecretDTO` is never returned.

This is the fail-closed contract. Never weaken it with a catch-and-continue pattern.

## 3.6 `pop_events()` Usage

Call `aggregate.pop_events()` exactly once per aggregate, immediately after `uow.commit()` returns. `pop_events()` clears `_pending_events` — calling it twice returns an empty list the second time.

Calling `pop_events()` inside the UoW block (before commit) is wrong: the events would be drained before persistence, and `publish_batch` would receive an empty list.

Order of drain after commit:
```python
events: list[BaseDomainEvent] = []
events.extend(credential.pop_events())
# if rotation_policy was also mutated:
# events.extend(policy.pop_events())
await self._event_publisher.publish_batch(events)
```

## 3.7 `publish_batch()` Failure Handling

```python
try:
    await self._event_publisher.publish_batch(events)
except Exception as exc:
    logger.warning("Event publication failed: %s", exc)
    # Do NOT re-raise. Commit already succeeded.
```

The commit is durable. Event publication failure is non-fatal at the application layer. The infrastructure layer handles redelivery (outbox pattern, retry — M25C/M25D concern).

## 3.8 Optimistic Locking

`OptimisticLockConflict` is raised by the infrastructure implementation of `save()` when the aggregate's `_version` does not match the stored version. The application service must not catch this. It propagates to the caller unchanged.

```python
# In application service:
await uow.credentials.save(credential)
# If OptimisticLockConflict is raised here, it exits the `async with` block.
# UoW __aexit__ calls rollback().
# OptimisticLockConflict propagates to the caller.
# Never catch this in the application layer.
```

## 3.9 Validation Helpers

`_validation.py` helpers are called at the very start of each service method, before any `await` call. The sequence is:
1. `validate_uuid` for all UUID fields.
2. `validate_str` for all string fields with max-length constraints.
3. Enum construction for category/state/trigger fields (try/except `ValueError` → `ApplicationValidationError`).
4. Cross-field validation (e.g., `CUSTOM` requires `schema_id`).

These validations run synchronously. If any fails, `ApplicationValidationError` is raised before any async I/O occurs.

## 3.10 Value Object Construction

All VO construction happens inside the service method. Constructors that raise `ValueError` or `InvalidArgument` (e.g., nil UUID check in `CredentialId.__post_init__`) should be allowed to propagate — they indicate a programming error if they occur after `validate_uuid` passed.

Pattern:
```
# Validate raw primitive first
validate_uuid(cmd.credential_id, "credential_id")
# Then construct VO
credential_id = CredentialId(cmd.credential_id)
```

Never construct VOs inside command or query dataclasses.

## 3.11 DTO Construction

DTOs are constructed exclusively in `from_aggregate` / `from_entity` classmethods. Service methods call these classmethods at the end — never construct DTOs manually with positional arguments in service methods.

For `ResolvedSecretDTO` (no classmethod): construct inline in `resolve_credential` only.

## 3.12 Dependency Injection Expectations

The application services are pure constructors receiving collaborators. They never:
- Instantiate repository implementations.
- Create database connections.
- Read from environment variables.
- Import from infrastructure.

The DI container (M25C) is responsible for providing concrete implementations. From M25B's perspective, every collaborator is an abstract type. Type annotations use the ABC types from `TYPE_CHECKING` blocks to avoid circular imports at module load time.

---

# 4. Phase-by-Phase Pitfall Reference

## Phase 1 Pitfalls

| Pitfall | Consequence | Prevention |
|---|---|---|
| Domain imports at module top level in `i_unit_of_work.py` | Circular import at startup | All domain imports inside `TYPE_CHECKING` |
| `__aenter__`/`__aexit__` declared abstract | Cannot use `_committed` flag pattern | Concrete context manager on `IUnitOfWork` |
| Missing `from __future__ import annotations` | mypy deferred annotation failures | Add to every file |
| Sentinel constant in `i_unit_of_work.py` | Violates §14.4 decision | Do not add; was explicitly removed |

## Phase 2–3 Pitfalls

| Pitfall | Consequence | Prevention |
|---|---|---|
| Using domain types in command fields | Commands depend on domain at runtime | Use stdlib `UUID`, `str`, `int`, `bool` only |
| `frozen=False` on any command/query | Mutable shared state bugs | Always `frozen=True, slots=True` |
| Business logic in command `__post_init__` | Commands must be dumb data | No validation in commands |

## Phase 4 Pitfalls

| Pitfall | Consequence | Prevention |
|---|---|---|
| `config` in `VaultBackendDTO` | Security leak of backend credentials | Field must not exist |
| `encrypted_payload` in `VersionDTO` | Encryption material exposure | Field must not exist |
| `to_dict()` on `ResolvedSecretDTO` | Accidental plaintext serialization | Method must not exist |
| Returning `credential.tags` reference | DTO mutation affects aggregate | Always `dict(credential.tags)` |
| Using `uuid.UUID.__str__` on VO directly | Wrong string; VO wraps UUID | `str(vo_instance)` calls VO's `__str__` |

## Phase 5 Pitfalls

| Pitfall | Consequence | Prevention |
|---|---|---|
| `generate_dek()` inside UoW block | KMS failure after UoW open requires rollback | Move KMS calls before `async with uow` |
| `aggregate.pop_events()` before commit | Events drained before persistence | Call only after `uow.commit()` |
| `uow.commit()` before `append_entry()` | Inverts fail-closed invariant | Use `_write_audit_and_commit` helper always |
| Two separate `save()` calls in CommitRotation | Non-atomic version promotion | Use `atomic_promote` exclusively |
| Reading `credential._pending_new_version_id` | Private field access | Query `list_by_credential(states=[PENDING])` |
| Publishing events on `ApplicationAuditFailure` | Events published without committed data | `_publish` called only after successful commit |
| Calling domain services before loading aggregate | Domain services need loaded aggregate | Load first, then call service |

## Phase 6 Pitfalls

| Pitfall | Consequence | Prevention |
|---|---|---|
| `uow_factory` in query service | Query services use direct repo injection | Constructor takes `IRepository` directly |
| Audit entries in query methods | Violates read/write separation | Never call `audit_logs.append_entry` in queries |
| Permission check on `list_credentials` | Inconsistent with §14.4 | No `has_permission` call for list; rely on tenant isolation |

---

# 5. Repository Validation Checkpoints

Run after each phase. All must pass before the next phase begins.

## After Phase 1

```bash
mypy src/credential_vault/application/ports/ src/credential_vault/application/exceptions.py src/credential_vault/application/_validation.py --strict
ruff check src/credential_vault/application/
python -c "from credential_vault.application.ports.i_unit_of_work import IUnitOfWork; print('OK')"
python -c "from credential_vault.application.ports.i_event_publisher import IEventPublisher; print('OK')"
```

## After Phase 2

```bash
mypy src/credential_vault/application/commands/ --strict
ruff check src/credential_vault/application/commands/
pytest tests/credential_vault/application/commands/ -x
```

## After Phase 3

```bash
mypy src/credential_vault/application/queries/ --strict
pytest tests/credential_vault/application/queries/ -x
```

## After Phase 4

```bash
mypy src/credential_vault/application/dtos/ --strict
pytest tests/credential_vault/application/dtos/ -x
# Verify config not in VaultBackendDTO:
python -c "
from credential_vault.application.dtos.backend_dtos import VaultBackendDTO
import dataclasses
names = [f.name for f in dataclasses.fields(VaultBackendDTO)]
assert 'config' not in names, f'config must not be in VaultBackendDTO: {names}'
print('VaultBackendDTO OK')
"
# Verify encrypted_payload not in VersionDTO:
python -c "
from credential_vault.application.dtos.credential_dtos import VersionDTO
import dataclasses
names = [f.name for f in dataclasses.fields(VersionDTO)]
assert 'encrypted_payload' not in names
assert 'key_envelope' not in names
print('VersionDTO OK')
"
```

## After Phase 5

```bash
mypy src/credential_vault/application/services/ --strict
pytest tests/credential_vault/application/services/test_credential_application_service.py -x -v
pytest tests/credential_vault/application/services/test_rotation_policy_application_service.py -x
pytest tests/credential_vault/application/services/test_expiration_policy_application_service.py -x
pytest tests/credential_vault/application/services/test_vault_backend_application_service.py -x
# Verify no infrastructure imports:
grep -rn "infrastructure\|sqlalchemy\|fastapi\|pydantic" src/credential_vault/application/ && exit 1 || echo "OK"
# Verify domain not modified:
git diff --exit-code src/credential_vault/domain/ || echo "DOMAIN MODIFIED — STOP"
```

## After Phase 6

```bash
mypy src/credential_vault/application/ --strict
pytest tests/credential_vault/application/ -x -v
```

## After Phase 7 (tests written)

```bash
pytest tests/credential_vault/application/ -v --tb=short
# Verify no test accesses private fields:
grep -n "_pending_new_version_id\|_pending_rotation_context\|_pending_events" tests/credential_vault/application/ -r && echo "PRIVATE FIELD ACCESS IN TESTS" || echo "OK"
```

## After Phase 8 (final integration)

```bash
mypy src/credential_vault/ --strict
ruff check src/credential_vault/
ruff format --check src/credential_vault/
pytest tests/credential_vault/ -x
git diff --exit-code src/credential_vault/domain/
grep -rn "infrastructure\|sqlalchemy\|fastapi" src/credential_vault/application/ && exit 1 || echo "Clean"
```

---

# 6. Final Implementation Completion Checklist

Complete this checklist in order. Every item must be checked before M25B is declared complete.

## Structure

- [ ] `application/` directory contains exactly 27 files matching the spec §3 tree
- [ ] `application/__init__.py` exists and is empty
- [ ] `application/exceptions.py` contains exactly 4 exception classes
- [ ] `application/_validation.py` contains exactly 4 helpers; no domain imports at top level
- [ ] `application/ports/i_unit_of_work.py` defines `IUnitOfWork` with 6 typed repo attrs, 2 abstract methods, concrete context manager
- [ ] `application/ports/i_event_publisher.py` defines `IEventPublisher` with 1 abstract method
- [ ] No `SENTINEL_CREDENTIAL_ID` constant exists anywhere in `application/`
- [ ] 26 command dataclasses exist across 3 files; all `frozen=True, slots=True`
- [ ] 11 query dataclasses exist across 4 files; all `frozen=True, slots=True`
- [ ] 7 DTO classes exist across 4 files; all `frozen=True, slots=True`
- [ ] 6 application service classes exist across 6 files

## DTO correctness

- [ ] `VaultBackendDTO` has no `config` field
- [ ] `VersionDTO` has no `encrypted_payload` or `key_envelope` field
- [ ] `ResolvedSecretDTO` has no `to_dict()` method
- [ ] All DTO ID fields are `str`
- [ ] All DTO datetime fields are `str` (ISO 8601)
- [ ] `CredentialDTO.tags` is a copied dict, not a reference

## Authorization

- [ ] `CreateCredential` generates `credential_id = CredentialId(uuid7())` before calling `has_permission`
- [ ] `list_credentials` does NOT call `has_permission`
- [ ] All permission constants used are from `IPermissionPort` class attributes only
- [ ] No invented permission constants exist in application services
- [ ] Break-glass authorization delegated entirely to `BreakGlassService` via `CredentialResolverService`

## Transaction safety

- [ ] Every mutating credential service method calls `append_entry` before `commit`
- [ ] `commit` is never called before `append_entry` in any credential method
- [ ] `generate_dek()` and `encrypt()` are called BEFORE opening UoW in `create_credential` and `rotate_credential`
- [ ] `atomic_promote` is used in `commit_rotation` — not two separate `save()` calls
- [ ] `pop_events()` is called AFTER `uow.commit()` in every method
- [ ] `publish_batch` is called AFTER the `async with uow` block exits
- [ ] `publish_batch` failure is caught and logged — does NOT propagate
- [ ] `OptimisticLockConflict` is NOT caught in any application service method

## Private field safety

- [ ] No application service method reads `credential._pending_new_version_id`
- [ ] No application service method reads `credential._pending_rotation_context`
- [ ] `commit_rotation` uses `uow.versions.list_by_credential(states=[VersionState.PENDING])` to find pending version
- [ ] `abort_rotation` uses `uow.versions.list_by_credential(states=[VersionState.PENDING])` to find pending version

## Entity state correctness

- [ ] `target_version.version_state = VersionState.ACTIVE` is used (not `target_version.promote()`) in `recover_credential`
- [ ] `target_version.version_state = VersionState.ACTIVE` is used (not `target_version.promote()`) in `rollback_version`
- [ ] `current_active.supersede()` (domain method) is used before rollback target assignment in `rollback_version`
- [ ] `aborted_version.revoke()` (domain method) is used in `abort_rotation`

## Policy and backend services

- [ ] No `audit_log` interactions in `RotationPolicyApplicationService`
- [ ] No `audit_log` interactions in `ExpirationPolicyApplicationService`
- [ ] No `audit_log` interactions in `VaultBackendApplicationService`
- [ ] `VaultBackend.create()` `config` is stored in aggregate; `VaultBackendDTO` does not expose it

## Query services

- [ ] `CredentialQueryService` and `AuditQueryService` receive repository references directly, not `uow_factory`
- [ ] No `commit()` call in any query service method
- [ ] No `append_entry()` call in any query service method
- [ ] No domain mutation in any query service method
- [ ] `list_credentials` relies on `tenant_id` for isolation — no `has_permission` call

## Domain integrity

- [ ] `git diff src/credential_vault/domain/` shows zero changes
- [ ] No new files added under `credential_vault/domain/`
- [ ] No imports from `credential_vault.application` appear in any domain file

## Static analysis

- [ ] `mypy src/credential_vault/application/ --strict` exits 0
- [ ] `mypy src/credential_vault/ --strict` exits 0
- [ ] `ruff check src/credential_vault/application/` exits 0
- [ ] `ruff format --check src/credential_vault/application/` exits 0
- [ ] No import of `infrastructure`, `sqlalchemy`, `fastapi`, `pydantic`, `psycopg`, `asyncpg` in any `application/` file

## Tests

- [ ] Every public method on every application service has a test file entry
- [ ] Every method has at minimum: happy path, access denied, domain exception propagation, audit fail-closed (where applicable)
- [ ] `commit_rotation` test verifies `list_by_credential(states=[PENDING])` is called, not private field access
- [ ] `resolve_credential` audit-fail-closed test verifies no `ResolvedSecretDTO` is returned
- [ ] `VaultBackendDTO` test verifies no `config` field
- [ ] `VersionDTO` test verifies no `encrypted_payload` or `key_envelope` field
- [ ] `ResolvedSecretDTO` test verifies no `to_dict` method
- [ ] All tests pass: `pytest tests/credential_vault/application/ -x`

## Final sign-off

- [ ] All checklist items above are checked
- [ ] Test run output shows 0 failures, 0 errors
- [ ] mypy output shows 0 errors
- [ ] ruff output shows 0 violations
- [ ] Domain diff is clean (zero changes)
- [ ] M25B is ready for M25C (infrastructure layer)
