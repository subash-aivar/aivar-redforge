# M25B Implementation Specification — Application Layer
## Enterprise Credential Vault & Secret Management
### Version 1.0 | Status: DRAFT FOR IMPLEMENTATION

---

# 1. Scope

M25B implements the **application layer** of the Credential Vault bounded context. It sits between the domain layer (M25A) and the infrastructure/presentation layers (M25C, M25D). M25B introduces no new domain capabilities; it orchestrates the domain objects produced in M25A.

**M25B delivers:**
- Application service classes (orchestrators)
- Command and query input models (CQRS)
- DTOs (read-side response models)
- `IUnitOfWork` and `IEventPublisher` application port ABCs
- Audit entry construction from application-layer events
- Domain event dispatch contract

**M25B does NOT deliver:**
- HTTP endpoints or FastAPI routers (M25C)
- Repository implementations (M25C)
- Port implementations (encryption, KMS, permissions) (M25C)
- Database migrations (M25C)
- Infrastructure wiring / DI container (M25C)
- Scheduler / background worker (M25D)

---

# 2. Objectives

1. Every mutating operation is transactional: commit succeeds or nothing persists.
2. Domain events are published **after** the transaction commits, never before.
3. Audit entries are written **inside** the transaction. If audit write fails, the transaction rolls back (fail-closed).
4. Authorization is enforced before any aggregate is loaded or mutated.
5. Application services are pure orchestrators — no business logic, no direct SQL, no HTTP concerns.
6. Commands and queries carry raw Python primitives (str, UUID, int); VO construction happens inside the service, not at the call site.
7. All application service methods are `async`.
8. Every public signature is fully typed and passes `mypy --strict`.

---

# 3. Package Structure

```
backend/src/credential_vault/application/
├── __init__.py
├── exceptions.py                    # ApplicationException hierarchy
├── _validation.py                   # Shared validation helpers (module-private)
├── commands/
│   ├── __init__.py
│   ├── credential_commands.py       # 18 command dataclasses
│   ├── policy_commands.py           # 6 command dataclasses
│   └── backend_commands.py          # 2 command dataclasses
├── queries/
│   ├── __init__.py
│   ├── credential_queries.py        # 4 query dataclasses
│   ├── policy_queries.py            # 4 query dataclasses
│   ├── backend_queries.py           # 2 query dataclasses
│   └── audit_queries.py             # 1 query dataclass
├── dtos/
│   ├── __init__.py
│   ├── credential_dtos.py           # CredentialDTO, VersionDTO, ResolvedSecretDTO
│   ├── policy_dtos.py               # RotationPolicyDTO, ExpirationPolicyDTO
│   ├── backend_dtos.py              # VaultBackendDTO
│   └── audit_dtos.py                # AuditEntryDTO
├── ports/
│   ├── __init__.py
│   ├── i_unit_of_work.py            # IUnitOfWork ABC
│   └── i_event_publisher.py         # IEventPublisher ABC
└── services/
    ├── __init__.py
    ├── credential_application_service.py
    ├── credential_query_service.py
    ├── rotation_policy_application_service.py
    ├── expiration_policy_application_service.py
    ├── vault_backend_application_service.py
    └── audit_query_service.py
```

**Total new files: 27**
**Zero changes to `credential_vault/domain/`**

---

# 4. Application Layer Architecture

## 4.1 Layering Rules

```
Presentation (M25C) → Application (M25B) → Domain (M25A) → Infrastructure (M25C)
```

- Application services depend on domain ABCs (`ICredentialRepository`, domain services, ports) only.
- Application services depend on `IUnitOfWork` and `IEventPublisher` defined in `application/ports/`.
- Application services **never** import from infrastructure.
- Domain services are injected into application services via constructor; they are not instantiated inside methods.

## 4.2 CQRS Split

**Command side** (`services/credential_application_service.py` etc.):
- Accepts a command dataclass
- Loads aggregate(s) via `IUnitOfWork`
- Calls domain methods
- Writes audit entry inside UoW
- Commits UoW
- Drains + publishes domain events
- Returns a DTO (or `None` for hard_delete)

**Query side** (`services/credential_query_service.py` etc.):
- Accepts a query dataclass
- Reads from repositories directly (no UoW required for reads)
- Maps aggregate/entity to DTO
- Returns DTO or list of DTOs
- Never emits events, never writes audit entries

## 4.3 Event Publication Contract

```
1. UoW.commit()
2. For each modified aggregate: drain events via aggregate.pop_events()
3. Call IEventPublisher.publish_batch(events)
4. If publish fails: log warning, do NOT rollback (commit already succeeded)
```

Event publication failure is non-fatal. Downstream consumers handle redelivery via outbox or retry (M25D concern).

## 4.4 Audit Contract

```
1. Before commit: construct AuditEntry
2. Call uow.audit_logs.append_entry(audit_log_id, entry, tenant_id)
3. If append_entry raises: raise ApplicationException — transaction rolls back
4. commit()
```

Audit is inside the transaction boundary. No commit without audit.

---

# 5. Commands

All command fields use Python primitives (`str`, `UUID`, `int`, `bool`, `dict`). VO construction is deferred to the application service. All commands are `@dataclass(frozen=True, slots=True)`.

## 5.1 `credential_commands.py`

### `CreateCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | Required |
| `name` | `str` | Converted to `CredentialName` in service |
| `category` | `str` | Maps to `CredentialCategory` |
| `subtype` | `str` | Maps to `CredentialType.subtype` |
| `schema_id` | `UUID \| None` | Required only for CUSTOM |
| `owner_principal_id` | `UUID` | Maps to `PrincipalId` |
| `vault_backend_id` | `UUID` | Maps to `VaultBackendId` |
| `plaintext_secret` | `bytes` | Encrypted immediately; not stored |
| `description` | `str \| None` | Max 2048 chars |
| `tags` | `dict[str, str]` | Max 50 keys |
| `expires_at` | `datetime \| None` | Version-level expiry override |

### `ResolveCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `purpose` | `str` | Max 512 chars |
| `client_ip` | `str \| None` | Valid IPv4/IPv6 |
| `request_id` | `str \| None` | Max 128 chars |
| `break_glass` | `bool` | Default `False` |
| `justification` | `str \| None` | Required when `break_glass=True` |

### `RotateCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `new_plaintext_secret` | `bytes` | New secret value |
| `trigger` | `str` | Maps to `RotationTrigger` |
| `policy_id` | `UUID \| None` | Present when trigger=POLICY/SCHEDULED |
| `notes` | `str \| None` | Max 1024 chars |

### `CommitRotationCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `AbortRotationCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `reason` | `str` | Max 1024 chars |

### `DisableCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `reason` | `str` | Max 1024 chars |

### `EnableCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `RevokeCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `reason` | `str` | Max 1024 chars |

### `EmergencyRevokeCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `justification` | `str` | Max 2048 chars, required |

### `ExpireCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | System-initiated (scheduler) |
| `principal_id` | `UUID` | System principal |

### `RecoverCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `target_version_id` | `UUID` | The version to restore as active |
| `justification` | `str` | Max 2048 chars |

### `HardDeleteCredentialCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `RollbackVersionCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `target_version_id` | `UUID` | Must be SUPERSEDED version |

### `UpdateCredentialMetadataCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `description` | `str \| None` | |
| `tags` | `dict[str, str]` | |

### `AttachRotationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `policy_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `DetachRotationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `AttachExpirationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `policy_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `DetachExpirationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |

## 5.2 `policy_commands.py`

### `CreateRotationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `name` | `str` | Max 256, unique per tenant |
| `interval_days` | `int \| None` | 1–3650 or None (manual) |
| `max_versions_kept` | `int` | 1–100 |
| `notify_days_before` | `int` | 0–90 |
| `auto_rotate` | `bool` | |

### `UpdateRotationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `policy_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `interval_days` | `int \| None` | |
| `max_versions_kept` | `int` | |
| `notify_days_before` | `int` | |
| `auto_rotate` | `bool` | |

### `DeleteRotationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `policy_id` | `UUID` | |
| `principal_id` | `UUID` | |

### `CreateExpirationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `name` | `str` | Max 256, unique per tenant |
| `ttl_days` | `int` | 1–3650 |
| `warn_days_before` | `int` | 1–90, must be < ttl_days |
| `hard_expire` | `bool` | |

### `UpdateExpirationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `policy_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `ttl_days` | `int` | |
| `warn_days_before` | `int` | |
| `hard_expire` | `bool` | |

### `DeleteExpirationPolicyCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `policy_id` | `UUID` | |
| `principal_id` | `UUID` | |

## 5.3 `backend_commands.py`

### `RegisterVaultBackendCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `name` | `str` | Max 256 |
| `backend_type` | `str` | Maps to `VaultBackendType` |
| `config` | `dict[str, str]` | Max 100 keys, values max 2048 chars |
| `is_default` | `bool` | |

### `DeleteVaultBackendCommand`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `backend_id` | `UUID` | |
| `principal_id` | `UUID` | |

---

# 6. Queries

All query fields are primitives. All are `@dataclass(frozen=True, slots=True)`.

## 6.1 `credential_queries.py`

### `GetCredentialQuery`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | Permission: READ |

### `ListCredentialsQuery`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `states` | `list[str] \| None` | Filter by `CredentialState` values |
| `limit` | `int` | Default 100, max 1000 |
| `offset` | `int` | Default 0 |

### `GetVersionQuery`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `version_id` | `UUID` | |
| `principal_id` | `UUID` | Permission: READ |

### `ListVersionsQuery`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | |
| `states` | `list[str] \| None` | Filter by `VersionState` |

## 6.2 `policy_queries.py`

### `GetRotationPolicyQuery`

| Field | Type |
|---|---|
| `tenant_id` | `UUID` |
| `policy_id` | `UUID` |
| `principal_id` | `UUID` |

### `ListRotationPoliciesQuery`

| Field | Type |
|---|---|
| `tenant_id` | `UUID` |
| `principal_id` | `UUID` |

### `GetExpirationPolicyQuery`

| Field | Type |
|---|---|
| `tenant_id` | `UUID` |
| `policy_id` | `UUID` |
| `principal_id` | `UUID` |

### `ListExpirationPoliciesQuery`

| Field | Type |
|---|---|
| `tenant_id` | `UUID` |
| `principal_id` | `UUID` |

## 6.3 `backend_queries.py`

### `GetVaultBackendQuery`

| Field | Type |
|---|---|
| `tenant_id` | `UUID` |
| `backend_id` | `UUID` |
| `principal_id` | `UUID` |

### `ListVaultBackendsQuery`

| Field | Type |
|---|---|
| `tenant_id` | `UUID` |
| `principal_id` | `UUID` |

## 6.4 `audit_queries.py`

### `ListAuditEntriesQuery`

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | `UUID` | |
| `credential_id` | `UUID` | |
| `principal_id` | `UUID` | Permission: READ |
| `since` | `datetime \| None` | Inclusive lower bound |
| `operations` | `list[str] \| None` | Filter by `AuditOperation` |
| `limit` | `int` | Default 100, max 1000 |
| `offset` | `int` | Default 0 |

---

# 7. DTOs

All DTOs are `@dataclass(frozen=True, slots=True)`. All ID fields are `str` (UUID serialized via `str()`). All datetime fields are `str` (ISO 8601 UTC, `isoformat()`). DTOs have a `def to_dict(self) -> dict[str, object]` method.

## 7.1 `credential_dtos.py`

### `CredentialDTO`

| Field | Type |
|---|---|
| `credential_id` | `str` |
| `tenant_id` | `str` |
| `name` | `str` |
| `category` | `str` |
| `subtype` | `str` |
| `schema_id` | `str \| None` |
| `state` | `str` |
| `owner_principal_id` | `str` |
| `active_version_id` | `str \| None` |
| `rotation_policy_id` | `str \| None` |
| `expiration_policy_id` | `str \| None` |
| `vault_backend_id` | `str` |
| `description` | `str \| None` |
| `tags` | `dict[str, str]` |
| `created_at` | `str` |
| `updated_at` | `str` |
| `version` | `int` |

### `VersionDTO`

| Field | Type |
|---|---|
| `version_id` | `str` |
| `credential_id` | `str` |
| `tenant_id` | `str` |
| `version_number` | `int` |
| `version_state` | `str` |
| `created_by` | `str` |
| `created_at` | `str` |
| `expires_at` | `str \| None` |
| `rotation_trigger` | `str \| None` |
| `rotation_policy_id` | `str \| None` |

Note: `encrypted_payload` and `key_envelope` are **never** included in DTOs.

### `ResolvedSecretDTO`

| Field | Type | Notes |
|---|---|---|
| `credential_id` | `str` | |
| `version_id` | `str` | |
| `plaintext_secret` | `bytes` | Caller responsible for zeroizing |
| `resolved_at` | `str` | ISO 8601 UTC |

`ResolvedSecretDTO` does NOT have `to_dict()`. It is never serialized to JSON by the application layer.

## 7.2 `policy_dtos.py`

### `RotationPolicyDTO`

| Field | Type |
|---|---|
| `policy_id` | `str` |
| `tenant_id` | `str` |
| `name` | `str` |
| `interval_days` | `int \| None` |
| `max_versions_kept` | `int` |
| `notify_days_before` | `int` |
| `auto_rotate` | `bool` |
| `created_at` | `str` |
| `updated_at` | `str` |
| `version` | `int` |

### `ExpirationPolicyDTO`

| Field | Type |
|---|---|
| `policy_id` | `str` |
| `tenant_id` | `str` |
| `name` | `str` |
| `ttl_days` | `int` |
| `warn_days_before` | `int` |
| `hard_expire` | `bool` |
| `created_at` | `str` |
| `updated_at` | `str` |
| `version` | `int` |

## 7.3 `backend_dtos.py`

### `VaultBackendDTO`

| Field | Type | Notes |
|---|---|---|
| `backend_id` | `str` | |
| `tenant_id` | `str` | |
| `name` | `str` | |
| `backend_type` | `str` | |
| `is_default` | `bool` | |
| `created_at` | `str` | |
| `updated_at` | `str` | |
| `version` | `int` | |

Note: `config` dict is **never** included in `VaultBackendDTO`. Config values may contain sensitive data.

## 7.4 `audit_dtos.py`

### `AuditEntryDTO`

| Field | Type |
|---|---|
| `entry_id` | `str` |
| `audit_log_id` | `str` |
| `credential_id` | `str` |
| `tenant_id` | `str` |
| `operation` | `str` |
| `outcome` | `str` |
| `principal_id` | `str` |
| `occurred_at` | `str` |
| `detail` | `str` |
| `client_ip` | `str \| None` |
| `request_id` | `str \| None` |

---

# 8. Application Services

## 8.1 `CredentialApplicationService`

**Constructor dependencies:**

| Parameter | Type |
|---|---|
| `uow_factory` | `Callable[[], IUnitOfWork]` |
| `event_publisher` | `IEventPublisher` |
| `key_mgmt_port` | `IKeyManagementPort` |
| `encryption_port` | `IEncryptionPort` |
| `permission_port` | `IPermissionPort` |
| `approval_port` | `IApprovalPort` |
| `access_control` | `AccessControlPolicyService` |
| `break_glass_svc` | `BreakGlassService` |
| `recovery_svc` | `RecoveryService` |
| `resolver_svc` | `CredentialResolverService` |

**Public method signatures:**

```python
async def create_credential(self, cmd: CreateCredentialCommand) -> CredentialDTO
async def resolve_credential(self, cmd: ResolveCredentialCommand) -> ResolvedSecretDTO
async def rotate_credential(self, cmd: RotateCredentialCommand) -> CredentialDTO
async def commit_rotation(self, cmd: CommitRotationCommand) -> CredentialDTO
async def abort_rotation(self, cmd: AbortRotationCommand) -> CredentialDTO
async def disable_credential(self, cmd: DisableCredentialCommand) -> CredentialDTO
async def enable_credential(self, cmd: EnableCredentialCommand) -> CredentialDTO
async def revoke_credential(self, cmd: RevokeCredentialCommand) -> CredentialDTO
async def emergency_revoke(self, cmd: EmergencyRevokeCommand) -> CredentialDTO
async def expire_credential(self, cmd: ExpireCredentialCommand) -> CredentialDTO
async def recover_credential(self, cmd: RecoverCredentialCommand) -> CredentialDTO
async def hard_delete_credential(self, cmd: HardDeleteCredentialCommand) -> None
async def rollback_version(self, cmd: RollbackVersionCommand) -> CredentialDTO
async def update_metadata(self, cmd: UpdateCredentialMetadataCommand) -> CredentialDTO
async def attach_rotation_policy(self, cmd: AttachRotationPolicyCommand) -> CredentialDTO
async def detach_rotation_policy(self, cmd: DetachRotationPolicyCommand) -> CredentialDTO
async def attach_expiration_policy(self, cmd: AttachExpirationPolicyCommand) -> CredentialDTO
async def detach_expiration_policy(self, cmd: DetachExpirationPolicyCommand) -> CredentialDTO
```

## 8.2 `CredentialQueryService`

**Constructor dependencies:**

| Parameter | Type |
|---|---|
| `credential_repo` | `ICredentialRepository` |
| `version_repo` | `ICredentialVersionRepository` |
| `permission_port` | `IPermissionPort` |

**Public method signatures:**

```python
async def get_credential(self, qry: GetCredentialQuery) -> CredentialDTO
async def list_credentials(self, qry: ListCredentialsQuery) -> list[CredentialDTO]
async def get_version(self, qry: GetVersionQuery) -> VersionDTO
async def list_versions(self, qry: ListVersionsQuery) -> list[VersionDTO]
```

## 8.3 `RotationPolicyApplicationService`

**Constructor dependencies:**

| Parameter | Type |
|---|---|
| `uow_factory` | `Callable[[], IUnitOfWork]` |
| `event_publisher` | `IEventPublisher` |
| `permission_port` | `IPermissionPort` |

**Public method signatures:**

```python
async def create_rotation_policy(self, cmd: CreateRotationPolicyCommand) -> RotationPolicyDTO
async def update_rotation_policy(self, cmd: UpdateRotationPolicyCommand) -> RotationPolicyDTO
async def delete_rotation_policy(self, cmd: DeleteRotationPolicyCommand) -> None
async def get_rotation_policy(self, qry: GetRotationPolicyQuery) -> RotationPolicyDTO
async def list_rotation_policies(self, qry: ListRotationPoliciesQuery) -> list[RotationPolicyDTO]
```

## 8.4 `ExpirationPolicyApplicationService`

**Constructor dependencies:**

| Parameter | Type |
|---|---|
| `uow_factory` | `Callable[[], IUnitOfWork]` |
| `event_publisher` | `IEventPublisher` |
| `permission_port` | `IPermissionPort` |

**Public method signatures:**

```python
async def create_expiration_policy(self, cmd: CreateExpirationPolicyCommand) -> ExpirationPolicyDTO
async def update_expiration_policy(self, cmd: UpdateExpirationPolicyCommand) -> ExpirationPolicyDTO
async def delete_expiration_policy(self, cmd: DeleteExpirationPolicyCommand) -> None
async def get_expiration_policy(self, qry: GetExpirationPolicyQuery) -> ExpirationPolicyDTO
async def list_expiration_policies(self, qry: ListExpirationPoliciesQuery) -> list[ExpirationPolicyDTO]
```

## 8.5 `VaultBackendApplicationService`

**Constructor dependencies:**

| Parameter | Type |
|---|---|
| `uow_factory` | `Callable[[], IUnitOfWork]` |
| `event_publisher` | `IEventPublisher` |
| `permission_port` | `IPermissionPort` |

**Public method signatures:**

```python
async def register_vault_backend(self, cmd: RegisterVaultBackendCommand) -> VaultBackendDTO
async def delete_vault_backend(self, cmd: DeleteVaultBackendCommand) -> None
async def get_vault_backend(self, qry: GetVaultBackendQuery) -> VaultBackendDTO
async def list_vault_backends(self, qry: ListVaultBackendsQuery) -> list[VaultBackendDTO]
```

## 8.6 `AuditQueryService`

**Constructor dependencies:**

| Parameter | Type |
|---|---|
| `audit_log_repo` | `IAuditLogRepository` |
| `credential_repo` | `ICredentialRepository` |
| `permission_port` | `IPermissionPort` |

**Public method signatures:**

```python
async def list_audit_entries(self, qry: ListAuditEntriesQuery) -> list[AuditEntryDTO]
```

---

# 9. Use Cases

Each operation below maps directly to one method on one application service. There are no separate use-case classes — the application service method IS the use case. This decision is fixed.

## 9.1 Credential Lifecycle Use Cases

### UC-01: Create Credential

**Input:** `CreateCredentialCommand`
**Output:** `CredentialDTO`

**Steps:**
1. Validate command fields (see §18).
2. Generate `credential_id = CredentialId(uuid7())`. This must happen first so that a real `CredentialId` is available for the permission check.
3. Call `permission_port.has_permission(PrincipalId(owner_principal_id), credential_id, PERMISSION_WRITE, TenantId(tenant_id))`. If False → raise `AccessDenied`. No sentinel, no fabricated ID.
4. Check `uow.credentials.exists_by_name(CredentialName(name), TenantId(tenant_id))`. If True → raise `CredentialAlreadyExists`.
5. Verify vault backend exists: `uow.vault_backends.get_by_id(VaultBackendId(vault_backend_id), TenantId(tenant_id))`.
6. Generate `version_id = VersionId(uuid7())`.
7. Generate `audit_log_id = AuditLogId(uuid7())`.
8. Call `key_mgmt_port.generate_dek()` → `(dek_bytes, key_envelope)`.
9. Call `encryption_port.encrypt(plaintext_secret, dek_bytes)` → `encrypted_payload`. Port zeros `dek_bytes`.
10. Construct `CredentialVersion(version_id, credential_id, tenant_id, version_number=1, encrypted_payload, key_envelope, state=PENDING, rotation_context=None, now, PrincipalId(owner), expires_at)`.
11. Call `Credential.create(credential_id, tenant_id, name, type, owner, backend_id, description, tags, now)`.
12. Call `credential.activate(tenant_id, version_id, now)`.
13. Call `version.promote()`.
14. Call `AuditLog.create(audit_log_id, credential_id, tenant_id, now)`.
15. Open UoW, save version, credential, audit_log; append `AuditEntry(CREATED, SUCCESS)`.
16. Commit UoW.
17. Drain + publish events from credential.
18. Return `CredentialDTO.from_aggregate(credential)`.

**Precondition violations that raise before UoW:**
- `AccessDenied` (step 3)
- `CredentialAlreadyExists` (step 4)
- `VaultBackendNotFound` (step 5)
- `InvalidArgument` (name/tags/description validation)

---

### UC-02: Resolve Credential

**Input:** `ResolveCredentialCommand`
**Output:** `ResolvedSecretDTO`

**Steps:**
1. Validate command.
2. Construct `AccessContext` from command fields.
3. Open UoW.
4. Load `credential = uow.credentials.get_by_id(credential_id, tenant_id)`.
5. Load `active_version = uow.versions.get_active_version(credential_id, tenant_id)`.
6. Call `resolver_svc.resolve(credential, active_version, context)` → `ResolvedSecret`. This call:
   - Validates break_glass or normal ACL (raises `AccessDenied`, `CredentialIsRevoked`, etc.)
   - Decrypts
   - Attaches `CredentialAccessed` or `BreakGlassAccessed` event to `credential._pending_events`
   - Returns `ResolvedSecret`
7. Construct `AuditEntry(ACCESSED or BREAK_GLASS, SUCCESS)` with `detail` containing `purpose` and `client_ip`.
8. `uow.audit_logs.append_entry(audit_log_id, entry, tenant_id)`. **If this fails → exception propagates, UoW rolls back, secret is NOT returned (fail-closed).**
9. `uow.credentials.save(credential)` (persists the attached access event record if needed).
10. Commit UoW.
11. Drain events from credential → publish.
12. Return `ResolvedSecretDTO(credential_id, version_id, resolved_secret.get_plaintext(), resolved_at)`.

**Audit log_id lookup:** Load `audit_log = uow.audit_logs.get_by_credential(credential_id, tenant_id)` before step 7 to obtain `audit_log_id`.

**Failure modes:**
- `AccessDenied` → UoW rolled back, no secret returned
- `CredentialIsRevoked` / `CredentialIsExpired` / `CredentialIsDeleted` → UoW rolled back
- `ActiveVersionNotFound` → UoW rolled back
- `InsufficientApprovers` (break-glass) → UoW rolled back
- audit `append_entry` failure → UoW rolled back, `ApplicationAuditFailure` raised (fail-closed)

---

### UC-03: Rotate Credential (Begin)

**Input:** `RotateCredentialCommand`
**Output:** `CredentialDTO`

**Steps:**
1. Validate command.
2. Open UoW.
3. Load credential.
4. Call `access_control.assert_can_rotate(credential, AccessContext(principal, purpose="rotation"))`.
5. Generate `new_version_id = VersionId(uuid7())`.
6. Build `RotationContext(trigger, initiated_by, previous_version_id=credential.active_version_id, policy_id, notes)`.
7. Call `key_mgmt_port.generate_dek()` → new dek + envelope.
8. Call `encryption_port.encrypt(new_plaintext, dek)` → new `EncryptedPayload`.
9. Construct new `CredentialVersion(new_version_id, credential_id, tenant_id, version_number=current+1, PENDING, rotation_context, now)`.
10. Call `credential.begin_rotation(tenant_id, new_version_id, context, now)`.
11. `uow.versions.save(new_version)`.
12. `uow.credentials.save(credential)`.
13. Append `AuditEntry(ROTATION_STARTED, SUCCESS)`.
14. Commit, drain, publish.
15. Return `CredentialDTO.from_aggregate(credential)`.

**Note on `version_number`:** Query `uow.versions.list_by_credential(credential_id, tenant_id)` to get the current max version_number, add 1.

---

### UC-04: Commit Rotation

**Input:** `CommitRotationCommand`
**Output:** `CredentialDTO`

**Steps:**
1. Open UoW.
2. Load credential (must be ROTATING).
3. Query the pending new version: `pending = await uow.versions.list_by_credential(CredentialId(credential_id), TenantId(tenant_id), states=[VersionState.PENDING])`. The list must contain exactly one entry; if empty, raise `InvalidStateTransition(current="ROTATING", attempted="commit_rotation")`. Take `new_version = pending[0]`; `new_version_id = new_version.version_id`.
4. `old_version_id = credential.active_version_id`.
5. Load `old_version = uow.versions.get_by_id(old_version_id, tenant_id)`.
6. `new_version.promote()` → PENDING → ACTIVE.
7. `old_version.supersede()` → ACTIVE → SUPERSEDED.
8. `credential.commit_rotation(tenant_id, new_version_id, old_version_id, now)`.
9. `uow.versions.atomic_promote(new_version, supersede_version_id=old_version_id, tenant_id)`.
10. `uow.credentials.save(credential)`.
11. Optionally prune: if `rotation_policy` exists, check `uow.versions.count_superseded(credential_id, tenant_id) > policy.max_versions_kept`. If so, note for M25D (do NOT delete versions here; M25B does not prune).
12. Append `AuditEntry(ROTATION_COMMITTED, SUCCESS)`.
13. Commit, drain, publish.
14. Return `CredentialDTO`.

---

### UC-05: Abort Rotation

**Input:** `AbortRotationCommand`
**Output:** `CredentialDTO`

**Steps:**
1. Open UoW.
2. Load credential (must be ROTATING).
3. Query the pending new version: `pending = await uow.versions.list_by_credential(CredentialId(credential_id), TenantId(tenant_id), states=[VersionState.PENDING])`. Must contain exactly one entry; if empty, raise `InvalidStateTransition(current="ROTATING", attempted="abort_rotation")`. Take `aborted_version = pending[0]`.
4. `aborted_version.revoke()`.
5. `credential.abort_rotation(tenant_id, reason, PrincipalId(principal_id), now)`.
6. `uow.versions.update(aborted_version)`.
7. `uow.credentials.save(credential)`.
8. Append `AuditEntry(ROTATION_ABORTED, SUCCESS, detail=reason)`.
9. Commit, drain, publish.
10. Return `CredentialDTO`.

---

### UC-06: Disable / Enable / Revoke / Emergency Revoke / Expire

All follow the same pattern:

1. Open UoW.
2. Load credential.
3. Authorization check via `permission_port.has_permission` for the relevant permission constant.
4. Call the corresponding aggregate method.
5. `uow.credentials.save(credential)`.
6. Append `AuditEntry(operation, SUCCESS, detail=reason)`.
7. Commit, drain, publish.
8. Return `CredentialDTO`.

**Permission mapping:**

| Use Case | `IPermissionPort` constant |
|---|---|
| Disable | `PERMISSION_WRITE` |
| Enable | `PERMISSION_WRITE` |
| Revoke | `PERMISSION_REVOKE` |
| Emergency Revoke | `PERMISSION_EMERGENCY_REVOKE` |
| Expire | System-initiated; no permission check required |

---

### UC-07: Recover Credential

**Input:** `RecoverCredentialCommand`
**Output:** `CredentialDTO`

**Steps:**
1. Validate command.
2. Check `permission_port.has_permission(principal, credential_id, WRITE, tenant)`.
3. Open UoW.
4. Load credential.
5. Load `target_version = uow.versions.get_by_id(target_version_id, tenant_id)`.
6. Build `AccessContext(principal, purpose="recovery", break_glass=False, justification=justification)`.
7. Call `recovery_svc.validate_recovery(credential, target_version, context)`. Raises if not approved or state invalid.
8. Call `credential.recover(tenant_id, PrincipalId(principal_id), target_version_id, now)`. The aggregate sets `active_version_id = target_version_id` and emits `CredentialRecovered`.
9. Set `target_version.version_state = VersionState.ACTIVE`.

   **Architecture note:** `CredentialVersion.version_state` is a public mutable slot attribute (no underscore prefix). `CredentialVersion` defines `promote()` (PENDING → ACTIVE), `supersede()`, and `revoke()`, but no method for the back-transition SUPERSEDED → ACTIVE or REVOKED → ACTIVE that recovery requires. M25A is frozen. Direct assignment to the public `version_state` attribute is therefore the architecture-compliant mechanism for this transition at the application layer. The domain invariant is fully enforced by `RecoveryService.validate_recovery()` before any mutation occurs.

10. `uow.versions.update(target_version)`.
11. `uow.credentials.save(credential)`.
12. Append `AuditEntry(RECOVERED, SUCCESS, detail=justification)`.
13. Commit, drain, publish.
14. Return `CredentialDTO`.

---

### UC-08: Hard Delete

**Input:** `HardDeleteCredentialCommand`
**Output:** `None`

**Steps:**
1. Check `permission_port.has_permission(principal, credential_id, DELETE, tenant)`.
2. Open UoW.
3. Load credential.
4. `credential.hard_delete(tenant_id, PrincipalId(principal_id), now)`.
5. `uow.credentials.save(credential)` (state → DELETED; aggregate is not removed from DB).
6. Append `AuditEntry(DELETED, SUCCESS)`.
7. Commit, drain, publish.
8. Return `None`.

**Invariant:** Physical row deletion is out of scope for M25B. The credential is soft-deleted (state=DELETED). Purge is an infrastructure/compliance concern.

---

### UC-09: Rollback Version

**Input:** `RollbackVersionCommand`
**Output:** `CredentialDTO`

**Steps:**
1. Check `PERMISSION_WRITE`.
2. Open UoW.
3. Load credential (must be ACTIVE).
4. Load `target_version = uow.versions.get_by_id(target_version_id, tenant_id)`. Verify `target_version.version_state == VersionState.SUPERSEDED`; if not, raise `InvalidStateTransition`.
5. Load `current_active = uow.versions.get_by_id(credential.active_version_id, tenant_id)`.
6. `current_active.supersede()` → ACTIVE → SUPERSEDED (domain method).
7. `target_version.version_state = VersionState.ACTIVE`.

   **Architecture note:** Same justification as UC-07. `version_state` is a public mutable attribute. `CredentialVersion` defines no domain method for the SUPERSEDED → ACTIVE back-transition. Direct assignment to the public attribute is the architecture-compliant mechanism for rollback at the application layer.

8. `credential.rollback_version(tenant_id, target_version_id, PrincipalId(principal_id), now)`.
9. `uow.versions.update(current_active)`.
10. `uow.versions.update(target_version)`.
11. `uow.credentials.save(credential)`.
12. Append `AuditEntry(VERSION_ROLLED_BACK, SUCCESS)`.
13. Commit, drain, publish.
14. Return `CredentialDTO`.

---

### UC-10: Update Metadata

**Input:** `UpdateCredentialMetadataCommand`
**Output:** `CredentialDTO`

1. Check `PERMISSION_WRITE`.
2. Open UoW.
3. Load credential.
4. `credential.update_metadata(tenant_id, description, tags, PrincipalId(principal_id), now)`.
5. `uow.credentials.save(credential)`.
6. Append `AuditEntry(METADATA_UPDATED, SUCCESS)`.
7. Commit, drain, publish.
8. Return `CredentialDTO`.

---

### UC-11: Attach / Detach Policies

Pattern for all four policy attachment use cases:

1. Check `PERMISSION_MANAGE_POLICY`.
2. Open UoW.
3. Load credential.
4. If attaching: verify policy exists (`uow.rotation_policies.get_by_id(...)` or `uow.expiration_policies.get_by_id(...)`).
5. Call `credential.attach_rotation_policy(...)` or equivalent.
6. `uow.credentials.save(credential)`.
7. Append `AuditEntry(POLICY_ATTACHED or POLICY_DETACHED, SUCCESS)`.
8. Commit, drain, publish.
9. Return `CredentialDTO`.

---

## 9.2 Policy Use Cases

### UC-12: Create Rotation Policy

1. Check `PERMISSION_MANAGE_POLICY` at tenant level.
2. Open UoW.
3. `RotationPolicy.create(RotationPolicyId(uuid7()), TenantId(tenant_id), name, interval_days, max_versions_kept, notify_days_before, auto_rotate, now)`.
4. `uow.rotation_policies.save(policy)` — raises `DuplicatePolicyName` if name taken.
5. Commit, drain, publish.
6. Return `RotationPolicyDTO.from_aggregate(policy)`.

No audit log for policy CRUD — policies are not secret-bearing aggregates.

### UC-13: Update Rotation Policy

1. Check `PERMISSION_MANAGE_POLICY`.
2. Open UoW.
3. Load policy.
4. `policy.update(tenant_id, interval_days, max_versions_kept, notify_days_before, auto_rotate, PrincipalId(principal_id), now)`.
5. `uow.rotation_policies.save(policy)`.
6. Commit, drain, publish.
7. Return `RotationPolicyDTO`.

### UC-14: Delete Rotation Policy

1. Check `PERMISSION_MANAGE_POLICY`.
2. Open UoW.
3. Load policy.
4. `policy.delete(tenant_id, PrincipalId(principal_id), now)`.
5. `uow.rotation_policies.delete(policy_id, tenant_id)` — raises `PolicyInUse` if referenced.
6. Commit, drain, publish.
7. Return `None`.

### UC-15–17: Expiration Policy CRUD

Identical pattern to UC-12–14 with `ExpirationPolicy` aggregate and `uow.expiration_policies`.

---

## 9.3 VaultBackend Use Cases

### UC-18: Register Vault Backend

1. Check `PERMISSION_ADMIN` at tenant level.
2. Open UoW.
3. `VaultBackend.create(VaultBackendId(uuid7()), TenantId(tenant_id), name, VaultBackendType(backend_type), config, is_default, now)`.
4. `uow.vault_backends.save(backend)`.
5. Commit, drain, publish.
6. Return `VaultBackendDTO.from_aggregate(backend)`.

### UC-19: Delete Vault Backend

1. Check `PERMISSION_ADMIN`.
2. Open UoW.
3. Load backend.
4. `backend.delete(tenant_id, PrincipalId(principal_id), now)`.
5. `uow.vault_backends.delete(backend_id, tenant_id)` — raises `VaultBackendInUse` if credentials exist.
6. Commit, drain, publish.
7. Return `None`.

---

## 9.4 Query Use Cases

### UC-20: Get Credential

1. Check `permission_port.has_permission(principal, credential_id, READ, tenant)`.
2. `credential = credential_repo.get_by_id(credential_id, tenant_id)`.
3. Return `CredentialDTO.from_aggregate(credential)`.

### UC-21: List Credentials

1. No per-credential `has_permission` call. Tenant isolation is enforced entirely by passing `TenantId(tenant_id)` to the repository. The repository contract guarantees no cross-tenant data is returned. See §14.4.
2. Parse `states` strings → `list[CredentialState]`.
3. `credentials = credential_repo.list_by_tenant(TenantId(tenant_id), states, limit, offset)`.
4. Return `[CredentialDTO.from_aggregate(c) for c in credentials]`.

### UC-22: Get / List Versions

1. Check `READ` on the parent credential.
2. Call `version_repo.get_by_id` or `version_repo.list_by_credential`.
3. Return `VersionDTO` or `list[VersionDTO]`.

### UC-23: List Audit Entries

1. Check `READ` on credential.
2. Load `audit_log = audit_log_repo.get_by_credential(credential_id, tenant_id)`.
3. Parse `operations` strings → `list[AuditOperation]`.
4. `entries = audit_log_repo.list_entries(audit_log.audit_log_id, tenant_id, since, operations, limit, offset)`.
5. Return `[AuditEntryDTO.from_entity(e) for e in entries]`.

---

# 10. Repository Interactions

## 10.1 Which repositories each service uses

| Service | Repositories Used |
|---|---|
| `CredentialApplicationService` | `credentials`, `versions`, `audit_logs`, `rotation_policies`, `expiration_policies`, `vault_backends` |
| `CredentialQueryService` | `credentials`, `versions` (direct injection, no UoW) |
| `RotationPolicyApplicationService` | `rotation_policies` |
| `ExpirationPolicyApplicationService` | `expiration_policies` |
| `VaultBackendApplicationService` | `vault_backends` |
| `AuditQueryService` | `audit_logs`, `credentials` (direct injection) |

## 10.2 Load order invariants

- Always load `Credential` before any `CredentialVersion` — tenant_id is asserted on load.
- Never load a `CredentialVersion` without knowing the parent `credential_id`.
- Always load `AuditLog` via `get_by_credential`, never by `audit_log_id` alone.
- `ICredentialVersionRepository.atomic_promote` is the ONLY correct way to simultaneously promote one version and supersede another. Never call `save()` twice for this operation.

## 10.3 Optimistic locking

Every `save()` call on a repository will compare the aggregate's `_version` field against the stored version. If mismatch → `OptimisticLockConflict`. Application services do **not** catch `OptimisticLockConflict`; they let it propagate. The presentation layer maps it to HTTP 409.

## 10.4 Version number resolution

When creating a new `CredentialVersion` during rotation, call `uow.versions.list_by_credential(credential_id, tenant_id)` to find the current max `version_number`, then set `version_number = max_version_number + 1`. Do this **before** encrypting the new payload.

---

# 11. Unit of Work

## 11.1 `IUnitOfWork` — `application/ports/i_unit_of_work.py`

```python
class IUnitOfWork(ABC):
    credentials: ICredentialRepository
    versions: ICredentialVersionRepository
    rotation_policies: IRotationPolicyRepository
    expiration_policies: IExpirationPolicyRepository
    vault_backends: IVaultBackendRepository
    audit_logs: IAuditLogRepository

    async def __aenter__(self) -> IUnitOfWork: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...
```

**Rules:**
- `__aexit__` calls `rollback()` automatically if `commit()` was not called.
- `commit()` may only be called once per UoW instance.
- Each application service method instantiates a fresh UoW via `uow_factory()`.
- Query services do NOT use UoW — they hold direct repository references.

## 11.2 `IEventPublisher` — `application/ports/i_event_publisher.py`

```python
class IEventPublisher(ABC):
    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None: ...
```

**Rules:**
- `publish_batch` is called **after** `uow.commit()` returns.
- `publish_batch` failure is non-fatal: log at WARNING level, do not re-raise.
- Empty `events` list: call is a no-op; do not skip the call.
- Implementation (M25C) uses transactional outbox or direct message broker.

## 11.3 Event collection

After `uow.commit()`, the application service calls `pop_events()` on every aggregate that was mutated in the unit of work. Order:

```
events = []
events.extend(credential.pop_events())
events.extend(rotation_policy.pop_events())   # if mutated
events.extend(expiration_policy.pop_events()) # if mutated
events.extend(vault_backend.pop_events())     # if mutated
await event_publisher.publish_batch(events)
```

`AuditLog` aggregate emits no domain events; skip it.

---

# 12. Transaction Boundaries

## 12.1 Boundaries per use case

| Use Case | Transaction Boundary |
|---|---|
| CreateCredential | Single UoW: save version + credential + audit_log + audit_entry |
| ResolveCredential | Single UoW: save credential (access event) + audit_entry |
| RotateCredential (begin) | Single UoW: save new version + credential + audit_entry |
| CommitRotation | Single UoW: atomic_promote(versions) + save credential + audit_entry |
| AbortRotation | Single UoW: update aborted version + save credential + audit_entry |
| DisableCredential | Single UoW: save credential + audit_entry |
| EnableCredential | Single UoW: save credential + audit_entry |
| RevokeCredential | Single UoW: save credential + audit_entry |
| EmergencyRevoke | Single UoW: save credential + audit_entry |
| ExpireCredential | Single UoW: save credential + audit_entry |
| RecoverCredential | Single UoW: update version + save credential + audit_entry |
| HardDeleteCredential | Single UoW: save credential + audit_entry |
| RollbackVersion | Single UoW: update x2 versions + save credential + audit_entry |
| UpdateMetadata | Single UoW: save credential + audit_entry |
| Attach/DetachPolicy | Single UoW: save credential + audit_entry |
| Create/Update/DeletePolicy | Single UoW: save/update/delete policy |
| RegisterBackend | Single UoW: save backend |
| DeleteBackend | Single UoW: delete backend |

## 12.2 Key invariants

- Never commit without writing audit entry first (for credential operations).
- `atomic_promote` on CommitRotation must be a single atomic repository operation — not two separate `save()` calls.
- If `key_mgmt_port.generate_dek()` or `encryption_port.encrypt()` fails, do NOT open the UoW. Fail before the transaction starts.
- If domain method raises (e.g., `InvalidStateTransition`), UoW rolls back via `__aexit__`.

## 12.3 Read-modify-write pattern

For all commands:

```
async with uow_factory() as uow:
    # 1. Load (read)
    # 2. Domain mutation (modify)
    # 3. Persist (write)
    # 4. Audit write
    await uow.commit()
# 5. Drain events
# 6. publish_batch (outside transaction)
```
