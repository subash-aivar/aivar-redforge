# M25C Implementation Specification — Part 2
## Enterprise Credential Vault: Infrastructure & API Layer
### Version 1.0 FROZEN | Sections 13–22

---

## §13. FastAPI API Layer

### Design rules

- Every endpoint receives tenant context from the JWT `organization_id` claim. Callers do not pass `tenant_id` in path or body — it is extracted from the token.
- Every endpoint extracts `principal_id` from the JWT `sub` claim.
- Pydantic v2 request and response schemas. `BaseModel` only — no `dataclass` schemas.
- HTTP status codes are informational (decided here in M25C, not in M25B). These are now binding for M25C.
- All routes are prefixed `/api/v1`.
- Routers are registered in `credential_vault/api/v1/__init__.py` and included in the main `redforge.api.v1` router.
- No business logic in route handlers. Handlers extract parameters, call the application service, map exceptions to HTTP responses, and return response schemas.
- `ResolvedSecretDTO.plaintext_secret` is a `bytes` field — in the HTTP response it is base64-encoded. The response schema has `secret_b64: str` and encodes it from the DTO.

### Exception-to-HTTP mapping

| Domain / Application Exception | HTTP Status |
|---|---|
| `CredentialNotFound` | 404 |
| `VersionNotFound` | 404 |
| `ActiveVersionNotFound` | 404 |
| `RotationPolicyNotFound` | 404 |
| `ExpirationPolicyNotFound` | 404 |
| `VaultBackendNotFound` | 404 |
| `CredentialAlreadyExists` | 409 |
| `DuplicatePolicyName` | 409 |
| `AccessDenied` | 403 |
| `InvalidStateTransition` | 422 |
| `ConcurrentRotationConflict` | 409 |
| `NoPolicyAttached` | 422 |
| `PolicyInUse` | 422 |
| `VaultBackendInUse` | 422 |
| `InsufficientApprovers` | 403 |
| `BreakGlassJustificationRequired` | 403 |
| `CredentialIsRevoked` | 422 |
| `CredentialIsExpired` | 422 |
| `CredentialIsDeleted` | 410 |
| `OptimisticLockConflict` | 409 |
| `ApplicationAuditFailure` | 500 |
| `ApplicationPortError` | 502 |
| `ApplicationValidationError` | 422 |
| `ResolvedSecretZeroized` | 500 |

Exception handlers are registered on the FastAPI app instance, not duplicated in each router.

### `/api/v1/credentials` router

| Method | Path | Handler | Status codes |
|---|---|---|---|
| `POST` | `/credentials` | `create_credential` | 201, 403, 409, 422, 502 |
| `GET` | `/credentials/{credential_id}` | `get_credential` | 200, 403, 404 |
| `GET` | `/credentials` | `list_credentials` | 200 |
| `POST` | `/credentials/{credential_id}/resolve` | `resolve_credential` | 200, 403, 404, 422 |
| `PATCH` | `/credentials/{credential_id}/metadata` | `update_metadata` | 200, 403, 404, 409, 422 |
| `POST` | `/credentials/{credential_id}/disable` | `disable_credential` | 200, 403, 404, 422 |
| `POST` | `/credentials/{credential_id}/enable` | `enable_credential` | 200, 403, 404, 422 |
| `POST` | `/credentials/{credential_id}/revoke` | `revoke_credential` | 200, 403, 404 |
| `POST` | `/credentials/{credential_id}/emergency-revoke` | `emergency_revoke` | 200, 403, 404 |
| `POST` | `/credentials/{credential_id}/rotate` | `rotate_credential` | 200, 403, 404, 409, 502 |
| `POST` | `/credentials/{credential_id}/commit-rotation` | `commit_rotation` | 200, 403, 404, 409, 422 |
| `POST` | `/credentials/{credential_id}/abort-rotation` | `abort_rotation` | 200, 403, 404, 422 |
| `POST` | `/credentials/{credential_id}/recover` | `recover_credential` | 200, 403, 404, 422 |
| `POST` | `/credentials/{credential_id}/rollback-version` | `rollback_version` | 200, 403, 404, 422 |
| `DELETE` | `/credentials/{credential_id}` | `hard_delete_credential` | 204, 403, 404 |
| `GET` | `/credentials/{credential_id}/versions` | `list_versions` | 200, 403, 404 |
| `GET` | `/credentials/{credential_id}/versions/{version_id}` | `get_version` | 200, 403, 404 |
| `POST` | `/credentials/{credential_id}/attach-rotation-policy` | `attach_rotation_policy` | 200, 403, 404, 422 |
| `POST` | `/credentials/{credential_id}/detach-rotation-policy` | `detach_rotation_policy` | 200, 403, 404 |
| `POST` | `/credentials/{credential_id}/attach-expiration-policy` | `attach_expiration_policy` | 200, 403, 404, 422 |
| `POST` | `/credentials/{credential_id}/detach-expiration-policy` | `detach_expiration_policy` | 200, 403, 404 |

### `/api/v1/credential-policies` router

| Method | Path | Handler | Status codes |
|---|---|---|---|
| `POST` | `/credential-policies/rotation` | `create_rotation_policy` | 201, 403, 409, 422 |
| `GET` | `/credential-policies/rotation/{policy_id}` | `get_rotation_policy` | 200, 403, 404 |
| `GET` | `/credential-policies/rotation` | `list_rotation_policies` | 200 |
| `PATCH` | `/credential-policies/rotation/{policy_id}` | `update_rotation_policy` | 200, 403, 404, 422 |
| `DELETE` | `/credential-policies/rotation/{policy_id}` | `delete_rotation_policy` | 204, 403, 404, 422 |
| `POST` | `/credential-policies/expiration` | `create_expiration_policy` | 201, 403, 409, 422 |
| `GET` | `/credential-policies/expiration/{policy_id}` | `get_expiration_policy` | 200, 403, 404 |
| `GET` | `/credential-policies/expiration` | `list_expiration_policies` | 200 |
| `PATCH` | `/credential-policies/expiration/{policy_id}` | `update_expiration_policy` | 200, 403, 404, 422 |
| `DELETE` | `/credential-policies/expiration/{policy_id}` | `delete_expiration_policy` | 204, 403, 404, 422 |

### `/api/v1/vault-backends` router

| Method | Path | Handler | Status codes |
|---|---|---|---|
| `POST` | `/vault-backends` | `register_vault_backend` | 201, 403, 409, 422 |
| `GET` | `/vault-backends/{backend_id}` | `get_vault_backend` | 200, 403, 404 |
| `GET` | `/vault-backends` | `list_vault_backends` | 200, 403 |
| `DELETE` | `/vault-backends/{backend_id}` | `delete_vault_backend` | 204, 403, 404, 422 |

### `/api/v1/audit-logs` router

| Method | Path | Handler | Status codes |
|---|---|---|---|
| `GET` | `/audit-logs/credentials/{credential_id}` | `list_audit_entries` | 200, 403, 404 |

---

## §14. Pydantic Schemas

### Schema design rules

- All schemas extend `pydantic.BaseModel`.
- `model_config = ConfigDict(str_strip_whitespace=True, frozen=True)` on all schemas.
- UUID fields are typed `uuid.UUID` — Pydantic v2 serializes to string automatically.
- `datetime` fields are typed `datetime` — serialized as ISO 8601 UTC strings.
- Response schemas mirror DTO fields exactly. They are named `*Response` and constructed from DTOs in the route handler.
- Request schemas are named `*Request`. Field names match command field names exactly to simplify construction.
- No business validation in schemas — validation belongs in the application service.

### Key schema notes

**`CreateCredentialRequest`**: `plaintext_secret: str` — the HTTP request carries the secret as a UTF-8 string; the route handler encodes it to `bytes` via `.encode("utf-8")` before passing to the command.

**`ResolveCredentialResponse`**: `secret_b64: str` — computed from `dto.plaintext_secret` via `base64.b64encode(...).decode()`. The route handler calls `resolved_secret.zero()` in a `finally` block after constructing the response.

**`CredentialResponse`**: All fields from `CredentialDTO`. `tags: dict[str, str]`.

**`VersionResponse`**: All fields from `VersionDTO`. No `encrypted_payload`, no `key_envelope`.

**`VaultBackendResponse`**: All fields from `VaultBackendDTO`. No `config`.

**`AuditEntryResponse`**: All fields from `AuditEntryDTO`.

**`ListCredentialsResponse`**: `items: list[CredentialResponse]`, `total: int`, `limit: int`, `offset: int`.

**`ListVersionsResponse`**: `items: list[VersionResponse]`.

**Pagination query params**: `limit: int = Query(default=100, ge=1, le=1000)`, `offset: int = Query(default=0, ge=0)`.

---

## §15. Dependency Injection

### `CredentialVaultContainer`

`CredentialVaultContainer` is initialized once at application startup and registered with the FastAPI app as `app.state.cv_container`. It wires all application services with their concrete dependencies.

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
        # UoW factory
        self._uow_factory = make_credential_vault_uow_factory(session_factory)
        # Domain services (pure, no injection needed)
        self._access_control = AccessControlPolicyService()
        self._break_glass_svc = BreakGlassService(approval_adapter)
        self._recovery_svc = RecoveryService(approval_adapter)
        self._resolver_svc = CredentialResolverService(
            kms_adapter, encryption_adapter, self._access_control,
            self._break_glass_svc, self._recovery_svc
        )
        # Application services
        self.credential_service = CredentialApplicationService(
            self._uow_factory, event_publisher, kms_adapter, encryption_adapter,
            permission_adapter, approval_adapter, self._access_control,
            self._break_glass_svc, self._recovery_svc, self._resolver_svc
        )
        # Query services
        _read_only_session = session_factory  # Same factory; reads share sessions
        self.credential_query_service = CredentialQueryService(
            PgCredentialRepository(_read_session_placeholder),
            PgCredentialVersionRepository(_read_session_placeholder),
            permission_adapter,
        )
```

**Note on query service injection:** Query services need repository instances but not a UoW. The pattern is to use a separate `AsyncSession` per request for reads. The DI `Depends` function creates a short-lived session for the query service:

```python
async def get_credential_query_service(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> CredentialQueryService:
    container = request.app.state.cv_container
    return CredentialQueryService(
        PgCredentialRepository(session),
        PgCredentialVersionRepository(session),
        container.permission_adapter,
    )
```

The `get_async_session` dependency yields a session and closes it after the request.

### FastAPI `Depends` functions

```python
# commands
async def get_credential_service(request: Request) -> CredentialApplicationService:
    return request.app.state.cv_container.credential_service

# queries
async def get_credential_query_service(request: Request, session: AsyncSession = Depends(...)):
    ...
```

Route handlers use `Annotated[CredentialApplicationService, Depends(get_credential_service)]`.

---

## §16. Alembic Migration `0044`

**File:** `backend/src/redforge/infrastructure/database/migrations/versions/0044_credential_vault_foundation.py`

**Revision:** `0044`
**Down revision:** `0043`

### Migration structure

```python
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade() -> None:
    # 1. Create vault_backends (no FK dependencies)
    op.create_table(
        "credential_vault_vault_backends",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("backend_type", sa.String(64), nullable=False),
        sa.Column("is_default", sa.Boolean, nullable=False, default=False),
        sa.Column("config_encrypted", sa.LargeBinary, nullable=False),
        sa.Column("config_key_envelope", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer, nullable=False, default=1),
        sa.UniqueConstraint("tenant_id", "name", name="uq_cvvb_tenant_name"),
    )
    op.create_index("ix_cvvb_tenant", "credential_vault_vault_backends", ["tenant_id"])

    # 2. Create rotation_policies
    op.create_table("credential_vault_rotation_policies", ...)
    # 3. Create expiration_policies
    op.create_table("credential_vault_expiration_policies", ...)
    # 4. Create credentials (FKs to vault_backends, policies)
    op.create_table("credential_vault_credentials", ...)
    # 5. Create versions (FK to credentials)
    op.create_table("credential_vault_versions", ...)
    # 6. Create audit_logs (FK to credentials)
    op.create_table("credential_vault_audit_logs", ...)
    # 7. Create audit_entries (FK to audit_logs)
    op.create_table("credential_vault_audit_entries", ...)
    # 8. Create approval_requests
    op.create_table("credential_vault_approval_requests", ...)

def downgrade() -> None:
    # Drop in reverse FK order
    op.drop_table("credential_vault_approval_requests")
    op.drop_table("credential_vault_audit_entries")
    op.drop_table("credential_vault_audit_logs")
    op.drop_table("credential_vault_versions")
    op.drop_table("credential_vault_credentials")
    op.drop_table("credential_vault_expiration_policies")
    op.drop_table("credential_vault_rotation_policies")
    op.drop_table("credential_vault_vault_backends")
```

**FK deferral**: Use `deferrable=True, initially="DEFERRED"` on the `active_version_id` FK in `credential_vault_credentials`, because during `create_credential` the credential and version are saved in the same transaction, and the credential's `active_version_id` may be set before the version row is persisted. Alternatively, save version first (which M25B spec mandates).

**Migration idempotency**: Every `create_table` call uses the `if_not_exists=True` flag pattern to support re-entrant execution.

---

## §17. Observability

### OpenTelemetry

Every repository method is wrapped with a span:
```python
with tracer.start_as_current_span("credential_vault.repository.save") as span:
    span.set_attribute("db.table", "credential_vault_credentials")
    span.set_attribute("tenant_id", str(tenant_id))
    ...
```

`opentelemetry.instrumentation.sqlalchemy` is already configured globally — it automatically instruments all SQLAlchemy queries. No per-repository span wiring is needed for SQL-level tracing. The application-level span is added for semantic conventions.

### Prometheus metrics

Add to `credential_vault/infrastructure/metrics.py`:

```python
credential_operations_total = Counter(
    "credential_vault_operations_total",
    "Total credential operations",
    labelnames=["operation", "outcome", "tenant_id"],
)

credential_encryption_duration = Histogram(
    "credential_vault_encryption_duration_seconds",
    "Encryption/decryption duration",
    labelnames=["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0],
)

credential_kms_calls_total = Counter(
    "credential_vault_kms_calls_total",
    "Total KMS calls",
    labelnames=["operation", "outcome"],
)
```

Metric increments happen in the application service wrappers (M25C decorates or the service calls `metrics.credential_operations_total.labels(...).inc()` at the end of each method).

Actually, to keep application services infrastructure-free, metrics are recorded in a thin instrumentation wrapper around the application services. Each application service is wrapped by a `MetricsCredentialApplicationService` that delegates and records metrics. This wrapper lives in `credential_vault/infrastructure/metrics_wrapper.py`.

### Structured logging

Every security event logs at INFO via `structlog`:
- `credential.created` — credential_id, tenant_id, principal_id
- `credential.resolved` — credential_id, tenant_id, principal_id, break_glass, purpose
- `credential.rotated` — credential_id, tenant_id, trigger
- `credential.revoked` — credential_id, tenant_id, principal_id
- `credential.emergency_revoked` — credential_id, tenant_id, principal_id, justification
- `credential.deleted` — credential_id, tenant_id, principal_id
- `audit.append_failed` — WARNING, credential_id, error
- `encryption.dek_generated` — DEBUG, master_key_id (no DEK bytes)
- `kms.call_failed` — WARNING, operation, error

**Never log**: plaintext_secret, plaintext DEK bytes, decrypted payload, request body containing secrets.

---

## §18. Startup Validation

Extend `redforge.infrastructure.startup_validator` (or create `credential_vault/infrastructure/startup_validator.py`) with:

1. **Database connectivity**: Issue `SELECT 1` against the credential vault session factory.
2. **Migration head**: Compare Alembic current head against `0044`. Block startup if behind.
3. **KMS connectivity**: Issue `generate_dek()` and immediately discard. If `ApplicationPortError` → log WARNING but do not block (allows startup without KMS for test mode). In production (`ENVIRONMENT=production`), block startup.
4. **Permission port**: Issue a synthetic `has_permission(NIL_UUID, NIL_UUID, "READ", NIL_UUID)` call. Do not block on false result; block only on exception.
5. **Encryption round-trip**: Encrypt and decrypt a known test vector. Assert plaintexts match. Block startup if assertion fails.

---

## §19. Testing Strategy

### Repository integration tests

Each `test_pg_*_repository.py` uses a real PostgreSQL test database. Fixtures:
- `pg_engine` — creates an `AsyncEngine` from `TEST_DATABASE_URL` environment variable.
- `pg_session` — yields a single `AsyncSession` for the test, rolls back at the end.
- `pg_uow` — yields a `CredentialVaultUnitOfWork` with a real session, rolls back at the end.
- `apply_migrations` — session-scoped; runs `alembic upgrade 0044` before any test in the suite.

Required test cases per repository:

**`test_pg_credential_repository.py`**:
- `test_save_and_get_by_id_round_trip` — verify all fields map correctly
- `test_save_increments_row_version` — after two saves, `row_version == 2`
- `test_save_raises_optimistic_lock_conflict` — two sessions update same row; second raises
- `test_get_by_id_wrong_tenant_raises_not_found` — cross-tenant access blocked
- `test_exists_by_name_true_and_false`
- `test_list_by_tenant_with_state_filter`
- `test_list_by_tenant_pagination`
- `test_list_with_rotation_policy_returns_correct_ids`
- `test_unique_name_per_tenant_allows_same_name_different_tenants`

**`test_pg_credential_version_repository.py`**:
- `test_save_and_get_by_id`
- `test_get_active_version_returns_correct_state`
- `test_get_active_version_raises_if_no_active`
- `test_list_by_credential_ordered_ascending_version_number`
- `test_list_by_credential_with_state_filter`
- `test_atomic_promote_sets_new_active_and_supersedes_old`
- `test_atomic_promote_raises_if_no_active_to_supersede`
- `test_update_increments_row_version`
- `test_update_raises_optimistic_lock_conflict`
- `test_count_superseded_returns_correct_count`

**`test_credential_vault_uow.py`**:
- `test_commit_persists_data`
- `test_exception_causes_rollback` — verify data not persisted after exception
- `test_all_six_repos_accessible`
- `test_session_closed_after_exit`

**`test_aes_gcm_encryption_adapter.py`** (unit, no DB):
- `test_encrypt_decrypt_round_trip`
- `test_different_iv_per_call`
- `test_wrong_tag_raises_auth_failure`
- `test_dek_zeroed_after_encrypt`
- `test_dek_zeroed_after_decrypt`

**`test_local_kms_adapter.py`** (unit):
- `test_generate_and_unwrap_round_trip`
- `test_unwrap_wrong_key_id_raises`
- `test_dek_bytes_are_32`

### API integration tests

`test_credentials_api.py` uses `httpx.AsyncClient` with the FastAPI `TestClient`. Override `get_credential_service` Depends to inject a `CredentialApplicationService` backed by `CredentialVaultUnitOfWork` pointing at the test PostgreSQL database.

Required test cases:

- `test_create_credential_returns_201_with_location_header`
- `test_create_credential_duplicate_name_returns_409`
- `test_get_credential_not_found_returns_404`
- `test_get_credential_wrong_tenant_returns_404`
- `test_resolve_credential_returns_base64_secret`
- `test_resolve_credential_audit_fail_returns_500`
- `test_rotate_commit_abort_lifecycle`
- `test_list_credentials_empty_list_returns_200`
- `test_list_credentials_state_filter`
- `test_hard_delete_returns_204`
- `test_revoke_then_emergency_revoke_returns_200`

---

## §20. Quality Gates

Every phase must pass before the next phase begins.

| Gate | Command | Requirement |
|---|---|---|
| Format | `ruff format --check src/credential_vault/` | Zero violations |
| Lint | `ruff check src/credential_vault/` | Zero violations |
| Type | `mypy src/credential_vault/ --strict` | Zero errors |
| Domain integrity | `git diff --exit-code src/credential_vault/domain/` | Zero changes |
| Infra isolation | `grep -rn "fastapi\|pydantic" src/credential_vault/infrastructure/` | Zero matches (except `dependencies.py` shim) |
| Unit tests | `pytest tests/credential_vault/ -x --ignore=tests/credential_vault/infrastructure` | All pass |
| Integration | `pytest tests/credential_vault/infrastructure/ -x -m integration` | All pass |
| API tests | `pytest tests/credential_vault/api/ -x` | All pass |
| Migration up/down | `alembic upgrade 0044 && alembic downgrade 0043 && alembic upgrade 0044` | No error |

---

## §21. Acceptance Criteria

1. All 45 new files pass mypy --strict with zero errors.
2. `ruff check` and `ruff format --check` pass on all new files.
3. `alembic upgrade 0044` creates all eight tables with correct constraints and indexes. `alembic downgrade 0043` removes them cleanly.
4. All six repository implementations fulfill their domain ABC contracts verified by the integration test suite.
5. `CredentialVaultUnitOfWork` satisfies the fail-closed invariant: on exception, `rollback()` is called and no data is persisted.
6. `AesGcmEncryptionAdapter` encrypt-then-decrypt round-trip returns identical plaintext for arbitrary inputs.
7. All DEK bytes are zeroed after use in both `AesGcmEncryptionAdapter` and `LocalAesKwKmsAdapter`. Verified by inspection of the zeroization code path.
8. `StructlogEventPublisher` never raises; `publish_batch` failures are logged and swallowed.
9. All 21 credential API endpoints return correct HTTP status codes for all documented error paths. Verified by API test suite.
10. `config` field is absent from `VaultBackendDTO` and `VaultBackendResponse`.
11. `encrypted_payload` and `key_envelope` fields are absent from `VersionDTO` and `VersionResponse`.
12. No plaintext secret appears in any structured log entry.
13. No import from `credential_vault.infrastructure` or `credential_vault.api` appears in `credential_vault.domain` or `credential_vault.application`.
14. `git diff src/credential_vault/domain/ src/credential_vault/application/` is clean (zero changes to M25A and M25B).
15. `credential_vault_approval_requests` table is created with correct schema in migration `0044`.

---

## §22. Traceability Matrix

| M25B Requirement | M25C Deliverable |
|---|---|
| `IUnitOfWork` with 6 repos | `CredentialVaultUnitOfWork` + 6 `Pg*Repository` classes |
| `IEventPublisher` | `StructlogEventPublisher` |
| `IKeyManagementPort` | `LocalAesKwKmsAdapter`, `AwsKmsAdapter` |
| `IEncryptionPort` | `AesGcmEncryptionAdapter` |
| `IPermissionPort` | `RbacPermissionAdapter` |
| `IApprovalPort` | `ApprovalWorkflowAdapter` |
| 23 use cases → HTTP | 21 endpoints in 4 FastAPI routers |
| Optimistic concurrency | `row_version` column + UPDATE WHERE check |
| Fail-closed audit | `append_entry` INSERT before `commit()` |
| Tenant isolation | `tenant_id` on every query predicate |
| Config security | `config_encrypted` + `config_key_envelope` in `vault_backends` |
| `CredentialAlreadyExists` | `UNIQUE (tenant_id, name)` constraint on `credentials` table |

---

## §23. Risks and Mitigations

### R1 — Missing `list_by_backend_id` on `ICredentialRepository`

**Risk:** `delete_vault_backend` in M25B needs to check whether any credential uses the backend. `ICredentialRepository` does not have a `list_by_backend_id` method.

**Resolution:** Add `list_with_vault_backend(backend_id: VaultBackendId, tenant_id: TenantId) -> list[CredentialId]` to `ICredentialRepository` as an additional abstract method. This is a backward-compatible addition (new method on an ABC). M25B implementation guide §5D (`VaultBackendApplicationService`) must be updated to call this method before calling `uow.vault_backends.delete()`. **Cursor must add this method to both the domain ABC and the `PgCredentialRepository` implementation.**

### R2 — `EncryptionAuthTagFailure` not in M25A domain exceptions

**Risk:** AES-256-GCM authentication tag failure needs a domain exception. M25A did not define one.

**Resolution:** Add `EncryptionAuthTagFailure(DomainException)` to `credential_vault.domain.exceptions.domain_exceptions`. This is a domain-layer exception (not application-layer) because it is a correctness/integrity failure detectable from domain-layer port calls. Adding it does not modify existing M25A files' behavior — it is an additive extension.

### R3 — `KmsKeyNotFound` not in M25A domain exceptions

**Resolution:** Same pattern — add to domain exceptions alongside `EncryptionAuthTagFailure`.

### R4 — `BreakGlassService` and `RecoveryService` constructors require `IApprovalPort`

**Risk:** M25A may define these services as pure (no ports). If so, the container wiring in §15 is wrong.

**Resolution:** Verify constructor signatures before implementing. If pure, the port is passed to individual method calls, not the constructor. Update `CredentialVaultContainer` accordingly.

### R5 — `RBAC resource_type="credential"` not registered

**Risk:** `RbacPermissionAdapter` calls `effective_access_svc.has_permission(resource_type="credential", ...)`. The existing RBAC system may not have this resource type.

**Mitigation:** In development/test, return `True` for all permission checks when `CREDENTIAL_VAULT_PERMISSION_MODE=open`. In production, verify during startup.

---

## §24. Out of Scope

1. Outbox pattern for event publication (post-M25).
2. AWS KMS key rotation (auto-rekey of all credential versions on master key change) — M25D schedules DEK rewrap.
3. Multi-region KMS failover.
4. Secret versioning via external vault providers (HashiCorp Vault, Azure Key Vault) — backend type `HASHICORP_VAULT` and `AZURE_KEY_VAULT` are valid `backend_type` enum values but their adapters are not part of M25. They receive encrypted config only.
5. Webhook notifications on credential events.
6. Secret leakage detection (credential scanning).
7. SCIM provisioning for permission management.
8. Bulk credential import/export API.
9. Cursor pagination (continuation tokens) — offset pagination is sufficient for M25.
10. Rate limiting per-tenant on resolve endpoint — platform-level concern.
