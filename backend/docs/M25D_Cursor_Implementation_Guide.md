# M25D Cursor Implementation Guide
## Enterprise Credential Vault — Background Workers & Operational Automation
### Execution Authority: M25D Specification v1.0 FROZEN

---

## Document Purpose

This guide converts the frozen M25D specification into a sequential execution plan for Cursor. M25C must be complete and all tests passing before M25D begins.

**Prerequisites:**
- M25C implementation complete (all 45 files implemented, all tests passing)
- `alembic upgrade 0044` has been applied to the test database
- `mypy src/credential_vault/ --strict` passes with zero errors

**Frozen inputs:**
- `M25D_Spec_Part1.md` — Sections 1–12
- `M25D_Spec_Part2.md` — Sections 13–22
- M25A domain + M25B application + M25C infrastructure — frozen

**New directory:**
- `backend/src/credential_vault/workers/`
- `backend/tests/credential_vault/workers/`

---

# 1. Overall Strategy

## 1.1 Worker architecture summary

Workers are asyncio background tasks following the exact `ContinuousValidationSchedulerWorker` pattern (see `backend/src/redforge/application/continuous_validation/scheduler_worker.py`). Every worker has:
- `start() / stop()` lifecycle methods
- `is_running: bool` property
- `stats() -> dict` method
- `_poll_loop()` coroutine (infinite loop with `asyncio.sleep`)
- `_run_cycle()` coroutine (one cycle of work)

## 1.2 What Cursor must never do

- Access domain aggregates directly — use application services via commands.
- Commit sessions inside workers — session lifecycle belongs to `CredentialVaultUnitOfWork`.
- Exception for `VersionPrunerWorker` and `DekRewrapWorker` — these do NOT use the application service. They open their own sessions directly (see §3.3 and §3.4).
- Log plaintext secrets, DEK bytes, or key material.
- Implement `auto_commit=False` rotation (leave the credential in ROTATING state) differently from `auto_commit=True` — it is the same `rotate_credential` call, just without the subsequent `commit_rotation`.
- Delete ACTIVE, PENDING, or REVOKED versions in the pruner — only SUPERSEDED.
- Start the DEK rewrap worker unless both environment variables are set.

---

# 2. Pre-Implementation: Domain Additive Extensions

Before any worker code, apply additive extensions to domain and application files.

### Step 1 — Add domain events to `credential_events.py`

Add four new event classes at the end of the file. See M25D Spec §13.1 for field definitions.

### Step 2 — Add `auto_commit` and `commit_window_hours` to `RotationPolicy`

In `credential_vault/domain/aggregates/rotation_policy.py`:
1. Add `"auto_commit"` and `"commit_window_hours"` to `__slots__`.
2. Add to `__init__` with `auto_commit: bool = True, commit_window_hours: int = 24`.
3. Update `create()` classmethod to accept and pass these fields.
4. Update `RotationPolicyUpdated` event payload if it includes policy fields.

### Step 3 — Add `list_with_active_rotation_policy` to `ICredentialRepository`

Abstract method:
```python
@abstractmethod
async def list_with_active_rotation_policy(
    self,
    tenant_id: TenantId,
    limit: int = 1000,
    offset: int = 0,
) -> list[Credential]:
    """Returns ACTIVE credentials with a rotation_policy_id set."""
```

### Step 4 — Update `RotationPolicyDTO` and commands

- `RotationPolicyDTO`: add `auto_commit: bool`, `commit_window_hours: int`.
- `CreateRotationPolicyCommand`: add `auto_commit: bool = True`, `commit_window_hours: int = 24`.
- `UpdateRotationPolicyCommand`: add same fields.

### Step 5 — Implement `list_with_active_rotation_policy` in `PgCredentialRepository`

```python
async def list_with_active_rotation_policy(
    self, tenant_id: TenantId, limit: int = 1000, offset: int = 0
) -> list[Credential]:
    result = await self._session.execute(
        select(CredentialModel)
        .where(
            CredentialModel.tenant_id == tenant_id.value,
            CredentialModel.rotation_policy_id.is_not(None),
            CredentialModel.state == "ACTIVE",
        )
        .order_by(CredentialModel.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    rows = result.scalars().all()
    return [self._to_domain(row) for row in rows]
```

### Step 6 — Validate additive changes

```bash
mypy src/credential_vault/domain/ --strict
mypy src/credential_vault/application/ --strict
mypy src/credential_vault/infrastructure/ --strict
pytest tests/credential_vault/ -x --ignore=tests/credential_vault/workers/ -v
```

All must pass. Then commit the additive changes: "add rotation policy auto_commit; add CredentialExpirationWarning event; add list_with_active_rotation_policy".

---

# 3. Sequential Implementation Phases

---

## Phase 1: Migration `0045`

### Objective
Create migration adding worker schedule state tables and new rotation policy columns.

### File to create (1)

`backend/src/redforge/infrastructure/database/migrations/versions/0045_credential_vault_worker_state.py`

### Column additions to `credential_vault_rotation_policies`

```python
op.add_column(
    "credential_vault_rotation_policies",
    sa.Column("auto_commit", sa.Boolean, nullable=False, server_default="true"),
)
op.add_column(
    "credential_vault_rotation_policies",
    sa.Column("commit_window_hours", sa.Integer, nullable=False, server_default="24"),
)
```

Use `server_default` (not `default`) so existing rows get the default value without requiring a table rewrite. This is safe for a column addition on a non-empty table.

### Three new tables

Create in this order:
1. `credential_vault_rotation_schedule_state`
2. `credential_vault_expiration_schedule_state`
3. `credential_vault_dek_rewrap_progress`

For `rotation_schedule_state` primary key FK to credentials: use `deferrable=True, initially="DEFERRED"` if credentials may not exist at insert time (e.g., during reconciliation before credential is fully committed). Actually: the reconciliation only runs for existing active credentials, so standard FK is fine.

### Downgrade

```python
op.drop_table("credential_vault_dek_rewrap_progress")
op.drop_table("credential_vault_expiration_schedule_state")
op.drop_table("credential_vault_rotation_schedule_state")
op.drop_column("credential_vault_rotation_policies", "commit_window_hours")
op.drop_column("credential_vault_rotation_policies", "auto_commit")
```

### Validation checklist

```bash
alembic upgrade 0045
alembic downgrade 0044
alembic upgrade 0045
echo "Migration 0045 OK"
```

### Exit criteria
Round-trip passes. Three new tables exist. Two new columns exist on rotation_policies.

---

## Phase 2: Schedule Repositories

### Objective
Implement the three schedule/progress repositories. No worker logic yet.

### Files to create (4)

| # | File |
|---|---|
| 1 | `workers/__init__.py` |
| 2 | `workers/rotation_scheduler/__init__.py` |
| 3 | `workers/rotation_scheduler/rotation_schedule_repository.py` |
| 4 | `workers/expiration_scanner/__init__.py` |
| 5 | `workers/expiration_scanner/expiration_schedule_repository.py` |
| 6 | `workers/dek_rewrap/__init__.py` |
| 7 | `workers/dek_rewrap/dek_rewrap_progress_repository.py` |
| 8 | `workers/version_pruner/__init__.py` |
| 9 | `workers/version_pruner/version_pruner_repository.py` |

### `RotationScheduleRepository`

All methods use a session passed at construction or per-call. Use the per-call pattern (session factory, open session per call) for workers to avoid holding long-lived sessions.

```python
class RotationScheduleRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def claim_batch(self, batch_size: int) -> list[ScheduleItem]:
        async with self._sf() as session:
            result = await session.execute(
                text("""
                    SELECT credential_id, tenant_id, next_due_at
                    FROM credential_vault_rotation_schedule_state
                    WHERE next_due_at <= NOW()
                      AND (claimed_at IS NULL OR claim_expires_at < NOW())
                    ORDER BY next_due_at ASC
                    LIMIT :n
                    FOR UPDATE SKIP LOCKED
                """),
                {"n": batch_size},
            )
            rows = result.all()
            if not rows:
                await session.rollback()
                return []
            ids = [row.credential_id for row in rows]
            await session.execute(
                text("""
                    UPDATE credential_vault_rotation_schedule_state
                    SET claimed_at = NOW(), claim_expires_at = NOW() + INTERVAL '10 minutes'
                    WHERE credential_id = ANY(:ids)
                """),
                {"ids": ids},
            )
            await session.commit()
            return [ScheduleItem(credential_id=UUID(str(r.credential_id)), tenant_id=UUID(str(r.tenant_id))) for r in rows]
```

**`ScheduleItem`** is a simple `@dataclass(frozen=True, slots=True)` data class:
```python
@dataclass(frozen=True, slots=True)
class ScheduleItem:
    credential_id: uuid.UUID
    tenant_id: uuid.UUID
```

Define `ScheduleItem` in the repository module (not in domain).

**Other repository methods:**

```python
async def release_claim(self, credential_id: uuid.UUID, tenant_id: uuid.UUID) -> None: ...
async def update_after_rotation(self, credential_id: uuid.UUID, tenant_id: uuid.UUID, next_due_at: datetime) -> None: ...
async def upsert_for_credential(self, credential_id: uuid.UUID, tenant_id: uuid.UUID, next_due_at: datetime) -> None: ...
async def delete(self, credential_id: uuid.UUID, tenant_id: uuid.UUID) -> None: ...
```

### `VersionPrunerRepository`

```python
@dataclass(frozen=True, slots=True)
class PruneCandidate:
    credential_id: uuid.UUID
    tenant_id: uuid.UUID
    superseded_count: int
    max_versions_kept: int

class VersionPrunerRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None: ...

    async def find_credentials_exceeding_max_versions(
        self, batch_size: int
    ) -> list[PruneCandidate]:
        """
        Finds credentials where superseded version count > max_versions_kept.
        Uses a subquery join between credentials, rotation_policies, and version counts.
        """
        async with self._sf() as session:
            result = await session.execute(
                text("""
                    SELECT c.id, c.tenant_id,
                           COUNT(v.id) AS superseded_count,
                           p.max_versions_kept
                    FROM credential_vault_credentials c
                    JOIN credential_vault_rotation_policies p ON p.id = c.rotation_policy_id
                    JOIN credential_vault_versions v ON v.credential_id = c.id
                      AND v.version_state = 'SUPERSEDED'
                    WHERE c.state = 'ACTIVE'
                      AND c.rotation_policy_id IS NOT NULL
                    GROUP BY c.id, c.tenant_id, p.max_versions_kept
                    HAVING COUNT(v.id) > p.max_versions_kept
                    LIMIT :n
                """),
                {"n": batch_size},
            )
            return [PruneCandidate(
                credential_id=UUID(str(r.id)),
                tenant_id=UUID(str(r.tenant_id)),
                superseded_count=r.superseded_count,
                max_versions_kept=r.max_versions_kept,
            ) for r in result.all()]

    async def get_superseded_version_ids(
        self, credential_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[uuid.UUID]:
        """Returns SUPERSEDED version IDs ordered by version_number ASC (oldest first)."""
        async with self._sf() as session:
            result = await session.execute(
                text("""
                    SELECT id FROM credential_vault_versions
                    WHERE credential_id = :cid AND tenant_id = :tid
                      AND version_state = 'SUPERSEDED'
                    ORDER BY version_number ASC
                """),
                {"cid": credential_id, "tid": tenant_id},
            )
            return [UUID(str(r.id)) for r in result.all()]

    async def delete_superseded_versions(
        self,
        version_ids: list[uuid.UUID],
        tenant_id: uuid.UUID,
    ) -> int:
        async with self._sf() as session:
            result = await session.execute(
                text("""
                    DELETE FROM credential_vault_versions
                    WHERE id = ANY(:ids) AND tenant_id = :tid
                      AND version_state = 'SUPERSEDED'
                    RETURNING id
                """),
                {"ids": version_ids, "tid": tenant_id},
            )
            await session.commit()
            deleted = result.rowcount
            return deleted
```

### Validation checklist

```bash
mypy src/credential_vault/workers/ --strict
ruff check src/credential_vault/workers/
pytest tests/credential_vault/workers/ -x -k "repository" -m integration
```

---

## Phase 3: Rotation Scheduler Worker

### Files to create (1)

`workers/rotation_scheduler/rotation_scheduler_worker.py`

### Implementation skeleton

```python
@dataclass(frozen=True, slots=True)
class _RotationResult:
    credential_id: uuid.UUID
    success: bool
    error: str | None = None

class RotationSchedulerWorker:
    def __init__(
        self,
        credential_service: CredentialApplicationService,
        schedule_repo: RotationScheduleRepository,
        rotation_planner: RotationPlannerService,
        credential_query_service: CredentialQueryService,
        version_repo: ICredentialVersionRepository,
        policy_repo: IRotationPolicyRepository,
        session_factory: async_sessionmaker[AsyncSession],
        system_principal_id: uuid.UUID,
        worker_id: str = "rotation-scheduler-1",
        poll_interval_s: float = 60.0,
        batch_size: int = 10,
        max_concurrent: int = 3,
    ) -> None:
        self._cred_svc = credential_service
        self._schedule_repo = schedule_repo
        self._rotation_planner = rotation_planner
        self._version_repo_factory = ... # session-scoped repo factory
        self._policy_repo_factory = ...
        self._session_factory = session_factory
        self._system_principal_id = system_principal_id
        self.worker_id = worker_id
        self._poll_interval_s = poll_interval_s
        self._batch_size = batch_size
        self._max_concurrent = max_concurrent
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._rotated = 0
        self._failed = 0
        self._cycles = 0

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await self._reconcile_schedule_state()
        self._task = asyncio.create_task(self._poll_loop(), name=self.worker_id)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def stats(self) -> dict[str, object]:
        return {
            "rotated": self._rotated,
            "failed": self._failed,
            "cycles": self._cycles,
        }
```

### `_reconcile_schedule_state`

Called once at startup. Queries all ACTIVE credentials with rotation policies and inserts missing schedule state entries via `RotationScheduleRepository.upsert_for_credential`.

```python
async def _reconcile_schedule_state(self) -> None:
    async with self._session_factory() as session:
        repo = PgCredentialRepository(session)
        version_repo = PgCredentialVersionRepository(session)
        policy_repo = PgRotationPolicyRepository(session)
        # paginate through all active credentials with rotation policies
        offset = 0
        while True:
            credentials = await repo.list_with_active_rotation_policy(
                TenantId(...), limit=500, offset=offset  # NOTE: list ALL tenants
            )
            # Actually need a cross-tenant variant:
            # See note below
            if not credentials:
                break
            for cred in credentials:
                ...
            offset += 500
```

**Note:** `list_with_active_rotation_policy` takes a `tenant_id` parameter in the current spec. For reconciliation, we need all tenants. Add a `list_all_with_active_rotation_policy(limit, offset)` method to `ICredentialRepository` (omit the `tenant_id` filter). This is a scheduler-internal operation — no permission check is needed. Alternatively, query the `credential_vault_credentials` table directly in the reconciliation method (bypassing the domain repository) to avoid another ABC method. Use the direct query approach in M25D.

```python
async def _reconcile_schedule_state(self) -> None:
    logger.info("rotation_scheduler.reconcile_start")
    async with self._session_factory() as session:
        result = await session.execute(
            text("""
                SELECT c.id, c.tenant_id,
                       v.created_at AS version_created_at,
                       p.interval_days
                FROM credential_vault_credentials c
                JOIN credential_vault_versions v ON v.id = c.active_version_id
                JOIN credential_vault_rotation_policies p ON p.id = c.rotation_policy_id
                WHERE c.state = 'ACTIVE'
                  AND c.rotation_policy_id IS NOT NULL
                  AND p.auto_rotate = TRUE
                  AND p.interval_days IS NOT NULL
            """)
        )
        rows = result.all()
        now = datetime.now(UTC)
        for row in rows:
            next_due = row.version_created_at + timedelta(days=row.interval_days)
            await self._schedule_repo.upsert_for_credential(
                credential_id=UUID(str(row.id)),
                tenant_id=UUID(str(row.tenant_id)),
                next_due_at=next_due,
            )
        await session.commit()
    logger.info("rotation_scheduler.reconcile_complete", count=len(rows))
```

### `_process_credential`

```python
async def _process_credential(self, item: ScheduleItem) -> None:
    try:
        # Load what we need for due-check (pre-flight)
        async with self._session_factory() as session:
            version_repo = PgCredentialVersionRepository(session)
            policy_repo = PgRotationPolicyRepository(session)
            cred_repo = PgCredentialRepository(session)

            credential = await cred_repo.get_by_id(
                CredentialId(item.credential_id), TenantId(item.tenant_id)
            )
            if credential.rotation_policy_id is None:
                await self._schedule_repo.delete(item.credential_id, item.tenant_id)
                return
            policy = await policy_repo.get_by_id(
                credential.rotation_policy_id, TenantId(item.tenant_id)
            )
            if not policy.auto_rotate or policy.interval_days is None:
                await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)
                return
            active_version = await version_repo.get_active_version(
                CredentialId(item.credential_id), TenantId(item.tenant_id)
            )

        # Due check (pure domain logic — no I/O)
        now = datetime.now(UTC)
        if not self._rotation_planner.is_rotation_due(credential, policy, active_version.created_at, now):
            next_due = self._rotation_planner.next_rotation_at(active_version.created_at, policy)
            await self._schedule_repo.update_after_rotation(item.credential_id, item.tenant_id, next_due)
            return

        # Generate new secret
        new_secret = os.urandom(active_version.key_envelope is not None and 32 or 32)
        # Always 32 bytes for AES-256 compatibility

        # Trigger rotation
        rotate_cmd = RotateCredentialCommand(
            tenant_id=item.tenant_id,
            credential_id=item.credential_id,
            principal_id=self._system_principal_id,
            new_plaintext_secret=new_secret,
            trigger="SCHEDULED",
            policy_id=credential.rotation_policy_id.value if credential.rotation_policy_id else None,
            notes=f"Scheduled rotation by {self.worker_id}",
        )
        await self._cred_svc.rotate_credential(rotate_cmd)

        if policy.auto_commit:
            commit_cmd = CommitRotationCommand(
                tenant_id=item.tenant_id,
                credential_id=item.credential_id,
                principal_id=self._system_principal_id,
            )
            await self._cred_svc.commit_rotation(commit_cmd)

        # Update schedule state
        next_due = now + timedelta(days=policy.interval_days)
        await self._schedule_repo.update_after_rotation(item.credential_id, item.tenant_id, next_due)
        self._rotated += 1
        logger.info("rotation_scheduler.credential_rotated",
                    credential_id=str(item.credential_id),
                    auto_commit=policy.auto_commit)

    except ConcurrentRotationConflict:
        logger.warning("rotation_scheduler.concurrent_rotation_conflict",
                       credential_id=str(item.credential_id))
        await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)
        self._failed += 1
    except CredentialNotFound:
        logger.warning("rotation_scheduler.credential_not_found",
                       credential_id=str(item.credential_id))
        await self._schedule_repo.delete(item.credential_id, item.tenant_id)
    except Exception as exc:
        logger.warning("rotation_scheduler.credential_rotation_failed",
                       credential_id=str(item.credential_id), error=str(exc))
        await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)
        self._failed += 1
    finally:
        # Always zero the new_secret from memory
        if 'new_secret' in dir():
            # new_secret is bytes (immutable) — cannot zero
            pass
        # Note: zeroization happens inside AesGcmEncryptionAdapter.encrypt()
```

### Validation checklist

```bash
mypy src/credential_vault/workers/rotation_scheduler/ --strict
ruff check src/credential_vault/workers/rotation_scheduler/
pytest tests/credential_vault/workers/test_rotation_scheduler_worker.py -x -m integration -v
```

### Exit criteria
All 10 rotation scheduler tests pass. SKIP LOCKED test verifies no duplicate rotation.

---

## Phase 4: Expiration Scanner Worker

### Files to create (1)

`workers/expiration_scanner/expiration_scanner_worker.py`

### Key implementation details

The expiration scanner follows the same `_poll_loop` → `_run_cycle` → `_process_credential` pattern as the rotation scheduler.

```python
async def _process_credential(self, item: ScheduleItem) -> None:
    async with self._session_factory() as session:
        cred_repo = PgCredentialRepository(session)
        version_repo = PgCredentialVersionRepository(session)
        policy_repo = PgExpirationPolicyRepository(session)

        credential = await cred_repo.get_by_id(
            CredentialId(item.credential_id), TenantId(item.tenant_id)
        )
        if credential.state != CredentialState.ACTIVE:
            await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)
            return

        active_version = await version_repo.get_active_version(
            CredentialId(item.credential_id), TenantId(item.tenant_id)
        )
        policy = None
        if credential.expiration_policy_id is not None:
            policy = await policy_repo.get_by_id(
                credential.expiration_policy_id, TenantId(item.tenant_id)
            )

    now = datetime.now(UTC)
    if self._policy_evaluator.is_version_expired(active_version, policy, now):
        expire_cmd = ExpireCredentialCommand(
            tenant_id=item.tenant_id,
            credential_id=item.credential_id,
            principal_id=self._system_principal_id,
        )
        await self._cred_svc.expire_credential(expire_cmd)
        logger.info("expiration_scanner.credential_expired",
                    credential_id=str(item.credential_id))
    elif policy and self._policy_evaluator.should_warn_expiration(active_version, policy, now):
        expiry = active_version.expires_at or self._policy_evaluator.compute_version_expiry(
            active_version.created_at, policy
        )
        days_remaining = (expiry - now).days
        event = CredentialExpirationWarning(
            credential_id=CredentialId(item.credential_id),
            tenant_id=TenantId(item.tenant_id),
            version_id=active_version.version_id,
            days_until_expiry=days_remaining,
            expiry_at=expiry,
        )
        await self._event_publisher.publish_batch([event])
        logger.info("expiration_scanner.warning_emitted",
                    credential_id=str(item.credential_id),
                    days_remaining=days_remaining)

    next_scan = now + timedelta(seconds=self._poll_interval_s * 10)
    await self._schedule_repo.update_after_scan(
        item.credential_id, item.tenant_id, next_scan
    )
```

**`ExpireCredentialCommand`** — verify this command exists in `credential_commands.py` from M25B. If it doesn't exist (check the commands file), add it: `@dataclass(frozen=True, slots=True)` with `tenant_id, credential_id, principal_id`.

### Validation checklist

```bash
mypy src/credential_vault/workers/expiration_scanner/ --strict
pytest tests/credential_vault/workers/test_expiration_scanner_worker.py -x -m integration -v
```

---

## Phase 5: Version Pruner Worker

### Files to create (1)

`workers/version_pruner/version_pruner_worker.py`

### Key implementation — `_run_cycle`

```python
async def _run_cycle(self) -> None:
    candidates = await self._pruner_repo.find_credentials_exceeding_max_versions(self._batch_size)
    if not candidates:
        return

    for candidate in candidates:
        to_prune = candidate.superseded_count - candidate.max_versions_kept
        if to_prune <= 0:
            continue

        all_superseded = await self._pruner_repo.get_superseded_version_ids(
            candidate.credential_id, candidate.tenant_id
        )
        # oldest first (query orders by version_number ASC)
        to_delete = all_superseded[:to_prune]

        if not to_delete:
            continue

        deleted = await self._pruner_repo.delete_superseded_versions(
            to_delete, candidate.tenant_id
        )

        logger.info("version_pruner.versions_deleted",
                    credential_id=str(candidate.credential_id),
                    deleted=deleted,
                    max_kept=candidate.max_versions_kept)

        # Publish domain event
        event = CredentialVersionsPruned(
            credential_id=CredentialId(candidate.credential_id),
            tenant_id=TenantId(candidate.tenant_id),
            pruned_count=deleted,
            remaining_superseded=candidate.superseded_count - deleted,
        )
        await self._event_publisher.publish_batch([event])
        self._deleted_total += deleted
```

**Critical:** Never delete `to_delete = all_superseded` without taking only `[:to_prune]`. Always verify `to_prune > 0`.

### Validation checklist

```bash
mypy src/credential_vault/workers/version_pruner/ --strict
pytest tests/credential_vault/workers/test_version_pruner_worker.py -x -m integration -v
```

---

## Phase 6: DEK Rewrap Worker

### Files to create (1)

`workers/dek_rewrap/dek_rewrap_worker.py`

### Key implementation — `_run_cycle`

```python
async def _run_cycle(self) -> None:
    if not self._rewrap_authorized:
        return

    # Fetch batch of versions needing rewrap
    async with self._session_factory() as session:
        result = await session.execute(
            text("""
                SELECT v.id, v.tenant_id, v.wrapped_dek, v.master_key_id,
                       v.wrapping_algorithm, v.key_created_at, v.row_version
                FROM credential_vault_versions v
                LEFT JOIN credential_vault_dek_rewrap_progress p ON p.version_id = v.id
                WHERE v.master_key_id != :target_key_id
                  AND (p.rewrapped_at IS NULL OR p.version_id IS NULL)
                ORDER BY v.created_at ASC
                LIMIT :n
            """),
            {"target_key_id": self._target_master_key_id, "n": self._batch_size},
        )
        rows = result.all()

    if not rows:
        logger.info("dek_rewrap.complete", worker_id=self.worker_id)
        self._running = False  # exit when done
        return

    for row in rows:
        await asyncio.sleep(self._rate_limit_delay_ms / 1000.0)
        await self._rewrap_one(row)

async def _rewrap_one(self, row: Any) -> None:
    old_envelope = KeyEnvelope(
        wrapped_dek=row.wrapped_dek,
        master_key_id=row.master_key_id,
        wrapping_algorithm=row.wrapping_algorithm,
        created_at=row.key_created_at,
    )
    try:
        new_envelope = await self._kms_adapter.rewrap_dek(old_envelope, self._target_master_key_id)
    except Exception as exc:
        logger.warning("dek_rewrap.version_rewrap_failed",
                       version_id=str(row.id), error=str(exc))
        await self._progress_repo.record_error(UUID(str(row.id)), str(exc))
        return

    async with self._session_factory() as session:
        result = await session.execute(
            text("""
                UPDATE credential_vault_versions
                SET wrapped_dek = :new_wrapped, master_key_id = :new_key_id,
                    wrapping_algorithm = :new_algo, key_created_at = :new_at,
                    row_version = row_version + 1
                WHERE id = :vid AND row_version = :expected_ver
            """),
            {
                "new_wrapped": new_envelope.wrapped_dek,
                "new_key_id": new_envelope.master_key_id,
                "new_algo": new_envelope.wrapping_algorithm,
                "new_at": new_envelope.created_at,
                "vid": row.id,
                "expected_ver": row.row_version,
            },
        )
        if result.rowcount == 0:
            logger.warning("dek_rewrap.optimistic_lock_conflict", version_id=str(row.id))
            await session.rollback()
            return
        await session.commit()

    await self._progress_repo.record_success(UUID(str(row.id)), row.master_key_id, self._target_master_key_id)
    logger.info("dek_rewrap.version_rewrapped", version_id=str(row.id))
    self._rewrapped_total += 1
```

### Guard against unauthorized activation

```python
def __init__(self, ...) -> None:
    self._rewrap_authorized = (
        os.environ.get("CREDENTIAL_VAULT_REWRAP_AUTHORIZED", "false").lower() == "true"
        and bool(target_master_key_id)
    )
    if not self._rewrap_authorized:
        logger.warning("dek_rewrap.not_authorized_skipping_activation")
```

### Validation checklist

```bash
mypy src/credential_vault/workers/dek_rewrap/ --strict
pytest tests/credential_vault/workers/test_dek_rewrap_worker.py -x -m integration -v
```

---

## Phase 7: Worker Host and Wiring

### Files to create (1)

`workers/host.py`

### Container integration

Update `CredentialVaultContainer` (M25C) to build and return a `CredentialVaultWorkerHost`:

```python
# In CredentialVaultContainer.__init__():
self._session_factory = session_factory
self._worker_host: CredentialVaultWorkerHost | None = None

def build_worker_host(self, system_principal_id: uuid.UUID) -> CredentialVaultWorkerHost:
    """Call once at application startup to wire workers."""
    schedule_repo = RotationScheduleRepository(self._session_factory)
    expiration_repo = ExpirationScheduleRepository(self._session_factory)
    pruner_repo = VersionPrunerRepository(self._session_factory)
    rewrap_repo = DekRewrapProgressRepository(self._session_factory)
    target_key_id = os.environ.get("CREDENTIAL_VAULT_REWRAP_MASTER_KEY_ID")

    rotation_worker = RotationSchedulerWorker(
        credential_service=self.credential_service,
        schedule_repo=schedule_repo,
        rotation_planner=RotationPlannerService(),
        session_factory=self._session_factory,
        system_principal_id=system_principal_id,
        poll_interval_s=float(os.environ.get("CREDENTIAL_VAULT_ROTATION_POLL_S", "60")),
        batch_size=int(os.environ.get("CREDENTIAL_VAULT_ROTATION_BATCH_SIZE", "10")),
        max_concurrent=int(os.environ.get("CREDENTIAL_VAULT_ROTATION_MAX_CONCURRENT", "3")),
    )
    expiration_worker = ExpirationScannerWorker(
        credential_service=self.credential_service,
        schedule_repo=expiration_repo,
        policy_evaluator=PolicyEvaluatorService(),
        event_publisher=event_publisher,
        session_factory=self._session_factory,
        system_principal_id=system_principal_id,
        poll_interval_s=float(os.environ.get("CREDENTIAL_VAULT_EXPIRATION_POLL_S", "300")),
        batch_size=int(os.environ.get("CREDENTIAL_VAULT_EXPIRATION_BATCH_SIZE", "20")),
    )
    pruner_worker = VersionPrunerWorker(
        pruner_repo=pruner_repo,
        event_publisher=event_publisher,
        session_factory=self._session_factory,
        poll_interval_s=float(os.environ.get("CREDENTIAL_VAULT_PRUNER_POLL_S", "3600")),
        batch_size=int(os.environ.get("CREDENTIAL_VAULT_PRUNER_BATCH_SIZE", "50")),
    )
    rewrap_worker = None
    if target_key_id:
        rewrap_worker = DekRewrapWorker(
            kms_adapter=self.kms_adapter,
            rewrap_repo=rewrap_repo,
            session_factory=self._session_factory,
            target_master_key_id=target_key_id,
            rate_limit_delay_ms=int(os.environ.get("CREDENTIAL_VAULT_REWRAP_RATE_LIMIT_MS", "50")),
        )

    self._worker_host = CredentialVaultWorkerHost(
        rotation_worker=rotation_worker,
        expiration_worker=expiration_worker,
        pruner_worker=pruner_worker,
        rewrap_worker=rewrap_worker,
    )
    return self._worker_host
```

### FastAPI lifespan registration

In `redforge/main.py` or wherever the FastAPI app lifespan is defined:

```python
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # ... existing startup ...
    # Credential vault workers
    cv_container = app.state.cv_container
    system_principal_id = UUID(os.environ["CREDENTIAL_VAULT_SYSTEM_PRINCIPAL_ID"])
    if os.environ.get("CREDENTIAL_VAULT_WORKERS_ENABLED", "true").lower() == "true":
        worker_host = cv_container.build_worker_host(system_principal_id)
        await worker_host.start()
        app.state.cv_worker_host = worker_host

    yield

    # Shutdown
    if hasattr(app.state, "cv_worker_host"):
        await app.state.cv_worker_host.stop()
    # ... existing shutdown ...
```

### Validation checklist

```bash
mypy src/credential_vault/workers/ --strict
ruff check src/credential_vault/workers/
pytest tests/credential_vault/workers/ -x -m integration -v
```

---

## Phase 8: Final Integration

### Full validation suite

```bash
# 1. Format
ruff format --check src/credential_vault/

# 2. Lint
ruff check src/credential_vault/

# 3. Type check — full bounded context
mypy src/credential_vault/ --strict

# 4. Verify only approved domain changes
git diff --name-only src/credential_vault/domain/
# Expected: events/credential_events.py, aggregates/rotation_policy.py,
#           repositories/i_credential_repository.py, exceptions/domain_exceptions.py
# (Plus M25C additions: same four files)

# 5. Application changes — only approved additions
git diff --name-only src/credential_vault/application/
# Expected: commands/credential_commands.py, commands/policy_commands.py,
#           dtos/policy_dtos.py

# 6. No infrastructure imports in domain or application
grep -rn "sqlalchemy\|asyncpg\|cryptography\|boto3\|fastapi" src/credential_vault/domain/ && exit 1 || echo "OK"

# 7. All unit tests
pytest tests/credential_vault/ -x --ignore=tests/credential_vault/infrastructure/ --ignore=tests/credential_vault/workers/ -v

# 8. All infrastructure integration tests
pytest tests/credential_vault/infrastructure/ -x -m integration -v

# 9. All worker integration tests
pytest tests/credential_vault/workers/ -x -m integration -v

# 10. All API tests
pytest tests/credential_vault/api/ -x -v

# 11. Migration round-trip
alembic upgrade 0045
alembic downgrade 0044
alembic upgrade 0045
echo "Migration 0045 OK"

# 12. No plaintext secrets in structlog
grep -rn "plaintext\|dek\|secret.*log\|log.*secret" src/credential_vault/workers/ && echo "REVIEW LOGGING" || echo "OK"
```

---

# 4. Final Completion Checklist

## Pre-implementation domain extensions
- [ ] `CredentialRotationScheduled` event added to `credential_events.py`
- [ ] `CredentialExpirationWarning` event added to `credential_events.py`
- [ ] `CredentialVersionsPruned` event added to `credential_events.py`
- [ ] `DekRewrapCompleted` event added to `credential_events.py`
- [ ] `auto_commit` and `commit_window_hours` added to `RotationPolicy.__slots__` and `__init__`
- [ ] `RotationPolicy.create()` updated with new fields
- [ ] `RotationPolicyDTO` includes `auto_commit` and `commit_window_hours`
- [ ] `CreateRotationPolicyCommand` and `UpdateRotationPolicyCommand` include new fields
- [ ] `list_with_active_rotation_policy` abstract method on `ICredentialRepository`
- [ ] All pre-implementation changes pass `mypy --strict` + pytest

## Migration `0045`
- [ ] `auto_commit BOOLEAN NOT NULL DEFAULT TRUE` added to `credential_vault_rotation_policies`
- [ ] `commit_window_hours INTEGER NOT NULL DEFAULT 24` added
- [ ] `credential_vault_rotation_schedule_state` created with SKIP LOCKED index
- [ ] `credential_vault_expiration_schedule_state` created
- [ ] `credential_vault_dek_rewrap_progress` created
- [ ] Migration round-trip passes

## Schedule repositories
- [ ] `RotationScheduleRepository.claim_batch` uses `SELECT FOR UPDATE SKIP LOCKED`
- [ ] Claims released in all error paths
- [ ] `claim_expires_at` set to `NOW() + INTERVAL '10 minutes'`
- [ ] `VersionPrunerRepository.delete_superseded_versions` filters `AND version_state = 'SUPERSEDED'`
- [ ] `ScheduleItem` and `PruneCandidate` are frozen dataclasses (not domain types)

## Rotation scheduler worker
- [ ] `_reconcile_schedule_state` runs at `start()` before `_poll_loop`
- [ ] SKIP LOCKED prevents double-rotation in concurrent worker scenario
- [ ] `auto_commit=True`: both `rotate_credential` and `commit_rotation` called
- [ ] `auto_commit=False`: only `rotate_credential` called
- [ ] `ConcurrentRotationConflict` releases claim and continues
- [ ] `CredentialNotFound` deletes schedule state entry
- [ ] New plaintext secret generated with `os.urandom(32)` — not logged

## Expiration scanner worker
- [ ] Only ACTIVE credentials are evaluated
- [ ] Already-EXPIRED credentials skipped (domain raises `InvalidStateTransition`)
- [ ] `CredentialExpirationWarning` event published before expiry (not after)
- [ ] `PolicyEvaluatorService.is_version_expired` used (not manual date comparison)

## Version pruner worker
- [ ] Only SUPERSEDED versions are deleted
- [ ] Delete query includes `AND version_state = 'SUPERSEDED'` guard
- [ ] Oldest versions deleted first (version_number ASC)
- [ ] `CredentialVersionsPruned` event published after deletion
- [ ] `to_prune` correctly computed as `superseded_count - max_versions_kept`

## DEK rewrap worker
- [ ] Activation requires both `CREDENTIAL_VAULT_REWRAP_AUTHORIZED=true` AND `CREDENTIAL_VAULT_REWRAP_MASTER_KEY_ID` set
- [ ] Rate limit delay (`asyncio.sleep`) applied between versions
- [ ] Optimistic lock check: `rowcount == 0` → skip, log, continue
- [ ] `rewrapped_at IS NOT NULL` entries skipped
- [ ] Worker sets `_running = False` when no more versions need rewrap
- [ ] No key material logged

## Worker host
- [ ] `start()` starts all configured workers
- [ ] `stop()` stops all workers in reverse order
- [ ] `is_healthy` returns `False` if any worker is not running
- [ ] `rewrap_worker` is `None` when `CREDENTIAL_VAULT_REWRAP_MASTER_KEY_ID` unset
- [ ] Registered with FastAPI lifespan (start on startup, stop on shutdown)

## Tests
- [ ] All 10 rotation scheduler tests pass
- [ ] All 5 expiration scanner tests pass
- [ ] All 6 version pruner tests pass
- [ ] All 5 DEK rewrap tests pass
- [ ] All 4 worker host tests pass
- [ ] SKIP LOCKED concurrency test passes

## Final static analysis
- [ ] `mypy src/credential_vault/ --strict` → 0 errors
- [ ] `ruff check src/credential_vault/` → 0 violations
- [ ] `ruff format --check src/credential_vault/` → 0 violations
- [ ] `grep -rn "plaintext\|secret" logs in workers/` — no secrets logged
- [ ] M25 complete: domain frozen, application frozen, infrastructure wired, workers running
