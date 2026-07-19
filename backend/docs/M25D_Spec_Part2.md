# M25D Implementation Specification — Part 2
## Enterprise Credential Vault: Background Workers & Operational Automation
### Version 1.0 FROZEN | Sections 13–22

---

## §13. Domain Additive Extensions Required by M25D

The following are additive changes to existing M25A/M25B files. They do not alter any existing behavior.

### 13.1 New domain events (add to `credential_events.py`)

Four new `@dataclass(frozen=True, slots=True)` event classes:
- `CredentialRotationScheduled`
- `CredentialExpirationWarning`
- `CredentialVersionsPruned`
- `DekRewrapCompleted`

See §7 in Part 1 for field definitions.

### 13.2 `RotationPolicy` — new fields

Add to `RotationPolicy.__slots__`:
```python
"auto_commit",          # bool — commit immediately after rotate
"commit_window_hours",  # int — hours allowed for manual commit
```

Add to `RotationPolicy.__init__`:
```python
self.auto_commit: bool = auto_commit
self.commit_window_hours: int = commit_window_hours
```

Default `auto_commit=True`, `commit_window_hours=24`.

Update `RotationPolicy.create()` classmethod to accept the new fields with defaults.

Update `RotationPolicyDTO.from_aggregate()` to include the new fields.

Update `CreateRotationPolicyCommand` and `UpdateRotationPolicyCommand` to include them.

### 13.3 `ICredentialRepository` — new method

Add `list_with_active_rotation_policy(tenant_id: TenantId, limit: int, offset: int) -> list[Credential]` as an abstract method. Used by the rotation scheduler reconciliation to populate `rotation_schedule_state`. Only returns credentials where `rotation_policy_id IS NOT NULL AND state = 'ACTIVE'`.

### 13.4 Verification before implementing

```bash
mypy src/credential_vault/domain/ --strict
pytest tests/credential_vault/domain/ -x
```

Both must pass after the additive changes before M25D implementation begins.

---

## §14. Integration with Application Services

Workers interact with the application layer exclusively through command objects. They never construct aggregates directly.

### Commands issued by workers

| Worker | Command(s) issued |
|---|---|
| `RotationSchedulerWorker` | `RotateCredentialCommand(trigger="SCHEDULED")`, optionally `CommitRotationCommand` |
| `ExpirationScannerWorker` | `ExpireCredentialCommand` |
| `VersionPrunerWorker` | None — uses infrastructure repository directly |
| `DekRewrapWorker` | None — updates ORM model directly via session |

### System principal authorization

The `system_principal_id` must have `PERMISSION_ROTATE` (for rotation worker) and `PERMISSION_WRITE` (for expiration worker) granted in the RBAC system. The startup validator checks:
```python
allowed = await permission_adapter.has_permission(
    PrincipalId(system_principal_id), SYNTHETIC_CREDENTIAL_ID, PERMISSION_ROTATE, SYNTHETIC_TENANT_ID
)
```
If `False`, log a WARNING. In production mode, block worker startup.

### UoW factory sharing

Workers receive the same `Callable[[], IUnitOfWork]` factory used by the application services. Each triggered operation opens a fresh UoW. Workers do not hold long-lived UoW instances.

---

## §15. Testing Strategy

### Test environment

All worker integration tests run against a real PostgreSQL test database (same `TEST_DATABASE_URL` as M25C tests). The test database must have migrations `0044` and `0045` applied before the worker test suite runs.

### Worker test conftest

```python
# tests/credential_vault/workers/conftest.py

@pytest_asyncio.fixture
async def seeded_credential(pg_uow, make_credential_factory):
    """Returns a persisted ACTIVE credential with rotation policy attached."""
    ...

@pytest_asyncio.fixture
async def rotation_scheduler_worker(pg_engine, credential_service):
    worker = RotationSchedulerWorker(
        credential_service=credential_service,
        schedule_repo=RotationScheduleRepository(pg_engine),
        rotation_planner=RotationPlannerService(),
        ...
        poll_interval_s=0.1,   # fast polling for tests
        batch_size=5,
    )
    return worker
```

### Required test cases per worker

**`test_rotation_scheduler_worker.py`**:
- `test_rotation_triggered_when_due` — Seed a credential with interval_days=1; set version.created_at to 2 days ago. Run one cycle. Verify credential.state == ROTATING (or ACTIVE if auto_commit=True).
- `test_rotation_not_triggered_when_not_due` — Same but version.created_at = 30 minutes ago. Verify no rotation.
- `test_rotation_auto_commit_true` — Verify commit_rotation called after rotate_credential when auto_commit=True.
- `test_rotation_auto_commit_false` — Verify only rotate_credential called; credential left in ROTATING state.
- `test_claim_released_after_success` — After rotation, claimed_at IS NULL.
- `test_claim_released_after_failure` — After ConcurrentRotationConflict, claimed_at IS NULL.
- `test_skip_locked_concurrency` — Two workers running concurrently on same claimed credential; exactly one succeeds.
- `test_stale_claim_reclaimed_after_expiry` — Set claim_expires_at = 5 minutes ago. Worker claims the item.
- `test_reconciliation_populates_schedule_state` — Start worker with credential that has no schedule entry; verify reconciliation inserts it.
- `test_worker_start_stop` — verify `is_running` True after start, False after stop.

**`test_expiration_scanner_worker.py`**:
- `test_expired_credential_gets_expired` — version.expires_at = 1 hour ago; one cycle; credential.state == EXPIRED.
- `test_not_expired_credential_skipped`
- `test_hard_expire_policy_triggers_expiration` — policy.hard_expire=True, policy.ttl_days=1; version.created_at = 2 days ago.
- `test_warning_event_emitted_before_expiry` — version.expires_at = 3 days from now, policy.warn_days_before=7; verify CredentialExpirationWarning published.
- `test_already_expired_credential_skipped` — credential.state == EXPIRED; no second expire_credential call.

**`test_version_pruner_worker.py`**:
- `test_superseded_versions_pruned_to_max` — Create credential with 5 SUPERSEDED versions, max_versions_kept=2. Run pruner. Verify 3 deleted, 2 remain.
- `test_active_version_not_pruned` — Active version must not be deleted regardless of max_versions_kept.
- `test_pending_version_not_pruned` — PENDING version must not be deleted.
- `test_revoked_version_not_pruned_by_pruner` — REVOKED versions are not pruned (only SUPERSEDED).
- `test_pruner_does_not_prune_below_max` — If count <= max_versions_kept, nothing deleted.
- `test_oldest_superseded_deleted_first` — Verify version_number ordering; oldest versions deleted first.

**`test_dek_rewrap_worker.py`**:
- `test_rewrap_updates_master_key_id` — After rewrap, version.master_key_id == new_master_key_id.
- `test_rewrapped_version_decryptable_with_new_key` — Decrypt after rewrap; plaintext unchanged.
- `test_already_rewrapped_versions_skipped` — Set rewrapped_at; verify version not processed again.
- `test_rate_limit_delay_applied` — Verify asyncio.sleep called between versions.
- `test_worker_exits_when_no_versions_remain` — Worker marks itself done when all versions rewrapped.

**`test_worker_host.py`**:
- `test_all_workers_start` — start() launches all workers; is_healthy == True.
- `test_stop_stops_all_workers` — stop() terminates all; is_running == False for each.
- `test_stats_returns_per_worker_stats`
- `test_rewrap_worker_absent_when_not_configured`

---

## §16. Data Flow Diagrams

### Rotation Scheduler Data Flow

```
@startuml
participant "RotationSchedulerWorker" as W
participant "rotation_schedule_state" as SS
participant "CredentialApplicationService" as SVC
database "PostgreSQL" as PG

W -> SS : claim_batch(SKIP LOCKED)
SS --> W : [ScheduleItem list]
loop per ScheduleItem
    W -> PG : load credential, version, policy
    W -> W : RotationPlannerService.is_rotation_due(...)
    alt due
        W -> SVC : rotate_credential(cmd)
        SVC -> PG : UoW open → save version + credential → audit → commit
        SVC --> W : CredentialDTO
        alt auto_commit
            W -> SVC : commit_rotation(cmd)
            SVC -> PG : atomic_promote → audit → commit
        end
        W -> SS : update next_due_at, release claim
    else not due
        W -> SS : update last_checked_at, release claim
    end
end
@enduml
```

### Expiration Scanner Data Flow

```
@startuml
participant "ExpirationScannerWorker" as W
participant "expiration_schedule_state" as SS
participant "PolicyEvaluatorService" as PE
participant "CredentialApplicationService" as SVC
participant "IEventPublisher" as PUB

W -> SS : claim_batch(SKIP LOCKED)
loop per item
    W -> PE : is_version_expired(version, policy, now)
    alt expired
        W -> SVC : expire_credential(cmd)
    else should_warn
        W -> PUB : publish_batch([CredentialExpirationWarning])
    end
    W -> SS : update next_scan_at, release claim
end
@enduml
```

---

## §17. Error Handling

### Worker error isolation

All worker cycle exceptions are caught at the `_poll_loop` level. A failing cycle logs a WARNING and resumes after `poll_interval_s`. Individual credential failures within a cycle are caught at the item level — one failed credential does not abort the cycle.

### Non-retriable errors

- `CredentialNotFound` — claim is released; schedule entry is deleted (credential no longer exists).
- `EncryptionAuthTagFailure` — during DEK rewrap: mark `error` column in progress table; skip; continue.
- `KmsKeyNotFound` — during DEK rewrap: stop the rewrap worker entirely (cannot proceed without KMS key).

### Retriable errors (implicit on next cycle)

- `ConcurrentRotationConflict` — credential already in ROTATING state; release claim; re-check on next cycle.
- `OptimisticLockConflict` — release claim; re-check on next cycle.
- `ApplicationPortError` — log WARNING; release claim.
- Database connectivity errors — caught by `_poll_loop`; entire cycle fails; backoff and retry.

### Exponential backoff

`_poll_loop` tracks consecutive failures. On N consecutive failures, sleep `min(poll_interval_s * (2 ** N), max_backoff_s)` where `max_backoff_s = 600`. Reset on any success.

---

## §18. Quality Gates

| Gate | Command | Requirement |
|---|---|---|
| Format | `ruff format --check src/credential_vault/workers/` | Zero violations |
| Lint | `ruff check src/credential_vault/workers/` | Zero violations |
| Type | `mypy src/credential_vault/workers/ --strict` | Zero errors |
| Domain integrity | `git diff --exit-code src/credential_vault/domain/` | Only M25D-approved additions |
| Application integrity | `git diff --exit-code src/credential_vault/application/` | Only command/DTO field additions |
| Unit tests | `pytest tests/credential_vault/workers/ -x --ignore tests/credential_vault/workers/test_*_integration*` | All pass |
| Integration tests | `pytest tests/credential_vault/workers/ -x -m integration` | All pass |
| Migration | `alembic upgrade 0045 && alembic downgrade 0044 && alembic upgrade 0045` | No error |

---

## §19. Acceptance Criteria

1. `RotationSchedulerWorker` triggers `rotate_credential` within one poll cycle for any credential with `next_due_at <= NOW()`.
2. `RotationSchedulerWorker` with `auto_commit=True` completes the full rotation (ACTIVE → ROTATING → ACTIVE) in a single poll cycle.
3. Two concurrent `RotationSchedulerWorker` instances never rotate the same credential in the same cycle. Verified by the SKIP LOCKED concurrency test.
4. A stale claim (claim_expires_at in the past) is re-claimable by any worker on the next cycle.
5. `ExpirationScannerWorker` transitions credentials to EXPIRED state within one poll cycle of `expires_at` passing.
6. `ExpirationScannerWorker` emits `CredentialExpirationWarning` events for credentials within `warn_days_before` of expiry. Events are published via `IEventPublisher`.
7. `VersionPrunerWorker` leaves exactly `max_versions_kept` SUPERSEDED versions after each pruner cycle for any credential that exceeds the cap.
8. `VersionPrunerWorker` never deletes ACTIVE, PENDING, or REVOKED versions.
9. `DekRewrapWorker` produces a valid decrypt-then-compare round-trip after rewrap: `decrypt(rewrapped_version) == original_plaintext`.
10. `DekRewrapWorker` records `rewrapped_at` in the progress table; re-running the worker after completion processes zero versions.
11. `CredentialVaultWorkerHost.is_healthy` returns `True` when all workers are running; `False` when any worker has stopped.
12. All four workers handle asyncio cancellation cleanly — no hanging tasks after `stop()`.
13. No plaintext secret, DEK byte, or key material appears in any structlog event from any worker.
14. Migration `0045` upgrade and downgrade passes round-trip on test PostgreSQL.
15. All new files pass `mypy --strict` with zero errors.

---

## §20. Traceability Matrix

| M25D Deliverable | Spec Reference | Test Coverage |
|---|---|---|
| `RotationSchedulerWorker` | §5.1, §9 | `test_rotation_scheduler_worker.py` (10 tests) |
| `ExpirationScannerWorker` | §5.2, §9 | `test_expiration_scanner_worker.py` (5 tests) |
| `VersionPrunerWorker` | §5.3 | `test_version_pruner_worker.py` (6 tests) |
| `DekRewrapWorker` | §5.4 | `test_dek_rewrap_worker.py` (5 tests) |
| `CredentialVaultWorkerHost` | §5.5 | `test_worker_host.py` (4 tests) |
| Migration `0045` | §8 | Migration round-trip test |
| `RotationPolicy.auto_commit` | §13.2 | Rotation worker tests |
| New domain events | §13.1 | Expiration warning test |
| SKIP LOCKED concurrency | §11 | `test_skip_locked_concurrency` |
| Stale claim recovery | §9 | `test_stale_claim_reclaimed_after_expiry` |
| DEK zeroization in rotation | §9, §3 | Rotation worker + `AesGcmEncryptionAdapter` |

---

## §21. Risks and Mitigations

### R1 — `RotationPolicy.auto_commit` field addition changes `RotationPolicy.create()` signature

**Risk:** Existing test fixtures constructing `RotationPolicy` directly may fail.

**Mitigation:** Add `auto_commit: bool = True, commit_window_hours: int = 24` as keyword-only parameters with defaults to `create()`. All existing callers are unaffected.

### R2 — Scheduled rotation secret length is policy-independent

**Risk:** For structured credentials (API keys, database passwords), generating `os.urandom(32)` may produce invalid secrets.

**Mitigation:** M25D generates a generic random secret. Secret format validation is out of scope. Operator documentation notes that CUSTOM category credentials requiring specific formats should set `auto_rotate=False` and use manual rotation. This is an architectural limitation of M25; post-M25 work can introduce `ISecretGeneratorPort`.

### R3 — `system_principal_id` must be pre-provisioned in RBAC

**Risk:** The system service account may not exist or may not have ROTATE/WRITE permissions in the RBAC system.

**Mitigation:** Startup validator checks and logs WARNING. Provide a migration or admin script to create the service account with correct permissions. Document in operator runbook.

### R4 — DEK rewrap is a write-heavy operation at scale

**Risk:** At 50ms rate-limit per version, rewrapping 100,000 versions takes ~83 minutes. This may be too slow for large tenants.

**Mitigation:** `CREDENTIAL_VAULT_REWRAP_RATE_LIMIT_MS` is configurable down to 0 (no delay). For large-scale rewrap, operators can increase batch_size and decrease delay. Parallelism via multiple `DekRewrapWorker` instances is out of scope for M25.

### R5 — `VersionPrunerWorker` bypasses the domain aggregate

**Risk:** Direct SQL DELETE without going through `CredentialApplicationService` means no domain event is emitted via `pop_events()`.

**Mitigation:** The worker publishes `CredentialVersionsPruned` directly via `IEventPublisher` after deletion. The event is constructed manually in the worker, not via aggregate. This is architecturally acceptable for operational cleanup operations that have no aggregate-level semantic.

---

## §22. Out of Scope

1. Multi-region credential replication.
2. Secret format-specific generators (API key format, password complexity rules).
3. Approval workflow for automated rotation (break-glass for system-initiated operations).
4. Cross-tenant rotation campaigns.
5. Rotation dry-run mode.
6. Notification delivery (email, Slack, PagerDuty) for expiration warnings — `CredentialExpirationWarning` events may be consumed by notification adapters in post-M25 work.
7. Celery task queue integration.
8. Priority scheduling (urgent rotation ahead of schedule).
9. Pause/resume of individual workers via API.
10. Rotation history reporting API (audit trail is in audit_entries; no separate report in M25).
