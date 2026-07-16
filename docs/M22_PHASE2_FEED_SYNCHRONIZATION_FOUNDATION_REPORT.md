# M22 Phase 2 — Feed Synchronization Foundation: Implementation Report

**Status**: COMPLETE (Phase 2 of 7 only — Phases 3-7 explicitly out of scope, not started)
**Date**: 2026-07-16
**Migration head**: `0036` (was `0035`)
**Commit status**: NOT COMMITTED, NOT PUSHED — awaiting review per explicit instruction.

---

## 1. Scope

This phase implements the **feed synchronization platform** for M22 Threat Intelligence — the
generic, provider-agnostic machinery that will let STIX/TAXII (and other) feed connectors plug in
during Phase 3 without any change to core synchronization logic. Per the explicit instruction, this
phase does **not** implement any real feed provider, parser, or client.

**Implemented** (per the approved brief):

- Migration `0036` — 2 tables (`feeds`, `feed_sync_runs`), schema-only, no data seeding.
- Domain layer — value objects (`FeedKey`, `SyncSchedule`, `RetryPolicy`), two aggregate roots
  (`Feed`, `FeedSyncRun`), domain events, repository interfaces, domain exceptions.
- Infrastructure layer — SQLAlchemy ORM models, concrete repositories, ORM↔domain mappers,
  PostgreSQL advisory-lock-backed concurrency control.
- Application layer — `FeedAdminService` (registration/lifecycle/configuration),
  `FeedQueryService` (read-only), `FeedSyncOrchestrationService` (the actual synchronization
  execution model: retry/backoff, locking, idempotent checkpoint advancement), a background
  `FeedSyncSchedulerWorker`, and the `FeedSyncExecutor`/`FeedConnectorRegistry` plug-in seam for
  Phase 3.
- API layer — internal administration endpoints, platform-permission gated.
- Tests — domain unit tests, PostgreSQL repository/orchestration/migration/API integration tests.

**Explicitly NOT implemented** (deferred to later M22 phases, per instruction):

- STIX / TAXII parsing or client
- Threat Fusion Engine
- Attack Path Engine
- Investigation-context integration
- Frontend
- Any real `FeedSyncExecutor` implementation (only the Protocol + registry + a test-only stub
  used exclusively inside the PostgreSQL integration suite to prove the seam works)

---

## 2. Architecture Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **Two aggregate roots, not one.** `Feed` (configuration + lifecycle + scheduling state) and `FeedSyncRun` (one execution's history) are separate aggregates linked only by `feed_id`, mirroring the `InvestigationCase`/`investigation_events` and `ReferenceDataIngestionRecord` precedents already in the repository. | A `FeedSyncRun` has its own independent lifecycle (`pending → running → succeeded/failed`) and its own invariants (exactly one non-terminal run per feed) that must be enforced at the database level regardless of what the `Feed` aggregate is doing concurrently; conflating them into one aggregate would force either an unbounded child collection inside `Feed` (unlimited run history loaded into one aggregate) or awkward partial loading, breaking the aggregate consistency boundary. |
| 2 | **Global vs. tenant scope via a `scope` discriminator + `organization_id`, reusing the exact `IngestionScope` enum, `CHECK` constraint, and dual partial-unique-index pattern from Phase 1's `stix_ingestion_log`.** | Feeds must support both platform-wide feeds (e.g. a shared CISA KEV feed) and customer-specific feeds (e.g. a tenant's own TAXII collection) without the two ever colliding on `feed_key`. Reusing the proven Phase 1 pattern (rather than inventing a new one) keeps the two mechanisms — reference-data ingestion scoping and feed scoping — structurally identical and auditable by the same mental model. |
| 3 | **Concurrency safety is two-layered: a per-feed PostgreSQL advisory lock (`pg_advisory_xact_lock`) for the "only one synchronization attempt in flight" race, plus a database-level partial unique index (`ux_fsr_feed_active_run` on `feed_sync_runs.feed_id WHERE status IN ('pending','running')`) as the actual source of truth.** | The advisory lock narrows the race window and avoids most conflicting attempts ever reaching the database, but the partial unique index — not the lock — is what the code actually depends on for correctness: a caller who somehow bypasses the lock (a bug, a lock-key collision, a second uncoordinated process) still cannot insert a second non-terminal run row; the `IntegrityError` is caught and re-raised as the domain-level `FeedSyncAlreadyRunningError`. This mirrors the exact "advisory lock narrows the race, unique index proves it" pattern used for M19 DDoS incidents and M20 behavior detections. |
| 4 | **The scheduler worker (`FeedSyncSchedulerWorker`) uses a single *global* `pg_try_advisory_xact_lock` (non-blocking) to coordinate multiple worker replicas, separate from the per-feed lock used during an individual sync.** | If the platform ever runs more than one API/worker replica, only one replica's scheduler loop should poll for and dispatch due feeds at a time — a *blocking* lock would just queue every replica's poll cycle behind one winner; a *non-blocking* `pg_try_advisory_xact_lock` lets every replica poll on its own cadence and simply skip a cycle if another replica already holds the coordination lock, which is the same pattern the existing NDR/DDoS background workers use elsewhere in the codebase. |
| 5 | **The orchestration service is deliberately split into three separate, short-lived transactions (`_start_run`, the connector call, `_finalize_run`) rather than one long transaction wrapping the whole sync.** | The connector call is the one step that talks to something outside PostgreSQL (an HTTP feed, in Phase 3) and can legitimately take seconds to minutes; holding a database transaction — and therefore the per-feed advisory lock — open for that entire duration would starve every other operation on that feed's row and needlessly extend the advisory-lock hold time. `_start_run` acquires the lock, validates state, inserts the `RUNNING` `FeedSyncRun` row, and commits (releasing the lock) before the connector is ever invoked; `_finalize_run` re-acquires a fresh, short transaction afterward to record the outcome. Retries of the connector call itself happen entirely between those two transactions, using the existing `RetryExecutor`/`RetryConfig` from `application.platform.retry_strategy` (no new retry/backoff implementation — this is the same exponential-backoff-with-jitter utility already used elsewhere in the platform). |
| 6 | **Extensibility seam is a `Protocol` (`FeedSyncExecutor`) + a plain in-memory `FeedConnectorRegistry` keyed by `FeedSourceKind`, not an abstract base class or a database-driven plug-in table.** | `FeedSourceKind` is a closed domain enum (`static_http_download`, `http_api_incremental`, `manual_upload` — deliberately generic, non-STIX/TAXII-specific names; a future `stix_taxii_2_1` value can be added in Phase 3 without touching this phase's code); the registry is populated at process startup by whichever connectors are actually compiled into the running binary. No sync logic anywhere in this phase imports, references, or has any knowledge of STIX or TAXII. `UnknownFeedConnectorError` (a `ValidationError`, HTTP 422) is raised — honestly, not silently — whenever a sync is attempted for a `FeedSourceKind` with no registered connector, which today is *every* source kind, since Phase 2 registers none in production wiring. |
| 7 | **`InvalidFeedStatusTransitionError` is a `ConflictError` (HTTP 409), not a `ValidationError` (422).** | An illegal lifecycle transition (e.g. pausing a `DRAFT` feed) is a well-formed request that conflicts with the resource's current state, not a malformed request — the same classification already used for `FeedNotActiveError` and `FeedSyncAlreadyRunningError` in this same exception module, kept consistent for predictable client-side error handling. |
| 8 | **`checkpoint` is an opaque `str \| None` on both `Feed` (last successfully committed checkpoint) and `FeedSyncRun` (`checkpoint_before`/`checkpoint_after` for this specific run).** | The synchronization platform has no idea what a "checkpoint" means for any given connector — it could be a TAXII cursor, an HTTP `ETag`, a byte offset, a page token. Treating it as an opaque string (never parsed, never validated, only passed through to and from the connector via `FeedSyncContext`/`FeedSyncOutcome`) is what actually keeps Phase 3 connector implementations free to define their own checkpoint format without any Phase 2 migration or domain-model change. |

---

## 3. Repository-First Research (what was read before writing code)

Per instruction, the following were read completely before any code was written:

- `docs/architecture/m22/m22_architecture_freeze.html` (authoritative spec)
- `docs/architecture/m22/m22_hardening_review.html` (corrections, P0-P3 findings)
- `docs/M22_PHASE1_THREAT_INTEL_FOUNDATION_REPORT.md`
- M22 Phase 1 implementation in full: `domain/threat_intel/reference_data_*.py`,
  `infrastructure/database/repositories/threat_intel_reference_data_repository.py`,
  `infrastructure/database/migrations/versions/0035_threat_intel_reference_data.py`,
  `application/threat_intel/reference_data_admin_service.py`
- `application/platform/retry_strategy.py` (existing `RetryConfig`/`RetryExecutor` — reused
  verbatim, not reimplemented)
- Existing advisory-lock/partial-unique-index concurrency patterns:
  `domain/behavior/` (M20), `domain/ddos/` (M19), `domain/investigations/` (M21) equivalents and
  their migrations
- Existing background worker lifecycle pattern (`start()`/`stop()`, FastAPI lifespan wiring) from
  an existing NDR/DDoS worker
- Platform identity: `domain/platform_identity/value_objects.py`, `api/security.py`
- Audit: `infrastructure/audit/contracts.py`, `platform_audit_log.py`
- `application/platform/startup_validator.py`, `application/platform/runtime_container.py`
- `backend/pyproject.toml` (ruff/mypy config, pytest config)

No architecture was invented. Every naming, layering, concurrency, and testing decision mirrors an
existing, working pattern already in the repository.

---

## 4. Files Added / Modified

### New files

| File | Purpose |
|---|---|
| `backend/src/redforge/domain/threat_intel/feed_value_objects.py` | `FeedKey`, `SyncSchedule`, `RetryPolicy` VOs; `FeedSourceKind`, `FeedStatus`, `FeedSyncRunStatus`, `FeedSyncTrigger` enums; `MIN_SYNC_INTERVAL_SECONDS` guard. |
| `backend/src/redforge/domain/threat_intel/feed_exceptions.py` | Domain-specific validation/conflict exceptions. |
| `backend/src/redforge/domain/threat_intel/feed_events.py` | `FeedRegistered`, `FeedActivated`, `FeedPaused`, `FeedDisabled`, `FeedSyncRunStarted`, `FeedSyncRunSucceeded`, `FeedSyncRunFailed` domain events. |
| `backend/src/redforge/domain/threat_intel/feed_entity.py` | `Feed` aggregate root (registration, lifecycle, configuration, sync bookkeeping). |
| `backend/src/redforge/domain/threat_intel/feed_sync_run_entity.py` | `FeedSyncRun` aggregate root (one execution's start/succeed/fail lifecycle). |
| `backend/src/redforge/domain/threat_intel/feed_repository.py` | Repository protocols (`FeedRepository`, `FeedSyncRunRepository`). |
| `backend/src/redforge/infrastructure/database/models/feed_sync.py` | SQLAlchemy ORM models (`FeedModel`, `FeedSyncRunModel`). |
| `backend/src/redforge/infrastructure/database/migrations/versions/0036_feed_sync_foundation.py` | Migration 0036 (schema-only). |
| `backend/src/redforge/infrastructure/database/repositories/feed_sync_repository.py` | Concrete repositories, ORM↔domain mappers, advisory-lock helpers, `IntegrityError` → domain-exception translation. |
| `backend/src/redforge/application/threat_intel/feed_connector.py` | `FeedSyncContext`/`FeedSyncOutcome` DTOs, `FeedSyncExecutor` Protocol, `FeedConnectorRegistry` — the Phase 3 plug-in seam. |
| `backend/src/redforge/application/threat_intel/feed_admin_service.py` | `FeedAdminService` — register/activate/pause/disable/update-configuration, audit-logged. |
| `backend/src/redforge/application/threat_intel/feed_query_service.py` | `FeedQueryService` — read-only feed/run queries. |
| `backend/src/redforge/application/threat_intel/feed_sync_orchestration_service.py` | `FeedSyncOrchestrationService` — the synchronization execution model (locking, retry/backoff, idempotent finalize). |
| `backend/src/redforge/application/threat_intel/feed_sync_worker.py` | `FeedSyncSchedulerWorker` — background poll loop for due feeds. |
| `backend/src/redforge/api/v1/feed_sync.py` | Internal admin REST endpoints. |
| `backend/tests/domain/test_feed_domain.py` | 71 domain unit tests. |
| `backend/tests/integration/test_m22_feed_sync_pg.py` | 33 PostgreSQL integration/API tests. |
| `docs/M22_PHASE2_FEED_SYNCHRONIZATION_FOUNDATION_REPORT.md` | This report. |

### Modified files

| File | Change |
|---|---|
| `backend/src/redforge/infrastructure/database/models/__init__.py` | Registered `FeedModel`/`FeedSyncRunModel`. |
| `backend/src/redforge/domain/platform_identity/value_objects.py` | Added `PLATFORM_FEED_SYNC_READ`/`PLATFORM_FEED_SYNC_MANAGE` permissions; wired into `SECURITY_ADMIN`/`AUDITOR` roles. |
| `backend/src/redforge/infrastructure/audit/contracts.py` | Added `FEED_REGISTERED`, `FEED_CONFIGURATION_UPDATED`, `FEED_ACTIVATED`, `FEED_PAUSED`, `FEED_DISABLED`, `FEED_SYNC_TRIGGERED` `AuditAction`s. |
| `backend/src/redforge/api/v1/__init__.py` | Mounted the new feed-sync router. |
| `backend/src/redforge/api/dependencies.py` | Added `get_feed_connector_registry` accessor. |
| `backend/src/redforge/application/platform/runtime_container.py` | Added `feed_connector_registry`/`feed_sync_scheduler` fields; registry initialized (empty — no connectors registered in Phase 2). |
| `backend/src/redforge/application/platform/startup_validator.py` | `_EXPECTED_MIGRATION_HEAD`: `"0035"` → `"0036"`. |
| `backend/src/redforge/app.py` | Wired `FeedSyncSchedulerWorker` start/stop into the FastAPI lifespan hooks. |
| `backend/tests/unit/test_sprint29_replay_pipeline.py` | Updated 2 hardcoded `"0035"` expected-head assertions to `"0036"`. |
| `backend/tests/unit/test_startup_validator.py` | Updated hardcoded mocked migration version `"0035"` → `"0036"`. |
| `backend/tests/integration/test_m22_reference_data_pg.py` | `test_migration_head_is_0035` renamed to `test_migration_head_is_current` and updated to assert `"0036"` — see §7 note on why. |
| `docs/PROJECT_CONTEXT.md` | Added M22 Phase 2 milestone row; updated the "Last verified"/test-baseline header. |

---

## 5. Database Schema (Migration 0036)

2 tables:

- **`feeds`** — one row per registered feed (global or tenant-scoped). Columns: `feed_key`,
  `display_name`, `source_kind`, `scope`/`organization_id` (Phase 1 scoping pattern reused
  verbatim), `status`, `connector_config` (JSON, connector-opaque), `credential_ref` (opaque
  pointer to wherever real secrets live — no secret material stored in this table),
  `schedule_interval_seconds`, `retry_max_attempts`/`retry_base_delay_seconds`/
  `retry_max_delay_seconds`/`retry_jitter_factor`, `checkpoint` (opaque), `consecutive_failure_count`,
  `last_sync_started_at`/`last_sync_completed_at`/`last_sync_status`, `next_sync_due_at`,
  full audit columns (`created_at`/`updated_at`/`created_by`/`updated_by`).
  - `ck_feeds_ck_feeds_scope_org_pairing` `CHECK` constraint: `organization_id IS NULL` iff
    `scope = 'GLOBAL'`, `organization_id IS NOT NULL` iff `scope = 'TENANT'`.
  - Two mutually exclusive partial unique indexes: `ux_feeds_global_key` on `feed_key` where
    `scope = 'GLOBAL'`, `ux_feeds_tenant_org_key` on `(organization_id, feed_key)` where
    `scope = 'TENANT'` — global and tenant feed-key namespaces never collide.
  - `ix_feeds_active_next_sync_due` partial index on `next_sync_due_at` where
    `status = 'active'` — the exact index the scheduler's `list_due_for_sync` query needs.
- **`feed_sync_runs`** — one row per synchronization attempt, cascade-deleted with its parent
  feed. Columns: `feed_id` (FK, `ON DELETE CASCADE`), `status`, `trigger`, `checkpoint_before`/
  `checkpoint_after`, `items_fetched`/`items_processed`/`items_failed`, `retry_attempts_used`,
  `error_message`, `started_at`/`finished_at`, `created_by`.
  - `ux_fsr_feed_active_run` partial unique index on `feed_id` where
    `status IN ('pending', 'running')` — the database-level backstop that makes "at most one
    non-terminal run per feed" true regardless of any application-level locking bug.

Verified:

- Clean `alembic upgrade head` from an empty database (`0001` → `0036`, all 36 migrations, in
  order, zero errors).
- Clean `downgrade -1` / `upgrade head` round-trip on `0036` (reversibility proven — downgrade
  drops both new tables cleanly, re-upgrade recreates them identically).
- The pre-existing M22 Phase 1 proof database (already at `0035`) upgrades cleanly to `0036` with
  zero impact on the 5 existing reference-data tables or their 39 Phase 1 tests (all still pass —
  see §7).

---

## 6. Permissions & API

Two new platform-level permissions:

- `PLATFORM_FEED_SYNC_READ`
- `PLATFORM_FEED_SYNC_MANAGE`

Wired into the `SECURITY_ADMIN` and `AUDITOR` platform roles via `PLATFORM_ROLE_PERMISSIONS`.

New router (`api/v1/feed_sync.py`), mounted under the existing v1 API at `/threat-intel/feeds`,
gated by `require_platform_permission`:

| Method & Path | Purpose | Permission |
|---|---|---|
| `POST /feeds` | Register a new feed | MANAGE |
| `GET /feeds` | List feeds (filterable by status/source kind) | READ |
| `GET /feeds/{id}` | Get one feed | READ |
| `PATCH /feeds/{id}` | Update configuration (schedule/retry policy/connector config) | MANAGE |
| `POST /feeds/{id}/activate` \| `/pause` \| `/disable` | Lifecycle transitions | MANAGE |
| `POST /feeds/{id}/sync` | Trigger an immediate synchronization | MANAGE |
| `GET /feeds/{id}/runs` | List execution history | READ |
| `GET /feeds/{id}/runs/{run_id}` | Get one run | READ |

This is strictly internal administration — no public Threat Intelligence API surface added, and
`POST /feeds/{id}/sync` honestly returns `422 UnknownFeedConnectorError` for every request in this
phase's production wiring, since no real connector is registered anywhere outside the test suite.

---

## 7. Quality Gates — Results

All gates were run against this exact working tree, uncommitted, per instruction.

### Ruff

```
.venv/bin/ruff check src/ tests/
```

Result: **All checks passed** for every file touched or added in this phase (confirmed by scoping
`ruff check` to exactly the 25 files listed in §4, and separately confirming via `git status` that
the 5 pre-existing findings in two unrelated M21-era test files —
`tests/application/test_investigation_correlation.py`, `tests/domain/test_investigation_domain.py`
— are in files this phase never touched).

### Mypy

```
.venv/bin/mypy src/redforge/
```

Result: **Success: no issues found in 782 source files.** Zero errors, including every new/modified
Phase 2 file.

### Unit / Domain / Application tests

```
.venv/bin/pytest tests/ -q --ignore=tests/integration
```

Result: **4,010 passed**, 0 failed. Of these, **71** are the new M22 Phase 2 domain unit tests
(`tests/domain/test_feed_domain.py`) covering `FeedKey`/`SyncSchedule`/`RetryPolicy` validation,
every enum, `Feed` aggregate registration/lifecycle/configuration/sync-bookkeeping, `FeedSyncRun`
aggregate lifecycle, and every custom exception path.

Two pre-existing hardcoded-migration-head assertions were mechanically updated from `"0035"` to
`"0036"` to keep pace with the new head (`tests/unit/test_sprint29_replay_pipeline.py`,
`tests/unit/test_startup_validator.py`) — no other change to either file.

### PostgreSQL integration tests

Against a real PostgreSQL instance (`localhost:5432`), three independent proof databases:

**M22 Phase 2 proof database** (`redforge_m22_feed_sync_proof_test`, newly created this phase,
migrated `0001` → `0036`):

```
.venv/bin/pytest tests/integration/test_m22_feed_sync_pg.py -q
→ 33 passed
```

Covers, in order: migration structure verification (scope/org `CHECK` constraint, both partial
unique indexes on `feeds`, the partial unique active-run index on `feed_sync_runs`, the cascading
FK); `FeedRepository`/`FeedSyncRunRepository` add/get/update/find-by-key/list-due-for-sync,
duplicate-key conflict mapping, global/tenant scope non-collision, DB-level scope/org-pairing
rejection, and the database's own active-run uniqueness backstop; `FeedAdminService` full
lifecycle + audit trail + duplicate-key rejection; `FeedQueryService` filtering and not-found
handling; `FeedSyncOrchestrationService` end-to-end — unknown-connector honest failure (no run row
ever created), successful sync (checkpoint/schedule advancement), transient-failure-then-success
via the real `RetryExecutor`, permanent-failure-after-exhausting-retries (feed failure counter
increments, checkpoint never advances), non-active-feed rejection, and a genuine **10-way
concurrent `trigger_sync` race** against the same feed via `asyncio.gather()` proving exactly one
caller succeeds and the other nine observe `FeedSyncAlreadyRunningError`, never a second run row;
real-HTTP API acceptance (401 unauthenticated, 403 without the platform role/permission, full
register→activate→trigger→list-runs round trip, 404/409/422 error-path proofs).

The orchestration tests use a deliberately generic, test-only stub connector
(`_StubExecutor`/`_SlowStubExecutor` in the test file itself) registered against
`FeedSourceKind.STATIC_HTTP_DOWNLOAD` purely to exercise the `FeedConnectorRegistry` seam — it is
not, and does not resemble, a STIX/TAXII implementation, and it exists only inside the test module,
never in production wiring.

**M22 Phase 1 proof database** (`redforge_m22_reference_data_proof_test`), upgraded `0035` → `0036`
in place:

```
.venv/bin/pytest tests/integration/test_m22_reference_data_pg.py -q
→ 39 passed
```

Confirms the Phase 2 migration and new `feeds`/`feed_sync_runs` tables introduce **zero regression**
to the Phase 1 reference-data tables. One test (`test_migration_head_is_0035`) was renamed to
`test_migration_head_is_current` and its assertion updated from `"0035"` to `"0036"` — this proof
database is migrated with `alembic upgrade head`, so pinning the assertion to a specific historical
head would make every future, unrelated migration break this Phase 1 suite; the test now
intentionally tracks the moving head instead.

**M21 proof database** (`redforge_m21_proof_test`) — deliberately left untouched at `0035` (no
`alembic upgrade` was run against it this phase):

```
.venv/bin/pytest tests/integration/test_m21_investigation_pg.py -q
→ 51 passed
```

Confirms the M21 Investigation bounded context is completely unaffected by this phase, whether or
not its proof database is ever upgraded past `0035`.

### Migration verification

```
alembic upgrade head       (0001 → 0036, clean, empty DB)
alembic downgrade -1        (0036 → 0035, clean)
alembic upgrade head        (0035 → 0036, clean)
psql \d feeds / \d feed_sync_runs   → schema matches design exactly (verified column-by-column)
```

### Startup validator verification

`_EXPECTED_MIGRATION_HEAD` is now `"0036"`. Unit tests
(`tests/unit/test_startup_validator.py`, `tests/unit/test_sprint29_replay_pipeline.py`) updated to
assert against the new head and pass.

---

## 8. Test Baseline Summary

| Suite | Count | Result |
|---|---|---|
| Non-integration (unit + domain + application + api) | 4,010 collected | All pass |
| M22 Phase 2 PostgreSQL integration | 33 | All pass |
| M22 Phase 1 PostgreSQL integration (regression check) | 39 | All pass |
| M21 PostgreSQL integration (regression check) | 51 | All pass, unchanged |
| Ruff | — | Clean on all Phase 2 files; 5 pre-existing unrelated findings in M21 test files, untouched |
| Mypy (`src/redforge/`) | — | Clean: 0 errors in 782 source files |

---

## 9. Documentation Updated

- `docs/PROJECT_CONTEXT.md` — added the M22 Phase 2 milestone row to the Completed Milestones
  table; updated the "Last verified" line and test-baseline header to reflect the new migration
  head (`0036`) and measured test counts.
- This report (`docs/M22_PHASE2_FEED_SYNCHRONIZATION_FOUNDATION_REPORT.md`).

---

## 10. Explicit Confirmation of Stop Conditions

- Phase 2 only was implemented. No STIX parsing, TAXII client, Threat Fusion, Attack Path Engine,
  Investigation-context integration, or frontend code was written. `FeedConnectorRegistry` is
  registered empty in production wiring (`runtime_container.py`) — no real connector exists
  anywhere outside a test-only stub confined to the PostgreSQL integration test module.
- Ruff, Mypy, unit tests, PostgreSQL integration tests, migration verification, and startup
  validator verification were all run, with results reported above.
- Documentation was updated.
- This implementation report was produced.
- **No commit was made. No push was made.** The working tree is left exactly as-is, awaiting
  review.
