# PostgreSQL Async Engine Lifecycle & Full-Suite Reliability Report

## Scope

A dedicated closure of the backend's full-suite test reliability, triggered by the full backend pytest suite consistently showing 20 failed / 8 errors (later 4 failed / 8 errors, later 1 failed / 0 errors) across repeated runs, all traced to the same underlying class of defect: process-global async database resources outliving the PostgreSQL connection pool / event loop they were bound to, plus several genuine, pre-existing test-fixture and schema gaps this instability had been masking. This is infrastructure and data-integrity work, not a continuation of M17's RBAC feature work — no RBAC/frontend code was touched.

## Baseline

- HEAD at start: `87b830d` (M17 commit, already pushed).
- Working tree: clean.
- Last observed full-suite result before this pass: 4097 passed / 20 failed / 5 skipped / 8 errors.

## Root cause #1 (the primary, cross-cutting defect): stale `@lru_cache`-memoized DB-bound dependency providers

### Reproduction

Two genuinely separate event loops, each running a full `create_app()` lifespan against the same real PostgreSQL database (mirroring exactly how pytest-asyncio's `loop_scope="module"` isolates full-app-lifespan test files from each other within one pytest process):

```python
for i in range(5):
    asyncio.run(run_one(i))   # each asyncio.run() = a fresh event loop
```

On the pre-fix code, cycle 0 and 1 succeed; cycle 2 crashes with `RuntimeError: Event loop is closed` inside asyncpg's connection pool. On the fixed code, all 5 cycles pass cleanly, repeatably.

### Diagnosis

`backend/src/redforge/api/dependencies.py`'s `_session_factory()`:

```python
@lru_cache
def _session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=get_engine(), class_=AsyncSession, expire_on_commit=False)
```

`functools.lru_cache` with no arguments memoizes for the lifetime of the **process**, not the lifetime of the **engine**. `infrastructure/database/engine.py`'s `create_engine()`/`dispose_engine()` cycle a fresh `AsyncEngine` (and its own asyncpg connection pool, bound to whatever event loop was running at construction time) on every `create_app()` lifespan. Verified directly:

```python
e1 = create_engine(url); sf1 = dependencies._session_factory()
await dispose_engine()
e2 = create_engine(url); sf2 = dependencies._session_factory()
# sf1 is sf2  →  True   (same cached sessionmaker object, both times)
# sf2.kw["bind"] is e1  →  True   (still bound to the FIRST, now-disposed engine)
```

Every request in a **second or later** `create_app()` instance within the same process silently receives a sessionmaker bound to the **first** instance's engine — whose connections belong to a different (and by then possibly closed) event loop. This is not limited to `_session_factory()` itself: roughly 40 other `@lru_cache`-decorated service-provider functions in the same module construct a service object once, capturing whatever `_session_factory()` returned at that first call, and hold it for the rest of the process.

This is a production-safe pattern in real deployment (one process, one `create_app()` call, for the process's entire life) — the defect only manifests when more than one `create_app()` lifespan runs in one interpreter, which the backend's own test suite does routinely (`test_rbac_live_acceptance.py`, `test_network_security_restart_durability.py`, and every other full-app-lifespan integration test file).

### Fix

`clear_cached_dependencies()` (new, `api/dependencies.py`): introspects the module's own globals for any callable carrying `functools.lru_cache`'s `cache_clear` attribute and calls it — covering every current and future cached provider without needing an explicit, driftable list. Called from two points in `app.py`:

1. Defensively at the **start** of `_start_database()`, before `create_engine()` — guards against a previous app instance's shutdown hook not having run to completion in this same process.
2. At the **end** of `_shutdown_database()`, immediately after `dispose_engine()` — the primary fix, guaranteeing the next `create_engine()` in this process is picked up by every provider.

This is the smallest fix that addresses the actual defect (stale caches outliving their engine) without changing the underlying architecture (still one global engine per running process, still `@lru_cache` for real per-process singleton behavior) and without touching any of the ~40 individual provider functions.

## Root cause #2: proof/race test databases require a pre-migrated schema, but two of them were dropped without re-migrating

During the initial diagnosis pass, all disposable `*_proof_test`/`*_race_test`/`*_live_acceptance` databases were dropped to guarantee a clean baseline (most of these self-manage their own schema via `Base.metadata.create_all()` with an explicit table subset and recreate cleanly). Two files — `test_rbac_live_acceptance.py` (`redforge_rbac_proof_test`) and `test_network_security_restart_durability.py` (`redforge_network_security_proof_test`) — instead run the **real** `create_app()` with a real lifespan and depend on the target database already being migrated to head via `alembic upgrade head` (matching the documented precedent from earlier milestones' "owned proof database" fixtures). Dropping these two without immediately re-migrating them caused every authenticated request in those tests to 500 with `relation "..." does not exist`. Fixed by recreating and migrating both databases to head. This was a self-inflicted diagnostic-process mistake, not a code defect — documented here for completeness and to make the precondition explicit for future test runs.

## Root cause #3: `test_security_operations_postgres_proof.py` never created the M16 network-security tables it now queries

`application/security_operations/stream_service.py`'s `fetch_merged_candidates()` merges 5 sources: M11 execution events, M14 drift events, M14 policy lifecycle events, M15 runtime health transitions, and **M16 network validation run events** (`NetworkValidationRunEventModel`/`network_validation_run_events`, plus `NetworkMonitoringPolicyLifecycleEventModel`/`network_monitoring_policy_lifecycle_events`). This test file's own `Base.metadata.create_all(tables=_TABLES)`-based proof-database fixture was written before M16 added those two tables to the merge and was never updated — every one of its 7 tests failed at setup with `UndefinedTableError`, and the failed setup's uncommitted `INSERT INTO validation_execution_events` transaction was left open, blocking the module-scoped teardown's `DROP TABLE ... CASCADE` indefinitely (a genuine, reproducible hang, not a flake — confirmed via `pg_stat_activity` showing an `idle in transaction` session blocking a `Lock`-waiting `DROP TABLE`). Fixed by importing both models and adding their tables to `_TABLES` and the teardown's `_ALL_TABLE_NAMES`. All 7 tests now pass in under 4 seconds, reliably, with no hang.

## Root cause #4: same class of gap in `test_protocol_aware_service_validation_postgres_proof.py`

This file's proof-database fixture also never created `security_graph_nodes`/`security_graph_edges` — a code path under test now writes to the Security Graph projection (via `SecurityConditionService`) that this fixture's `_TABLES` list predates. Fixed by importing `SecurityGraphNodeModel`/`SecurityGraphEdgeModel` and adding them.

## Root cause #5 (genuine, real data-integrity defect, pre-existing since M4): `security_graph_nodes` missing its own documented unique constraint

`infrastructure/database/models/security_graph.py`'s own module docstring states plainly that the canonical identity for a Security Graph node is `(organization_id, source_domain, source_entity_id)` — but the ORM model's `__table_args__` only ever declared `UniqueConstraint("id", "organization_id")`, never that triple. `SecurityGraphRepository.upsert_node()` already has the correct INSERT-then-catch-`IntegrityError`-and-recover race-safety pattern (identical to `upsert_edge()`'s, which **is** correctly backed by a constraint) — but with no constraint to violate, two concurrent projections of the same source entity can both successfully `INSERT`, producing two rows for one logical node. This was masked for the file's entire history because the fixture also lacked the tables needed to reach this code path at all (root cause #4) — once that was fixed, `test_concurrent_execution_converges_on_one_canonical_service_asset` immediately surfaced the missing constraint via a genuine `MultipleResultsFound` crash under real concurrent load.

**Fix**: new migration `0027_security_graph_node_identity_constraint.py` adds `UniqueConstraint("organization_id", "source_domain", "source_entity_id", name="ux_sg_nodes_org_domain_entity")` on `security_graph_nodes`, and the ORM model's `__table_args__` is updated to match. Verified no existing duplicate `(organization_id, source_domain, source_entity_id)` rows in the dev database before applying (clean). `_EXPECTED_MIGRATION_HEAD` bumped 0026→0027 (`application/platform/startup_validator.py`) and the two tests asserting that constant updated alongside it, matching the established pattern for every prior migration bump in this repository.

## Root cause #6: same class of defect for canonical SERVICE assets, surfaced immediately after fixing #5

With the Security Graph crash gone, the SAME test's own assertion (`assert len(external_ids) == len(set(external_ids))`) still failed: duplicate canonical `AIAsset` rows for the same service endpoint under concurrent discovery. Investigation found the actual production schema (migrated via Alembic) **does** carry the correct backstop — a partial unique index `ux_ai_assets_org_external_id` on `(organization_id, external_id) WHERE external_id != ''`, created in migration `0013` via raw `op.create_index(..., postgresql_where=...)`. Because this index was **never declared on `AIAssetModel.__table_args__`** (only ever created via raw Alembic DDL), this test's `Base.metadata.create_all(tables=_TABLES)`-based fixture — which reflects only what the ORM model declares — has no way to know it exists, and never creates it in the isolated proof database. `TenantAssetService.resolve_asset()`'s own INSERT-then-catch-`IntegrityError` pattern (already correct, matching `get_or_create_for_target()`'s) had nothing to catch. **This is a test-fixture gap, not a schema defect** — real dev/prod databases have always had the correct constraint. Fixed by adding the same raw `CREATE UNIQUE INDEX ... WHERE external_id != ''` statement to this fixture, alongside its existing (also raw-DDL, also not ORM-declared) `ux_ai_assets_id_org` constraint creation.

## Verification

- `ruff check .`: clean.
- `mypy src/redforge/`: clean, 660 source files.
- Isolated reproduction (2 genuinely separate event loops, 5 cycles): passes reliably, both files (root cause #1's minimal repro and the real `test_rbac_live_acceptance.py`/`test_network_security_restart_durability.py` files) — each re-run 2+ times with no flake.
- `test_security_operations_postgres_proof.py`: 7/7 passed, 3.05s, no hang (previously: 0/7, indefinite hang).
- `test_protocol_aware_service_validation_postgres_proof.py`: 14/14 passed, re-run 3 additional times with no flake (previously: 13/14, one genuine concurrency crash).
- Migration proof: clean `0001→0027→0026→0027` up/down/up on an isolated, destroyed-after-use database.
- Full backend suite, run twice from a genuinely clean state (all disposable proof/race databases dropped and, where required, freshly migrated to head; no leftover test rows in the dev database): see the companion checkpoint document for exact counts.

## What was explicitly NOT changed

- The process-global engine singleton architecture in `infrastructure/database/engine.py` itself — this remains correct and appropriate for a real single-process deployment; the defect was exclusively in the cache layer sitting on top of it in `api/dependencies.py`, not the engine module itself.
- No M17 RBAC/frontend code, no migration before `0026`, no application business logic beyond the two genuine concurrency-safety constraints described above.
- No test was skipped, xfailed, or excluded to reach a green suite — every fix addresses the actual root cause of a real failure.
