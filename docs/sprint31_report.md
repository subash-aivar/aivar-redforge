# Sprint 31 Report — Enterprise Durable Read Models

**Date**: 2026-07-10  
**Tests**: 2,936 passed, 5 skipped (+18 over Sprint 30)  
**Ruff**: Clean  
**Mypy --strict**: Clean  
**Migration head**: 0009  
**Architecture score**: 9.1/10

---

## Objectives Completed

| Objective | Result |
|-----------|--------|
| PostgreSQL-backed projection repositories | ✅ `PostgreSQLReadModelRepository` — duck-typed, session-scoped |
| Durable projection persistence after replay | ✅ `flush_to_durable_repo()` on all 9 projections, inside same `AsyncSession` as checkpoint |
| Cross-tenant replay integrity enforcement | ✅ `entry.org != envelope.org` → log, metric, return False — handler never invoked |
| DLQ exhausted state (terminal) | ✅ `mark_exhausted()` on both InMemory and PostgreSQL DLQ |
| In-flight reservation + duplicate prevention | ✅ `SELECT FOR UPDATE SKIP LOCKED`; TTL = 300s; `release_inflight()` on failure |
| Handler invocation metrics | ✅ 7 counters/histograms: `handlers_invoked`, `projection_execution_time`, `checkpoint_latency`, `events_replayed`, `events_skipped`, `projection_failures`, `cross_tenant_rejected` |
| Live checkpoint diagnostics | ✅ `GET /runtime/checkpoints` queries PostgreSQL; falls back to -1 without DB |
| Worker `is_running` fix | ✅ `replay_status()` uses `worker.is_running` directly; `stats()` includes `"state"` key |
| KGProjection evaluation | ✅ Evaluated and deferred — constructor requires `KnowledgeGraph` not in `RuntimeContainer` |

---

## Files Modified

**New files:**
- `src/redforge/infrastructure/database/migrations/versions/0009_dlq_exhausted_inflight.py`
- `tests/unit/test_sprint31_durable_read_models.py` (14 tests)
- `tests/api/test_sprint31_diagnostics.py` (4 tests)

**Modified (infrastructure):**
- `infrastructure/platform/models.py` — `reserved_until`, `exhausted_at` columns on `DeadLetterEntryModel`
- `infrastructure/platform/dead_letter_queue.py` — `mark_exhausted()`, `release_inflight()`, `SELECT FOR UPDATE SKIP LOCKED`, TTL

**Modified (application):**
- `application/platform/runtime_contracts.py` — `RuntimeDLQ` extended with `mark_exhausted()`, `release_inflight()`
- `application/platform/dead_letter_queue.py` — `InMemoryDeadLetterQueue`: `_requeued_ids`, `_inflight_ids`, `_exhausted_ids`; atomic claim in `list_pending_replay()`
- `application/platform/replay_worker.py` — `_exhausted` counter; `stats()` includes `state`; calls `mark_exhausted()` / `release_inflight()`
- `application/platform/projections/base.py` — `flush_to_durable_repo(target_repo, org_id)` default no-op
- `application/platform/projections/{campaign,inventory,validation,risk,intelligence,evidence,connector_activity,asset_timeline,organization_activity}_projection.py` — constructor `repo: Any`; `flush_to_durable_repo()` implemented; `cast()` on `get()` return
- `application/platform/projection_registry.py` — `flush_all_to_durable_repo()`; `projections` property
- `application/platform/runtime_container.py` — `session_factory: Any = None`
- `application/platform/startup_validator.py` — `_EXPECTED_MIGRATION_HEAD = "0009"`

**Modified (API and app):**
- `app.py` — `runtime.session_factory = _session_factory`; cross-tenant check; PG flush in `_real_replay_fn`; 7 handler metrics
- `api/v1/runtime.py` — `list_checkpoints()` queries PostgreSQL; `replay_status()` uses `worker.is_running`

**Updated pre-existing tests (3 files, 4 tests):**
- `tests/unit/test_startup_validator.py` — migration mock `"0009"`
- `tests/unit/test_sprint29_replay_pipeline.py` — migration assertions updated to `"0009"`
- `tests/unit/test_replay_worker.py` — `test_skips_entries_exceeding_max_retries` checks `["exhausted"] == 1`

---

## Architecture Decisions

### 1. `flush_to_durable_repo()` uses live projection instances (not fresh)

Creating fresh `CampaignProjection` instances for PostgreSQL writes would start cumulative counters at zero. The solution is to call `flush_to_durable_repo()` on the **live shared projection instances** after `engine.process()` updates their in-memory state. The flush writes current (correct) cumulative state to PostgreSQL within the same `AsyncSession` as the checkpoint write — atomically.

**Trade-off**: Two concurrent replay workers calling `flush_to_durable_repo()` on the same shared instances create a race. Mitigated by requiring `max_concurrent=1` in production until Sprint 32 adds isolated instances.

### 2. Cross-tenant check placed before all handler code

`fetch_by_event_id` intentionally has no org filter (it queries by event_id which is globally unique). The org check happens immediately after fetch, before any handler, checkpoint, or read model write. This satisfies the security requirement that cross-tenant events can never modify any state.

### 3. DLQ in-flight uses SELECT FOR UPDATE SKIP LOCKED

An atomic UPDATE claims entries: sets `status='in_flight'`, `reserved_until=NOW()+300s`. Second workers see `SKIP LOCKED` and get no rows. Expired entries (`status='in_flight' AND reserved_until < NOW()`) are re-claimable by the next batch poll. No separate "expired entry recovery" job required.

### 4. `session_factory: Any` on RuntimeContainer

Avoids importing SQLAlchemy's `async_sessionmaker` in the application layer. `app.py` (infrastructure boundary) sets it after DB startup. The type is duck-typed at runtime. Consistent with the existing duck-typing approach on projection constructors.

### 5. KGProjection deferred

`KGProjection.__init__` signature is `(graph: KnowledgeGraph, repo: Any)`. Adding `KnowledgeGraph` to `RuntimeContainer` would couple the runtime container to the knowledge graph application service — a cross-concern dependency that violates bounded context separation. Deferred to Sprint 32 with a deliberate design pass.

---

## Tests

| Category | Count | Notes |
|----------|-------|-------|
| `test_sprint31_durable_read_models.py` | 14 | Flush, cross-tenant, duck-typed repo, worker state, DLQ exhausted/in-flight |
| `test_sprint31_diagnostics.py` | 4 | Checkpoint fallback to -1, names match registry, replay status counters |
| Pre-existing tests updated | 4 | Migration version → 0009; exhausted counter key |
| **Total passing** | **2,936** | +18 net |

---

## Technical Debt

### Resolved this sprint

- DEBT-S30-3: `worker_running` always false — fixed via `worker.is_running`
- No durable read model flush — resolved via `flush_to_durable_repo()` pattern

### Added this sprint

| ID | Priority | Description |
|----|----------|-------------|
| DEBT-S31-1 | P1 | Concurrent replay race — shared projection instances; `max_concurrent=1` mitigation in production |
| DEBT-S31-2 | P1 | KGProjection not wired — KnowledgeGraph not in RuntimeContainer |
| DEBT-S31-3 | P1 | No exhausted-depth metric/alert |
| DEBT-S31-4 | P2 | Process restart doesn't load projection state from PostgreSQL |
| DEBT-S31-5 | P2 | `/runtime/checkpoints` adds DB round-trip per request |
| DEBT-S31-6 | P2 | `_inflight_ids/_exhausted_ids` accessed directly in tests |

---

## Known Limitations

1. **`max_concurrent=1` required in production**: Two replay workers share the same projection instances. Concurrent `flush_to_durable_repo()` writes non-deterministic cumulative state to PostgreSQL. This is a correctness gap, not a crash.

2. **KGProjection excluded from replay**: DLQ entries for KG-related events cannot be replayed to repair the knowledge graph until Sprint 32.

3. **Read model recovery on restart is eventual**: After process restart, in-memory projections start empty. They catch up as new events arrive. `GET /runtime/checkpoints` still returns correct PostgreSQL positions, but the in-memory projections will lag until fully caught up.

4. **Exhausted entries are permanent**: There is no operator workflow to discard or archive exhausted DLQ entries. They accumulate in the `dead_letter_entries` table with `status='exhausted'`.

---

## Next Sprint Recommendation

**Sprint 32 — Concurrent Replay Safety + KGProjection**

Primary objectives:
1. **Isolated projection instances per replay session** — create a `ProjectionRegistry.clone()` that returns fresh instances with their own `InMemoryReadModelRepository`, loaded from PostgreSQL state. Eliminates the shared-instance race and unblocks `max_concurrent > 1`.
2. **KGProjection registration** — add `KnowledgeGraph` to `RuntimeContainer`; wire `KGProjection` into `ProjectionRegistry`.
3. **Process restart recovery** — on startup, load last-known read model state from `PostgreSQLReadModelRepository` into in-memory projections before accepting live events.
4. **Exhausted-depth alerting** — counter metric `dlq.exhausted.depth` updated on every `mark_exhausted()`; expose via `GET /runtime/dlq/stats`.
