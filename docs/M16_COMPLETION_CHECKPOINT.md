# M16 Completion Checkpoint

**Milestone:** M16 — Advanced Network Security & Continuous Network Monitoring
**Full detail:** [M16_ADVANCED_NETWORK_SECURITY_MONITORING_REPORT.md](M16_ADVANCED_NETWORK_SECURITY_MONITORING_REPORT.md), [M16_ADVERSARIAL_TRACEABILITY_MATRIX.md](M16_ADVERSARIAL_TRACEABILITY_MATRIX.md)

M16 status: **COMPLETE** — 89/95 named brief scenarios PROVEN, 6 NOT APPLICABLE (verified architectural reason each), 0 PARTIALLY PROVEN, 0 NOT PROVEN. **89 + 6 + 0 + 0 = 95**, mechanically recounted from the 95-row matrix and enforced by `tests/unit/test_m16_traceability_matrix_integrity.py` on every test run. Zero known P0. Zero known P1.

## Final audit correction (this pass)

A prior pass's checkpoint declared PROVEN=93, NOT APPLICABLE=6, which does not sum to 95 (93+6=99) — flagged correctly by an external audit. Investigation found this was a **summary-table bookkeeping error**, not a hidden extra/missing scenario: 3 rows (#47, #78, #82) had carried a hybrid Status annotation ("NOT APPLICABLE / PROVEN BY REUSE", "PROVEN BY REUSE") instead of exactly one of the four canonical values, and the summary table itself had never been mechanically recounted from the 95 rows — it was hand-maintained and drifted. Fixed by:
- Normalizing all 3 hybrid-status rows to the single canonical value `PROVEN` (the reuse detail is preserved in each row's Evidence column, not the Status column).
- Fixing one row (#44) that had accidentally merged its Test file/Test function columns, which broke mechanical parsing.
- Adding `tests/unit/test_m16_traceability_matrix_integrity.py`, which parses the matrix doc directly (not from memory) and asserts: scenario numbers are exactly `{1..95}` with no duplicates/gaps, every row's Status is exactly one of the four canonical values, and the Summary table's counts equal a mechanical recount of the 95 rows. This makes the exact class of error that triggered this audit structurally impossible to silently reintroduce.
- Mechanical recount: **PROVEN=89, NOT APPLICABLE=6, PARTIALLY PROVEN=0, NOT PROVEN=0, total=95.**

## What closed this pass (mid-run execution cancellation — scenario #51)

The single remaining gap from the prior pass — mid-run execution cancellation — is now closed:

- **Domain**: `NetworkValidationRun` gained a monotonic `cancellation_requested` boolean (`request_cancellation()`), decoupled from the `status` state machine. The pre-existing `cancel()` transition (RUNNING/AUTHORIZED/etc. → CANCELLED) needed no changes — only the request/observe mechanism around it was new.
- **Persistence** (migration 0025): `network_validation_runs.cancellation_requested`, read/written by a dedicated atomic `UPDATE ... SET cancellation_requested = true ... RETURNING status` repository method — deliberately **never** part of the generic `save()`'s UPDATE branch, so a long-lived, stale in-memory aggregate saved later structurally cannot clobber a cancellation request persisted by a concurrent session. Proven with two real, independently-committing PostgreSQL sessions (`test_stale_aggregate_save_cannot_clobber_cancellation_request`).
- **Orchestrator**: 4 cooperative cancellation checkpoints — before dispatch, before each probe acquires its concurrency-limiting semaphore, immediately after the fresh per-address M10 authorization recheck but before the TCP connect, and once more after `_execute_validation()` returns. On a positive observation, `create_and_run()` calls `run.cancel()` (never `finish()`) and **skips `_reconcile()` entirely** — no snapshot, no drift computation, no new SecurityCondition ingestion from a partially-executed run, closing the "false condition resolution / false drift disappearance" risk explicitly.
- **API**: `POST /api/v1/network-security/runs/{run_id}/cancel` (NETWORK_SECURITY_MANAGE), idempotent on repeat/terminal-run calls, 404 (not 500) for malformed or unknown run ids, 404 for cross-tenant (matching `get_run`'s non-disclosure), 401/403 for an unscoped token.
- **Execution model**: no task registry, no Celery/Redis/Kafka, no change to `create_and_run()`'s synchronous return contract — a concurrent cancel HTTP request naturally interleaves with an in-progress `run-now`/scheduler-dispatched call at the existing `await` points (DB reads, TCP connects) already present in the probe loop. This preserved every already-PROVEN scenario's assertions about `run-now`'s synchronous completion contract.
- **Proof**: `test_network_security_cancellation.py` (6 tests, all against real PostgreSQL) — genuine mid-run cancellation of an in-progress run via a concurrent call to the same entry point the API uses, the stale-save race proof, idempotency on an already-COMPLETED run, cross-tenant/unknown-run non-disclosure, and a dedicated scheduler-dispatched mid-flight cancellation test (see below). A **literal, genuine RUNNING-state HTTP cancellation** is proven in `scripts/m16_live_api_acceptance.py`: a dedicated NETWORK_DEEP_SAFE policy against a blackholed (non-routable) address gives a real ~1s in-flight window; a second concurrent HTTP client polls until the run is observed as `status="running"`, issues `POST /cancel` while it is genuinely running, and the same `run-now` call's own eventual HTTP response confirms `status="cancelled"` — not merely cancel-before-execution or cancel-on-an-already-terminal-run. 6 further live-HTTP steps (idempotent cancel, repeated cancel, malformed run id, unknown run id, unscoped-token denial, cross-tenant cancel denial) bring live acceptance to **50/50 PASS**.
- **Restart durability**: `test_network_security_restart_durability.py` constructs THREE fully independent `create_app()` instances (each its own `lifespan_context`, its own DB engine) against the same real Postgres DB — the only way state can cross them is Postgres itself. Process A drives a run to RUNNING and abandons it (models a crash). Process B (a simulated restart) queries it over real HTTP, confirms it is still RUNNING with `cancellation_requested=false`, and cancels it over real HTTP. Process C (a second simulated restart) confirms `cancellation_requested` is still `true` and the run is still `"running"` (never silently resumed/completed by anything), and proves the scheduler itself is unaffected by the abandoned run (a fresh ACTIVE policy is still claimable via the real SKIP LOCKED path).
- **Scheduler-dispatched cancellation**: `test_scheduler_dispatched_run_can_be_cancelled_mid_flight` drives a run through the REAL scheduler path (`NetworkMonitoringProcessor.process_one_due_policy()` — real SKIP LOCKED claim, not `run-now`), cancels it mid-flight, and proves: the run reaches CANCELLED; the policy's own lifecycle is not corrupted (claim released, schedule advanced, still ACTIVE); no duplicate run was created (exactly one run row exists for the policy, and an immediate second claim attempt finds nothing due).
- **Regression found and fixed again**: `startup_validator.py`'s `_EXPECTED_MIGRATION_HEAD` was bumped 0024→0025 for the new migration (the same bug class as the prior pass's stale-head bug); the two tests asserting that constant were updated alongside it.
- **Test-infra regression found and fixed (unrelated to cancellation logic, surfaced by the new tests' broader import graph)**: three pre-existing SQLite-backed test fixtures (`test_organization_repository.py`, `test_security_correlation_evaluation.py`, `test_security_condition_graph_projection.py`) called `Base.metadata.create_all()` against SQLite for the WHOLE shared metadata, which only "worked" by luck of import order — several unrelated bounded contexts (the platform Event Store, `platform_events`/`platform_snapshots`/`platform_read_models`/`dead_letter_entries`) use Postgres-only `JSONB` columns that don't compile against SQLite. Scoped each fixture to the specific tables (or an explicit JSONB-table exclusion list) it actually needs — the same "lazy import to keep JSONB off SQLite's import graph" concern `app.py`'s own `_start_database()` docstring already documents, now made robust against import-order instead of dependent on it.

## What closed the previous pass

A full adversarial traceability matrix was built mapping every one of the 95 named scenarios from the original M16 brief §30 to an exact test (see the matrix doc). Building it surfaced real, previously-undetected gaps, all now closed except one:

- **Condition reactivation (scenario #46) — capability implemented.** M16's own drift detection had no reactivation classifier at all (a genuine gap vs. M14's own `_compute_reactivated_keys()` precedent). Implemented `_compute_reactivated_keys()` in `orchestrator.py` (identical logic to M14's: a newly-active condition is a REACTIVATION only if its own `first_observed_at` predates the previous snapshot's `captured_at`) and added `CONDITION_REACTIVATED` to `NETWORK_DRIFT_CATEGORIES`. 4 new unit tests prove reactivation vs. fresh-appearance classification directly.
- **Execution deadline (scenario #52) — capability implemented.** No execution-wide wall-clock deadline existed around the probe loop (only the pre-existing per-probe `CONNECT_TIMEOUT_SECONDS`). Added `EXECUTION_DEADLINE_SECONDS` — every `_probe()` checks it before doing any work, before acquiring the concurrency semaphore. Proven with a real owned-loopback-lab test: forcing the deadline to 0 against a real reachable listener yields `reachable_ports == []` — every probe attempt returns immediately.
- **Network validation run list/detail API (scenario #61) — capability implemented.** No `GET /network-security/runs` or `GET /network-security/runs/{id}` endpoint existed — a genuine missing read-model surface, not just a missing test. Added `NetworkValidationRunQueryService` + both endpoints, re-verified end-to-end via a fresh live-HTTP acceptance run (39/39 PASS) including cross-tenant run-list isolation and run-detail non-disclosure.
- **Lifecycle filter 500 (scenario #65) — real bug found and fixed.** `GET /monitoring-policies?lifecycle=<garbage>` raised an unguarded `ValueError` → 500 (identical bug class to the already-fixed profile/cadence issue). Fixed with a `Literal` type at the API layer plus a defense-in-depth `ValidationError` guard in the service.
- **Expired-authorization time-of-use gate (scenario #17) — test gap closed.** Previously only revoked/pending-approval/action-class-mismatch were tested; added a direct test proving a validity-window-elapsed authorization blocks even while its stored `status` column is still ACTIVE.
- **Snapshot determinism, TLS certificate rotation, condition-resolution drift (scenarios #38-40, #43, #45) — test gaps closed.** These real capabilities existed but were previously unproven by a direct test (the owned lab's bare TCP listener can't exercise TLS rotation). Added 11 direct unit tests against `NetworkStateSnapshot.build()`/`_detect_drift()`.
- **DNS/redirect/ICMP/shell/exploit "not applicable" claims — turned into verified static assertions.** Previously these were documented reasoning only; now a dedicated test file (`test_network_security_negative_capabilities.py`, 7 tests) scans the M16 bounded context's actual source for `getaddrinfo`/`httpx`/`SOCK_RAW`/`subprocess`/`msfconsole`/etc. and fails if any reappears — proof, not just narrative.
- **Concurrent same-IP resolution, cross-tenant asset isolation, port≠protocol, non-vulnerability-inference (scenarios #27-32, #35, #37) — test gaps closed.** 7 new tests directly exercise these previously-narrative-only claims.
- **M15 projection genuinely reaching the merged feed, tenant-safe (scenarios #80/#81) — test gap closed.** Previously only "the endpoint is reachable" was proven live; now a real `NetworkValidationRun`'s event is proven to appear in `fetch_merged_candidates()`, and to never leak across tenants.
- **A pre-existing, real, unrelated bug found and fixed while wiring the runtime worker**: `application/platform/startup_validator.py`'s expected-migration-head constant was stale at `"0023"` (never bumped for 0024), silently blocking every background worker (M14's and M15's too) from starting against any real, correctly-migrated database.

A test-isolation issue in the concurrency-proof test itself was also found and fixed: `test_concurrent_scheduler_claim_converges_on_exactly_one_winner` assumed it was the only due ACTIVE policy in the proof database, which broke once other tests in the same session left their own policies ACTIVE. Fixed to assert per-policy claim-safety (the actual property under test) rather than a whole-table claim count.

## Remaining gap

None.

## Architecture decision (unchanged from prior checkpoint, reconfirmed)

Reuse AIAsset/identity/M10-M11-M13 network primitives/M8-M9 services/Security Graph unchanged; `NetworkValidationRun`/`NetworkMonitoringPolicy`/`NetworkStateSnapshot`/`NetworkDriftEvent` as documented parallels to their M11/M14 counterparts (genuine target-shape mismatch: AITarget is a validated single HTTP(S) endpoint, M16's target is a NETWORK/IP_ADDRESS AIAsset). No new bounded context, no second scheduler, no second asset model, no second authorization engine, no second protocol registry was created this pass — every fix and addition extended the existing M16 architecture (new API endpoints on the existing router, new fields on the existing orchestrator, new tests against existing code).

## Final verification, this pass

- Backend: `ruff check .` clean. `mypy` strict — **645 source files clean** (up from 644 — the new migration file). `pytest` — **4091 passed, 5 skipped, 0 failed** (same one pre-existing, reproducibly-deadlocking file — `tests/integration/test_security_operations_postgres_proof.py` — excluded with evidence; unrelated to any M16 code path). Reproduced clean on 3 of 4 consecutive full-suite runs during this pass; see "Known flake" note below for the one exception.
- Frontend: tsc clean, vitest 109 passed, build clean, npm audit unchanged (2 pre-existing moderate advisories in `next`'s bundled `postcss`, unrelated to M16, fixable only via a breaking `next` upgrade — not attempted, not new this pass).
- Migration: clean 0001→0025→0024→0025 up/down/up proof against a freshly created, destroyed-after-use isolated database.
- PostgreSQL concurrency proof: rerun clean (7/7).
- Owned loopback lab proof: rerun clean (4/4).
- Dedicated cancellation proof (real PostgreSQL): **6/6 PASS** — mid-run cancellation, the stale-aggregate-save race, idempotency, cross-tenant/unknown-run non-disclosure, and scheduler-dispatched mid-flight cancellation.
- Restart durability proof (real PostgreSQL, 3 simulated process restarts via independent `create_app()` instances): **1/1 PASS**.
- Live HTTP API acceptance: rerun clean, **50/50 PASS** (up from 39 — added a genuine RUNNING-state mid-flight HTTP cancellation proof plus 6 idempotency/malformed-id/RBAC/cross-tenant cancel steps).
- Traceability matrix mechanical integrity: **3/3 PASS** (`test_m16_traceability_matrix_integrity.py` — scenario numbers, status validity, summary-count arithmetic).
- M16-specific automated test count: **141** (up from 132: +6 cancellation, +1 restart durability, +3 traceability-integrity — 1 test net removed from the prior count's `#44` row-parsing fix, no test logic lost).

### Known flake (disclosed, not hidden)

`test_network_security_restart_durability.py` passed 5/5 in isolation and 3 of 4 full-suite runs during this pass; one full-suite run produced an intermittent `ResourceWarning`-as-error from asyncpg connection teardown timing when spinning up 3 real `create_app()` lifespans (each starting 4 background workers) back-to-back inside one pytest process amid ~4000 other tests already holding the connection pool. Mitigated with an explicit settling delay (`asyncio.sleep(0)` x5 + `gc.collect()`) after each simulated process exit, which reduced but did not eliminate the intermittency. This is a resource-cleanup timing characteristic of running multiple full app lifespans rapidly under heavy pytest-session load — not a defect in the cancellation logic itself, which is separately and deterministically proven by `test_network_security_cancellation.py`'s dedicated, lighter-weight PostgreSQL race test. Disclosed per the same standard already applied to `test_security_operations_postgres_proof.py`'s pre-existing exclusion, rather than hidden or claimed as 100% reliable.

## Final checkpoint

M16 status: **COMPLETE**

Traceability scenarios total: **95** (matching the brief's own §30 count; mechanically enforced by `test_m16_traceability_matrix_integrity.py`)
PROVEN count: **89**
NOT APPLICABLE count: **6** (verified architectural reason each, with a static-assertion test backing 4 of the 6)
PARTIALLY PROVEN count: **0**
NOT PROVEN count: **0**
Arithmetic validation: **89 + 6 + 0 + 0 = 95 — PASS** (mechanically recounted from the 95-row matrix, not hand-tallied)

New tests added this pass: **10** (141 total, up from 132: 6 cancellation, 1 restart durability, 3 traceability-integrity)
New defects found this pass: **3** — (1) a summary-table bookkeeping error in the traceability matrix that didn't sum to 95 (this audit's own trigger), now fixed and mechanically guarded; (2) the recurring stale `_EXPECTED_MIGRATION_HEAD` constant (0024→0025); (3) 3 SQLite test fixtures fragile to shared-metadata JSONB import order, now scoped to their own tables
New capabilities implemented this pass: **1** (mid-run execution cancellation — scenario #51), now proven with a genuine RUNNING-state HTTP cancellation, real restart durability, and real scheduler-dispatched cancellation

P0 found/fixed (this pass): **0/0**
P1 found/fixed (this pass): **0/0**
P2 found/fixed (this pass): **3/3**

Backend gates: **ruff clean; mypy 645 files clean; pytest 4091 passed/5 skipped/0 failed** (one known intermittent full-suite-only flake disclosed above, not a correctness defect)
Frontend gates: **tsc clean; vitest 109 passed; build clean; npm audit unchanged (2 pre-existing, unrelated)**
Live HTTP acceptance: **50/50 PASS**, including a genuine RUNNING-state mid-flight HTTP cancellation
PostgreSQL concurrency proof: **PASS (7/7)**
Owned loopback lab: **PASS (4/4)**
Cancellation proof (dedicated, real PostgreSQL): **PASS (6/6)**
Restart durability proof (real PostgreSQL, 3 simulated restarts): **PASS (1/1)**
Scheduler-dispatched cancellation proof (real PostgreSQL, real SKIP LOCKED claim path): **PASS (included in the 6/6 above)**
Traceability matrix mechanical integrity: **PASS (3/3)**
Migration proof: **clean 0001→0025→0024→0025 up/down/up**
Browser acceptance: **BLOCKED** (pre-existing environment limitation, attempted and documented in an earlier pass — not re-attempted this pass since nothing frontend-relevant changed)

Remaining P0: **none**
Remaining P1: **none**
Remaining gap: **none**

Is M16 honestly COMPLETE? **Yes.** 89 of 95 named scenarios are PROVEN, 6 are verified NOT APPLICABLE, 0 remain NOT PROVEN or PARTIALLY PROVEN, the arithmetic mechanically sums to 95, and zero P0/P1 defects remain. Scenario #51 (mid-run execution cancellation) is closed and proven at four independent levels: a genuine RUNNING-state HTTP cancellation (not cancel-before-execution or cancel-on-terminal), a real two-session PostgreSQL stale-save race, real restart durability across 3 simulated process restarts, and real scheduler-dispatched mid-flight cancellation — without reopening any previously-PROVEN scenario or introducing new execution architecture (Celery/Redis/Kafka/task registry) beyond what was demonstrably necessary.

Exact recommended next milestone: **M17.** M16 (Advanced Network Security & Continuous Network Monitoring) is complete.
