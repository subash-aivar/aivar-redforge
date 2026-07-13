# M14 — Continuous Validation Scheduler, Security Drift Detection & Revalidation Engine

Full detail report. See
[M14_COMPLETION_CHECKPOINT.md](M14_COMPLETION_CHECKPOINT.md) for the
concise summary.

## 1. Architecture decision

M14 evolves the M11-M13 one-shot validation flow into a continuous
control plane: CONTINUOUS VALIDATION POLICY → DUE-TIME SCHEDULING →
FRESH M10 AUTHORIZATION CHECK → REVALIDATION EXECUTION → CANONICAL
CURRENT STATE → PREVIOUS STATE COMPARISON → SECURITY DRIFT →
CONDITION/CORRELATION LIFECYCLE UPDATE → LIVE CHANGE FEED → CRISP DRIFT
RESULT.

This is a reconnaissance-first extension of M11's own
`domain/validation_execution/` bounded context — deliberately NO
`ContinuousScanExecution` or any second execution aggregate. Every
actual validation run, scheduled or on-demand, goes through the exact
same `ValidationExecutionService.create_and_run()` call used since M11,
gated by the same fresh-per-call `ExecutionPolicyService.evaluate()`
M10 check — never bypassed, never cached, never weakened for a
scheduled trigger.

Every explicit prohibition in the brief was honored by construction: no
demo code, no fake schedules, no fake drift, no frontend-owned
scheduling truth, no arbitrary cron expression from clients, no
arbitrary commands, no scanner flags, no exploit execution, no
credential attacks, no C2, no persistence, no destructive validation.

## 2. Reconnaissance findings

- `application/scheduler.py` exists but is dead code (unreferenced) —
  confirmed before choosing names, to avoid resurrecting it under a
  different meaning.
- `domain/posture/` already owns an unrelated concept named "drift"
  (LLM output/behavioral drift) — `DriftEvent`/`DriftType` would
  collide semantically even without a class-name clash. M14 uses
  `SecurityDriftEvent`/`SecurityDriftCategory` throughout.
- `ValidationExecution` (M11) already has every hook needed to add
  provenance without a new aggregate: a new `ExecutionTrigger` StrEnum
  (MANUAL/SCHEDULED/ON_DEMAND) plus `continuous_policy_id`/
  `scheduled_due_at` fields, set at construction time exactly like
  M12's own `adaptive_rule_id` precedent.
- `DLQReplayWorker` (Sprint 28/29) is the established background-worker
  lifecycle pattern in this codebase (bounded poll loop, `start()`/
  `stop()`, health probe) — mirrored exactly for
  `ContinuousValidationSchedulerWorker` rather than inventing a new
  pattern.
- `SecurityCondition`/`SecurityCorrelation` (M8/M9) both already carry
  an `identity_key` needed for stable cross-run comparison in a
  snapshot — confirmed present, not added.
- `TenantAssetService`/`AssetDTO.metadata` (M12/M13) already exposes
  each SERVICE asset's own `port` — needed for the port-scoped
  condition-reconciliation fix (see §7).
- `SqlAlchemyContinuousValidationPolicyRepository` needed a genuinely
  new capability the existing repositories didn't have: an atomic
  "claim the next due row" operation. The standard Postgres job-queue
  idiom — `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED)
  RETURNING *` — was chosen over a naive read-then-write because only
  the atomic form is safe under multiple concurrent scheduler workers.

## 3. Domain model

`domain/continuous_validation/value_objects.py`:

- `PolicyLifecycle` (DRAFT/ACTIVE/PAUSED/DISABLED) with an explicit
  `_POLICY_LIFECYCLE_TRANSITIONS` map and `is_legal_policy_transition()`
  — DISABLED is terminal, no re-activation path exists.
- `ValidationCadence` (HOURLY/EVERY_6_HOURS/DAILY/WEEKLY) — closed,
  server-owned; `cadence_interval_seconds()` is the only source of
  interval truth. No client-supplied cron expression is representable
  anywhere in the domain model.
- `SecurityDriftCategory` — 13 members covering condition/correlation/
  service/port drift; `CORRELATION_REACTIVATED` deliberately excluded
  (not yet representable given M9's own correlation lifecycle).
- `CLAIM_LEASE_SECONDS = 300` — a claimed-but-abandoned row (worker
  crash mid-run) becomes reclaimable after 5 minutes.

`domain/continuous_validation/entity.py`:

- `ContinuousValidationPolicy` — aggregate with `create()`/`activate()`/
  `pause()`/`resume()`/`disable()`/`is_due()`/`advance_schedule()`/
  `release_claim()`. `advance_schedule()` uses floor-division to
  coalesce missed runs (`intervals_missed = floor((now - next_due_at) /
  interval)`) rather than looping — a policy paused for a week and then
  resumed jumps directly to the next future due time, it does not
  attempt to "catch up" with a burst of executions.
- `SecurityDriftEvent` — append-only fact: category, subject
  (condition/correlation/service key), before/after value, detected_at.
- `ServiceSnapshotEntry` / `ValidationStateSnapshot` — the normalized
  comparison projection; `build()` classmethod constructs one from a
  completed execution's own evidence, `_compute_fingerprint()` is a
  deterministic sha256 over the normalized content, `is_identical_to()`
  is the fast-path zero-drift check.

`domain/continuous_validation/exceptions.py` —
`ContinuousValidationPolicyNotFoundError`, `InvalidPolicyTransitionError`,
`PolicyDisabledForExecutionError` (added during the P0-1 security fix,
see §7), `PolicyNotDueError`.

## 4. Distributed claiming and idempotency

`SqlAlchemyContinuousValidationPolicyRepository.claim_one_due_policy()`
issues a single atomic statement equivalent to:

```sql
UPDATE continuous_validation_policies
SET claimed_at = :now, claim_owner = :worker_id
WHERE id = (
    SELECT id FROM continuous_validation_policies
    WHERE organization_id = :org AND lifecycle = 'ACTIVE'
      AND next_due_at <= :now
      AND (claimed_at IS NULL OR claimed_at < :now - INTERVAL '300 seconds')
    ORDER BY next_due_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;
```

`SKIP LOCKED` means two concurrent workers racing for the same due row
never block each other and never double-claim it — proven under a
genuine concurrent race, not assumed (§11).

A second, independent idempotency layer sits at the database level: a
partial unique index on `validation_executions(continuous_policy_id,
scheduled_due_at) WHERE continuous_policy_id IS NOT NULL`. Even if a
claim were somehow duplicated, the second `create_and_run()` call for
the same `(policy_id, due_at)` pair fails with `IntegrityError` at
insert time — a genuine database constraint backstop, not
application-level trust alone.

## 5. Snapshot-based drift detection

`application/continuous_validation/snapshot_builder.py` builds a
`ValidationStateSnapshot` fresh from each completed execution's own
real evidence — reachable ports, resolved IPs, per-service protocol
state, active condition/correlation identity keys. The sha256
fingerprint over this normalized content gives an O(1) "did anything
change at all" fast path: an identical fingerprint against the
previous snapshot short-circuits to zero drift without a single
field-by-field comparison.

`application/continuous_validation/drift_detector.py`'s pure
`detect_drift()` performs the field-by-field comparison only when
fingerprints differ, emitting one `SecurityDriftEvent` per genuine
change: `_drift()` for scalar-valued changes (port reachability,
condition appeared/resolved/reactivated), `_service_drift()` for
per-service protocol-state transitions.

`CONDITION_REACTIVATED` is detected without a peek-before-ingest step:
a condition's own `first_observed_at` is compared against the
*previous* snapshot's `captured_at` — if `first_observed_at` is more
recent than the last snapshot, the condition is new-since-last-run
even though its identity_key existed before (M8's own
resolve-then-re-observe semantics already stamp a fresh
`first_observed_at` on reactivation).

## 6. Condition lifecycle: rule-ownership / revalidation coverage

`application/continuous_validation/condition_reconciliation.py`
implements the one deliberate, narrowly-scoped exception to M8's
original "explicit resolution only" design: absence-based resolution.
A condition may be resolved because this run's evidence *no longer
shows it*, but only when the specific rule's covering step(s)
genuinely, successfully re-checked the underlying fact THIS run.

`_CONDITION_RULE_COVERAGE` maps each known `stable_rule_id` to the
step type(s) that constitute real re-evaluation coverage for it (e.g.
`TLS_CERTIFICATE_EXPIRED` ← `tls_handshake`). A step "covers" its rule
only if it reached `StepStatus.COMPLETED`, and — for the four M13
protocol-validated step types (ssh_banner/mysql_handshake/
postgresql_handshake/redis_ping) — only if it reached
`protocol_validation_state == "validated"`, never merely
HINTED/INCONCLUSIVE. A rule whose covering step was skipped, failed,
timed out, cancelled, or fell short of VALIDATED is simply absent from
`compute_covered_rule_ids()` — its conditions are never touched this
run, silence rather than a false resolution.

## 7. P0 defects found and fixed (adversarial review)

Independent adversarial multi-agent code review covered DDD hygiene,
M10 authorization reuse, drift determinism, asset handling, correlation
reuse, Security Graph non-modification, tenancy isolation, and secrets
handling — all confirmed correct with no issue found. The
scheduler-correctness and condition-reconciliation dimensions surfaced
two genuine P0 defects and one P1, all fixed with dedicated
from-scratch regression tests written to reproduce each bug *before*
the fix.

**P0-1 — TOCTOU lost-update on policy lifecycle.**
`_release_and_advance()` captured a `ContinuousValidationPolicy` object
in memory at claim time, then — after the (potentially long)
`create_and_run()` call completed — called `repository.save()` on that
stale object, unconditionally overwriting `lifecycle`/`next_due_at`/
`claimed_at`/`claim_owner`. An operator's `disable()` or `pause()`
call, committed while the run was still in flight, was silently
clobbered back to ACTIVE with a freshly advanced schedule. Fixed by
adding `get_by_id_for_organization_for_update()` (a row-locked
`SELECT ... FOR UPDATE` read) to the repository, and a new
`_mutate_under_lock()` helper in `processor.py` that re-reads the
*current* row under lock, aborts the mutation entirely if the fresh
row is now DISABLED, and only otherwise applies the schedule/claim
update. `_release_and_advance()` and a new `_release_claim_only()`
(§8) both delegate to it. `policy_service.py`'s own `_transition()`
uses the same locked read for `activate`/`pause`/`resume`/`disable`,
closing the same race from the operator-action side.
Verified by `test_disable_during_in_flight_run_is_never_resurrected`.

**P0-2 — execution-wide vs. port-scoped condition coverage.**
`compute_covered_rule_ids()` treated a rule as covered if ANY step of
its covering type(s) succeeded ANYWHERE in the execution.
`PLAINTEXT_SENSITIVE_SERVICE_OBSERVED` is covered by four *different*
step types (ssh_banner/mysql_handshake/postgresql_handshake/
redis_ping), each tied to a *different* port and asset. This meant
validating MySQL on port 3306 would incorrectly authorize resolving a
stale, never-re-examined Redis-port (6379) condition for the exact same
rule_id, purely because "some" covering step type ran somewhere.
Fixed by adding `_PORT_SCOPED_RULES`, a new
`compute_covered_ports_by_rule()` (returns, per rule, the exact set of
ports whose covering step genuinely validated this run, parsed from
`source_fact_ref`), and `_asset_ports()` in `processor.py` (reads each
asset's own port from `AssetDTO.metadata["port"]`, populated since
M13). `_resolve_absent_conditions()` now skips resolution for a
rule+asset pair whenever the rule is port-scoped and that asset's own
port is not in the covered-ports set for this run.
Verified by `test_condition_reconciliation_is_scoped_per_port_not_globally`,
which required two sub-fixes during test authoring: (a) the hand-
crafted MySQL greeting's capability flags initially still had the
`CLIENT_SSL` bit set inside the `0xFFFF` test constant, defeating the
plaintext condition entirely — fixed with `0xFFFF & ~0x0800`; (b)
`RedisPingValidator` has no SSL-capability concept at all and
structurally can never produce `PLAINTEXT_SENSITIVE_SERVICE_OBSERVED`
— the test was redesigned to use the real local PostgreSQL server
(port 5432, no-SSL, matching M12/M13's own established precedent for
this port) as the second, always-covered port instead of Redis.

## 8. P1 defect found and fixed

**Over-eager schedule advancement on transient failure.**
`process_one_due_policy()` routed every exception from
`create_and_run()` — not just a genuine claim-collision — through
`_release_and_advance()`, which always advances `next_due_at` to the
next cadence boundary. A transient DB or network error would silently
skip an entire cadence period with zero audit trail. Fixed by
distinguishing `except IntegrityError` (the genuine claim-collision
backstop from §4 — safe, and correct, to advance normally) from
`except Exception` (any other failure — routed to the new
`_release_claim_only()`, which releases the claim *without* advancing
`next_due_at`, so the identical due boundary is retried on the next
poll cycle instead of being silently skipped).

## 9. P2 — documented, not fixed

Correlation lookup inside `_reconcile()` uses
`list_for_org(..., limit=500)` — organization-wide with client-side
filtering by asset. Correlations beyond the first 500 (by creation
order) are invisible to a given policy's drift snapshot. Judged
low-severity and scale-only (requires an organization with 500+ active
correlations); a proper fix needs a new per-entity correlation
repository query, deferred as a documented limitation rather than
built speculatively this milestone.

## 10. Pre-existing bug found (out of scope, flagged)

Adversarial API testing found `EntityId.from_string()` raises a bare
`ValueError` for a non-ULID string, which `ErrorHandlerMiddleware`
(catching only `RedForgeError` subclasses) does not map — falling
through to an unhandled 500 instead of a 404. Fixed locally at all
three new M14 GET-by-id call sites (`_safe_entity_id()` helpers in
`drift_service.py`/`policy_service.py`, inline in `processor.py`'s
`run_now()`). This same pattern likely predates M14 at other
`EntityId.from_string()` call sites (e.g.
`ValidationExecutionService.get_by_id()`); rather than fix unrelated
M11-M13 files under an M14 change, this was flagged via
`mcp__ccd_session__spawn_task` (task `task_9957666e`, "Fix malformed-ID
500s across pre-M14 GET-by-id endpoints") for separate follow-up.

## 11. Migration

Migration 0022: 3 new tables (`continuous_validation_policies`,
`validation_state_snapshots`, `security_drift_events`) plus 3 new
nullable columns on `validation_executions` (`trigger`,
`continuous_policy_id`, `scheduled_due_at`) and the partial unique
index `ix_validation_executions_policy_due_unique` on
`(continuous_policy_id, scheduled_due_at) WHERE continuous_policy_id
IS NOT NULL`. Clean migration proof: fresh empty database
(`redforge_m14_clean_migration_proof`) → `alembic upgrade head`
(0001→0022) in full → all 3 new tables and 3 new columns confirmed
present → `alembic history` confirms 0022 is the latest revision (no
M15 schema) → `alembic downgrade -1` cleanly removes them → `alembic
upgrade head` cleanly restores them, head back at 0022 → database
destroyed. `_assert_isolated_proof_database()` applied to every
destructive statement.

## 12. Background worker

`application/continuous_validation/scheduler_worker.py`'s
`ContinuousValidationSchedulerWorker` mirrors `DLQReplayWorker`'s
lifecycle pattern exactly: a bounded poll loop
(`runtime_continuous_validation_poll_interval_s`), `start()`/`stop()`,
and a health probe wired via `dynamic_health.py`'s new
`make_continuous_validation_scheduler_health_probe()`. Registered in
`RuntimeContainer` and started/stopped from `app.py`'s existing
lifespan hooks, in the same reverse-teardown order already established
for the replay worker.

## 13. REST API

`api/v1/continuous_validation.py` — 10 routes:
`POST/GET /continuous-validation/policies`, `GET
/continuous-validation/policies/{id}`, `POST
/continuous-validation/policies/{id}/activate|pause|resume|disable|run-now`,
`GET /continuous-validation/policies/{id}/drift`, `GET
/continuous-validation/drift/{id}`, `GET
/continuous-validation/change-feed`. All tenant-scoped exactly like
every prior milestone's API surface; `run-now` goes through the exact
same `create_and_run()` M10 gate as a scheduled trigger, with
`ExecutionTrigger.ON_DEMAND` recorded as provenance.

## 14. Frontend

A genuinely new page, `/continuous-validation` (not folded into
Validation Operations, since a continuous policy is a distinct
top-level concept from a single execution): policy list/create form,
lifecycle and cadence badges (`displayEnum()` for badges, Title-Case
labels reserved for dropdown option text — matching the established
`validation-operations-helpers.tsx` convention exactly), policy detail
view with a drift-event timeline. Added as its own nav entry.

## 15. Adversarial test coverage

- `tests/unit/test_continuous_validation_domain.py` — 32 pure domain
  tests (lifecycle transitions, cadence math, snapshot fingerprinting,
  drift categories).
- `tests/api/test_continuous_validation_isolation.py` — 20 full HTTP
  isolation tests (`_AlwaysAllowPolicyPort` test double for the M10
  gate, real SQLite schema, real auth flow, cross-tenant isolation,
  malformed-ID 404 regression).
- `tests/integration/test_continuous_validation_lab_proof.py` — 11
  dedicated real-PostgreSQL/owned-local-lab proof tests (§16).

## 16. Owned local continuous-validation lab proof

`test_continuous_validation_lab_proof.py` proves, against real owned
local TCP fixtures and a real local PostgreSQL server:

- STATE A — baseline run produces zero fabricated drift.
- STATE B — a real mutation (a fixture's behavior changes) produces
  drift on the very next scheduled run.
- STATE C — reintroducing the original state reactivates the *same*
  canonical condition (not a duplicate).
- Identical re-run produces zero new drift (fingerprint fast path).
- Real-socket port-reachability drift (a port closes/opens between
  runs).
- Revocation before dispatch yields zero network calls (M10 gate
  re-proven for a scheduled trigger).
- Concurrent scheduler claim (`asyncio.gather()`, a genuine race)
  yields exactly one execution for the same due policy.
- Restart preserves policy and drift state.
- Claim atomicity verified directly at the repository level.
- `test_disable_during_in_flight_run_is_never_resurrected` — the P0-1
  regression test.
- `test_condition_reconciliation_is_scoped_per_port_not_globally` — the
  P0-2 regression test, using a real local PostgreSQL server (5432) as
  the deliberately SSL-capable second port after discovering
  `RedisPingValidator` structurally never sets an SSL-capability flag.

## 17. PostgreSQL concurrency proof

Same file as §16 — `test_concurrent_scheduler_claim_yields_exactly_one_execution`
runs multiple simultaneous `claim_one_due_policy()` calls via
`asyncio.gather()` against the identical due policy row and asserts
exactly one caller receives it, the rest receive `None` — the
`FOR UPDATE SKIP LOCKED` claim proven under a genuine simultaneous
race, not a sequential re-run. Dedicated isolated database, destroyed
after.

## 18. Live API acceptance

Real server, real dedicated PostgreSQL, driven by a single `async def
main()` using `httpx.AsyncClient` + `ASGITransport` with manual
`app.router.lifespan_context()` management (replacing an initial
`TestClient`-plus-`asyncio.run()` combination that crashed with a
dual-event-loop conflict — `TestClient` owns its own internal portal
loop, incompatible with direct `asyncio.run()`-driven DB setup in the
same script). 41/41 steps PASS: register → create org → distinct
`SECURITY_MANAGER` approver seeded via direct membership (self-approval
is forbidden by M10 design) → register AI target → M10 authorization
create/submit/approve → ACTIVE → create continuous validation policy →
activate → run-now (goes through the real M10 gate; the owned local lab
HTTP server on 127.0.0.1 required the same test-only SSRF-boundary
monkeypatch used throughout the M11-M13 proof suites, since the
production `network_adapters.ALLOWED_ADDRESS_CLASSES` default is
PUBLIC-only) → drift observed on a real mutation → pause → resume →
disable → cross-tenant policy/drift isolation → unauthenticated 401 →
process restart preserves policy and drift history.

## 19. Browser acceptance

**BLOCKED** — for the identical, pre-existing environment reason
M10/M11/M12/M13's own checkpoints documented: the preview browser's
React tree never mounts past an initial "Loading…" placeholder on the
new `/continuous-validation` page, despite every JS bundle request
returning 200 OK and zero console errors logged. Environment-level
(hydration never completes in this preview harness), not an
application defect. Corroborated by clean `tsc`, a clean production
`next build` (route present at 4.44 kB), and 89 passing Vitest tests
(14 new).

## 20. Quality gates

**Backend**: `ruff check .` — all checks passed. `mypy src` (strict) —
601 source files, 0 issues. `pytest` — **3,913 passed, 5 skipped**
(baseline 3,850; +63, 0 regressions).

**Frontend**: `tsc --noEmit` — 0 errors. `next build` — succeeds,
`/continuous-validation` route present. `vitest` — **89 passed**
(baseline 75; +14). `npm audit` — 2 pre-existing moderate advisories
(postcss/next transitive), unchanged, no new dependencies.

## 21. Documentation

`docs/PROJECT_CONTEXT.md` §10 (Completed Milestones) updated with the
M14 row. This report and
[M14_COMPLETION_CHECKPOINT.md](M14_COMPLETION_CHECKPOINT.md) added.
