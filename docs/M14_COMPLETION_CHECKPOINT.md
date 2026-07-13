# M14 Completion Checkpoint

**Milestone:** M14 — Continuous Validation Scheduler, Security Drift Detection & Revalidation Engine
**Status: M14 COMPLETE**
**Full detail:** [M14_CONTINUOUS_VALIDATION_DRIFT_ENGINE_REPORT.md](M14_CONTINUOUS_VALIDATION_DRIFT_ENGINE_REPORT.md)

## Architecture decision
CONTINUOUS VALIDATION POLICY → DUE-TIME SCHEDULING → FRESH M10
AUTHORIZATION CHECK → REVALIDATION EXECUTION → CANONICAL CURRENT STATE
→ PREVIOUS STATE COMPARISON → SECURITY DRIFT → CONDITION/CORRELATION
LIFECYCLE UPDATE → LIVE CHANGE FEED → CRISP DRIFT RESULT. No second
execution aggregate — every real validation run, scheduled or
on-demand, goes through the SAME `ValidationExecutionService.
create_and_run()` M10 gate used since M11.

## Scheduler
`ContinuousValidationSchedulerWorker` mirrors `DLQReplayWorker`'s
lifecycle pattern exactly (bounded poll loop, start/stop, health
probe), wired into `RuntimeContainer`/`app.py`.

## Due-policy claiming
Atomic `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED)
RETURNING *` — the standard Postgres job-queue claim idiom, bounded
300-second lease. Proven to yield exactly one execution under a
genuine concurrent multi-worker race.

## Idempotency
Database-enforced via a partial unique index on
`validation_executions(continuous_policy_id, scheduled_due_at) WHERE
continuous_policy_id IS NOT NULL` — a real constraint backstop, not
application-level trust alone.

## Cadence
Closed, server-owned `ValidationCadence` (HOURLY/EVERY_6_HOURS/DAILY/
WEEKLY). No client-supplied cron expression representable anywhere.
Missed-run coalescing via floor-division schedule advancement, never a
catch-up loop.

## Drift taxonomy
Closed `SecurityDriftCategory` (13 members; `CORRELATION_REACTIVATED`
deliberately excluded). `ValidationStateSnapshot` sha256 fingerprint
gives a fast zero-drift path on a genuinely unchanged re-run.

## Condition reconciliation
Rule-ownership/revalidation coverage — only a rule whose covering
step(s) genuinely completed (protocol steps: genuinely reached
VALIDATED, never HINTED/INCONCLUSIVE) THIS run is eligible for
absence-based resolution. Refined to be PORT-scoped, not just
rule-scoped, for M13's multi-port protocol rule (see P0-2 below).

## Correlation reuse
M9's correlation engine reused completely unchanged — no new
correlation rule needed this milestone.

## Security Graph
No ontology bump — stays at v5. No new node/edge semantics.

## Migration head
**0022.**

## PostgreSQL concurrency proof
Multiple genuinely simultaneous `claim_one_due_policy()` calls
(`asyncio.gather()`) against the identical due policy converge on
exactly one winner, the rest receive `None` — proven, not assumed.
Dedicated isolated database, destroyed after.

## Owned local continuous-validation lab proof
STATE A (baseline, zero fabricated drift) → STATE B (real mutation
produces drift) → STATE C (reintroduction reactivates the same
canonical condition), plus identical-rerun zero-new-drift, real-socket
port-reachability drift, revocation-before-dispatch zero-network-calls,
concurrent-claim exactly-one-execution, restart-preserves-state,
repository-level claim-atomicity, and both P0 regression tests. 11/11
proof tests passing.

## Live API acceptance
Real server, real dedicated PostgreSQL, rewritten as `httpx.
AsyncClient`/`ASGITransport` with manual lifespan management
(replacing an initial `TestClient`+`asyncio.run()` dual-event-loop
crash). 41/41 steps PASS, including full M10 authorization setup,
policy create→activate→run-now→drift-on-mutation→pause→disable, and
cross-tenant isolation.

## Browser acceptance
**BLOCKED** — identical pre-existing environment limitation
M10/M11/M12/M13 already documented. Not an application defect —
corroborated by clean tsc/build and 89 passing Vitest tests (14 new).

## Bugs found/fixed
Two P0s found via adversarial review and fixed: (1) a TOCTOU
lost-update where a disabled-mid-run policy could be silently
resurrected by a stale in-memory save — fixed with a row-locked
read-modify-write (`_mutate_under_lock()`); (2) a multi-port protocol
condition rule was treated as globally covered by any one port's
successful validator — fixed with per-rule, per-port coverage
tracking (`compute_covered_ports_by_rule()`). One P1 fixed:
over-eager schedule advancement on transient (non-collision) failures
— fixed by releasing the claim without advancing on any exception
other than the expected `IntegrityError`. One P2 documented, not
fixed: correlation lookup capped at 500 org-wide, scale-only. One
pre-existing, out-of-scope bug found (malformed-ID 500→404) — fixed
locally at all 3 new M14 call sites, flagged via spawned follow-up
task for the same pattern at pre-M14 call sites.

## Backend quality gates
ruff: all checks passed. mypy (strict) on `src/`: 601 files, 0 issues.
pytest: **3,913 passed, 5 skipped** (baseline 3,850; +63, 0 regressions).

## Frontend quality gates
tsc: 0 errors. build: succeeds (`/continuous-validation` route
present). vitest: **89 passed** (baseline 75; +14).

## npm advisory state
2 pre-existing moderate advisories (postcss/next transitive) —
unchanged, no new dependencies.

## PROVEN
Atomic SKIP-LOCKED claiming (including under a genuine concurrent
race), database-enforced execution idempotency, snapshot-fingerprint
zero-drift fast path, drift detection across STATE A/B/C, port-scoped
condition reconciliation, the TOCTOU and port-scoping fixes (each via
a dedicated from-scratch regression test), M9 correlation reuse, clean
migration, live API acceptance (all 41 steps), quality gates (backend
+ frontend).

## CLAIMED-UNPROVEN
None.

## FAILED
None.

## BLOCKED
Interactive browser click-through (preview environment hydration
limitation, not an application defect — identical to M10-M13).

## Remaining M14 P0
None.

## Remaining M14 P1
None known. (One documented P2 — 500-row correlation lookup cap —
and one spawned follow-up task for a pre-existing malformed-ID 500
pattern at pre-M14 call sites, both explicitly out of scope for M14
itself.)

## Is M14 honestly COMPLETE?
**Yes.**

## Exact recommended next milestone
**M15** — natural continuations include (a) live SSE-based event/drift
streaming now that the change-feed has a proven, ordered, tenant-scoped
foundation to stream from (M13's own checkpoint already flagged this
as ready once M14 landed), (b) a dedicated per-entity correlation
repository query to remove the 500-row org-wide cap documented as
M14's P2, or (c) extending the closed `SecurityDriftCategory` taxonomy
to represent `CORRELATION_REACTIVATED`, deliberately deferred this
milestone as not yet representable.
