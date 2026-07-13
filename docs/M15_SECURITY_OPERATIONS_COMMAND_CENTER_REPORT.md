# M15 — Security Operations Command Center & Real-Time Execution Telemetry

Full detail report. See
[M15_COMPLETION_CHECKPOINT.md](M15_COMPLETION_CHECKPOINT.md) for the
concise summary.

## 1. Architecture decision

M15 transforms the M1-M14 security engines into ONE enterprise
operational command plane: SECURITY TRUTH PRODUCERS → CANONICAL
OPERATIONAL EVENT PROJECTION → TENANT-SAFE EVENT STREAM → SECURITY
OPERATIONS READ MODEL → COMMAND CENTER → EXECUTION LIVE TELEMETRY →
SECURITY CHANGE FEED → CRISP OPERATOR DRILL-DOWN.

This bounded context owns nothing and mutates nothing. Every write
still goes exclusively through the pre-existing M10-M14 services
(`ValidationExecutionService`, `ContinuousValidationPolicyService`,
`SecurityDriftService`). There is no publish/mutation endpoint anywhere
in `api/v1/security_operations.py` — every route is structurally a GET,
proven directly by asserting the router's own registered HTTP methods.

## 2. Reconnaissance findings

- The pre-existing Sprint 24/25 generic event-sourcing subsystem
  (`domain/platform/events.py`'s `EventEnvelope`/`EventBatch`,
  `infrastructure/platform/event_store.py`'s `PostgreSQLEventStore`,
  the `platform_events` table from migration 0007) is fully built —
  global-position sequence, tenant-scoped, ordered indexes exactly
  shaped for this milestone's need — but has **zero production
  writers**. Grepping for `EventBatch(`/`event_store.append(`/
  `make_envelope(` construction sites outside test files returns
  nothing.
- The entire pre-existing domain-event-collection convention used by
  organizations/memberships/targets (`collect_events()` +
  `EventPublisherPort.publish()`) also terminates in a no-op: the only
  real implementation, `infrastructure/events.py`'s
  `NullEventPublisher`, discards every event. This is a repo-wide dead
  pattern, not specific to any one bounded context.
- `application/scheduler.py` is confirmed dead/unreferenced code (no
  new collision risk).
- `ValidationExecution` (M11) already has a genuinely comprehensive
  durable event log — `validation_execution_events`, with 19 of 20
  `ExecutionEventType` values already actively emitted at their exact
  transition points in `execution_service.py`. Two gaps: the
  AUTHORIZED→RUNNING transition (`execution.start()`,
  `execution_service.py`) had no corresponding `_emit()` call, and an
  operator's cancellation *request* (distinct from the eventual
  observed cancellation) was never durably logged.
- `ContinuousValidationPolicy` (M14) has **no durable lifecycle log at
  all** — only the current `lifecycle` column survives; the domain
  entity's own `PolicyActivated`/`PolicyPaused`/etc. events are
  collected into an in-memory buffer that, like every other bounded
  context's `collect_events()` output, is never drained in production.
- Runtime health (`application/platform/dynamic_health.py`,
  unchanged since Sprint 26) is **100% live-computed on every call**,
  with zero persistence and zero transition-detection logic anywhere —
  `checked_at` records when a check ran, never when a status last
  changed.
- `DLQReplayWorker`'s checkpoint/poll pattern
  (`idempotent_projection_engine.py`) is the established background-
  worker lifecycle shape in this codebase — mirrored exactly for the
  new `RuntimeHealthTransitionWorker`.
- JWT/session model: bearer-header-only everywhere (`api/security.py`),
  zero cookie infrastructure anywhere in the codebase. A token becomes
  organization-scoped only via `POST /auth/organizations/{id}/select`;
  `TenantContext.organization_id` is trusted directly from the signed
  JWT's `org` claim, never from client request data.
- A genuine, separate Super Admin/platform-role system exists
  (`PlatformContext`/`require_platform_permission`,
  `domain/platform_identity/`) with real cross-org endpoints for
  users/organizations/access/audit, but it does **not** currently
  expose cross-tenant *security data* (findings/validations/
  executions) — `PlatformPermission.PLATFORM_SECURITY_READ` is
  declared and granted to SUPER_ADMIN/SECURITY_ADMIN/AUDITOR but wired
  to zero endpoints. M15 does not add a cross-tenant security-data
  view under this permission — that would be new scope beyond a
  tenant-scoped read projection, honestly documented as not built
  rather than fabricated.
- Migration head at the start of this milestone: 0022. Security Graph
  ontology: v5 (unchanged — M15 touches no graph node/edge semantics).

## 3. Architecture decision: event infrastructure reuse vs. evolution

Given the above, M15 deliberately does **not** wire into the dormant
`platform_events`/`EventStore` machinery. Doing so would have required
invasive edits deep inside `execution_service.py`'s 1000+-line, 3900-
test-covered dispatch loop, resurrecting a subsystem with zero
production track record, and confronting a real correctness hazard
(the store's own docstring discloses `global_position` is unique but
not strictly commit-order-monotonic under concurrent transactions).

Instead, M15 extends the two bounded contexts that **already** have
comprehensive, production-proven durable logs
(`validation_execution_events`, `security_drift_events`) and adds two
small, purpose-built, additive tables for the two genuine gaps found
(§2): `continuous_validation_policy_lifecycle_events` and
`runtime_component_health_transitions` (+ `runtime_component_health_state`
for dedup bookkeeping only). The cross-domain "Operational Event" feed
is a query-time merge across these four sources
(`application/security_operations/stream_service.py`'s
`fetch_merged_candidates()`), not one physical event table.

This is a considered, disclosed deviation from the textbook "wire into
the one true event store" answer — the trade-off is minimized blast
radius on a battle-tested core versus the theoretical elegance of a
single physical stream. Given this milestone's time budget and the
existing subsystem's complete absence of production usage, minimizing
regression risk on M11-M14 won out.

## 4. Cursor & ordering

A composite, lexicographically-sortable string cursor —
`f"{occurred_at_fixed_width_iso}|{source_tag}|{row_id}"` — IS the SSE
wire-level `id:`/`Last-Event-ID` value directly; no separate numeric
global position is needed. ISO-8601 UTC timestamps rendered with a
fixed 6-digit fractional part (`_canonical_ts()`) sort identically
whether compared lexicographically or chronologically — a
`datetime.isoformat()` call alone would silently omit the fractional
part when `microsecond == 0`, breaking this property, which is why a
dedicated formatter exists.

`source_tag` (E/D/P/R for execution/drift/policy-lifecycle/runtime)
breaks ties deterministically on the rare case of an identical
microsecond across two different sources. `row_id` (each source's own
ULID primary key) guarantees global uniqueness as the final tiebreaker.

**Commit-visibility safety margin.** `EVENT_VISIBILITY_LAG_SECONDS`
(2.0s default) — a row is only surfaced once its `occurred_at` is
older than `now - lag`. This guards against a real hazard: a slower
transaction with an EARLIER `occurred_at` that commits AFTER a faster
transaction with a LATER `occurred_at` has already gone out — without
the margin, a client's cursor would advance past the later event and
permanently skip the earlier one once it finally commits. Proven
directly in `tests/integration/test_security_operations_postgres_proof.py::
test_ordering_survives_out_of_order_commit_under_visibility_lag` via
two genuinely concurrent sessions with controlled commit ordering.

## 5. Operational event envelope & projection registry

`domain/security_operations/operational_event.py`'s `OperationalEvent`
is the ONE shape ever returned to a browser — built exclusively by
`application/security_operations/projection_registry.py`'s projector
functions, never by forwarding a raw internal row's own fields. Every
field is a short, bounded, backend-controlled scalar (240-character
hard truncation on title/summary as a defensive backstop). Traced every
string-interpolation call site in the projection registry back to its
payload origin — all values (`reason_code`, `step_type`,
`stable_rule_id`, `reachable_ports`) are bounded, pre-extracted
constants, never a raw exception, SQL string, or evidence blob.

`SourceDomain` and `OperationalImportance` are closed, server-owned
enums. The registry is deliberately selective, not exhaustive — only
"operationally significant" execution event types are projected onto
the cross-domain Live Operations Feed / Security Change Feed (the
brief explicitly warns against flooding the feed with every internal
step); the FULL, unfiltered per-execution event list remains available
separately via the execution telemetry detail endpoint.

## 6. Execution telemetry & phase derivation

`application/security_operations/execution_phase.py` maps every
`ExecutionEventType` to a closed `ExecutionPhase` (AUTHORIZATION →
RESOLUTION → DISCOVERY → SERVICE_VALIDATION → ADAPTIVE_VALIDATION →
PROTOCOL_VALIDATION → CONDITION_PROCESSING → CORRELATION → SNAPSHOT →
DRIFT → COMPLETED → UNKNOWN); a step-level event refines to
PROTOCOL_VALIDATION specifically when its payload's `step_type` is one
of the 4 M13 protocol-validated types. An unmapped event type resolves
to UNKNOWN, never a fabricated phase.

`application/security_operations/execution_telemetry_service.py`
builds the summary/detail views directly from `ValidationExecutionService.
list_by_organization()`/`list_events()` — no new execution aggregate,
no fake progress percentage anywhere (proven by an explicit `"%" not in
phase` assertion in both the isolation tests and the live API
acceptance run). `result_summary` is a crisp, deterministic sentence
built from real counts (services validated, conditions observed,
failure/denial reason) — never LLM-authored prose.

Two pre-existing gaps closed with minimal, low-risk edits mirroring the
exact `_emit()` pattern already used 19 other times in
`execution_service.py`: `EXECUTION_STARTED` on the AUTHORIZED→RUNNING
transition, `CANCELLATION_REQUESTED` on an operator's cancel call. A
pre-existing malformed-ID→500 gap (the same pattern M14 itself found
and flagged for pre-M14 call sites) was closed locally at this new
call site (`get_detail()` now catches `ValueError` from
`EntityId.from_string()` and raises `ValidationExecutionNotFoundError`
→ 404).

## 7. Security operations summary & change feed

`SecurityOperationsSummaryService` computes every count live: active
targets/assets via existing list methods, running/blocked/failed
validations via real `GROUP BY` queries bounded by server-controlled
periods (1h/24h/7d/30d — closed `BoundedPeriod` enum, no client SQL),
critical/high conditions via the existing `get_summary_for_org()`
aggregate, active correlations and canonical assets via a documented
1000-row bounded-list-length approximation (mirroring M14's own
established 500-row correlation-lookup precedent), and runtime
unhealthy count from the live health engine. **Deliberately omits**
"recently resolved conditions" — `security_conditions` (M8) has no
dedicated resolution timestamp (only `last_observed_at`, stamped on
every fresh *observation*, not on `resolve()`), and fabricating an
approximation would silently misrepresent when a condition was
actually resolved. Documented as a considered omission, not an
oversight.

`SecurityChangeFeedService` reuses the identical four-source merge
`stream_service.py` uses for the live feed, applied as a bounded,
filterable, paginated historical query (source domain / importance /
entity ID filters, all closed enums) instead of a live poll.

## 8. Durable SSE stream

`GET /api/v1/security-operations/events/stream` — tenant-scoped,
RBAC-gated, cursor-resumable. Each iteration opens one short-lived,
bounded DB query via `poll()`; no per-client unbounded in-memory queue,
no database connection held between polls. A malformed `Last-Event-ID`
safely resets to reading from the beginning rather than ever producing
a 500 — since none of the four source tables prune/retire old rows,
there is no "expired cursor" case to handle separately.

`GET /api/v1/security-operations/events` is a non-streaming JSON-
polling variant of the identical cursor semantics, for clients that
prefer request/response polling over an open stream.

## 9. SSE authentication decision

A native browser `EventSource` cannot set an `Authorization` header,
and this codebase has no cookie-based session mechanism to lean on
instead. Rather than add a new stream-ticket-minting endpoint or
introduce cookies as a parallel auth mechanism, the frontend client
(`useSecurityOperationsStream.ts`) reads the `text/event-stream` wire
format itself over a `fetch()` `ReadableStream`, sending the exact same
`Authorization: Bearer` header every other request already uses — zero
new backend auth surface, zero new token type. The JWT is never placed
in a URL or query string (proven directly in both the frontend hook
unit test and the live API acceptance script).

## 10. Multi-instance safety

Nothing relies on in-process memory as the source of truth for cursor
or resume state. The cursor is a pure function of durable database
rows (`make_cursor()`); the frontend's own cursor tracking is a
convenience for constructing the next `Last-Event-ID` header, not an
authority. Proven directly: the live API acceptance script starts a
SECOND, entirely fresh `uvicorn` process and confirms it resumes from
the exact same durable cursor a client obtained from the FIRST process
instance — no shared process memory anywhere in that proof.

## 11. Runtime operations

`RuntimeOperationsService` (the `/runtime` read endpoint) always calls
the live `RuntimeHealthEngine.aggregate_health()` directly — current
health status is never read from the new dedup-bookkeeping table,
preserving the pre-existing "100% live-computed" guarantee unchanged.

`RuntimeHealthTransitionWorker` (background, mirrors
`DLQReplayWorker`'s lifecycle shape exactly) polls the same health
engine and calls `SqlAlchemyRuntimeHealthRepository.
record_transition_if_changed()`, which uses `SELECT ... FOR UPDATE` on
the single current-status row to serialize concurrent instances —
whichever transaction gets there first records the transition; every
other concurrently-blocked instance sees the row already updated and
correctly does nothing. Proven under a genuine `asyncio.gather()` race
(8 concurrent callers, exactly 1 records the transition). Runtime
health is deliberately **broadcast** into every organization's
feed/stream (not tenant-scoped — runtime components are platform-wide
infrastructure) — the one documented, deliberate exception to strict
tenant isolation, proven alongside the isolation tests themselves so
it's never mistaken for a leak.

## 12. RBAC

`Permission.SECURITY_OPERATIONS_READ` — a new member on the existing
tenant `Permission` enum, granted to all six roles (OWNER/ADMIN/
SECURITY_MANAGER/ANALYST/MEMBER/VIEWER), mirroring `VALIDATIONS_READ`'s
own universal distribution, since this bounded context is a pure read
projection over data every role can already read some form of. The
`OperatorPermission`/`require_operator_permission` naming from stale
prior-session task history does not exist anywhere in the repository
and was not reintroduced — repository truth wins over a stale task
description. Because the permission is universal, there is no distinct
role left to produce a genuine "authenticated but wrong permission" 403
for this specific permission; that dimension is instead proven at the
RBAC-table level (`test_all_tenant_roles_have_security_operations_read`)
and via the unauthenticated-401 tests.

## 13. Migration

Migration 0023 adds exactly 3 small tables:
`continuous_validation_policy_lifecycle_events` (FK to
`continuous_validation_policies`), `runtime_component_health_state`
(dedup bookkeeping, platform-wide), `runtime_component_health_transitions`
(durable transition history, platform-wide). No existing table's
schema is touched. Clean migration proof: fresh empty database
(`redforge_m15_clean_migration_proof`) → `alembic upgrade head`
(0001→0023, all 23 migrations) → all 3 new tables + FK constraint +
indexes confirmed present via `\d` → `alembic history` confirms 0023 is
latest (no M16 schema) → `alembic downgrade -1` cleanly removes them →
`alembic upgrade head` cleanly restores them, head back at 0023 →
database destroyed.

**A genuine near-miss during this proof, disclosed transparently**: an
initial attempt set `DATABASE_URL` (without the app's actual
`REDFORGE_` `env_prefix`) before running `alembic upgrade head`,
which pydantic-settings silently ignored, falling back to the default
connection string — the **shared dev database**. This upgraded the
shared dev DB from 0022 to 0023 directly. Verified this was safe:
migration 0023 is purely additive (3 new tables, no drops), and the
shared dev DB needed exactly this upgrade anyway since
`_EXPECTED_MIGRATION_HEAD` is now `"0023"`. No downgrade was ever run
against it. The correct isolated proof (using `REDFORGE_DATABASE_URL`)
was then run properly against a genuinely separate database.
`application/platform/startup_validator.py`'s `_EXPECTED_MIGRATION_HEAD`
bumped to `"0023"`; `test_sprint29_replay_pipeline.py`/
`test_startup_validator.py`'s hardcoded `"0022"` assertions updated to
`"0023"` (the same pre-existing hardcoded-head pattern M14 itself
found and fixed for `"0021"`→`"0022"`).

## 14. API surface

`api/v1/security_operations.py` — 7 routes, all GET, all gated by
`Permission.SECURITY_OPERATIONS_READ`: `/summary`, `/changes`,
`/events`, `/events/stream`, `/executions`, `/executions/{id}`,
`/runtime`. Proven structurally read-only by asserting every route's
registered HTTP methods are a subset of `{GET, HEAD}`
(`test_no_write_methods_registered_on_security_operations_router`).

## 15. Frontend

`frontend/src/lib/securityOperations.ts` (API client),
`useSecurityOperationsStream.ts` (SSE client hook),
`security-operations-helpers.tsx` (closed-enum presentation helpers,
mirroring `continuous-validation-helpers.tsx`'s established
convention exactly), `security-operations/page.tsx` (command center:
operations header with a truthful CONNECTED/RECONNECTING/DISCONNECTED
badge — never "LIVE" merely because the page loaded — summary cards,
live operations feed, active executions, security change feed, runtime
components), `security-operations/executions/[id]/page.tsx` (telemetry
detail: backend-derived phase, full timeline, crisp result summary, no
fabricated percentage anywhere).

## 16. Adversarial test coverage

- `tests/unit/test_security_operations_domain.py` — 14 pure unit tests
  (bounded-period mapping, projection registry selectivity/importance
  mapping, phase derivation, cursor lexicographic-chronological
  equivalence including the microsecond-zero edge case, malformed-
  cursor safe degradation).
- `tests/api/test_security_operations_isolation.py` — 23 full HTTP
  isolation tests: unauthenticated-401 across all 5 GET endpoints and
  the stream, cross-tenant 404/isolation (execution detail, summary,
  events), malformed execution ID / cursor / state filter / source
  domain / period all handled without a 500, cursor resume with no
  duplicates, deterministic cursor ordering, no write methods on the
  router, sentinel-absence across every response body, backend-derived
  phase with no fabricated percentage, runtime components restricted
  to known statuses, RBAC-table-level universal-permission proof, and
  an SSE-frame-formatting unit test (see §17 for why full HTTP
  consumption of the stream isn't attempted here).
- `tests/integration/test_security_operations_postgres_proof.py` — 7
  dedicated real-PostgreSQL integration tests (see §18/§19).

## 17. A genuine testability finding (not a product defect)

While writing the SSE isolation tests, a probe confirmed httpx's
`ASGITransport` does **not** propagate a client-side disconnect to
`Request.is_disconnected()` (real ASGI servers like `uvicorn` detect
genuine socket closure; `ASGITransport` has no socket to close), and
appears to buffer an entire streaming response rather than yielding
partial chunks — attempting to consume even one line of an
intentionally infinite `StreamingResponse` under `ASGITransport` hangs
indefinitely. This is an environment/test-harness limitation, not a
product bug (the pattern is standard, widely-used FastAPI/Starlette
SSE behavior under a real server). Resolved by: unit-testing the SSE
frame-formatting helper directly, proving the underlying `poll()`
method's correctness via the equivalent non-streaming `/events`
endpoint (the SSE handler is a thin framing wrapper around the exact
same method), and proving genuine end-to-end SSE streaming/disconnect/
reconnect against a REAL running `uvicorn` server in the live API
acceptance script (§19).

## 18. Owned local operations lab proof

`test_security_operations_postgres_proof.py` proves, against a real
owned local HTTP target and real PostgreSQL: a real
`ValidationExecution`'s own durable events visible through `poll()`;
a `ContinuousValidationPolicy`'s create/activate/pause lifecycle
transitions visible as operational events; cursor resume strictly
excludes everything already seen (no duplicates); restart durability
(a brand-new `SecurityOperationsStreamService` instance, simulating a
process restart, reads back the identical event history); cross-tenant
isolation (org B never sees org A's execution/policy events) proven
alongside the deliberate runtime-transition broadcast exception (both
orgs DO see the same platform-wide runtime transition).

## 19. PostgreSQL concurrency proof

Same file — two dedicated proofs: (a) 8 genuinely concurrent
`record_transition_if_changed()` calls for the identical HEALTHY→
UNHEALTHY flip, via real `asyncio.gather()`, converge on exactly ONE
recorded transition row; (b) the commit-visibility safety margin's
anti-skip property proven directly — two real, separate sessions, one
holding an uncommitted transaction with an EARLIER `occurred_at` while
a second session's LATER-`occurred_at` event commits first; a
mid-race `poll()` shows neither (both too recent under the lag); once
the first session finally commits and the lag is removed, both events
appear, correctly ordered by `occurred_at` despite committing in the
opposite order. Dedicated isolated database
(`redforge_security_operations_proof_test`), destroyed after.

## 20. Live API acceptance

A REAL running `uvicorn` server (not `ASGITransport` — see §17), real
dedicated PostgreSQL, real `httpx.AsyncClient` over genuine loopback
TCP. 47/47 steps PASS: startup/health, tenant registration, M10
authorization (distinct-approver-approves), validation execution
creation with real telemetry detail (non-empty timeline, no fake
percentage), continuous validation policy create/activate/run-now,
summary counts reflecting real state, **genuine chunked-transfer SSE
connection and frame delivery**, Last-Event-ID reconnect with strictly-
newer, non-duplicate resume, malformed-cursor safety, runtime
operations, bounded-period/page-size rejection (422), full cross-
tenant isolation (summary/events/execution-guess/policy-guess all
non-disclosing), unauthenticated 401 for both REST and the stream, no
mutation endpoint under this namespace, malformed execution ID → 404
not 500, and — after a full process restart with a second, independent
`uvicorn` instance — durable cursor resume proven from a server that
shares no process memory with the first.

## 21. Browser acceptance

**BLOCKED** — for the identical, pre-existing environment reason
M10-M14's own checkpoints documented: the preview browser's React tree
never mounts past an initial "Loading…" placeholder, reproduced
identically on the new `/security-operations` route with a real
backend and frontend dev server both running. Every JS bundle request
returned 200 OK and zero console errors were logged. Environment-level
(hydration never completes in this preview harness), not an
application defect. Corroborated by clean `tsc`, a clean production
`next build` (route present, `/security-operations` 4.04 kB,
`/security-operations/executions/[id]` 2.8 kB dynamic), and 106
passing Vitest tests (17 new).

## 22. Independent adversarial review

A fresh subagent, given no context beyond the code itself, reviewed
tenant isolation, cursor integrity, RBAC coverage, sanitization,
backpressure, runtime-transition dedup, multi-instance safety, and
migration safety. Found **zero P0/P1 defects** — tenant isolation,
RBAC, cursor integrity, and sanitization all held under deliberate
adversarial testing. Three genuine P2s found and fixed:

- **Frontend dedup-Set leak** (`useSecurityOperationsStream.ts`): the
  bounded-buffer trim deleted from the dedup `Set` by `event_id`, but
  the `Set` is keyed by the SSE frame `id` (== `cursor`) — the delete
  never matched, so the `Set` grew unbounded for a long-lived tab.
  Fixed: delete by `cursor`, the actual insertion key.
- **First-sighting INSERT race** (`runtime_health_repository.py`):
  `SELECT ... FOR UPDATE` cannot lock a row that doesn't exist yet, so
  two instances observing a brand-new component for the very first
  time concurrently could both attempt the same-primary-key INSERT,
  raising `IntegrityError` for the loser. Fixed with
  `INSERT ... ON CONFLICT DO NOTHING` — correct either way, since a
  first observation is a baseline, not a transition to report.
- **Unbounded `result_summary`** (`execution_telemetry_service.py`):
  lacked the same defensive length cap `OperationalEvent` itself
  already applies to title/summary. Fixed with the identical
  truncate-as-a-backstop pattern (500 chars).

## 23. Bugs found/fixed — summary

Two genuine durable-trail gaps closed in M11's `execution_service.py`
(EXECUTION_STARTED, CANCELLATION_REQUESTED — both single-line additions
matching an existing 19-occurrence pattern). One pre-existing
malformed-ID→500 pattern (the same one M14 itself found and flagged)
closed locally at the one new call site that inherited it. Three P2s
found by independent adversarial review, all fixed (§22). One transient,
unrelated pre-existing test flake observed once in the full 3957-test
run (`test_concurrent_execution_converges_on_one_canonical_service_asset`,
an M13 proof test) and confirmed non-reproducing on immediate re-run
in isolation and in a second full-suite run — not a regression from
this milestone's changes, no file this milestone touches is involved
in that test's failure path.

## 24. Backend quality gates

`ruff check .` — all checks passed. `mypy src` (strict) — 619 source
files, 0 issues. `pytest` — **3,957 passed, 5 skipped** (baseline
3,913; +44 new tests: 14 unit + 23 API-isolation + 7 PostgreSQL
integration = 44).

## 25. Frontend quality gates

`tsc --noEmit` — 0 errors. `next build` — succeeds,
`/security-operations` and `/security-operations/executions/[id]`
routes present. `vitest` — **106 passed** (baseline 89; +17: 7 page
tests, 4 execution-detail-page tests, 6 stream-hook tests). `npm audit`
— 2 pre-existing moderate advisories (postcss/next transitive),
unchanged, no new dependencies.

## 26. Documentation

`docs/PROJECT_CONTEXT.md` §10 (Completed Milestones) updated with the
M15 row. This report and
[M15_COMPLETION_CHECKPOINT.md](M15_COMPLETION_CHECKPOINT.md) added.
