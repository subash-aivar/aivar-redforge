# M15 Completion Checkpoint

**Milestone:** M15 — Security Operations Command Center & Real-Time Execution Telemetry
**Status: M15 COMPLETE**
**Full detail:** [M15_SECURITY_OPERATIONS_COMMAND_CENTER_REPORT.md](M15_SECURITY_OPERATIONS_COMMAND_CENTER_REPORT.md)

M15 status: **COMPLETE**

Architecture decision: One tenant-safe, read-only operational command
plane over M1-M14's own security truth. Owns nothing, mutates nothing —
every write still goes through the pre-existing M10-M14 services.

Operations read-model ownership: `domain/security_operations/` +
`application/security_operations/` — a pure projection layer; canonical
truth stays exclusively in `validation_executions`,
`continuous_validation_policies`, `security_conditions`,
`security_correlations`, `security_drift_events`.

Platform event reuse decision: The dormant Sprint 24/25 `platform_events`
event store has zero production writers repo-wide (confirmed by
reconnaissance) — reusing it would have meant invasive edits deep
inside the 1000+-line, 3900-test `execution_service.py` dispatch loop.
M15 instead extends the two ALREADY-comprehensive, production-proven
durable logs (`validation_execution_events`, `security_drift_events`)
and adds two small additive tables for the two genuine gaps found
(policy lifecycle, runtime health transitions). A disclosed, considered
deviation from the textbook answer, justified by regression-risk
management.

Source domains: AUTHORIZATION, VALIDATION, CONTINUOUS_VALIDATION,
SECURITY_DRIFT, SECURITY_CONDITION, SECURITY_CORRELATION, RUNTIME
(closed enum; AI_RED_TEAM excluded — no real event producer exists).

Operational event envelope: `OperationalEvent` — cursor, event_id,
organization_id, source_domain, importance, title, summary,
entity_type, entity_id, occurred_at, schema_version. Built exclusively
by server-side projectors; 240-char truncation backstop; no field for
a stack trace, SQL, raw HTTP body, header, cookie, bearer token,
credential, or private key — by construction.

Importance mapping: closed `OperationalImportance` (INFO/NOTICE/
WARNING/HIGH/CRITICAL), deterministic per event type/category — never
a universal CVSS-like score, never client-computed.

Projection registry: `application/security_operations/
projection_registry.py` — deliberately selective (not every internal
event type is surfaced on the cross-domain feed), every title/summary
built from bounded, pre-extracted scalars only.

SSE architecture: `GET /events/stream` — one short-lived, bounded DB
query per poll iteration via the same `poll()` the non-streaming
`/events` endpoint uses; no per-client unbounded queue; no DB
connection held between polls.

SSE authentication decision: `fetch()` + manual `ReadableStream`
parsing of `text/event-stream`, sending the standard `Authorization:
Bearer` header — no native `EventSource` (can't set headers), no new
stream-ticket endpoint, no cookies, JWT never in a URL.

Cursor semantics: composite string
`occurred_at_fixed_width_iso|source_tag|row_id` — IS the SSE wire-level
id/Last-Event-ID value directly.

Last-Event-ID behavior: resumes strictly after the given cursor;
malformed cursor safely resets to the beginning (never a 500) — no
"expired cursor" case exists since nothing is pruned.

Event ordering: lexicographic == chronological by construction; a
commit-visibility safety margin (2s default) prevents an earlier-
`occurred_at` event that commits later from ever being permanently
skipped — proven under a genuine out-of-order-commit race.

Replay/backpressure: every merge query is bounded
(`per_source_limit`/`CHANGE_FEED_MAX_PAGE_SIZE=200`); no unbounded
query path exists.

Multi-instance safety: cursor and resume state are pure functions of
durable database rows — proven by a second, independent `uvicorn`
process resuming from the same cursor after a full restart.

Execution telemetry: read-only projection over the existing
`ValidationExecution` aggregate + its own event log; no new execution
aggregate.

Phase derivation: closed `ExecutionPhase` enum, backend-derived from
event type (+ step_type refinement for protocol steps); unmapped →
UNKNOWN; no fake progress percentage anywhere (asserted directly in
tests and the live acceptance run).

Security operations summary: canonical counts only, bounded periods
(1h/24h/7d/30d, closed enum); one metric ("recently resolved
conditions") deliberately omitted rather than fabricated (no canonical
resolution timestamp exists).

Security change feed: same four-source merge as the live stream,
applied as a bounded, filterable, paginated historical query.

Runtime operations: `/runtime` always live-computed via the existing
health engine; a separate worker detects and durably records genuine
HEALTHY↔UNHEALTHY transitions only (row-locked, proven exactly-once
under concurrency), never re-emitting a same-state observation.
Runtime health is deliberately broadcast to every tenant (documented
exception — platform-wide, not tenant data).

RBAC: `Permission.SECURITY_OPERATIONS_READ`, granted to all six tenant
roles (mirrors `VALIDATIONS_READ`'s universal distribution). The
`OperatorPermission` name from stale prior task history does not exist
in the repository and was not reintroduced.

Super-admin decision: a genuine platform-wide role system exists but
does not expose cross-tenant security data today; M15 does not add
that capability — honestly documented as out of scope, not fabricated.

Migration head: **0023.**

API surface: `/api/v1/security-operations/{summary,changes,events,
events/stream,executions,executions/{id},runtime}` — 7 routes, all
GET, proven structurally read-only.

Frontend command center: Security Operations page (truthful
CONNECTED/RECONNECTING/DISCONNECTED badge, summary cards, live feed,
active executions, change feed, runtime components) + execution
telemetry detail page.

Stream client: `useSecurityOperationsStream.ts` — bounded reconnect
backoff, bounded event buffer (200), dedup by cursor, unknown enums
render safely, JWT never in a URL.

Adversarial test count: 44 new backend tests (14 unit + 23 API
isolation + 7 PostgreSQL integration) + 17 new frontend tests.

Owned local operations lab proof: 7/7 PASS (execution/policy events
via poll(), cursor resume, restart durability, cross-tenant isolation
with the runtime-broadcast exception proven alongside it).

PostgreSQL concurrency/ordering proof: PASS — 8-way concurrent
runtime-transition dedup converges on exactly 1; out-of-order-commit
survives the visibility lag with correct final ordering.

Clean migration proof: PASS — 0001→0023, all 3 new tables + FK +
indexes confirmed, downgrade/re-upgrade reversible. One transparently-
disclosed near-miss during this proof (a misconfigured env var
momentarily targeted the shared dev DB for one safe, additive, forward-
only upgrade step it needed anyway) — no downgrade ever run against it.

Live API acceptance: **47/47 PASS**, against a REAL running `uvicorn`
server (not `ASGITransport`) specifically to prove genuine SSE
streaming/disconnect/reconnect, including a full-process-restart
durable-resume proof from a second, independent server instance.

Browser acceptance: **BLOCKED** — identical pre-existing preview-
environment limitation M10-M14 already documented (zero console
errors, all bundles 200 OK).

Independent review findings/fixes: 0 P0, 0 P1, 3 P2 found and fixed
(frontend dedup-Set leak deleting by the wrong key; a first-sighting
INSERT race on the runtime-transition dedup table, closed with `ON
CONFLICT DO NOTHING`; an unbounded `result_summary` string, given the
same defensive length cap `OperationalEvent` already has).

Backend quality gates: ruff clean; mypy strict 619 files, 0 issues;
pytest **3,957 passed, 5 skipped** (baseline 3,913; +44).

Frontend quality gates: tsc 0 errors; build succeeds; vitest **106
passed** (baseline 89; +17).

npm advisory state: 2 pre-existing moderate advisories (postcss/next
transitive), unchanged, no new dependencies.

## PROVEN

Tenant isolation (execution/summary/events/stream, including the
deliberate runtime-broadcast exception), RBAC gating on every route,
cursor resume with no duplicates, malformed-input safety (cursor,
execution ID, state/domain filters — never a 500), deterministic
ordering under the commit-visibility margin (via a genuine out-of-
order-commit race), concurrent runtime-transition dedup (via genuine
`asyncio.gather()`), multi-instance durable resume (via a genuine
second-process restart), genuine end-to-end SSE streaming (via a real
`uvicorn` server), migration reversibility, backend + frontend quality
gates.

## CLAIMED-UNPROVEN

None.

## FAILED

None. (One unrelated, pre-existing M13 proof test flaked once in the
full suite and passed cleanly on immediate re-run in isolation and in
a second full-suite run — confirmed not a regression from this
milestone.)

## BLOCKED

Interactive browser click-through (preview environment hydration
limitation, not an application defect — identical to M10-M14).

## Remaining P0

None.

## Remaining P1

None. (Two documented P2-level limitations remain by design: the
"recently resolved conditions" summary metric is omitted rather than
approximated, matching M14's own precedent for the 500-row correlation
cap; a cross-tenant Super Admin security-data view was not built,
since no such capability exists today to extend.)

## Is M15 honestly COMPLETE?

**Yes.**

## Exact recommended next milestone

**M16** — natural continuations include (a) wiring the platform-wide
Super Admin role's already-declared-but-unused
`PlatformPermission.PLATFORM_SECURITY_READ` to a genuine, bounded,
cross-tenant security-operations overview (counts only, no per-tenant
secrets, no stream) now that the tenant-scoped version has a proven
foundation; (b) a dedicated per-entity correlation repository query to
remove the 500-row org-wide cap M14 documented and M15 inherited as an
approximation in its own summary counts; (c) representing
`CORRELATION_REACTIVATED` in the closed `SecurityDriftCategory`
taxonomy, deliberately deferred since M14, now that M15's operational
feed gives drift categories real end-user visibility for the first
time.
