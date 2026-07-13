# M11 Completion Checkpoint

**Milestone:** M11 — Gated Safe Active Validation Orchestration
**Status: M11 COMPLETE**
**Full detail:** [M11_GATED_SAFE_ACTIVE_VALIDATION_REPORT.md](M11_GATED_SAFE_ACTIVE_VALIDATION_REPORT.md)

## Architecture decision
First milestone to perform REAL active network validation (DNS/TCP/TLS/HTTP),
entirely behind M10's `ExecutionPolicyService` gate — reused unchanged.
`active_validation` already existed in M10's closed `ActionClass` taxonomy,
so no M10 change was needed. M8's `SecurityCondition` pipeline reused
unchanged via a new `SourceCategory.ACTIVE_VALIDATION` producing path. No
Security Graph ontology bump — executions reference existing canonical
entities only.

## Implementation completed
New `domain/validation_execution/` bounded context (`ValidationExecution`,
child `ValidationStep`, standalone `ExecutionEvent` log); 9-state lifecycle
with `finish()` computed from real step outcomes only; mandatory M10 policy
gate evaluated **twice** per execution (creation + immediately before
dispatch, closing the revoked-between-checks race); one closed
`SAFE_ACTIVE_BASELINE_V1` profile, 6 bounded step types, server builds the
entire plan — no client-submitted steps/ports/commands anywhere; real
network-boundary/SSRF defense (categorical deny of loopback/link-local/
private/multicast/reserved/metadata, fail-closed on unparseable input) plus
a DNS-rebinding/foreign-target defense on every redirect hop; real adapters
(genuine TCP connects, a real TLS handshake with real certificate parsing,
manual per-hop-revalidated HTTP redirects, a pure deterministic 3-rule
security-header evaluator); Authorization/Cookie/Set-Cookie/bearer-token
headers redacted before persistence, API, or events; migration 0019 (3
tables, composite tenant FKs, step-order/event-sequence uniqueness); 7 REST
endpoints (no arbitrary-execution endpoint, no direct adapter import in the
router); Validation Operations frontend (overview, canonical-target-only
start form, filterable list, live-polling detail with step/event timeline
and a crisp result panel); 51 adversarial backend tests (18 network-
boundary unit + 33 API-level, 3 against the REAL M10 services end-to-end)
plus 7 dedicated real-PostgreSQL proof tests.

## Bugs found and fixed
**P0** — `create_and_run()` holds one in-memory aggregate for its whole
lifecycle; every intermediate `_save()` overwrote `cancellation_requested`
from that stale in-memory copy, silently clobbering a genuinely concurrent
`POST /cancel` request back to `False` before the running step loop's
fresh-read check ever observed it. Found via the real-PostgreSQL proof
(a NullPool-based concurrency test ruled out connection staleness as the
cause). Fixed by making the flag monotonic (OR, never overwrite) in
`SqlAlchemyValidationExecutionRepository.save()`; re-verified the same
scenario now correctly ends `CANCELLED`.

No other defects found.

## Execution lifecycle
`PENDING → POLICY_CHECKING → AUTHORIZED → RUNNING → {COMPLETED,
PARTIALLY_COMPLETED, FAILED}`, or `DENIED`/`CANCELLED` from any
non-terminal state. `deny()` is legal from `AUTHORIZED` specifically so the
second, time-of-use policy check can actually transition to DENIED.
`fail_preflight()` handles target-normalization failure (AUTHORIZED→FAILED,
zero steps).

## Policy integration
`evaluate()` called twice: at creation, and immediately before step
dispatch. Proven with a fake `ExecutionPolicyPort` returning ALLOW then DENY
across the two calls within one `create_and_run()` invocation — a
sequencing test no real HTTP workflow could express — plus 3 tests using
the REAL M10 `SecurityAuthorizationService`/`ExecutionPolicyService` driven
through the actual create/submit/approve/revoke lifecycle, proving the
integration is genuine, not mocked.

## Network boundary
`classify_address()` categorically denies LOOPBACK/LINK_LOCAL/PRIVATE/
MULTICAST/RESERVED/METADATA (known-metadata-IP denylist for AWS/GCP/Azure/
ECS), allows only PUBLIC, fails closed on unparseable input. Applied
identically to the initial resolution and to every redirect hop. DNS-
rebinding defense: a redirect is only followed if its resolved addresses
intersect the ORIGINAL target's own validated set — a genuinely different
target (even with individually-public addresses) is refused as a pivot.

## Validation profile & adapters
`SAFE_ACTIVE_BASELINE_V1` — DNS resolution, TCP connectivity, TLS handshake
(HTTPS targets only), HTTP metadata, HTTP security headers, service
reachability. Real `asyncio`/`ssl`/`httpx` adapters; TLS handshake proven
against a genuine, freshly-generated self-signed certificate (real protocol
version, cipher, subject CN, SHA-256 fingerprint). `ServiceReachabilityResult`
explicitly distinguishes port-open from service-validated.

## Limits
`max_steps=6`, `max_resolved_addresses=4`, `per_step_timeout=5s`,
`total_timeout=30s`, `redirect_limit=3`, `max_concurrency=1`,
`max_events=200`, bounded evidence per step. Event emission silently stops
past `max_events` rather than erroring.

## Events
Standalone, append-only `ExecutionEvent` log (deliberately not the
aggregate's buffered-domain-event pattern) — 13 event types, polling-based
retrieval (`after_sequence`/`limit`), proven persisted in strictly
increasing sequence and organization-scoped at the query level (a foreign
tenant gets a 200 + empty list, zero data disclosed, never the real
tenant's events).

## Condition/finding semantics
TCP-open and HTTP-200 are observations, never Findings. Only the
deterministic header-rule evaluator produces a `SecurityCondition`
(`evidence_state="validated"`, `source_category="active_validation"`),
deduped via M8's existing identity-key upsert — repeated validation updates
the same condition, never duplicates.

## Security Graph decision
No ontology bump. Executions reference existing canonical `ai_target`/
`AIAsset` entities; no new node/edge type introduced.

## Migration head
**0019.**

## PostgreSQL proof
Isolated self-created database, `alembic upgrade head` (0001→0019), then
full lifecycle via the real HTTP API plus 7 dedicated proof tests: real TLS
against a genuine self-signed cert, condition dedup, event ordering,
policy-revocation-blocks-dispatch, the P0 cancellation race (found, fixed,
re-verified), and restart persistence. Database destroyed after.

## Clean migration proof
Fresh empty database → 0001→0019 in full → all 3 M11 tables + composite FKs
+ indexes confirmed present → no M12 schema → downgrade→re-upgrade
reversibility proven → database destroyed. One operator mistake during
this step (an improperly-scoped downgrade briefly hit the shared dev
database) was caught immediately, confirmed zero data loss (all affected
tables were empty), and corrected before continuing.

## Live API acceptance
Real server (isolated port 8000), real PostgreSQL, a genuine `AITarget`
pointing at an owned local test service. Full flow through the real M10
authorization workflow (create→submit→approve→ACTIVE) then M11 (create→
real ALLOW→plan built→real DNS resolution correctly denies the owned
target's own loopback address→crisp truthful FAILED result→repeat
stable→revoke→immediate DENY zero steps→restart→persistence
confirmed→cross-tenant 404+empty-list→no secrets→401 unauthenticated): all
steps PASS.

## Browser acceptance
**BLOCKED** — identical pre-existing environment limitation M10 already
documented: the preview browser never attaches a React effect/event-handler
tree on any page, reproduced on both the new `/validation-operations` page
and the untouched, pre-existing `/authorization` page. Not an application
defect — corroborated by clean tsc/build and 65 passing Vitest tests (11
new) exercising the identical component tree.

## Backend quality gates
ruff: all checks passed. mypy (strict) on `src/`: 573 files, 0 issues.
pytest: **3,755 passed, 5 skipped** (baseline 3,697; +58, 0 regressions).

## Frontend quality gates
tsc: 0 errors. build: succeeds, `/validation-operations` route present.
vitest: **65 passed** (baseline 54; +11).

## npm advisory state
2 pre-existing moderate advisories — unchanged, no new dependencies.

## PROVEN
Domain lifecycle, mandatory double policy gate (including genuine M10
integration, not mocked), network-boundary/SSRF/DNS-rebinding defense (real
adapters against real owned test servers, including a real TLS handshake),
observation/condition/finding semantics, execution limits, event ordering
and tenant-scoping, PostgreSQL proof (including the P0 concurrency fix),
clean migration, live API acceptance (all steps), quality gates (backend +
frontend).

## CLAIMED-UNPROVEN
None.

## FAILED
None remaining — the P0 (cancellation-flag clobbering race) found during
the real-PostgreSQL proof was fixed and re-verified before this checkpoint.

## BLOCKED
Interactive browser click-through (preview environment hydration
limitation, not an application defect — identical to M10's own documented
limitation).

## Remaining M11 P0
None.

## Remaining M11 P1
None known.

## Is M11 honestly COMPLETE?
**Yes.**

## Exact recommended next milestone
**M12** — a natural continuation is widening `SAFE_ACTIVE_BASELINE_V1`
into additional closed, server-controlled profiles (still fully within the
non-destructive observation boundary this milestone established), and/or
building live SSE-based event streaming now that the polling-based event
log has a proven, ordered, tenant-scoped foundation to stream from.
