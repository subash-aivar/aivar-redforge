# M10 — Authorized PT Scope & Execution Policy Control Plane

Full detail report. See [M10_COMPLETION_CHECKPOINT.md](M10_COMPLETION_CHECKPOINT.md)
for the concise summary.

## 1. Reconnaissance and canonical architecture decision

Before writing any code, the existing repository was inspected for prior
authorization/policy work. Findings:

- `domain/authorization/` and `application/authorization/` existed as **empty
  placeholder directories**, reserved since M8. No code to conflict with.
- Migration `0016`'s docstring explicitly recorded that `security_authorizations`,
  `security_authorization_scope`, and `security_authorization_decisions` had
  been prematurely scaffolded ahead of M9/M10's actual implementation, then
  removed as unreviewed speculative schema. Those three table names were
  therefore the de facto reserved names for this milestone; a fourth table
  (`security_authorization_approvals`) was added for the approval record.
- `domain/policies/` already means something else entirely: `ValidationPolicy`
  (which attacks run against which targets, with what strategy/schedule).
  `ExecutionPolicyService` was named carefully to avoid colliding with that
  existing, unrelated use of "policy".
- Two RBAC universes already exist and are deliberately kept separate:
  tenant `Permission` (keyed by `MembershipRole`) and `PlatformPermission`
  (keyed by `PlatformRole`, platform-wide). `domain/identity/value_objects.py`
  states explicitly: *"there is no second, competing authorization mechanism
  anywhere in the codebase"* for tenant scope. M10 extends the **existing**
  `Permission` enum with `AUTHORIZATIONS_READ/CREATE/APPROVE/APPROVE_CREDENTIAL/
  EVALUATE` rather than inventing a third RBAC universe — the safer, DDD-correct
  choice given that explicit invariant.
- The only real active-execution dispatch path in the platform is
  `CampaignEngine.execute_campaign()`/`.trigger()`
  (`application/campaigns/campaign_engine.py`) → `ValidationService.execute()`.
  `api/v1/execution_plans.py` is an inert stub (no persistence, `GET` always
  404s) — confirmed and now explicitly documented as reviewed rather than
  silently ignored. Campaigns have no REST route at all; the engine is only
  reachable via the scheduler or direct application-layer calls.

## 2. Canonical domain

`domain/authorization/` — one bounded context, no duplicate network/cloud/AI
authorization truth:

- **`SecurityAuthorization`** (aggregate root) — tenant-owned, holds
  `action_classes: frozenset[ActionClass]`, `scope: frozenset[AuthorizationScopeEntry]`,
  a `ValidityWindow`, and `AuthorizationStatus`.
- **`AuthorizationApproval`** (separate small aggregate, not nested) — one
  record per authorization, created at submission, decided at most once.
  Kept separate rather than embedded so its history is immutable and
  independently auditable — the same pattern `Invitation`/`Membership` use
  in `domain/identity/entities.py`.
- **`ExecutionPolicyDecision`** (value object) — the outcome of one
  `evaluate()` call: decision, reason code, action class, entity refs,
  authorization id, timestamp.

### Lifecycle

```
DRAFT --submit_for_approval()--> PENDING_APPROVAL
PENDING_APPROVAL --approve()--> ACTIVE
PENDING_APPROVAL --reject()--> REJECTED (terminal)
ACTIVE --revoke()--> REVOKED (terminal)
ACTIVE --mark_expired()--> EXPIRED (terminal; idempotent no-op if already EXPIRED)
```

No other transition exists; every illegal one raises
`InvalidAuthorizationTransitionError`. **Reapproval policy**: REJECTED and
EXPIRED are terminal — there is no path back to PENDING_APPROVAL or ACTIVE. A
requester who wants to try again creates a brand-new DRAFT authorization.
This keeps every `AuthorizationApproval` row an immutable, never-overwritten
historical fact instead of something that could be resubmitted and silently
lose its original decision.

Time-of-use: `SecurityAuthorization.is_active_now(now)` recomputes
`status == ACTIVE and validity.contains(now)` on every call — nothing caches
an ALLOW result. `mark_expired()` exists only to bring the persisted status
in line with reality for listing purposes; it is never required for
correctness (`ExecutionPolicyService` always recomputes fresh).

## 3. Action classification

Closed 8-member `ActionClass` `StrEnum`. Two explicit sets:

- `CATEGORICALLY_DENIED_ACTION_CLASSES` = `{EXPLOIT_EXECUTION, POST_EXPLOITATION,
  DESTRUCTIVE_ACTION}` — `ExecutionPolicyService.evaluate()` denies these
  unconditionally (`ACTION_CLASS_DENIED`), regardless of any authorization's
  scope, and `SecurityAuthorizationService.create()` refuses to even let a
  client request them, since no execution capability exists for them anywhere
  in the platform.
- `AUTHORIZABLE_ACTION_CLASSES` = the other 5 (`PASSIVE_DISCOVERY`,
  `READ_ONLY_ASSESSMENT`, `SAFE_VALIDATION`, `ACTIVE_VALIDATION`,
  `CREDENTIAL_VALIDATION`) — an explicit allowlist rather than "everything not
  denied", so a future new enum member defaults to unauthorizable until a
  deliberate decision adds it here.

**Design note on approval uniformity** (documented rather than left implicit):
the brief's language ("PASSIVE_DISCOVERY/READ_ONLY_ASSESSMENT may be allowed
under bounded tenant permissions") was read as license to skip the approval
step for those two classes. That path was deliberately **not** taken — every
authorizable class goes through the identical DRAFT→PENDING_APPROVAL→ACTIVE
lifecycle and identical self-approval-forbidden rule, uniformly, for every
action class. This is the simpler, stricter, and more auditable reading, and
avoids a second approval code path to keep correct. `CREDENTIAL_VALIDATION`
gets a *stronger* approval tier (`Permission.AUTHORIZATIONS_APPROVE_CREDENTIAL`,
checked in `SecurityAuthorizationService._decide()`) rather than a weaker one
for any class.

Unknown action class strings (not in the enum at all) are denied the same
way as categorically-denied ones (`ACTION_CLASS_DENIED`) — fails safe, no 500.

## 4. Authorization scope

`AuthorizationScopeEntry(entity_type: ScopeEntityType, entity_id: str)`.
`ScopeEntityType` is limited to `ai_target` and `ai_asset` — the only two
entity types this codebase has real, canonical, tenant-owned identity for
today (M1's `AITarget`, M22's inventory `AIAsset`). No free-text hostname
lists, no cloud-account/network-device scoping (no canonical identity exists
for those yet — not fabricated).

`EntityOwnershipPort.is_owned_by_organization(entity_type, entity_id, org_id)`
is the single check used identically in two places:

1. `SecurityAuthorizationService._verify_and_parse_scope()` — at
   authorization-creation time, before a scope entity is ever attached.
2. `ExecutionPolicyService.evaluate()` — defensively, again, at every
   decision (denies with `TENANT_MISMATCH` if an entity in the request
   doesn't resolve to a real, same-tenant entity).

Production wiring (`TenantEntityOwnershipChecker`,
`application/authorization/ownership.py`) is backed by the *existing*
`AITargetService`/`TenantAssetService` — not a new lookup table. `valid_from`/
`valid_until` (`ValidityWindow`) are the only other scope-adjacent fields;
no `maximum execution count` field was added since no execution architecture
exists yet to enforce it truthfully (would have been a decorative field).

## 5. Approval architecture

`AuthorizationApproval` fields: `requester_user_id`, `approver_user_id`
(nullable until decided), `decision` (nullable until decided), `requested_at`,
`decided_at` (nullable), `reason`. Created once, at
`submit_for_approval()`; decided at most once, via `decide()`, which raises
`ApprovalAlreadyDecidedError` if called twice.

**Self-approval prevention** is enforced at the domain layer itself —
`SecurityAuthorization.approve()`/`.reject()` and
`AuthorizationApproval.decide()` all independently check
`approver_user_id == requester_user_id` and raise
`SelfApprovalForbiddenError` — unconditionally, regardless of role,
including the org's OWNER (proven by a dedicated adversarial test using the
OWNER identity specifically, to rule out any identity-based bypass, not just
an ordinary member).

No magic identity check anywhere (`is_subash`-style hardcoding does not
exist) — the check is pure `EntityId` equality between two independently
verified users.

## 6. Execution policy service and reason codes

`ExecutionPolicyService.evaluate(organization_id, actor_user_id, action_class,
entity_refs)` — deterministic Python control flow, no LLM, no rule
expression engine. Precedence (each step denies with a specific code, so the
client never has to guess which):

1. Unrecognized or categorically-denied action class → `ACTION_CLASS_DENIED`.
2. Malformed entity refs (unknown `entity_type`) → `ENTITY_NOT_IN_SCOPE`.
3. Entity not owned by the caller's org → `TENANT_MISMATCH`.
4. Zero authorizations exist for the org at all → `AUTHORIZATION_NOT_FOUND`.
5. Authorizations exist, but none cover these entities → `ENTITY_NOT_IN_SCOPE`.
6. An authorization covers the entities, but not this action class →
   `ACTION_NOT_IN_SCOPE`.
7. A covering authorization is ACTIVE but past its validity window →
   `AUTHORIZATION_EXPIRED`.
8. A covering authorization is ACTIVE and within its window → **ALLOW**,
   `ALLOWED_BY_ACTIVE_AUTHORIZATION`.
9. A covering authorization is PENDING_APPROVAL → **APPROVAL_REQUIRED**.
10. Otherwise (DRAFT/REJECTED/REVOKED) → `AUTHORIZATION_NOT_ACTIVE`.

Steps 5/6 were originally collapsed into a single "no matching authorization"
check that pre-filtered by action class in the same SQL-ish query; the
adversarial test suite's separate "out-of-scope entity" and "out-of-scope
action" tests both landed on the same reason code, revealing the design
needed the two-stage entity-match-then-action-match precedence actually
implemented above. Fixed before merge, covered by dedicated tests for each.

Every call — ALLOW, DENY, and APPROVAL_REQUIRED alike — persists an
immutable `security_authorization_decisions` row (no update/delete method
exists on that repository), including a `raw_action_class` string preserving
exactly what the caller sent even when it didn't parse to a real enum
member (the `action_class` column is `NULL` in that case — never coerced
into a misleading real value).

## 7. Execution bypass review

Every code path that could plausibly dispatch an offensive action was
classified:

| Path | Classification | Action taken |
|---|---|---|
| `CampaignEngine.execute_campaign()` / `.trigger()` → `ValidationService.execute()` | **C. Potentially active** | Gated: `ExecutionPolicyPort` is a **required** constructor parameter (no default); both entry points call `_require_execution_allowed()` before any `Campaign` aggregate is created, raising `ExecutionNotAuthorizedError` on anything but ALLOW. |
| `api/v1/execution_plans.py` | **B. Inert stub** | Documented in the module docstring as reviewed; no gate added since there is nothing to gate (`POST` returns a plan object with no dispatch, `GET/{id}` always 404s). |
| Everything else searched (`attack`, `runtime`, `tool`, `payload`) | No further active dispatch found | No action needed. |

Regression test proving no bypass:
`tests/unit/test_campaign_engine.py::TestM10ExecutionPolicyGate::test_cannot_construct_without_execution_policy_service`
— asserts `TypeError` when `CampaignEngine` is constructed without the
parameter. Additional tests in the same class prove DENY and
APPROVAL_REQUIRED both block dispatch (no `Campaign` created, `repo.save_count == 0`),
and that `trigger()` (the scheduler path) is gated identically with an actor
identity of `"system:scheduler"`.

## 8. Concurrency correctness (found and fixed during implementation)

Initial implementation of `approve()`/`reject()` read the authorization and
approval rows with a plain `SELECT`, mutated them in memory, then saved —
a classic TOCTOU race: two concurrent approve() calls could both read
PENDING_APPROVAL, both transition in memory, and the second commit would
silently overwrite the first's decision with no error to either caller.

Fixed with `SELECT ... FOR UPDATE` locked reads
(`get_by_id_for_organization_for_update()`,
`get_by_authorization_id_for_update()`) used specifically in the
approve/reject path. The second transaction blocks until the first commits,
then observes the already-decided state and fails cleanly (either
`InvalidAuthorizationTransitionError` from the authorization-level lock, or
`ApprovalAlreadyDecidedError` from the approval-level lock, depending on
which lock resolves the race first — both are legitimate, non-silent
outcomes). Proven against real PostgreSQL in
`tests/integration/test_authorization_race.py`
(`test_concurrent_approval_produces_exactly_one_active_and_one_decision`):
exactly one of two simultaneous `approve()` calls succeeds, the authorization
ends ACTIVE with exactly one approval row in the database. SQLite (used in
the unit/adversarial suite) silently ignores `FOR UPDATE` — the guarantee is
real only against PostgreSQL, which is why this proof lives in the
integration suite, not the adversarial one.

## 9. Migration (0018)

`security_authorizations` (status/action_classes/validity/version, unique
`(id, organization_id)`, indexes on org+status, org+valid_until, org+requester),
`security_authorization_scope` (composite FK to `security_authorizations(id,
organization_id)`, unique `(authorization_id, entity_type, entity_id)`, index
on org+entity_type+entity_id for lookup), `security_authorization_approvals`
(composite FK, same tenant-integrity pattern as M4/M5's edge/membership
tables), `security_authorization_decisions` (deliberately **no** FK to
`security_authorizations` — a decision auditing `AUTHORIZATION_NOT_FOUND` has
no authorization row to reference, and a decision must never be blocked from
being written by a missing authorization). No execution/payload/credential
tables; no M11 schema.

## 10. APIs

`/api/v1/authorizations` (`api/v1/authorizations.py`) — 9 endpoints:
`POST ""` (create DRAFT), `GET ""` (list, status filter + pagination),
`GET "/summary"` (backend-derived lifecycle counts — added after the
frontend build revealed the brief's "no fabricated trends" requirement had
no backend source; a real `GROUP BY status` query, not client aggregation),
`POST "/evaluate"`, `GET "/decisions"` (tenant-wide audit history),
`GET "/{id}"`, `POST "/{id}/submit"`, `POST "/{id}/approve"`,
`POST "/{id}/reject"`, `POST "/{id}/revoke"`. Literal-path routes
(`/summary`, `/evaluate`, `/decisions`) are registered before the
`/{authorization_id}` parametrized route so they are never swallowed by the
path parameter. `organization_id`/`requester_user_id`/`approver_user_id` are
never client-supplied fields anywhere — always derived from the verified
`TenantContext`.

## 11. Frontend

`frontend/src/app/(app)/authorization/` — `page.tsx` (overview cards, tab
switcher between an Authorizations list and Policy Decision History,
status/lifecycle filter, collapsible create form restricted to the 5
authorizable action classes with dynamic scope-entry rows, detail modal with
approval history and per-authorization decision history, lifecycle-gated
action buttons) and `authorization-helpers.tsx` (pure presentation helpers —
`toCanonicalStatus()` never silently maps an unrecognized backend status to a
known one, mirroring `campaigns/campaign-graph.tsx`'s
`toCanonicalNodeState()` contract). `frontend/src/lib/authorizations.ts` is
the API client module, following the existing
`lib/securityConditions.ts` pattern exactly. Added one `NAV` entry to
`app/(app)/layout.tsx`. No client-side permission-check layer was invented
(none exists elsewhere in this codebase) — buttons are gated purely on
record/lifecycle state, and a genuine backend 403 surfaces through the
existing generic error-banner convention.

## 12. Adversarial tests

`tests/api/test_authorizations_isolation.py` — 32 tests (real SQLite engine
+ real routers + real services, `_FakeOwnershipChecker` test double for the
`EntityOwnershipPort` boundary) covering the full checklist: tenant
isolation and non-disclosing 404s, foreign-target/asset scope rejection,
client-cannot-forge-active/approver/decision/reason-code, self-approval and
unauthorized-approver denial (including against the OWNER identity, not just
an ordinary member), approval history preservation, rejected/revoked/expired
authorizations all denying, entity/action out-of-scope and unknown-action-class
denial, the full approve workflow (APPROVAL_REQUIRED before, ALLOW after),
revocation/expiration changing the *next* decision, tenant-scoped and
audited decisions, no-secrets-in-response, lifecycle-bypass prevention,
no active exploit endpoint, no hardcoded identity, invalid transitions, and
backend-derived summary counts.

`tests/integration/test_authorization_race.py` — 2 real-PostgreSQL
concurrency tests (concurrent approval, concurrent policy evaluation
auditability).

`tests/unit/test_campaign_engine.py::TestM10ExecutionPolicyGate` — 5 tests
proving the execution-bypass gate (construction requires the port, DENY/
APPROVAL_REQUIRED both block dispatch, ALLOW permits it, `trigger()` is
gated identically).

## 13. PostgreSQL proof

Isolated self-created database (`redforge_m10_clean_migration_proof`),
migrated 0001→head via real `alembic upgrade head`, then exercised the full
lifecycle through the real HTTP API (18 steps, all PASS): create
organization/users → create DRAFT → evaluate before submission (DENY) →
submit → self-approval denied → distinct ADMIN approver approves → ACTIVE →
evaluate (ALLOW + decision_id) → decision history contains it → out-of-scope
entity/action DENY → revoke → immediate DENY → state persists across a fresh
app instance built against the same database (restart proof) → second
tenant's guessed authorization ID → 404 (non-disclosing) → no raw secret
substrings in any response. Database dropped after — no residue.

## 14. Clean migration proof

Fresh database, `alembic upgrade head` from empty (0001→0018, all prior
milestones' migrations ran cleanly), `alembic current` confirmed `0018 (head)`.
Schema inspection confirmed: all 4 M10 tables present with the exact planned
columns; composite tenant-integrity FKs present on `security_authorization_scope`
and `security_authorization_approvals`; all planned indexes present
(`ix_security_authorizations_org_status`, `..._org_valid_until`,
`..._org_requester`, `ix_authorization_scope_org_entity`,
`ix_authorization_decisions_org_time/authorization/decision`, etc.); no M11
schema; `_EXPECTED_MIGRATION_HEAD` in `application/platform/startup_validator.py`
was found still pinned to `"0017"` (would have failed every real startup
against the new head) and updated to `"0018"`, with the 3 tests that pinned
the old value (`test_startup_validator.py`, `test_sprint29_replay_pipeline.py`)
corrected in the same change. Database dropped after — no residue.

## 15. Live API acceptance

Isolated backend process (`uvicorn ... --port 8000`, real PostgreSQL,
independent of the shared dev database), full 28-step flow from the brief,
**all 28 PASS**, including a real `AITarget` created via the production
`POST /api/v1/targets` endpoint as the scope entity (so ownership
verification runs through the real `TenantEntityOwnershipChecker`, not a
test double) and an actual process kill + restart to prove persistence.
Database and process cleaned up after — no residue.

## 16. Browser acceptance — BLOCKED

Attempted via the Browser preview tool against a real Next.js dev server and
the same live backend. Diagnostic finding: no element on any page in this
app — including the pre-existing, entirely untouched `/login` page — ever
receives a React fiber/event-handler attachment in this preview environment
(`Object.keys(el).filter(k => k.startsWith('__react'))` is empty everywhere,
across fresh tabs, hard reloads, and both `computer`-tool clicks and raw
`dispatchEvent` pointer-event sequences at the exact DOM-measured button
center). This is a preview-environment hydration limitation, not an
application defect: `tsc --noEmit` is clean, `next build` succeeds and
includes the `/authorization` route, and 54 Vitest component tests (13 new)
exercise the identical click handlers successfully via jsdom + Testing
Library. Marked BLOCKED per instruction; does not affect M10 completion.

## 17. Bugs found and fixed (P0/P1)

1. **P0 (concurrency)** — `approve()`/`reject()` had a TOCTOU race allowing a
   silent overwrite under concurrent approval. Fixed with `SELECT ... FOR
   UPDATE` locked reads; proven against real PostgreSQL.
2. **P1 (audit correctness)** — `ExecutionPolicyService.evaluate()`'s
   original precedence collapsed `ENTITY_NOT_IN_SCOPE` and
   `ACTION_NOT_IN_SCOPE` into the same code path (both surfaced as
   `AUTHORIZATION_NOT_FOUND`/one generic code), defeating the brief's
   requirement that these be independently auditable/distinguishable. Fixed
   with the two-stage entity-match-then-action-match precedence in §6.
3. **P1 (response completeness)** — `submit`/`approve`/`reject`/`revoke`
   endpoints initially returned `AuthorizationResponse` without the nested
   `approval` object (only `GET` attached it), so a client acting on the
   response of its own mutation couldn't see the approval it just decided.
   Fixed by fetching and attaching `approval` in all four mutation endpoints.
4. **P1 (API ergonomics)** — `reject`/`revoke` required a JSON body even
   though `reason` is optional, so calling them with no body 422'd with
   "Field required" for the body itself. Fixed with default empty bodies.
5. **P1 (staleness)** — `_EXPECTED_MIGRATION_HEAD` was still `"0017"` (see §14).
6. **P1 (audit integrity)** — an early draft of `ExecutionPolicyDecision`
   coerced an unparseable action-class string into a real (misleading)
   `ActionClass` member for storage. Changed `action_class` to `ActionClass |
   None`, with the true raw string preserved separately in
   `raw_action_class` — caught during self-review before any test needed to
   catch it.

## 18. Quality gates (final numbers)

Backend: `ruff check .` — all checks passed. `mypy src` (strict) — success,
552 source files. `pytest` — **3,697 passed, 5 skipped** (baseline 3,658 + 39
new: 32 adversarial + 2 Postgres race + 5 CampaignEngine gate tests, net of
the +1 summary-endpoint test also included).

Frontend: `npm audit` — 2 pre-existing moderate advisories (unchanged,
no new dependencies added). `npx tsc --noEmit` — clean. `npm run build` —
clean, `/authorization` route present. `npm test` (vitest run) — **54
passed** (baseline 41 + 13 new).
