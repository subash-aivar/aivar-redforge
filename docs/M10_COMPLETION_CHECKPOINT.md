# M10 Completion Checkpoint

**Milestone:** M10 — Authorized PT Scope & Execution Policy Control Plane
**Status: M10 COMPLETE**
**Full detail:** [M10_AUTHORIZED_PT_SCOPE_EXECUTION_POLICY_REPORT.md](M10_AUTHORIZED_PT_SCOPE_EXECUTION_POLICY_REPORT.md)

## Reconnaissance decision
`domain/authorization/` was an empty placeholder (reserved since M8, per
migration 0016's docstring). No prior authorization/policy control-plane
code existed anywhere. `domain/policies/` already means something unrelated
(`ValidationPolicy` — attack/target selection). The only real active-execution
dispatch path in the platform is `CampaignEngine`; campaigns have no REST
route at all.

## Implementation completed
New `domain/authorization/` bounded context (`SecurityAuthorization`,
`AuthorizationApproval`, `ExecutionPolicyDecision`); fixed 6-state lifecycle
with no illegal transitions; closed 8-class action taxonomy (3 categorically
denied, 5 authorizable); `ExecutionPolicyService.evaluate()` with a 10-code
reason precedence; extended the *existing* `Permission` enum rather than a
new RBAC universe; migration 0018 (4 tables, composite tenant FKs on 2 of
them, deliberately no FK on the decision-audit table); 9 REST endpoints
including a backend-derived `summary`; `CampaignEngine` gated with a
required `ExecutionPolicyPort` constructor parameter; Authorization &
Execution Policy frontend page; 39 new backend tests (32 adversarial + 2
Postgres-race + 5 CampaignEngine-gate) + 1 summary test; 13 new frontend tests.

## Bugs found and fixed
**P0** — `approve()`/`reject()` had a TOCTOU concurrency race allowing a
silent overwrite of a decided approval. Fixed with `SELECT ... FOR UPDATE`
locked reads on both the authorization and approval rows; proven against
real PostgreSQL (2/2 concurrency tests PASS).

**P1** — the policy-evaluation precedence originally collapsed
`ENTITY_NOT_IN_SCOPE` and `ACTION_NOT_IN_SCOPE` into the same code path,
caught by the adversarial suite's two separate tests for those cases; fixed
with an explicit entity-match-then-action-match precedence.

**P1** — mutation endpoints (`submit`/`approve`/`reject`/`revoke`) omitted
the nested `approval` object from their responses; fixed to fetch and attach
it on all four.

**P1** — `_EXPECTED_MIGRATION_HEAD` in the startup validator was still
`"0017"`; updated to `"0018"`, 2 pinned unit tests corrected.

## Authorization lifecycle
`DRAFT → PENDING_APPROVAL → ACTIVE → {REVOKED, EXPIRED}`, or
`PENDING_APPROVAL → REJECTED`. REJECTED/EXPIRED are terminal — reapproval
always creates a new DRAFT, never mutates history.

## Action taxonomy
`PASSIVE_DISCOVERY`, `READ_ONLY_ASSESSMENT`, `SAFE_VALIDATION`,
`ACTIVE_VALIDATION`, `CREDENTIAL_VALIDATION` (authorizable, uniform approval
requirement — no fast path for the first two); `EXPLOIT_EXECUTION`,
`POST_EXPLOITATION`, `DESTRUCTIVE_ACTION` (categorically denied — rejected
even at authorization-creation time; no execution capability exists for
these anywhere in the platform).

## Scope model
`(entity_type, entity_id)` restricted to `ai_target`/`ai_asset` — the only
two canonical, tenant-owned entity types that exist today. Verified via one
`EntityOwnershipPort`, used identically at creation time and at every
`evaluate()` call, backed in production by the existing
`AITargetService`/`TenantAssetService`. No display-name or substring matching.

## Approval architecture
Requester/approver/decision/timestamps/reason, one immutable-once-decided
record per authorization. Self-approval forbidden unconditionally at the
domain layer, proven against the org's own OWNER identity specifically (not
just an ordinary member) to rule out any identity-based bypass. No hardcoded
identity anywhere.

## Policy service
Deterministic Python control flow, no LLM, no rule expressions. 10 reason
codes with explicit precedence (unknown/denied action class →
entity-ownership → authorization-existence → entity-in-scope →
action-in-scope → time-of-use → lifecycle status). Every decision — ALLOW,
DENY, and APPROVAL_REQUIRED — persisted to an immutable, FK-less audit table.

## Execution bypass review
`CampaignEngine.execute_campaign()`/`.trigger()` — the only real active-
execution path — gated with a **required** `ExecutionPolicyPort` constructor
parameter (omission is a `TypeError`, proven by a regression test).
`api/v1/execution_plans.py` reviewed and confirmed inert; documented as such
in its module docstring rather than silently left alone.

## Migration head
**0018.**

## PostgreSQL proof
Isolated self-created database, `alembic upgrade head` (0001→0018), then the
full lifecycle exercised through the real HTTP API: 18/18 steps PASS
(create→submit→self-approval-denied→distinct-approver-approves→ALLOW→
out-of-scope DENY→revoke→immediate DENY→restart-persistence→cross-tenant
404→no-secrets). Database destroyed after.

## Clean migration proof
Fresh empty database → `alembic upgrade head` ran 0001→0018 in full →
`alembic current` = `0018 (head)` → all 4 M10 tables + composite FKs + all
planned indexes confirmed present → no M11 schema → database destroyed.

## Live API acceptance
Real server (isolated port 8000), real PostgreSQL, a genuine `AITarget`
created via the production API as the scope entity. Full 28-step flow: **28/28
PASS**, including an actual process kill + restart to prove persistence and
a second-tenant guessed-ID non-disclosing 404.

## Browser acceptance
**BLOCKED** — the preview browser environment never attaches a React
event-handler tree to any element on any page in this app, including the
pre-existing, untouched `/login` page (confirmed via `__reactProps`/
`__reactContainer` inspection across fresh tabs and reloads). An environment
limitation, not an application defect — independently proven via clean
tsc/build and 54 passing Vitest component tests (13 new) that exercise the
identical click handlers.

## Backend quality gates
ruff: all checks passed. mypy (strict): 552 files, 0 issues. pytest:
**3,697 passed, 5 skipped** (baseline 3,658; +39, 0 regressions).

## Frontend quality gates
tsc: 0 errors. build: succeeds, `/authorization` route present. vitest:
**54 passed** (baseline 41; +13).

## npm advisory state
2 pre-existing moderate advisories — unchanged, no new dependencies, no
forced upgrade.

## PROVEN
Domain lifecycle/taxonomy/scope/approval, execution-policy precedence (all
10 reason codes independently tested), self-approval prevention (incl.
against OWNER), execution-bypass gate (regression-tested), PostgreSQL
concurrency (2 tests), clean migration, live API acceptance (28/28), quality
gates (backend + frontend).

## CLAIMED-UNPROVEN
None.

## FAILED
None remaining — the P0 (concurrency race) and 4 P1s found during
implementation were all fixed and re-verified before this checkpoint.

## BLOCKED
Interactive browser click-through (preview environment hydration
limitation, not an application defect).

## Remaining M10 P0
None.

## Remaining M10 P1
None known.

## Is M10 honestly COMPLETE?
**Yes.**

## Exact recommended next milestone
**M11** — the first milestone that may introduce real, gated active
execution behind the ExecutionPolicyService boundary this milestone built
(e.g., wiring `PASSIVE_DISCOVERY`/`READ_ONLY_ASSESSMENT` to a real, safe
execution path, and/or building the campaign REST API that currently doesn't
exist, now that its authorization gate is in place).
