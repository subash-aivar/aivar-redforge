# M9 — Exposure Correlation & Attack Surface Intelligence Report

## 1. Reconnaissance decision

Read M6/M7/M8 architecture (asset relationships, network/cloud analyzers,
SecurityCondition repository/service, ontology v5, `TenantSecurityGraphService.
find_paths`). Key finding: **no relationship connects CLOUD_RESOURCE to HOST/
IP/SERVICE** — cloud and network-discovery asset graphs are disjoint. No
security-group/ingress-CIDR concept exists anywhere (cloud "public" is a
string-parsed boolean). No identity-to-resource access relationship is
modeled. These findings directly determined which of the milestone's 5
conceptual rules are implementable today (2) vs. must be deferred (3).

## 2. Canonical correlation ownership

New bounded context `domain/security_correlation/` — `SecurityCorrelation` is
the sole canonical truth for deterministic cross-fact relationships. No
`NetworkCorrelation`/`CloudCorrelation`/`AttackSurfaceFinding` was created.

## 3. SecurityCondition vs SecurityCorrelation vs Finding vs RiskIncident

- **SecurityCondition** (M8): a single deterministic condition affecting one asset.
- **SecurityCorrelation** (M9): a deterministic relationship BETWEEN already-canonical facts/conditions/entities — concentration/context, never exploitability.
- **Finding** (pre-existing): validated-only truth, untouched.
- **RiskIncident** (pre-existing): a separate risk-workflow aggregate with unrelated semantics — not reused, not modified.

## 4. Persisted aggregate vs read-model decision

**Persisted aggregate** (`SecurityCorrelation` + 2 association tables), per the
milestone's own required semantics: deterministic identity, ACTIVE/RESOLVED
lifecycle, repeat evaluation, concurrency safety, auditability, restart
persistence — none of which a stateless read-model can provide.

## 5. Exact files changed

Domain: `domain/security_correlation/value_objects.py`. Migration:
`migrations/versions/0017_security_correlation_foundation.py`. Models:
`infrastructure/database/models/security_correlation.py` (+`__init__.py`
update). Repository:
`infrastructure/database/repositories/security_correlation_repository.py`.
Application: `application/security_correlation/facts.py`,
`application/security_correlation/rules.py`,
`application/security_correlation/service.py`,
`application/security_correlation/attack_surface.py`. M8 additions reused by
M9: `count_by_dimension`... `list_asset_ids_with_multiple_active_conditions`
and `list_active_for_asset` passthrough added to
`security_condition_repository.py`/`security_conditions/service.py`. API:
`api/v1/security_correlations.py`, `api/v1/attack_surface.py`. DI:
`api/dependencies.py` (rule registry + 2 new services). Fixed:
`application/platform/startup_validator.py` (0016→0017). Frontend:
`frontend/src/lib/securityCorrelations.ts`,
`frontend/src/app/(app)/attack-surface/page.tsx` (+`.test.tsx`), nav entry.

## 6. Correlation identity strategy

`build_correlation_identity_key(organization_id, stable_rule_id, rule_version,
entity_ids)` → `f"{stable_rule_id}:{rule_version}:{sorted_deduped_entities}"`.
Entity order never matters (sorted); title/summary/operator_action excluded.
Proven via domain tests + PostgreSQL concurrency tests.

## 7. Database constraints

`security_correlations`: unique `(id, organization_id)`, unique
`(organization_id, identity_key)`. `security_correlation_conditions`/
`security_correlation_entities`: composite FK to the parent correlation's
`(id, organization_id)` AND to the referenced condition/asset's
`(id, organization_id)` — a cross-tenant association is a physical FK
violation. Unique pair constraints prevent duplicate associations.

## 8. External exposure classification semantics

5-level closed enum with explicit precedence array (index-based `max()`, never
alphabetical). `BROAD_INGRESS_CONFIGURED` and
`EXTERNALLY_REACHABLE_VALIDATED` are defined in the enum (architecture
requires the full model) but **never emitted** — no producing source exists
for either. Proven: `strongest_classification([PUBLIC_ADDRESS_OBSERVED,
BROAD_INGRESS_CONFIGURED]) == BROAD_INGRESS_CONFIGURED` (higher precedence
wins regardless of list order).

## 9. Evidence-state derivation

Both implemented rules derive OBSERVED (never INFERRED/VALIDATED): RULE 1
combines two OBSERVED facts (public IP relationship + OBSERVED
SecurityCondition) without claiming reachability was itself validated; RULE 3
concentrates OBSERVED-or-otherwise ACTIVE conditions without upgrading their
evidence. No implemented rule's predicate is itself explicitly validated, so
neither ever produces VALIDATED.

## 10. Rule engine architecture

`CorrelationRuleRegistry` — plain Python objects register by
`(stable_rule_id, rule_version)`; `register()` raises
`DuplicateRuleRegistrationError` on collision. No arbitrary expressions, no
browser input, no LLM-generated predicates — every rule is a hand-written
class reading only `facts.py`/`TenantSecurityConditionService` canonical data.

## 11. Exact implemented rules

- **PUBLIC_SENSITIVE_SERVICE_CONTEXT** (v1): public IP → `IP_ASSIGNED_TO_HOST`
  → HOST → `HOST_EXPOSES_SERVICE` → SERVICE with an active
  `SENSITIVE_SERVICE_OBSERVED` condition (M6's own sensitive-port list, not
  duplicated).
- **MULTIPLE_SECURITY_CONDITIONS_ON_ASSET** (v1): 2+ ACTIVE SecurityConditions
  (any source category) on one asset — real `GROUP BY ... HAVING COUNT(*) >=
  2` query, not a Python-side tally.

## 12. Exact deferred rules and why

- **BROAD_REMOTE_ADMIN_EXPOSURE_CONTEXT**: no security-group/ingress-CIDR
  concept exists anywhere in the cloud domain or AWS adapter; "public" is a
  string-parsed boolean, not structured ingress data. Fabricating this rule
  would require inventing data the platform doesn't have.
- **MULTI_SOURCE_CORROBORATED_CONDITION**: no structured "same bounded
  concern across sources" key exists beyond `stable_rule_id`
  (`canonical_references` is free-text JSON). A text-similarity matcher was
  explicitly forbidden by the milestone and would be unsafe regardless.
- **PRIVILEGED_IDENTITY_EXPOSURE_CONTEXT**: no identity-to-resource/host
  access relationship type exists in the ontology or asset-relationship
  model; same-org/same-account is explicitly insufficient per the milestone's
  own rule.

## 13. Source-independence semantics

Not yet load-bearing since MULTI_SOURCE_CORROBORATED_CONDITION is deferred —
documented for the next implementer: independence must be keyed on distinct
`SourceCategory` values, never on repeated runs from the same connector/source
category.

## 14. Correlation lifecycle

ACTIVE on creation and on any successful re-match; RESOLVED only after a
FULLY successful evaluation cycle (fact-gathering + every match's
persistence) finds the correlation's identity_key absent from the current
active set. Reappearance reactivates the SAME row (upsert always sets
`lifecycle="active"`, clears `resolved_at`) — never a duplicate. Proven via
9 SQLite behavior tests + 4 PostgreSQL concurrency tests.

## 15. Failed-evaluation resolution safety

`resolve_stale_for_rule()` is called only after a rule's `evaluate()` call and
every resulting `upsert()` succeeded, inside the same `SessionUnitOfWork` that
commits the matches — an exception anywhere before that point propagates and
skips resolution entirely for that rule (and is re-raised to the router/
caller, never silently swallowed).

## 16. Attack surface read model

`TenantAttackSurfaceService` — org-level summary (backend `GROUP BY`
aggregates via M8's `count_by_dimension`/
`list_asset_ids_with_multiple_active_conditions`, plus correlation counts) and
per-asset exposure summary (condition counts by evidence state, explicit
severity precedence `_highest_severity()`, external classification, sensitive
service count, active correlation count). No magic 0-100 score anywhere.

## 17. Security Graph reuse

No new graph engine. Correlations reference canonical entity IDs directly;
the frontend links a correlation's first entity to
`TenantAttackSurfaceService.get_asset_exposure_summary()` and the existing
Security Graph API for further navigation — no second traversal
implementation.

## 18. Ontology decision

**Kept at v5.** `SecurityCorrelation` is intelligence/read-model truth outside
the Security Graph — no `CORRELATION` node/edge added, matching the
milestone's stated default and M8's earlier decision to keep M10 control-plane
objects out of the graph.

## 19. Path query limits

Reused the pre-existing M4 `TenantSecurityGraphService.find_paths()` as-is
(`max_depth` default 4, hard-clamped `MAX_TRAVERSAL_DEPTH=6`,
`MAX_PATH_RESULTS=20`, server-controlled `relationship_kinds` allow-list) — no
new bounded-query implementation was needed or added.

## 20. APIs

`POST /security-correlations/evaluate` (TARGETS_MANAGE), `GET
/security-correlations` (filters: lifecycle/stable_rule_id/evidence_state,
paginated), `GET /security-correlations/{id}`, `GET /attack-surface/summary`,
`GET /attack-surface/assets/{asset_id}`. No endpoint accepts correlation
creation, evidence_state, or classification input.

## 21. Frontend

`/attack-surface` — backend-derived overview cards, filterable correlation
list (lifecycle/rule), correlation detail panel (rule ID+version, evidence
state, direct summary, direct operator action, affected entities, source
condition IDs, lifecycle, timestamps) linked to a per-asset exposure panel
(classification, highest severity, condition/service counts). Explicitly
labeled "Exposure Relationship Path", never "Attack Path" — proven by a
frontend test asserting no heading/button carries that mislabel. No mock
data, no fabricated counts, no client-side classification.

## 22. Adversarial tests

9 SQLite domain-flow tests (`test_security_correlation_evaluation.py`,
including the P0-regression test for the resolved-count aggregation bug), 9
API tests (`test_security_correlations_isolation.py`: tenant isolation,
non-disclosing 404s, idempotent evaluate, no creation endpoint, no magic
score, cross-tenant asset-exposure denial, unauthenticated denial), 4
rule-registry unit tests, 9 domain value-object tests (identity key,
precedence, closed enums).

## 23. PostgreSQL concurrency proof

`tests/integration/test_security_correlation_race.py` — isolated
self-created database, 4/4 PASS: 8-way concurrent evaluation → 1 correlation;
cross-tenant separation; title/summary/operator_action update → no
duplicate; resolve→reobserve→reactivation (same row).

## 24. Migration proof

Isolated empty database `redforge_m9_clean_migration_proof`: `alembic upgrade
head` ran 0001→0017 in full; `alembic current` → `0017 (head)`; schema
inspection confirmed all 3 new tables' FKs/uniques/indexes; confirmed **no**
M10 schema exists. Database destroyed after inspection.

## 25. Live API acceptance

Real server, real PostgreSQL, isolated port. Full flow: startup (PASS, after
confirming the startup-validator fix to `0017`) → health → register/org →
canonical assets + M8 conditions built via the trusted internal path (public
IP + host + sensitive service; a second host/condition for concentration) →
attack-surface summary before evaluation (PASS) → evaluate (PASS, 1
correlation created) → summary after evaluation (PASS) → list/detail (PASS,
direct language, correct entity/condition refs) → asset exposure summary
(PASS, correct classification, no magic score) → repeat evaluation → no
duplicate (PASS) → resolve source condition → re-evaluate → **found and
fixed a P0** (see below) → RESOLVED confirmed (PASS) → re-observe source
condition → re-evaluate → same correlation reactivated to ACTIVE (PASS,
verified same ID) → restart → persistence confirmed (PASS) → second tenant
register/select → guessed correlation ID denied (PASS, non-disclosing 404) →
cross-tenant list empty (PASS) → cross-tenant asset-exposure denied (PASS) →
runtime health (PASS). All test data cleaned up afterward.

## 26. Browser acceptance

**BLOCKED** — same environment tooling limitation as M8 (preview tooling
resolves only the repository-root backend launch config). Frontend
correctness independently proven via clean `tsc --noEmit`, clean `next
build`, and 5 new passing Vitest tests (41 total).

## 27. Principal review findings

DDD: one canonical `SecurityCorrelation`, no duplicate aggregates,
`SecurityCondition`/`Finding`/`RiskIncident` untouched. Correlation truth: no
title/summary/display-name matching in either implemented rule — both use
only typed relationship/condition data. Evidence: OBSERVED-only derivation
documented and correct for both rules. External classification: precedence
explicit, unreachable levels never emitted. Multi-tenant: every
lookup/association tenant-scoped, proven via API tests and DB FKs. Database:
identity uniqueness DB-enforced, proven under real concurrency. Lifecycle:
resolution-safety contract proven (transactional, post-success only).
Graph: no second engine, no synthetic edges, ontology unchanged. Frontend:
no mock data, no fabricated counts, no frontend-derived classification, no
attack-path mislabeling.

## 28. Security bugs caught and fixed

**P0 — evaluation summary resolved-count aggregation bug.** `evaluate()`
reassigned `resolved_count` inside the per-rule loop instead of accumulating
it, so the returned `CorrelationEvaluationSummary.resolved` reflected only
the LAST rule evaluated. Caught live: `PublicSensitiveServiceContextRule`
(registered first) resolved 1 correlation while
`MultipleSecurityConditionsOnAssetRule` (registered second, evaluated last)
resolved 0 — the API reported `resolved: 0` despite a real resolution having
occurred (confirmed by a direct GET on the correlation, which correctly
showed `lifecycle: resolved`). The underlying resolve logic itself was
correct; only the aggregate count returned to the caller was wrong. Fixed by
accumulating `resolved += ...` across all rules. Added a dedicated
regression test
(`test_evaluation_summary_resolved_count_sums_across_all_rules`) reproducing
the exact registry-order/resolve-order combination that triggered it.

## 29. Quality gates

Backend: `ruff check .` — all checks passed. `mypy` — 533 files, 0 issues.
`pytest` — **3,658 passed, 5 skipped** (baseline 3,621; +37 new M9 tests, 0
regressions).

Frontend: `npx tsc --noEmit` — 0 errors. `npm run build` — succeeds,
`/attack-surface` route compiles into the static build manifest. `npm test`
(vitest) — **41 passed** (baseline 36; +5). `npm audit` — 2 pre-existing
moderate advisories (unchanged, no framework upgrade performed).

## 30-33. PROVEN / CLAIMED-UNPROVEN / FAILED / BLOCKED

- **PROVEN:** domain identity/precedence, rule registry duplicate rejection,
  both implemented rules against real canonical facts, evaluation-cycle
  safety (resolve-only-after-success), reactivation, PostgreSQL concurrency
  (4 tests), clean migration (0001→0017), live API acceptance (full flow,
  including the P0 caught and fixed live), backend quality gates, frontend
  tsc/build/vitest, npm audit baseline unchanged.
- **CLAIMED-UNPROVEN:** none.
- **FAILED:** none remaining after the resolved-count fix.
- **BLOCKED:** interactive browser click-through (same environment tooling
  limitation as M8).

## 34. Remaining M9 P0

None.

## 35. Remaining M9 P1

None known. (Documented future work, not a defect: 3 conceptual rules remain
correctly deferred pending canonical facts that don't exist yet — see §12.)

## 36. Honest M9 completion decision

**M9 is COMPLETE.** Both implementable rules are real, tested, and proven
live; the 3 deferred rules are honestly documented with the exact missing
canonical fact each requires, not fabricated; the evaluation-cycle safety
contract, reactivation semantics, and external-classification precedence are
all proven under real PostgreSQL concurrency and a real running server; a
real P0 was found during live acceptance and fixed with a regression test
before declaring completion; the only unproven item (interactive browser
click-through) is an environment tooling limitation, honestly marked
BLOCKED.

**Recommended next milestone: M10 — Authorized PT Scope & Execution Policy
Foundation.**
