# M31 Phase 1 & Phase 2 Implementation Report

**Date:** 2026-07-21  
**Milestone:** M31 — AI Security Posture Management (AI-SPM)  
**Phases Delivered:** Phase 1 (AI System Asset Foundation + Shadow AI Triage) + Phase 2 (AI Threat Profiling + Risk Scoring)  
**Status:** COMPLETE — Quality gates passed  
**Commit / Push:** NOT performed (awaiting architecture review)

---

## Executive Summary

M31 Phase 1 and Phase 2 are implemented entirely inside the `ai_posture` bounded context, following `M31_ARCHITECTURE_FINALIZATION.md` (which supersedes Implementation Plan ambiguities).

- `AIThreatProfile` is an **independent aggregate root**; `AISystemAsset` holds only `AIThreatProfileRef`.
- Module layout uses top-level packages: `ai_posture`, plus Phase 3+/4+ stubs `ai_supply_chain` and `ai_agent_governance`.
- Canonical RBAC roles use `ai_posture:<role>` (including `ai_posture:engineer`).
- Shadow AI **individual + bulk triage**, discovery-only mode, and triage backlog age are Phase 1.
- Risk score GET is cache-only; compute is async/explicit only.

**Validation:** Ruff clean · MyPy `--strict` clean (68 files) · **51** Phase 1+2 tests passed · Alembic head **`0077`** (single head).

---

## 1. Features Implemented

### Phase 1 — `ai_posture` foundation

| Feature | Status |
|---------|--------|
| `AISystemAsset` lifecycle (Discover → PendingClassification → UnderReview → Registered → Deprecated → Decommissioned) | Done |
| `AIThreatProfileRef` / `AIRiskScoreRef` VOs on asset (no nested threat entity) | Done |
| M22 `AssetRef` ACL via `IInventoryQueryPort` (stub + tenant isolation) | Done |
| `ShadowAIAlert` raise / triage / confirm / false-positive / resolve | Done |
| Bulk triage (pattern filters) + bulk resolve (approver) | Done |
| Discovery-only mode (admin) | Done |
| Triage backlog age metric buckets | Done |
| Canonical `ai_posture:*` RBAC authorization | Done |
| HTTP API under `/api/v1/ai-posture` | Done |

### Phase 2 — Threat profiling + risk scoring

| Feature | Status |
|---------|--------|
| Independent `AIThreatProfile` AR + repository | Done |
| Threat assessment from cloud config signals (M26 ACL stub) | Done |
| Detection-rule completeness probe (M28 ACL stub, non-blocking) | Done |
| Attach `AIThreatProfileRef` on create; archive on asset decommission | Done |
| Deterministic `AIRiskScoreSnapshot` (`ScoreInputVersion = m31.v1`) | Done |
| Async compute endpoint; GET never computes | Done |
| Staleness sweep job entrypoint (profiles + score recompute) | Done |
| Phase 3/4 score components default to 0 via ACL stubs | Done |

### Explicitly out of scope (not started)

- Phase 3: `ai_supply_chain` provenance / MBOM / discovery / K8s audit ingestion
- Phase 4: `ai_agent_governance` agent envelopes
- Phase 5: compliance / graph / read models

---

## 2. Files Created

### Bounded contexts

- `backend/src/ai_posture/**` — full Phase 1+2 BC (~66 Python modules)
- `backend/src/ai_supply_chain/__init__.py` — Phase 3+ stub only
- `backend/src/ai_agent_governance/__init__.py` — Phase 4+ stub only

### Key `ai_posture` modules

**Domain:** aggregates (`AISystemAsset`, `ShadowAIAlert`, `AIThreatProfile`, `AIRiskScoreSnapshot`), VOs/enums/identifiers, events, exceptions, ports, repositories, services (`AISystemClassificationService`, `AIThreatAssessmentService`, `AIRiskScoringService`).

**Application:** commands, DTOs, `_auth`, UoW/event ports, services (`AISystemAssetApplicationService`, `ShadowAIAlertApplicationService`, `ThreatAssessmentApplicationService`, `RiskScoringApplicationService`).

**Infrastructure:** degraded ACL stubs, in-memory UoW/repos, SQLAlchemy models, structlog publisher, DI container, staleness sweep scheduler entrypoint.

**API:** FastAPI routes/schemas/dependencies wired into `redforge.api.v1`.

### Tests

- `backend/tests/ai_posture/**` — domain, application, auth, API, repository, migration chain, architecture invariant tests

### Migrations

- `0076_ai_posture_phase1_foundation.py`
- `0077_ai_posture_phase2_threat_risk.py`

### Docs

- `docs/architecture/m31/M31_PHASE1_PHASE2_IMPLEMENTATION_REPORT.md` (this file)

---

## 3. Files Modified

| File | Change |
|------|--------|
| `backend/src/redforge/api/v1/__init__.py` | Include `ai_posture` router |
| `backend/pyproject.toml` | `known-first-party` + ruff per-file-ignores for `ai_posture` (and stub BC names) |

No ADRs or architecture freeze documents were modified.

---

## 4. Database Migrations

| Revision | Down | Schema objects |
|----------|------|----------------|
| `0076` | `0075` | Schema `ai_posture`; tables `ai_system_assets`, `shadow_ai_alerts`, `ai_posture_tenant_settings` |
| `0077` | `0076` | Tables `ai_threat_profiles`, `ai_risk_score_snapshots` (+ index) |

**Alembic head:** `0077` (single head).

Runtime persistence for Phase 1+2 tests/dev uses **in-memory repositories**; SQLAlchemy models match the migration DDL for Phase 3+ PG repository work.

---

## 5. Tests Added

| Suite | Coverage |
|-------|----------|
| Domain | Asset lifecycle, shadow alert transitions, fingerprint determinism, threat assessment, independent profile AR, composite score weights, snapshot staleness |
| Application | Register/classify/approve, idempotent register, bulk triage/resolve, discovery-only, backlog age, tenant isolation, threat profile + risk compute, GET never computes, staleness sweep |
| Authorization | Role rank, auditor read-only, canonical `ai_posture:engineer` naming |
| Infrastructure | In-memory repos (tenant isolation, fingerprint, stale profiles/snapshots) |
| API | Register/get, 403 for reader, bulk triage, threat + risk endpoints |
| Migration | `0075→0076→0077` chain + single-head guard |
| Architecture | Module layout, no M22 domain imports outside ACL, profile/asset separation, Phase 3/4 stubs empty |

---

## 6. Test Summary

```
pytest tests/ai_posture -q
51 passed
```

---

## 7. Ruff Summary

```
ruff check src/ai_posture tests/ai_posture src/ai_supply_chain src/ai_agent_governance
All checks passed!
```

---

## 8. MyPy Summary

```
mypy --strict src/ai_posture src/ai_supply_chain src/ai_agent_governance
Success: no issues found in 68 source files
```

---

## 9. Architectural Observations

1. **Finalization Decision 1 held:** `AIThreatProfile` is a separate AR with its own repository; asset stores `AIThreatProfileRef` only. Architecture regression tests enforce this.
2. **No cross-context leakage:** `ai_posture` never imports M22/M26/M28 domain types; only local ACL VOs/ports + degraded stubs.
3. **Phase 3/4 packages exist as stubs only** — prevents accidental early implementation while preserving frozen module paths.
4. **RBAC naming** is canonical `ai_posture:*`; no `mlsecops:engineer` in domain enums.
5. **Score path purity:** GET `/risk-score` returns cached snapshot or null; compute is POST-only.
6. **In-memory UoW** is shared across requests in the default container for local/dev; production will need a per-request PG UoW factory (Phase 3 hardening / ops follow-up).
7. **Bulk resolve** preserves the human gate: analyst triage batch + separate approver resolution batch.

---

## 10. Remaining Work for Phase 3+

| Phase | Scope |
|-------|--------|
| **Phase 3** | `ai_supply_chain`: provenance verification (two-tier policy), MBOM, discovery coordinator, Hugging Face / registry / MCP discovery, **read-only Kubernetes cloud audit log ingestion**, PG repositories for posture tables |
| **Phase 4** | `ai_agent_governance`: agent envelopes, privilege/deviation signals feeding risk component |
| **Phase 5** | Compliance mappings, Security Graph projections, read models / dashboards, production ACL adapters replacing stubs |
| **Ops** | Wire real M22 inventory ACL adapter (compatibility already verified), schedule staleness sweep in production, migrate off shared in-memory UoW |

---

## STOP

Phase 1 + Phase 2 implementation is complete.

**Do not proceed to Phase 3 until architecture review approval.**  
**No commit. No push.**
