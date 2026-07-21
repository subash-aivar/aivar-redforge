# M31 Phase 3 & Phase 4 Implementation Report

**Date:** 2026-07-21  
**Milestone:** M31 — AI Security Posture Management (AI-SPM)  
**Phases Delivered:** Phase 3 (AI Supply Chain) + Phase 4 (AI Agent Governance)  
**Status:** COMPLETE — Quality gates passed  
**Commit / Push:** NOT performed (awaiting architecture review)

---

## 1. Executive Summary

M31 Phase 3 and Phase 4 are implemented as independent bounded contexts under the frozen module paths `backend/src/ai_supply_chain/` and `backend/src/ai_agent_governance/`, following `M31_ARCHITECTURE_FINALIZATION.md` with no ADR or architecture redesign.

- **Phase 3** delivers model provenance (two-tier verification), append-only provenance chain, MBOM, discovery scan coordination (HF / registry / MCP / cloud / Kubernetes cloud audit logs), tenant verification budgets, ACL ports, PG + in-memory persistence, and REST under `/api/v1/ai-supply-chain`.
- **Phase 4** delivers agent operational envelopes, version-pinned deviation evaluation, idempotent `ReportAgentAction`, human review workflow, revision advisories (human-only), PG + in-memory persistence, and REST under `/api/v1/ai-agent-governance`.
- Canonical RBAC remains `ai_posture:*`. `ai_agent_governance` does not import `ai_posture.domain` or `ai_posture.application`.
- Alembic single head: **`0079`** (`0077 → 0078 → 0079`).

**Validation:** Ruff clean · `ruff format --check` clean · MyPy `--strict` clean (**136** source files) · **22** Phase 3+4 tests passed (**29** including posture arch/migration regression) · Alembic head **`0079`**.

---

## 2. Features Implemented

### Phase 3 — `ai_supply_chain`

| Feature | Status |
|---------|--------|
| `ModelProvenance` aggregate + append-only `ProvenanceChainEntry` | Done |
| Two-tier verification (`IndependentHash` ≤ threshold / `ProviderAttestation` > threshold + `trust_delegation_note`) | Done |
| Size-threshold policy + admin-configurable threshold (min 1 GiB default 10 GiB) | Done |
| Tenant monthly egress budget / API call budget / concurrent account limits | Done |
| Unknown origin capped at `Unverified` | Done |
| Verified ↔ VerificationFailed retry recomputes (no shortcut) | Done |
| `ModelBillOfMaterials` + append-only components + M27 vuln ACL port | Done |
| `AIDiscoveryScanRun` + partition-isolated discovery coordinator | Done |
| Providers: Hugging Face, cloud AI, model registry, thin MCP adapter | Done |
| Kubernetes via **read-only cloud audit logs** (EKS/GKE/AKS) — no admission webhook | Done |
| Inventory match + shadow-alert raise ACL ports | Done |
| Streaming hash + provider signature adapters | Done |
| In-memory + PostgreSQL repositories / UoW | Done |
| DB immutability triggers on chain entries + MBOM components | Done |
| CQRS commands + query handlers + REST API + DI container | Done |
| `ai_posture:*` authorization | Done |

### Phase 4 — `ai_agent_governance`

| Feature | Status |
|---------|--------|
| `AgentOperationalEnvelope` lifecycle (Draft → Active → UnderRevision / Suspended / Retired) | Done |
| Authorized actions, resource scopes, sensitivity ceilings, human-approval requirements | Done |
| Version snapshots + `find_active_version_at` pinning | Done |
| `AgentDeviationEvent` detection + review state machine | Done |
| Idempotent `ReportAgentAction` (compliant / deviation / duplicate) | Done |
| Envelope revision advisory (threshold-based, human-only; never auto-applies) | Done |
| Admin-only removal of human-approval requirements | Done |
| In-memory + PostgreSQL envelope / deviation / idempotency repos + UoW | Done |
| CQRS commands + query handlers + REST API + DI container | Done |
| Architecture guard: no `ai_posture` domain/application imports | Done |

### Explicitly out of scope (not started)

- Phase 5: compliance mapping, security graph, dashboards / report read models
- Production live cloud SDK credentials (adapters are injectable; M26 vault wiring is ops pre-condition)
- Replacing Phase 2 risk-score ACL stubs with live supply-chain / agent query wiring (ports exist)

---

## 3. Files Created

### Bounded contexts

- `backend/src/ai_supply_chain/**` — **80** Python modules (Phase 3 complete BC)
- `backend/src/ai_agent_governance/**` — **56** Python modules (Phase 4 complete BC)

### Tests

- `backend/tests/ai_supply_chain/**`
- `backend/tests/ai_agent_governance/**`

### Migrations

- `0078_ai_supply_chain_phase3.py`
- `0079_ai_agent_governance_phase4.py`

### Docs

- `docs/architecture/m31/M31_PHASE3_PHASE4_IMPLEMENTATION_REPORT.md` (this file)

---

## 4. Files Modified

| File | Change |
|------|--------|
| `backend/src/redforge/api/v1/__init__.py` | Include supply-chain + agent-governance routers |
| `backend/pyproject.toml` | First-party names + ruff per-file-ignores for both BCs |
| `backend/tests/ai_posture/test_architecture_invariants.py` | Phase 3/4 no longer required empty; agent import boundary |
| `backend/tests/ai_posture/test_migration_chain.py` | Chain through `0079` single-head guard |

No ADRs or architecture freeze / finalization documents were modified.

---

## 5. Bounded Context Summary

| Context | Path | Responsibility | Depends on (ACL only) |
|---------|------|----------------|------------------------|
| `ai_supply_chain` | `src/ai_supply_chain/` | Provenance, MBOM, discovery, K8s audit ingestion | Inventory match, shadow alerts, vulnerability query, provider ports |
| `ai_agent_governance` | `src/ai_agent_governance/` | Envelopes, deviations, advisories | None from `ai_posture` domain/app (event-driven / query ACL later) |
| `ai_posture` | (unchanged this phase) | Assets, shadow triage, threat profiles, risk scores | Consumes integrity / deviation counts via future ACL |

Cross-context rules enforced: no circular imports; no shared mutable aggregates; tenant isolation on every repository path.

---

## 6. Aggregates Added

### Phase 3

| Aggregate | Notes |
|-----------|-------|
| `ModelProvenance` | Integrity + operational status; owns append-only chain |
| `ModelBillOfMaterials` | Components append-only; completion event |
| `AIDiscoveryScanRun` | Scan bookkeeping; partial failure partitions |

### Phase 4

| Aggregate | Notes |
|-----------|-------|
| `AgentOperationalEnvelope` | Versioned envelope; effective window |
| `AgentDeviationEvent` | Immutable core; review transitions only |

---

## 7. Entities Added

| Entity | Context | Notes |
|--------|---------|-------|
| `ProvenanceChainEntry` | Supply chain | Append-only; `verification_method`, `trust_delegation_note` |
| `AuthorizedAction` | Agent governance | Category + description within envelope |

---

## 8. Value Objects Added

### Phase 3 (selected)

`AISystemAssetRef`, `ModelProvenanceRef`, `SourceRegistryRef`, `TrainingDataLineageRef`, `CurrentChecksum`, `LastVerifiedChecksum`, `SignatureChainRef`, `MBOMComponent`, `DiscoveredAIService`, `ArtifactDescriptor`, `TenantVerificationSettings`, identifiers, enums (`VerificationMethod`, `ModelOrigin`, `DiscoverySourceType`, `KubernetesCloudProvider`, …).

### Phase 4 (selected)

`AISystemAssetRef`, `AgentOperationalEnvelopeRef`, `ObservedAction`, `AuthorizedResourceScope`, `RateCeiling`, `EnvelopeApprovedBy`, identifiers, enums (`EnvelopeState`, `AuthorizedActionCategory`, `DeviationType`, `ReviewState`, …).

---

## 9. Domain Services Added

| Service | Context |
|---------|---------|
| `ProvenanceVerificationService` | Supply chain — tier dispatch, hash / attestation |
| `ModelBillOfMaterialsBuilder` | Supply chain — MBOM assembly + CVE enrichment port |
| `AIDiscoveryScanCoordinator` | Supply chain — multi-source scan + partition isolation |
| `VerificationTierPolicy` | Supply chain — threshold validation policy |
| `EnvelopeComplianceEvaluationService` | Agent governance — pure evaluation against pinned version |
| `EnvelopeRevisionAdvisoryService` | Agent governance — human-only revision recommendations |

---

## 10. Repository Interfaces

### Phase 3

- `IModelProvenanceRepository`
- `IModelBillOfMaterialsRepository`
- `IDiscoveryScanRunRepository`
- `ITenantVerificationSettingsRepository` (settings VO access)

### Phase 4

- `IAgentOperationalEnvelopeRepository` (`save`, `save_version_snapshot`, `find_active_version_at`, …)
- `IAgentDeviationEventRepository` (incl. idempotency ledger)

---

## 11. Repository Implementations

| Implementation | Context |
|----------------|---------|
| In-memory UoW + repos | Both (default DI for tests/dev) |
| `PgModelProvenanceRepository` | Supply chain |
| `PgMBOMRepository` | Supply chain |
| `PgScanRepository` / `PgSettingsRepository` / `PgUnitOfWork` | Supply chain |
| `PgEnvelopeRepository` | Agent governance |
| `PgDeviationRepository` | Agent governance |
| `PgUnitOfWork` | Agent governance |

---

## 12. Commands

### Phase 3

`RecordModelProvenanceCommand`, `VerifyModelProvenanceCommand`, `ManualResetVerificationCommand`, `BuildMBOMCommand`, `RunDiscoveryScanCommand`, `SetVerificationThresholdCommand`

### Phase 4

`DraftEnvelopeCommand`, `AddAuthorizedActionCommand`, `ApproveEnvelopeCommand`, `ReviseEnvelopeCommand`, `SuspendEnvelopeCommand`, `RetireEnvelopeCommand`, `ReportAgentActionCommand`, `ReviewDeviationCommand`

---

## 13. Queries

### Phase 3 (`SupplyChainQueryHandler`)

`GetModelProvenanceQuery`, `GetMBOMByProvenanceQuery`, `GetIntegrityStatusForAssetQuery`, `ListRecentDiscoveryScansQuery`

### Phase 4 (`GovernanceQueryHandler`)

`GetEnvelopeQuery`, `GetEnvelopeAdvisoriesQuery`, `ListUnreviewedDeviationsQuery`, `CountRecentDeviationsForAssetQuery`

---

## 14. APIs

### `/api/v1/ai-supply-chain`

| Method | Path |
|--------|------|
| POST | `/provenances` |
| POST | `/provenances/{id}/verify` |
| POST | `/provenances/{id}/manual-reset` |
| GET | `/provenances/{id}` |
| POST | `/provenances/{id}/mbom` |
| POST | `/discovery-scans` |
| PUT | `/settings/verification-threshold` |

### `/api/v1/ai-agent-governance`

| Method | Path |
|--------|------|
| POST | `/envelopes` |
| POST | `/envelopes/{id}/actions` |
| POST | `/envelopes/{id}/approve` |
| POST | `/envelopes/{id}/revise` |
| POST | `/envelopes/{id}/suspend` |
| POST | `/actions/report` |
| POST | `/deviations/{id}/review` |
| GET | `/envelopes/{id}/advisories` |

---

## 15. Domain Events

### Phase 3

`ModelProvenanceRecorded`, `ProvenanceChainEntryAdded`, `ChecksumVerified`, `ProvenanceIntegrityMismatchDetected`, `ModelBillOfMaterialsCompleted`, `ModelBillOfMaterialsComponentAdded`, `AIDiscoveryScanCompleted`, `UnmatchedAIServiceDiscovered`

### Phase 4

`AgentOperationalEnvelopeDrafted`, `AgentOperationalEnvelopeApproved`, `AgentOperationalEnvelopeRevised`, `AgentOperationalEnvelopeSuspended`, `AgentOperationalEnvelopeRetired`, `AgentDeviationDetected`, `AgentDeviationReviewed`, `AgentDeviationConfirmed`, `AgentDeviationDismissedBenign`

---

## 16. Event Handlers

Outbound publishing via `StructlogEventPublisher` in each BC (same pattern as Phase 1+2). Cross-context consumers remain deferred to Phase 5 read models / production ACL wiring. Domain events are raised from aggregates and published after successful UoW commit by application services.

---

## 17. Database Migrations

| Revision | Down | Schema objects |
|----------|------|----------------|
| `0078` | `0077` | Schema `ai_supply_chain`; tables `model_provenance`, `provenance_chain_entries`, `model_bill_of_materials`, `mbom_components`, `ai_discovery_scan_runs`, `tenant_verification_settings`; **UPDATE/DELETE deny triggers** on chain + MBOM components |
| `0079` | `0078` | Schema `ai_agent_governance`; tables `agent_operational_envelopes`, `agent_deviation_events`, `agent_action_idempotency` |

**Alembic head:** `0079` (single head).

---

## 18. Test Summary

| Suite | Coverage |
|-------|----------|
| Domain (supply) | Tier-1/Tier-2 verification, unknown origin, retry paths, MBOM, discovery partial partition failure |
| Domain (agent) | Envelope lifecycle, deviation types, version pinning at action time |
| Application | Provenance app flow, full envelope → report → review, admin-only human-approval removal, idempotency |
| Architecture | Two-tier methods present; K8s audit-log (not webhook); agent BC forbids posture domain/app imports |
| Migration | `0078` / `0079` chain + single-head |
| Posture regression | Architecture + migration chain updated for Phase 3/4 |

```
pytest tests/ai_supply_chain tests/ai_agent_governance -q
22 passed

pytest tests/ai_supply_chain tests/ai_agent_governance \
  tests/ai_posture/test_architecture_invariants.py \
  tests/ai_posture/test_migration_chain.py -q
29 passed
```

---

## 19. Ruff Summary

```
ruff check src/ai_supply_chain src/ai_agent_governance \
  tests/ai_supply_chain tests/ai_agent_governance
All checks passed!

ruff format --check src/ai_supply_chain src/ai_agent_governance \
  tests/ai_supply_chain tests/ai_agent_governance
153 files already formatted
```

---

## 20. MyPy Summary

```
mypy --strict src/ai_supply_chain src/ai_agent_governance
Success: no issues found in 136 source files
```

---

## 21. Architectural Observations

1. **Frozen module paths held:** top-level `ai_supply_chain` and `ai_agent_governance` packages; no new BCs.
2. **Two-tier provenance policy** is enforced in domain policy + verification service; Tier 2 requires non-empty `trust_delegation_note`.
3. **Kubernetes integration is audit-log only** (`CloudAuditLogKubernetesAdmissionAdapter`); architecture tests reject webhook deployment semantics.
4. **Discovery partition isolation** includes per-cloud-account failure isolation with partial results retained.
5. **Agent evaluation is version-pinned** via `find_active_version_at(asset, occurred_at)` — not current draft.
6. **`ReportAgentAction` is idempotent** via tenant-scoped idempotency ledger.
7. **No `ai_posture` domain/application imports** from agent governance (architecture test).
8. **Append-only legal trail** defended at DB layer (triggers) and domain (immutable entity mutate APIs).
9. **Default DI still uses shared in-memory UoW** for tests/dev; production PG UoW factories are implemented and ready to wire per-request.
10. **Provider adapters are injectable stores** suitable for integration tests; live M26 credential vault binding remains an operational pre-condition, not Phase 5 product scope.

---

## 22. Remaining Scope for Phase 5

Per `M31_ARCHITECTURE_FINALIZATION.md` (updated Phase 5):

| Item | Notes |
|------|-------|
| AI Compliance Posture report | `requires_human_attestation` labeling; attesting identity + date |
| AI Supply Chain Integrity Report | Display `VerificationMethod`; Tier 2 labeled Provider-Attested |
| AI Asset Inventory Dashboard | Last-scan timestamp, discovery sources, coverage scope |
| Shadow AI Discovery Report | Scope section; `partial: true` partition flags |
| Audit read model | Full `RequiresHumanApprovalFor` change history |
| Security Graph projections | Cross-asset relationship / risk graph read models |
| Pre-condition | Confirm M24 `requires_human_attestation` catalog (or local mapping table) before Phase 5 start |
| Ops follow-ups (not Phase 5 exclusive) | Wire live M26 vault credentials; replace degraded ACL stubs; schedule production jobs |

---

## STOP

Phase 3 + Phase 4 implementation is complete.

**Do not proceed to Phase 5 until architecture review approval.**  
**No commit. No push.**
