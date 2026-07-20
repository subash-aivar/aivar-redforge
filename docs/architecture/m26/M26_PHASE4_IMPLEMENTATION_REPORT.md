# M26 Phase 4 — CSPM Implementation Report

**Status:** Complete — awaiting architecture review  
**Date:** 2026-07-19  
**Scope:** Cloud Security Posture Management (policy evaluation platform) only  
**Not committed / not pushed**

---

## 1. Verdict

M26 Phase 4 delivers a reusable, provider-agnostic CSPM policy evaluation platform on top of existing M26 CloudAsset inventory and M24 compliance catalog references. Evaluation is API-triggered (no workers/schedulers). Automatic remediation and attack-path analysis are explicitly out of scope and were not implemented.

---

## 2. What Was Implemented

### 2.1 Domain (`backend/src/redforge/domain/cloud_security/cspm/`)

| Aggregate / type | Role |
|---|---|
| `CSPMFinding` | Finding lifecycle, fingerprint, immutable history, domain events |
| `CSPMPolicy` | Versioned executable policy definition |
| `CSPMEvaluation` | Evaluation run record + diagnostics |
| `CSPMControlMapping` | Mapping to M24 framework keys / requirement refs |
| `CSPMDriftBaseline` | Drift baseline foundation (store only) |

**Entities:** `FindingEvidence`, `FindingHistory`, `EvaluationResult`, `RemediationReference`  
**Value objects:** `FindingSeverity`, `FindingStatus`, `FindingConfidence`, `ComplianceCoverage`, `EvaluationContext`, `ResourceSnapshot`, `PolicyVersion`, `RuleMetadata`, `ComplianceRef`  
**Events:** `CSPMFindingCreated/Updated/Resolved/Reopened`, `CSPMPolicyEvaluated`, `ComplianceStateChanged`  
**Repositories (ports):** finding, policy, evaluation, drift baseline

**Finding lifecycle (validated transitions):**  
`OPEN` → `CONFIRMED` | `SUPPRESSED` | `ACCEPTED_RISK` | `RESOLVED` | `EXPIRED`  
`CONFIRMED` → `SUPPRESSED` | `ACCEPTED_RISK` | `RESOLVED` | `EXPIRED`  
`SUPPRESSED` / `ACCEPTED_RISK` → `OPEN` | `RESOLVED` | `EXPIRED`  
`RESOLVED` → `REOPENED`  
`REOPENED` → `CONFIRMED` | `SUPPRESSED` | `ACCEPTED_RISK` | `RESOLVED` | `EXPIRED`  

Tracks: `first_seen`, `last_seen`, `resolved_at`, `reopened_at`, `suppressed_until`, `accepted_by`, `accepted_reason`.

### 2.2 Policy Engine (`domain/cloud_security/policy_engine/`)

`PolicyEvaluationEngine` — safe, deterministic, no `eval`/`exec`.

**Supported ops:** `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `exists`, `not_exists`, `empty`, `not_empty`, `contains`, `regex`, `in`, `not_in`, `collection_all` / `collection_any`, composite `all` / `any` / `not`, `always_true` / `always_false`.

**Convention:** rule describes a **bad** state; `matched=True` ⇒ open finding (`passed=False`).

Reusable beyond CSPM (K8s, runtime, SaaS, container, AI security) via snapshot dict + rule AST.

### 2.3 Evaluation Pipeline (`application/cloud_security/cspm/`)

- `ResourceSnapshotBuilder` — builds provider-agnostic snapshots from `CloudAsset.NormalizedConfig`
- `EvaluationContextFactory`
- `EvaluationPipeline` — batch / parallel (thread pool) evaluation, policy filtering by provider + asset type
- `CSPMAssessmentService` — orchestrates evaluate asset / account, finding upsert by fingerprint, status updates, summaries
- `CSPMDriftService` — baseline capture / compare foundation (no schedulers)
- Compliance ACL + Graph ACL ports

### 2.4 Policy Library

**29 YAML policies** under `infrastructure/cloud_security/cspm_policies/{aws,azure,gcp}/`.

- Versioned, tagged, severity, MITRE/CWE/CVSS metadata, compliance refs, remediation guidance (manual + IaC hints)
- Inheritance (`inherits_from`) with cycle detection
- `PyYAML` added as a runtime dependency; JSON still accepted by the loader for tests

### 2.5 Compliance Reuse (M24)

Mappings use existing `FrameworkKey` values (`soc2_type2`, `iso27001_2022`, `nist_csf_2_0`, `cis_benchmarks_v8`, `hipaa_security_rule`) + `requirement_ref`. No duplicated control catalog.

### 2.6 Inventory Reuse

Evaluation consumes M26 `CloudAsset` / `NormalizedConfig` only. No parallel inventory model.

### 2.7 Security Graph (ontology v9)

| Kind | Type |
|---|---|
| Node | `CSPM_FINDING`, `CONTROL` |
| Edge | `AFFECTS`, `VIOLATES`, `EVALUATED_BY` |

Projection is best-effort; no traversal / attack-path generation.

### 2.8 Remediation Framework

`RemediationReference` carries description, business/technical impact, manual steps, automated metadata, reference URLs, Terraform / CloudFormation / ARM / GCP deployment guidance. **No automatic remediation execution.**

### 2.9 Internal APIs (`/api/v1/cloud-foundation/cspm/*`)

| Method | Path |
|---|---|
| POST | `/evaluations` (trigger account / filtered evaluation) |
| POST | `/assets/{asset_id}/evaluate` |
| GET | `/evaluations`, `/evaluations/{id}` |
| GET | `/findings`, `/findings/{id}` |
| PATCH | `/findings/{id}/status` |
| GET | `/policies`, `/policies/{id}` |
| GET | `/summary/compliance`, `/summary/findings` |

Auth required (401 without bearer). No dashboards.

### 2.10 Database — Alembic `0049`

Schema `cloud_security`:

- `cspm_policies` — JSONB rule/metadata/remediation/compliance; optimistic `row_version`
- `cspm_findings` — evidence + history JSONB; unique `(organization_id, fingerprint)`; lifecycle timestamps; `row_version`
- `cspm_evaluations` — run diagnostics JSONB
- `cspm_drift_baselines` — baseline hash + snapshot JSONB

Indexes on org, status, asset, policy, fingerprint, enabled.

Startup validators (`redforge` + `credential_vault`) expect head **`0049`**.

---

## 3. Explicitly Not Implemented (per freeze / mission STOP)

- Cloud Risk Engine  
- Runtime Visibility  
- Kubernetes Security Analysis  
- Attack Path Analysis / graph traversal  
- AI Security Validation  
- Dashboards  
- Workers / scheduled scans  
- Automatic remediation  

---

## 4. Validation Results

| Gate | Result |
|---|---|
| Ruff (Phase 4 surface) | Pass |
| Mypy `--strict` (29/28 CSPM modules) | Pass |
| Phase 4 pytest | **84 passed** (domain, policy engine, pipeline, loader, ontology, API, PG repos, migration round-trip) |
| Alembic head | `0049` on `redforge` + `redforge_test` |
| Migration round-trip | `0049` → `0048` → `0049` verified |
| OpenAPI | 10 CSPM paths registered |
| Startup | App healthy; `/api/v1/runtime/status` 200; CSPM routes 401 without auth |
| Policy load | 29 YAML policies load; inheritance + circular detection OK |
| Evaluation smoke | Engine evaluates packaged AWS S3 rules against `NormalizedConfig` snapshots |

---

## 5. Design Notes for Reviewers

1. **Rule AST vs freeze string `condition`:** Mission requires boolean/composite ops, regex, collections, inheritance. Implemented as structured YAML `rule` trees, not free-form expression strings.
2. **Finding statuses:** Mission’s fuller set (`CONFIRMED`, `ACCEPTED_RISK`, `REOPENED`, `EXPIRED`) is implemented; broader than the freeze’s abbreviated OPEN/ACKNOWLEDGED/RESOLVED/SUPPRESSED table.
3. **Provider isolation:** No cloud SDK calls in evaluation; adapters remain discovery/CIEM only.
4. **Graph edges:** Skipped if endpoints missing — never fabricates CONTROL nodes without mapping context.

---

## 6. Key Paths

```
backend/src/redforge/domain/cloud_security/cspm/
backend/src/redforge/domain/cloud_security/policy_engine/
backend/src/redforge/application/cloud_security/cspm/
backend/src/redforge/infrastructure/cloud_security/cspm/
backend/src/redforge/infrastructure/cloud_security/cspm_policies/
backend/src/redforge/infrastructure/cloud_security/acl/cspm_*.py
backend/src/redforge/api/v1/cloud_cspm.py
backend/src/redforge/infrastructure/database/migrations/versions/0049_cspm_foundation.py
backend/tests/unit/cloud_security/cspm/
backend/tests/api/cloud_security/test_cloud_cspm_api.py
backend/tests/integration/cloud_security/test_cspm_*.py
```

---

## 7. Stop Condition

Phase 4 implementation is complete. **No commit. No push.** Waiting for architecture review before Phase 5+.
