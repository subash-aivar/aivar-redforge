# M26 Phase 5 — Kubernetes Security Implementation Report

**Status:** Complete — awaiting architecture review  
**Date:** 2026-07-19  
**Scope:** Kubernetes Security inventory, normalization, CSPM posture evaluation, APIs  
**Not committed / not pushed**

---

## 1. Verdict

M26 Phase 5 delivers Kubernetes cluster inventory and pod-security posture evaluation on top of the existing CSPM `PolicyEvaluationEngine`. Discovery and evaluation are API-triggered (no workers/schedulers). Privilege-escalation / attack-path analysis is explicitly out of scope; RBAC is inventory-only.

---

## 2. What Was Implemented

### 2.1 Domain (pre-existing — not redesigned)

`backend/src/redforge/domain/cloud_security/kubernetes/`

| Aggregate | Role |
|---|---|
| `KubernetesCluster` | Cluster registration, sync timestamps, security score |
| `KubernetesWorkload` | Workload inventory + `posture_snapshot()` for CSPM engine |
| `KubernetesNamespace` | Namespace inventory + network-policy flag |
| `KubernetesNode` | Node inventory |
| `KubernetesService` | Service exposure classification |
| `KubernetesRBACPrincipal` | RBAC inventory flags (wildcards, cluster-admin) — no paths |
| `KubernetesNetworkPolicy` | NetworkPolicy inventory |
| `KubernetesAdmissionPolicy` | Admission controller registration + evaluation events |

### 2.2 Ontology v10

`ONTOLOGY_VERSION = 10`

**Node kinds:** `K8S_CLUSTER`, `K8S_NAMESPACE`, `K8S_WORKLOAD`, `K8S_RBAC`, `K8S_NETWORK_POLICY`, `K8S_SERVICE`  
**Edge kinds:** `RUNS_IN`, `DEPLOYS`, `BINDS`, `ALLOWS`, `DENIES`, `HOSTS`, `USES` (distinct from `USES_MODEL`)  
**EXPOSES** extended: `K8S_WORKLOAD → K8S_SERVICE` (legacy `HOST/DEVICE → SERVICE` retained)

### 2.3 Migration 0050

Schema `cloud_security` tables:

- `kubernetes_clusters` (org+name unique)
- `kubernetes_namespaces`
- `kubernetes_workloads`
- `kubernetes_nodes`
- `kubernetes_services`
- `kubernetes_rbac_principals`
- `kubernetes_network_policies`
- `kubernetes_admission_policies`

`_EXPECTED_MIGRATION_HEAD` bumped to `"0050"` in both startup validators.

### 2.4 Infrastructure

`infrastructure/cloud_security/kubernetes/`:

- `mappings.py` — domain ↔ SQLAlchemy
- `repositories.py` — Pg* repos implementing domain Protocols
- `inventory_port.py` — raw-dict `KubernetesInventoryPort` (no k8s SDK types)
- `fake_inventory.py` — in-memory fake for tests/dev
- `acl/k8s_graph_acl.py` — best-effort Security Graph projection

### 2.5 Application services

`application/cloud_security/kubernetes/`:

| Service | Responsibility |
|---|---|
| `KubernetesNormalizationService` | Raw inventory dicts → domain aggregates |
| `ClusterDiscoveryService` | Discover/register cluster |
| `WorkloadDiscoveryService` | Workload sync |
| `RBACDiscoveryService` | RBAC inventory sync |
| `NetworkPolicyDiscoveryService` | NetworkPolicy sync |
| `AdmissionPolicyEvaluationService` | Admission evaluation events |
| `InventoryProjectionService` | Full inventory sync orchestrator |
| `PostureEvaluationService` | Snapshots + YAML policies + `PolicyEvaluationEngine` |
| `KubernetesSecurityService` | API facade |

### 2.6 CSPM Kubernetes policy library

**12 YAML policies** under `infrastructure/cloud_security/cspm_policies/kubernetes/`:

privileged, host_network, host_pid, host_ipc, allow_privilege_escalation, read_only_root_filesystem, run_as_non_root, capabilities, image_pull_policy, latest-tag, public exposure, privileged security level

`policy_loader.py` now scans `kubernetes/` alongside aws/azure/gcp.

### 2.7 API (`/api/v1/cloud-foundation`)

| Method | Path | Permission |
|---|---|---|
| POST | `/k8s/clusters/discover` | ORG_MANAGE |
| GET | `/k8s/clusters` | ORG_READ |
| GET | `/k8s/clusters/{id}` | ORG_READ |
| GET | `/k8s/clusters/{id}/namespaces` | ORG_READ |
| GET | `/k8s/clusters/{id}/workloads` | ORG_READ |
| GET | `/k8s/clusters/{id}/workloads/{wid}` | ORG_READ |
| GET | `/k8s/clusters/{id}/rbac` | ORG_READ |
| GET | `/k8s/clusters/{id}/network-policies` | ORG_READ |
| POST | `/k8s/clusters/{id}/evaluate` | ORG_MANAGE |
| GET | `/k8s/clusters/{id}/compliance-summary` | ORG_READ |

### 2.8 Security Graph projector

New `project_k8s_*` methods for nodes and edges (HOSTS, DEPLOYS, RUNS_IN, EXPOSES, BINDS, ALLOWS, DENIES, USES).

---

## 3. Explicit Out of Scope

- Workers / scheduled jobs
- Privilege escalation / attack-path analysis
- Duplicated policy engine (reuses CSPM `PolicyEvaluationEngine`)
- Kubernetes client SDK objects outside infrastructure (Fake inventory uses raw dicts)
- Full CSPM finding persistence for every K8s violation (evaluation returns structured results + updates cluster security score + emits `K8sPodSecurityViolationDetected`)

---

## 4. Validation

| Gate | Result |
|---|---|
| Ruff (Phase 5 surface) | Pass |
| Mypy `--strict` (34 modules) | Pass |
| Phase 5 pytest | **106 passed** (with `TEST_DATABASE_URL`) |
| Alembic | Head `0050` on `redforge` + `redforge_test`; round-trip covered |
| OpenAPI | 10 `/cloud-foundation/k8s/*` paths |
| Startup | Healthy; `/api/v1/runtime/status` 200; K8s routes **401** without auth |
| Policy load | 41 total policies (29 cloud + **12 K8s**); loader scans `kubernetes/` |
| CSPM integration smoke | Privileged + hostNetwork workload matched **8** K8s policies |

| Suite | Count |
|---|---|
| Unit (domain/normalization/policy/ontology/discovery) | ~93 |
| API | 10 |
| Integration (migration + repositories) | 3 |
| **Total Phase 5** | **106** |

---

## 5. Architecture Deviations

1. **Findings persistence:** Posture evaluation updates `security_score` and emits `K8sPodSecurityViolationDetected`; it does **not** upsert `cspm_findings` rows for synthetic `K8S_WORKLOAD` assets (avoids fabricating CloudAsset parents). Structured evaluation results are returned via API.
2. **Default inventory adapter:** DI wires `FakeKubernetesInventory` (raw dicts). Production kubeconfig adapters (ADR-006) are deferred — port is ready; no workers.
3. **Workers:** Freeze/plan mention `K8sSyncWorker` (15-min). Phase 5 mission explicitly forbids workers/scheduled jobs — discovery is **API-triggered only**.
4. **RBAC analysis:** Freeze lists privilege-escalation detections. Mission forbids privilege escalation / attack paths — RBAC is **inventory + metadata flags only** (wildcard / cluster-admin bound flags for posture, no path graphs).
5. **API prefix:** Freeze lists `GET /api/v1/cloud/k8s/clusters`. Implemented under `/api/v1/cloud-foundation/k8s/*` to match Phase 1–4 convention.

---

## 6. Remaining Out of Scope

- Runtime Security / eBPF / Falco / Sysdig / container runtime monitoring  
- Cloud Risk Engine  
- Attack Path Analysis / graph traversal  
- Cloud AI Security  
- Dashboards  
- Workers / scheduled jobs  
- Auto remediation  
- In-cluster agents  
- Container image scanning (M27+)  
- Live EKS/AKS/GKE kubeconfig adapters (port exists; Fake used for CI)

---

## 7. Key Paths

```
backend/src/redforge/domain/cloud_security/kubernetes/
backend/src/redforge/application/cloud_security/kubernetes/
backend/src/redforge/infrastructure/cloud_security/kubernetes/
backend/src/redforge/infrastructure/cloud_security/cspm_policies/kubernetes/
backend/src/redforge/api/v1/cloud_k8s.py
backend/src/redforge/infrastructure/database/migrations/versions/0050_kubernetes_security.py
backend/tests/unit/cloud_security/kubernetes/
backend/tests/api/cloud_security/test_cloud_k8s_api.py
backend/tests/integration/cloud_security/test_k8s_*.py
```

---

## 8. Stop Condition

Phase 5 implementation is complete. **No commit. No push.** Waiting for architecture review before Phase 6+.
