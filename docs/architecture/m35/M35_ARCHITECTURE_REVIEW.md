# M35 Architecture Review
## Enterprise Security Automation & Orchestration Platform

**Status:** REVIEW — PENDING APPROVAL  
**Date:** 2026-07-22  
**Reviewed by:** Chief Software Architect / Chief Security Architect / Distinguished Engineer  
**Precondition:** M34 COMPLETE (0113 migration head, 68+ M34 tests, incident / regulatory_notification / lessons_learned bounded contexts production-complete)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Repository State Assessment](#2-repository-state-assessment)
3. [M35 Scope Validation](#3-m35-scope-validation)
4. [DDD Architecture Review](#4-ddd-architecture-review)
5. [Bounded Context Analysis](#5-bounded-context-analysis)
6. [Domain Model Issues](#6-domain-model-issues)
7. [Authorization Architecture Review](#7-authorization-architecture-review)
8. [Integration Architecture Review](#8-integration-architecture-review)
9. [Persistence & Storage Review](#9-persistence--storage-review)
10. [Event Architecture Review](#10-event-architecture-review)
11. [Security Graph Review](#11-security-graph-review)
12. [Operational Resilience Review](#12-operational-resilience-review)
13. [Cross-Context Leakage Analysis](#13-cross-context-leakage-analysis)
14. [Tenant Isolation Review](#14-tenant-isolation-review)
15. [Migration Risk Analysis](#15-migration-risk-analysis)
16. [Issue Register](#16-issue-register)
17. [Architecture Verdict](#17-architecture-verdict)

---

## 1. Executive Summary

M35 introduces the **defensive automation layer**: versioned, tested, approval-gated security playbooks that automate repetitive SOC response operations. It mirrors the discipline of M29 (offensive engagement authorization) applied to defensive actions against production infrastructure.

M35 is architecturally the highest-risk milestone to date because:

1. **Blast radius of mistakes**: Automated defensive actions (IP blocks, credential revocations, host quarantine) affect production infrastructure. An incorrect trigger causes operational disruption, not merely a security gap.
2. **Authorization parity requirement**: M29 offensive operations are governed by `EngagementAuthorizationService`, `KillSwitchState`, multi-party approvals, and scope hashing. M35 defensive operations must achieve equivalent or greater rigor.
3. **Third-party surface**: The `integration_hub` bounded context connects to 15+ external systems (AWS, Azure, GCP, CrowdStrike, Okta, ServiceNow, etc.) — each is a potential failure domain.
4. **Evidence integrity requirement**: Every automated action must produce an `AutomationExecutionRecord` equivalent in immutability to M29's `AttackAction`.

The review identifies **9 conditions (C1–C9)** that must be resolved in the finalization document before implementation begins.

---

## 2. Repository State Assessment

### Confirmed Repository Baseline

| Item | Status |
|---|---|
| Migration head | `0113_incident_operational_metrics` |
| Test baseline | 2,883+ unit/integration tests passing (from M34 memory) |
| Bounded contexts (new) | `incident`, `regulatory_notification`, `lessons_learned` |
| Bounded contexts (prior) | `engagement`, `campaign`, `detection`, `vulnerability`, `analytics`, `ml_pipeline`, `reporting`, and 15+ others |
| Authorization pattern | `ContainmentAuthorizationService` (static matrix, M34); `EngagementAuthorizationService` (M29) |
| Event infrastructure | `EventPublisher` protocol + `InMemoryEventPublisher` + `NullEventPublisher` |
| Shared kernel | `src/redforge/` — domain, application, infrastructure layers |
| Evidence model | Established in M29 `evidence` bounded context |
| Kill switch | M29 `EngagementState` / `KillSwitchState` on `Engagement` aggregate |

### What M35 Inherits

- **M28 `DetectionFinding`** events as primary automation triggers
- **M34 `Incident` phase transitions** (`IncidentContained`, `IncidentEradicated`) as secondary triggers
- **M29 `Engagement` authorization pattern** as the design archetype for `PlaybookAuthorization`
- **M34 `ContainmentAction` aggregate** as the predecessor pattern for `AutomatedAction` aggregate
- **M33 analytics projection infrastructure** for read models

---

## 3. M35 Scope Validation

### Confirmed In-Scope (from Roadmap & Capability Matrix)

| Capability | Roadmap Reference | M35 Column |
|---|---|---|
| Defensive playbook lifecycle | REDFORGE_CAPABILITY_MATRIX | I |
| Event-triggered automation | REDFORGE_CAPABILITY_MATRIX | I |
| Cloud API action execution | REDFORGE_CAPABILITY_MATRIX | I |
| Identity revocation automation | REDFORGE_CAPABILITY_MATRIX | I |
| EDR containment integration | REDFORGE_CAPABILITY_MATRIX | I |
| ITSM integration (ticket creation) | REDFORGE_CAPABILITY_MATRIX | I |
| Automation execution records | REDFORGE_CAPABILITY_MATRIX | I |
| Rollback for automated actions | REDFORGE_CAPABILITY_MATRIX | I |

### Confirmed Out-of-Scope

- Offensive automation (M29/M30)
- General workflow automation platform
- ITSM replacement
- Endpoint response tooling (invokes via integration; does not host EDR logic)
- Threat hunting platform (M36)
- Autonomous AI suggestions (M36)
- Replacement of M28 detection engine

### Bounded Contexts Required

Three new bounded contexts are required (per roadmap specification):

1. **`playbook`** — Core domain: playbook lifecycle, versioning, testing, authorization gating
2. **`automated_action`** — Core domain: action execution, immutable execution records, rollback
3. **`integration_hub`** — Supporting domain: third-party connector framework for action execution targets

---

## 4. DDD Architecture Review

### Current DDD Conventions (Verified from Repository)

The repository consistently applies the following structural conventions across all bounded contexts:

```
src/{context}/
├── api/
│   ├── schemas/         # Pydantic request/response schemas
│   └── v1/              # FastAPI route handlers
│       └── routes.py
├── application/
│   ├── commands/        # Command objects (dataclasses)
│   ├── dtos/            # Data Transfer Objects
│   ├── ports/           # Outbound port definitions
│   ├── queries/         # Query objects
│   ├── read_models/     # Read model projections
│   └── services/        # Application services (orchestrate domain)
├── domain/
│   ├── aggregates/      # Aggregate roots with pop_events()
│   ├── entities/        # Non-root entities
│   ├── events/          # Domain events (frozen dataclasses)
│   ├── exceptions/      # Domain exceptions
│   ├── repositories/    # Repository interfaces (I-prefixed)
│   ├── services/        # Pure domain services (no infra)
│   └── value_objects/   # Value objects (frozen dataclasses/enums)
└── infrastructure/
    ├── acl/             # Anti-corruption layers (optional, when needed)
    ├── events/          # Event handlers/projectors
    ├── persistence/
    │   ├── models/      # SQLAlchemy ORM models
    │   └── repositories/# Concrete repository implementations (pg_*)
    └── scheduler/       # Scheduled workers (optional)
```

### M35 DDD Compliance Requirements

All three M35 bounded contexts **must** follow the above conventions without deviation.

**Critical requirement for `playbook` context:**
- `Playbook` aggregate must carry `__slots__` (as seen in `Incident` and `ContainmentAction`)
- Playbook versioning must be modeled as immutable `PlaybookVersion` entities, not as mutable state on the `Playbook` aggregate
- Authorization gate must be a domain service (not application service logic) analogous to `ContainmentAuthorizationService`

**Critical requirement for `automated_action` context:**
- `AutomatedAction` aggregate must produce `AutomationExecutionRecord` as an immutable audit trail entity
- The aggregate must not allow direct mutation of a completed execution record (same principle as M34 `IncidentCommunicationLogEntry` append-only model)

**Critical requirement for `integration_hub` context:**
- Connector adapters are infrastructure concerns; domain/application layers must depend only on `IActionConnector` port
- No third-party SDK imports may appear in domain or application layers

---

## 5. Bounded Context Analysis

### 5.1 `playbook` — Core Domain

**Classification:** Core domain (not generic; embodies playbook governance which is a competitive differentiator)

**Aggregate roots:**

| Aggregate | Responsibility | Key Invariants |
|---|---|---|
| `Playbook` | Lifecycle: DRAFT → UNDER_REVIEW → APPROVED → DEPRECATED | A DEPRECATED playbook cannot be executed; no rollback to DRAFT once APPROVED |
| `PlaybookVersion` | Immutable snapshot of playbook definition at a point in time | Created once; never mutated; version number monotonically increases per playbook |
| `PlaybookTestResult` | Dry-run execution outcome linked to a specific playbook version | Immutable after creation; test must precede APPROVED status |

**Entities (non-root):**
- `ActionStep` — embedded in `PlaybookVersion`; ordered sequence of action definitions
- `PlaybookTriggerConfig` — the conditions under which this playbook auto-invokes; embedded in `PlaybookVersion`

**Value Objects:**
- `PlaybookId`, `PlaybookVersionId`, `PlaybookTestResultId`
- `PlaybookStatus` (enum: DRAFT, UNDER_REVIEW, APPROVED, DEPRECATED)
- `ActionStepDefinition` (action type, target selector, parameters, rollback definition)
- `TriggerCondition` (trigger_type, threshold, source_context: M28|M34|M32)
- `ActionImpactLevel` (enum: LOW, MEDIUM, HIGH, CRITICAL — drives authorization gate level)
- `PlaybookAuthorizationPolicy` (required roles per action impact level)

**Repository interfaces:**
- `IPlaybookRepository` — CRUD + `find_active_for_trigger(trigger: TriggerCondition)`
- `IPlaybookVersionRepository` — append-only; `get_version(playbook_id, version_number)`
- `IPlaybookTestResultRepository` — append-only

**Domain services:**
- `PlaybookAuthorizationService` — static matrix: `ActionImpactLevel → minimum_role_required`
- `TriggerMatchingService` — evaluates whether an incoming event matches a `TriggerCondition`
- `PlaybookDryRunService` — executes playbook in simulation mode; records `PlaybookTestResult`

**Events:**
- `PlaybookCreated`, `PlaybookVersionPublished`, `PlaybookApproved`, `PlaybookDeprecated`
- `PlaybookTestCompleted` (outcome: PASSED | FAILED | PARTIAL)
- `PlaybookTriggered` (fired when trigger condition matches incoming event)

---

### 5.2 `automated_action` — Core Domain

**Classification:** Core domain (execution evidence integrity and rollback governance are competitive differentiators)

**Aggregate roots:**

| Aggregate | Responsibility | Key Invariants |
|---|---|---|
| `AutomationExecution` | Lifecycle of a single playbook invocation: PENDING → RUNNING → COMPLETED / FAILED / ROLLED_BACK / ESCALATED | Immutable audit trail; terminal states are final |
| `AutomatedActionRecord` | Immutable record of a single atomic action within an execution | Append-only; status transitions are forward-only; never deleted |
| `RollbackRecord` | Documents rollback of a reversible action | Created only once per `AutomatedActionRecord`; references original action ID |

**Entities (non-root):**
- `ExecutionStep` — tracks state of each `ActionStep` within a running execution
- `EscalationRequest` — created when automation pauses for human authorization

**Value Objects:**
- `AutomationExecutionId`, `AutomatedActionRecordId`, `RollbackRecordId`
- `ExecutionStatus` (PENDING, RUNNING, AWAITING_AUTHORIZATION, COMPLETED, FAILED, ROLLED_BACK, ESCALATED)
- `ActionOutcome` (SUCCESS, FAILURE, PARTIAL, SKIPPED_ROLLBACK_COMPLETE)
- `ActionEvidence` (connector response, timestamp, actor identity, checksum)
- `RollbackStatus` (PENDING, IN_PROGRESS, COMPLETED, FAILED, NOT_APPLICABLE)
- `PlaybookRef` (playbook_id, version_number — opaque cross-context reference)
- `TriggerRef` (source_context, source_event_type, source_event_id — the event that triggered execution)

**Repository interfaces:**
- `IAutomationExecutionRepository` — `save()`, `get()`, `find_by_playbook()`, `find_by_trigger()`
- `IAutomatedActionRecordRepository` — append-only; `find_by_execution()`
- `IRollbackRecordRepository` — append-only

**Domain services:**
- `AutomationAuthorizationService` — evaluates `ActionImpactLevel` against operator roles; equivalent to `ContainmentAuthorizationService` but for automated actions
- `RollbackEligibilityService` — determines whether an action is reversible and constructs rollback parameters
- `ExecutionBudgetService` — enforces per-tenant limits on concurrent executions and actions per hour

**Events:**
- `AutomationExecutionStarted`, `AutomationExecutionCompleted`, `AutomationExecutionFailed`
- `AutomatedActionRecorded` (immutable; one per atomic action)
- `AutomationEscalated` (human authorization required; execution paused)
- `AutomationRolledBack`, `RollbackFailed`

---

### 5.3 `integration_hub` — Supporting Domain

**Classification:** Supporting domain (enabler for `automated_action`; does not contain core business rules)

**Aggregate roots:**

| Aggregate | Responsibility | Key Invariants |
|---|---|---|
| `ConnectorRegistration` | Lifecycle of a registered external system connector | Cannot execute through an unhealthy connector without CISO override |
| `ConnectorHealthRecord` | Point-in-time health snapshot for a connector | Append-only; never mutated after creation |

**Entities:**
- `ConnectorCredentialRef` — opaque reference to credential in the credential vault (M42/M43 pattern); never contains actual credentials

**Value Objects:**
- `ConnectorId`, `ConnectorHealthRecordId`
- `ConnectorType` (enum: CLOUD_AWS, CLOUD_AZURE, CLOUD_GCP, EDR_CROWDSTRIKE, EDR_SENTINELONE, EDR_DEFENDER, NETWORK_PALOALTO, NETWORK_CISCO, IDENTITY_OKTA, IDENTITY_AZURE_AD, IDENTITY_PING, ITSM_SERVICENOW, ITSM_JIRA, COMM_SLACK, COMM_TEAMS)
- `ConnectorStatus` (REGISTERED, HEALTHY, DEGRADED, UNHEALTHY, DISABLED)
- `ConnectorHealthStatus` (HEALTHY, DEGRADED, UNHEALTHY)
- `ActionTarget` (connector_id, resource_identifier, action_type_supported)

**Port (key interface):**
```python
class IActionConnector(Protocol):
    async def execute(
        self,
        action_type: str,
        parameters: dict[str, object],
        tenant_id: str,
    ) -> ConnectorActionResult: ...

    async def rollback(
        self,
        original_action_id: str,
        parameters: dict[str, object],
        tenant_id: str,
    ) -> ConnectorActionResult: ...

    async def health_check(self, tenant_id: str) -> ConnectorHealthStatus: ...
```

**Repository interfaces:**
- `IConnectorRegistrationRepository` — `save()`, `get()`, `find_healthy_for_action_type()`
- `IConnectorHealthRecordRepository` — append-only

**Events:**
- `ConnectorRegistered`, `ConnectorHealthCheckCompleted`, `ConnectorHealthDegraded`, `ConnectorHealthRestored`, `ConnectorDisabled`

---

## 6. Domain Model Issues

### Issue 6.1 — Playbook Version Immutability Gap
**Severity:** HIGH  
**Description:** The roadmap and M29 analogy imply that a published `PlaybookVersion` is immutable (like `AttackPlan` versions in M29). However, if `ActionStep` definitions are allowed to be mutable after a version is published, the dry-run result (bound to the version) can become invalid without the system detecting it.  
**Root Cause:** Not yet defined — must be explicitly frozen in finalization.  
**Recommendation:** Enforce that `PlaybookVersion` status can only be: `DRAFT` (mutable) → `PUBLISHED` (immutable). Once `PUBLISHED`, the content hash must be computed and stored. Any dry-run result references this hash; if the hash changes, the dry-run result is invalidated automatically.  
**Future Risk:** Without content-hash enforcement, security engineers may run dry-runs on draft content and deploy a different production version.

### Issue 6.2 — AutomatedActionRecord Orphan Risk
**Severity:** MEDIUM  
**Description:** `AutomatedActionRecord` must reference both `AutomationExecution` and the external system's response. If the connector call succeeds but the database write of `AutomatedActionRecord` fails, the action is externally applied but internally unrecorded.  
**Root Cause:** Distributed transaction problem (external side effect + internal write).  
**Recommendation:** Outbox pattern: write `AutomatedActionRecord` in status `PENDING` before connector call; update to `COMPLETED`/`FAILED` after result. Never lose the record of what was attempted.

### Issue 6.3 — Kill Switch Absence
**Severity:** HIGH  
**Description:** M29 `Engagement` has `KillSwitchState` (ARMED/TRIGGERED) that immediately halts all offensive operations. M35 automated defensive operations can cause operational disruption. There is no per-platform kill switch in the M35 design as described.  
**Root Cause:** The roadmap document references M29 kill switch extension but does not define M35's own mechanism.  
**Recommendation:** `AutomationKillSwitch` value object on a per-tenant `AutomationPolicy` aggregate (or extend `AutomationExecution` to check a platform-level kill switch flag before starting each action step). Kill switch activation must halt all in-progress and queued executions for the tenant.

### Issue 6.4 — Connector Credential Storage
**Severity:** CRITICAL  
**Description:** `integration_hub` connectors must authenticate to external systems (AWS API keys, Okta tokens, CrowdStrike API credentials). Where these credentials are stored is architecturally undefined.  
**Root Cause:** Credential vault bounded context (M42/M43) may not be production-complete. M35 cannot store credentials in plaintext in the connector registration table.  
**Recommendation:** `ConnectorRegistration` stores only a `CredentialRef` (opaque ID referencing the credential vault). At execution time, `integration_hub` application service calls the credential vault to resolve the live credential. If no credential vault is available, the connector cannot execute. This is not a graceful degradation — it is a hard block. Plaintext credentials in the database are prohibited.

### Issue 6.5 — Dry-Run Realism
**Severity:** MEDIUM  
**Description:** The dry-run (`PlaybookTestResult`) must validate against a simulation environment. If dry-run simply skips connector calls and always returns SUCCESS, it provides false confidence that the production execution will match.  
**Root Cause:** Simulation fidelity is architecturally undefined.  
**Recommendation:** Dry-run must exercise the full playbook decision logic (trigger matching, authorization gate evaluation, action step sequencing, rollback resolution) with stubbed connector calls that return configurable mock responses. The dry-run must record which paths were exercised and which were not (partial coverage warning). The 95% prediction accuracy success criterion in the roadmap requires dry-run fidelity to be architectural, not aspirational.

### Issue 6.6 — Escalation Human-in-the-Loop Model
**Severity:** HIGH  
**Description:** High-impact actions require human authorization during execution. The mechanism for pausing an in-flight `AutomationExecution`, notifying the operator, receiving authorization, and resuming is architecturally undefined.  
**Root Cause:** The M34 model uses `ContainmentAction` PENDING_AUTH status and a separate `authorize()` command. M35 needs an equivalent mechanism for in-flight automations.  
**Recommendation:** `AutomationExecution` carries `ExecutionStatus.AWAITING_AUTHORIZATION` state. An `EscalationRequest` entity is created within the `automated_action` context. Authorization command `AuthorizeAutomationStep` resumes the execution. Timeout without authorization transitions execution to `FAILED` with reason `ESCALATION_TIMEOUT`.

---

## 7. Authorization Architecture Review

### 7.1 M29 Authorization Pattern (Established)

M29's authorization model is the gold standard in this repository:

```
EngagementAuthorizationService.evaluate(engagement, target, technique, time)
  → checks: state=ACTIVE, kill_switch=ARMED, scope.contains(target), technique in ROE, window.contains(time)
  → returns: AUTHORIZED | FORBIDDEN | DEFERRED

ContainmentAuthorizationService.assert_authorized(action_type, roles)
  → static matrix: ContainmentActionType → ContainmentAuthorizationLevel
  → _ROLE_LEVEL: operator role → authorization level
  → _LEVEL_RANK: level → numeric rank (analyst=1, commander=2, ciso=3)
```

### 7.2 M35 Authorization Requirements

M35 introduces a two-layer authorization model:

**Layer 1: Playbook Authorization (design-time)**
- When a playbook is approved, the approving operator must have `playbook:security_engineer` role minimum
- Each `ActionStep` carries an `ActionImpactLevel`; the playbook's maximum impact level determines which roles can approve it
- This mirrors M29 engagement approval quorum requirements

**Layer 2: Execution Authorization (runtime, per-action)**
- When an `AutomationExecution` reaches a step with `ActionImpactLevel.HIGH` or `ActionImpactLevel.CRITICAL`, execution pauses
- The operator who triggered the execution cannot self-authorize the escalation (separation of duties)
- A different operator with the required role issues `AuthorizeAutomationStep`
- This mirrors M29's multi-party approval model

**Condition C1:** The `PlaybookAuthorizationService` static matrix must be defined and frozen in the finalization document. The matrix must include at minimum:

| ActionImpactLevel | Playbook Approval Role | Runtime Authorization Role |
|---|---|---|
| LOW | `soc:analyst` | None (auto-execute) |
| MEDIUM | `soc:commander` | None (auto-execute) |
| HIGH | `soc:commander` | `soc:commander` (separate from trigger operator) |
| CRITICAL | `incident:ciso` | `incident:ciso` |

### 7.3 Automation Kill Switch

**Condition C2:** A per-tenant `AutomationKillSwitch` mechanism must be defined. When activated:
1. All `AutomationExecution` in status `RUNNING` or `AWAITING_AUTHORIZATION` transition to `FAILED` with reason `KILL_SWITCH_ACTIVATED`
2. No new `AutomationExecution` can be started while kill switch is active
3. Kill switch activation is an immutable event (`AutomationKillSwitchActivated`) in the audit trail
4. Kill switch deactivation requires `incident:ciso` role

---

## 8. Integration Architecture Review

### 8.1 Connector Framework Design

The `integration_hub` connector framework must satisfy:

1. **Uniform port**: All connectors implement `IActionConnector` — no action execution code may reference a specific connector implementation directly
2. **Timeout enforcement**: Every connector call must have a configured maximum execution time; no unbounded waits
3. **Rate limit handling**: Connectors must handle HTTP 429 with exponential backoff; rate limit budget must be tracked per connector per tenant
4. **Circuit breaker**: Circuit breaker pattern (established in Sprint 26 `RuntimeContainer`) must wrap each connector — if a connector returns errors consistently, it opens the circuit and execution escalates rather than retrying indefinitely
5. **Partial execution**: If step N of a 5-step playbook succeeds but step N+1's connector is unhealthy, the execution must not silently lose the record of steps 1..N

### 8.2 Connector Taxonomy (Frozen)

| ConnectorType | Actions Supported | Rollback Support |
|---|---|---|
| CLOUD_AWS | `isolate_ec2`, `revoke_iam_session`, `modify_security_group`, `enable_guardduty_finding_archive` | `restore_security_group`, `re-enable_iam_session` |
| CLOUD_AZURE | `isolate_vm`, `revoke_entra_session`, `modify_nsg` | `restore_nsg`, `re-enable_session` |
| CLOUD_GCP | `isolate_compute`, `revoke_service_account`, `modify_firewall` | `restore_firewall` |
| EDR_CROWDSTRIKE | `contain_host`, `kill_process` | `lift_host_containment` |
| EDR_SENTINELONE | `contain_host`, `kill_process` | `lift_host_containment` |
| EDR_DEFENDER | `isolate_device`, `restrict_app_execution` | `unisolate_device` |
| NETWORK_PALOALTO | `block_ip`, `block_url`, `quarantine_segment` | `unblock_ip`, `unblock_url` |
| NETWORK_CISCO | `block_ip`, `shut_interface` | `unblock_ip`, `restore_interface` |
| IDENTITY_OKTA | `revoke_user_session`, `disable_account`, `enforce_mfa` | `restore_user_session`, `enable_account` |
| IDENTITY_AZURE_AD | `revoke_sign_in_sessions`, `disable_account` | `enable_account` |
| IDENTITY_PING | `revoke_user_session`, `disable_account` | `enable_account` |
| ITSM_SERVICENOW | `create_incident`, `create_change_request` | None (informational; irreversible by nature) |
| ITSM_JIRA | `create_issue`, `add_comment` | None |
| COMM_SLACK | `send_message`, `send_alert` | None |
| COMM_TEAMS | `send_message`, `send_alert` | None |

**Rollback policy:** Actions with `Rollback Support = None` are classified `ActionImpactLevel.LOW`; they cannot be reversed but they do not affect production infrastructure. Actions with rollback support carry impact levels `MEDIUM` through `CRITICAL` based on operational impact.

### 8.3 External System Failure Handling

**Condition C3:** The failure handling contract for each connector must be defined at the architecture level:

```
Connector failure modes:
  TIMEOUT          → escalate to human authorization
  RATE_LIMITED     → backoff + retry up to max_retries; then escalate
  AUTH_FAILURE     → immediately fail execution step; alert operations; do NOT retry
  API_ERROR_4xx    → fail execution step; record error detail in AutomatedActionRecord
  API_ERROR_5xx    → retry with exponential backoff; circuit breaker applies
  CIRCUIT_OPEN     → immediately escalate; do NOT attempt connector call
```

---

## 9. Persistence & Storage Review

### 9.1 Migration Continuity

Current head: `0113_incident_operational_metrics`

M35 requires migrations `0114` through `0130` (estimate):

| Migration Range | Context | Tables |
|---|---|---|
| 0114–0118 | `playbook` | `playbooks`, `playbook_versions`, `playbook_action_steps`, `playbook_trigger_configs`, `playbook_test_results` |
| 0119–0124 | `automated_action` | `automation_executions`, `automation_execution_steps`, `automated_action_records`, `rollback_records`, `escalation_requests`, `automation_kill_switch_log` |
| 0125–0128 | `integration_hub` | `connector_registrations`, `connector_health_records`, `connector_action_audit`, `connector_rate_limit_tracking` |
| 0129–0130 | Security Graph | `security_graph` node/edge extensions for `PlaybookNode`, `AutomatedActionNode` |

### 9.2 Partition Strategy

**`automated_action_records`** — partition by `tenant_id` (HASH, 8 partitions). This table is append-only and grows proportionally with execution volume. Hash partitioning ensures even distribution.

**`automation_executions`** — partition by `created_at` (RANGE, monthly). Operational queries are time-bounded; range partitioning enables efficient `created_at` range scans and partition pruning.

**`playbook_versions`** — no partition required at this scale; low write rate.

### 9.3 Indexing Strategy

```sql
-- playbooks
CREATE INDEX ix_playbooks_tenant_status ON playbooks(tenant_id, status);
CREATE INDEX ix_playbooks_tenant_name ON playbooks(tenant_id, name);

-- playbook_trigger_configs
CREATE INDEX ix_trigger_configs_tenant_trigger_type ON playbook_trigger_configs(tenant_id, trigger_type);

-- automation_executions
CREATE INDEX ix_executions_tenant_playbook ON automation_executions(tenant_id, playbook_id);
CREATE INDEX ix_executions_tenant_status ON automation_executions(tenant_id, status);
CREATE INDEX ix_executions_tenant_created ON automation_executions(tenant_id, created_at);
CREATE INDEX ix_executions_trigger_ref ON automation_executions(source_event_id);

-- automated_action_records
CREATE INDEX ix_action_records_execution ON automated_action_records(execution_id);
CREATE INDEX ix_action_records_tenant_connector ON automated_action_records(tenant_id, connector_type);
CREATE INDEX ix_action_records_target_ref ON automated_action_records(target_asset_ref);
```

### 9.4 Caching Strategy

- **Playbook cache**: Active approved playbooks are cached per-tenant for 5 minutes (LRU); invalidated on `PlaybookApproved` or `PlaybookDeprecated` event
- **Trigger index cache**: `TriggerCondition → [playbook_id]` mapping cached per-tenant; invalidated on playbook version changes
- **Connector health cache**: Last known health status cached for 60 seconds; stale cache used if health check fails

---

## 10. Event Architecture Review

### 10.1 Cross-Context Event Consumption

M35 consumes events from external bounded contexts. These consumption contracts must be stable:

| Source Event | Source Context | M35 Consumer | Action |
|---|---|---|---|
| `DetectionFindingEscalated` | `detection` (M28) | `playbook` trigger engine | Evaluate active trigger conditions; start matching playbook executions |
| `IncidentContained` | `incident` (M34) | `playbook` trigger engine | Trigger eradication playbooks if configured |
| `IncidentEradicated` | `incident` (M34) | `playbook` trigger engine | Trigger recovery playbooks if configured |
| `ExposureThresholdBreached` | `exposure` (M32) | `playbook` trigger engine | Trigger prioritized response playbooks |

**Condition C4:** The exact payload contracts for `DetectionFindingEscalated` and `IncidentContained` must be confirmed with M28 and M34 domain owners. M35 must define ACL (Anti-Corruption Layer) translators that isolate M35 from upstream schema evolution.

### 10.2 Events Published by M35

| Event | Context | Consumer |
|---|---|---|
| `PlaybookTriggered` | `playbook` | `automated_action` (start execution) |
| `AutomationExecutionStarted` | `automated_action` | Analytics (M33), Security Graph |
| `AutomationExecutionCompleted` | `automated_action` | Analytics (M33), Security Graph, M34 Incident timeline |
| `AutomationExecutionFailed` | `automated_action` | Analytics (M33), Alert service |
| `AutomationEscalated` | `automated_action` | Notification service (alert SOC operator) |
| `AutomationRolledBack` | `automated_action` | Security Graph, Analytics |
| `ConnectorHealthDegraded` | `integration_hub` | Alert service, `automated_action` circuit breaker |

### 10.3 Event Schema Design

All M35 domain events must follow the established pattern:

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionStarted(BaseAutomationEvent):
    execution_id: str
    playbook_id: str
    playbook_version: int
    trigger_type: str          # M28_FINDING | M34_INCIDENT | M32_EXPOSURE | MANUAL
    source_event_id: str       # ID of the event that triggered execution
    total_steps: int
    max_impact_level: str      # Highest ActionImpactLevel in this execution
```

---

## 11. Security Graph Review

### 11.1 Required Node Types

```
PlaybookNode:
  node_type: PLAYBOOK
  properties: playbook_id, name, status, max_impact_level, version_count

AutomatedActionNode:
  node_type: AUTOMATED_ACTION
  properties: execution_id, action_type, connector_type, outcome, executed_at
```

### 11.2 Required Edge Types

```
TRIGGERED_PLAYBOOK:
  from: DetectionFindingNode (M28) | IncidentNode (M34) | ExposureRecordNode (M32)
  to:   PlaybookNode

EXECUTED_ACTION:
  from: PlaybookNode
  to:   AutomatedActionNode

ACTION_ON_ASSET:
  from: AutomatedActionNode
  to:   AssetNode (M22/M26)

ROLLED_BACK_BY:
  from: AutomatedActionNode (original)
  to:   AutomatedActionNode (rollback)
```

### 11.3 Graph Write Ownership Rule

Per Strategic Dependencies document (Section 8, Risk 1): M35 writes only edges **from its own nodes**. It never writes edges originating from M28, M34, or M32 nodes. Cross-context edges are the responsibility of ACL projection workers.

---

## 12. Operational Resilience Review

### 12.1 Playbook Execution Worker

Playbook executions are **not synchronous HTTP responses**. A single execution may span 30 seconds to several minutes (network calls to external systems). Architecture requires:

- **`PlaybookExecutionWorker`**: A background worker that dequeues `PlaybookTriggered` events and processes `AutomationExecution` instances
- **Idempotency**: `AutomationExecution.execution_id` derived from `(playbook_id, source_event_id)` — prevents duplicate executions for the same trigger event
- **Concurrency control**: Per-tenant maximum concurrent executions configurable; default 5; CISO-adjustable up to 50
- **Execution timeout**: Per-execution maximum wall time; default 10 minutes; beyond this, execution transitions to `FAILED` with `TIMEOUT` reason

### 12.2 Connector Health Worker

- **`ConnectorHealthWorker`**: Polls registered connectors on a configurable schedule (default: every 60 seconds per connector)
- On health degradation: publishes `ConnectorHealthDegraded`; circuit breaker opens for that connector
- On health restoration: publishes `ConnectorHealthRestored`; circuit breaker half-opens per existing Sprint 26 pattern

### 12.3 Rollback Worker

- **`RollbackWorker`**: Processes queued rollback requests asynchronously
- Rollback is not always possible (external state may have changed); `RollbackRecord` captures outcome including partial rollback
- Failed rollback alerts `soc:commander`; does not retry automatically

### 12.4 Trigger Evaluation Performance

- Playbook invocation latency target: **≤30 seconds from trigger event to first action** (roadmap SLA)
- Trigger evaluation must be in-memory (cached trigger index) — no database round-trip per evaluation
- Worker must dequeue from event bus with processing guarantee (at-least-once delivery)

---

## 13. Cross-Context Leakage Analysis

### Risk 13.1 — `playbook` Context Importing `incident` Domain Objects

**Risk:** The `playbook` context might import `IncidentPhase` or `IncidentSeverity` enums directly from the `incident` package to model trigger conditions.  
**Impact:** Context coupling. Changes to `incident` domain model break `playbook`.  
**Mitigation (mandatory):** `playbook` defines its own `TriggerSourceContext` enum (M28_FINDING | M34_INCIDENT | M32_EXPOSURE) and opaque `TriggerEventId` value object. ACL translators in `playbook.infrastructure.acl` convert M34 events to M35 internal representations.

### Risk 13.2 — `automated_action` Directly Calling `integration_hub` Application Service

**Risk:** `automated_action` worker may invoke `integration_hub` application service directly rather than through the `IActionConnector` port.  
**Impact:** Tight coupling; untestable without real connectors.  
**Mitigation (mandatory):** `automated_action` application service depends only on `IActionConnector` protocol. Concrete connector implementations in `integration_hub.infrastructure` are injected at composition root.

### Risk 13.3 — Security Graph Write From Multiple M35 Contexts

**Risk:** Both `playbook` and `automated_action` may write to the Security Graph, creating competing writers for related nodes/edges.  
**Impact:** Duplicate nodes; inconsistent edge state.  
**Mitigation:** Single graph projection worker in `automated_action.infrastructure.events` handles all M35 graph writes. `playbook` publishes events; `automated_action` KG projector consumes both sets of events. Idempotent node creation (upsert by stable ID).

---

## 14. Tenant Isolation Review

### 14.1 Playbook Tenant Isolation

- All `Playbook`, `PlaybookVersion`, `PlaybookTestResult` aggregates carry `tenant_id` as a required first-class attribute
- Repository implementations enforce `WHERE tenant_id = :tenant_id` on all queries (no exceptions)
- Trigger matching evaluated per-tenant; no cross-tenant trigger evaluation

### 14.2 Connector Isolation

- `ConnectorRegistration` is tenant-scoped; a connector registered for Tenant A cannot be used by Tenant B
- Connector credential refs are tenant-scoped in the credential vault
- Rate limit tracking is per-connector per-tenant

### 14.3 Execution Isolation

- `AutomationExecution` carries `tenant_id`; all state transitions assert `_assert_tenant()` (following the established `Incident` aggregate pattern)
- Kill switch operates per-tenant; one tenant's kill switch does not affect another

---

## 15. Migration Risk Analysis

### Risk 15.1 — Migration 0114+ Coupled to Credential Vault Availability

**Severity:** HIGH  
**Issue:** `connector_registrations` table must reference the credential vault. If the credential vault schema is not finalized, M35 migrations cannot be finalized.  
**Recommendation:** `connector_registrations.credential_ref` stored as `TEXT` (opaque vault key string) — no FK to credential vault tables. This decouples M35 migrations from vault schema evolution.

### Risk 15.2 — Trigger Config Table Volume

**Severity:** LOW  
**Issue:** If thousands of playbooks are registered, the trigger config evaluation on every incoming event becomes expensive.  
**Recommendation:** Materialized trigger index in application memory (per-tenant, refreshed on config change). Migration includes appropriate GIN index on `playbook_trigger_configs.trigger_condition JSONB` column for cold-start query.

### Risk 15.3 — Existing Event Store Replay

**Severity:** LOW  
**Issue:** Replay infrastructure (Sprint 25) must be extended to register M35 projection handlers.  
**Recommendation:** M35 provides `PlaybookProjectionHandler` and `AutomationExecutionProjectionHandler` registered in the `ProjectionRegistry` following the M30 pattern.

---

## 16. Issue Register

| ID | Severity | Description | Must Resolve Before |
|---|---|---|---|
| C1 | HIGH | `PlaybookAuthorizationService` static matrix not defined | Architecture Finalization |
| C2 | HIGH | Kill switch mechanism for M35 automation not defined | Architecture Finalization |
| C3 | HIGH | Connector failure handling contract not fully specified | Architecture Finalization |
| C4 | MEDIUM | ACL contracts for `DetectionFindingEscalated` and `IncidentContained` event consumption not confirmed | Phase 2 start |
| C5 | HIGH | `PlaybookVersion` content hashing for dry-run validity enforcement not defined | Architecture Finalization |
| C6 | CRITICAL | Credential storage for connectors: `CredentialRef` model not defined; plaintext prohibition not enforced | Architecture Finalization |
| C7 | HIGH | `AutomatedActionRecord` outbox pattern for preventing orphaned external actions not specified | Architecture Finalization |
| C8 | HIGH | Escalation pause/resume protocol for in-flight executions not defined | Architecture Finalization |
| C9 | MEDIUM | Security Graph edge ownership and write idempotency for M35 not specified | Phase 3 start |

---

## 17. Architecture Verdict

**Decision:** APPROVED WITH CONDITIONS (C1–C9)

All nine conditions must be resolved in `M35_ARCHITECTURE_FINALIZATION.md` before any implementation begins. Conditions C1, C2, C5, C6, C7, and C8 are blocking for Phase 1. Conditions C3 and C4 are blocking for Phase 2. Condition C9 is blocking for Phase 3.

The three-bounded-context decomposition (`playbook` / `automated_action` / `integration_hub`) is correct and approved. The authorization model must achieve parity with M29 offensive governance before implementation proceeds.

**Implementation may not begin until this review is countersigned and M35_ARCHITECTURE_FINALIZATION.md is produced.**
