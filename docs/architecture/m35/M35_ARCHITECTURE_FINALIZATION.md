# M35 Architecture Finalization
## Enterprise Security Automation & Orchestration Platform

**Status:** FROZEN FOR IMPLEMENTATION  
**Date:** 2026-07-22  
**Precondition:** M35 Architecture Review APPROVED WITH CONDITIONS (C1–C9)  
**Constraint:** Documentation only. No code, no migrations, no repository modifications until approved.

---

## Table of Contents

1. [Final Decisions (C1–C9)](#1-final-decisions-c1c9)
2. [Frozen DDD Model](#2-frozen-ddd-model)
3. [Frozen Event Contracts](#3-frozen-event-contracts)
4. [Frozen Repository Interfaces](#4-frozen-repository-interfaces)
5. [Frozen Command & Query Model](#5-frozen-command--query-model)
6. [Frozen Read Models](#6-frozen-read-models)
7. [Frozen Migration Plan](#7-frozen-migration-plan)
8. [Frozen Worker Specifications](#8-frozen-worker-specifications)
9. [Frozen Security Graph Extensions](#9-frozen-security-graph-extensions)
10. [Authorization Model](#10-authorization-model)
11. [ADRs (ADR-M35-001 through ADR-M35-007)](#11-adrs)
12. [Risk Dispositions (R01–R10)](#12-risk-dispositions)
13. [Frozen Phase Plan](#13-frozen-phase-plan)
14. [Implementation Readiness Assessment](#14-implementation-readiness-assessment)

---

## 1. Final Decisions (C1–C9)

---

### C1 — PlaybookAuthorizationService Static Matrix

**Condition from Review:** Define and freeze the `PlaybookAuthorizationService` static matrix.

#### Decision: Four-Level Impact Model with Separation of Duties

**`ActionImpactLevel` enum (frozen):**
```
LOW      — Informational/notification actions; no infrastructure change (ITSM ticket, Slack message)
MEDIUM   — Reversible, low-blast-radius actions (IP block on single host, session revocation)
HIGH     — Reversible, high-blast-radius actions (account disable, host quarantine, segment isolation)
CRITICAL — Potentially irreversible, enterprise-wide impact (mass credential revoke, production isolation)
```

**Playbook approval authorization matrix (frozen):**

| Max ActionImpactLevel in Playbook | Minimum Approval Role | Quorum Required |
|---|---|---|
| LOW | `soc:analyst` | Single approver |
| MEDIUM | `soc:commander` | Single approver |
| HIGH | `soc:commander` | Dual approver (two distinct users with `soc:commander` or higher) |
| CRITICAL | `incident:ciso` | Dual approver (one `soc:commander` + one `incident:ciso`) |

**Runtime execution authorization matrix (frozen):**

| ActionImpactLevel | Auto-Execute | Runtime Authorization Role | Separation of Duties |
|---|---|---|---|
| LOW | Yes | None | N/A |
| MEDIUM | Yes | None | N/A |
| HIGH | No | `soc:commander` | Must not be the same user who triggered execution |
| CRITICAL | No | `incident:ciso` | Must not be the same user who triggered or who approved HIGH gate |

**`PlaybookAuthorizationService` implementation contract (frozen):**

```python
class PlaybookAuthorizationService:
    _APPROVAL_MATRIX: dict[ActionImpactLevel, tuple[str, int]] = {
        ActionImpactLevel.LOW:      ("soc:analyst",    1),
        ActionImpactLevel.MEDIUM:   ("soc:commander",  1),
        ActionImpactLevel.HIGH:     ("soc:commander",  2),
        ActionImpactLevel.CRITICAL: ("incident:ciso",  2),  # enforced at application layer
    }

    _RUNTIME_MATRIX: dict[ActionImpactLevel, str | None] = {
        ActionImpactLevel.LOW:      None,          # auto-execute
        ActionImpactLevel.MEDIUM:   None,          # auto-execute
        ActionImpactLevel.HIGH:     "soc:commander",
        ActionImpactLevel.CRITICAL: "incident:ciso",
    }

    def assert_approval_authorized(
        self,
        max_impact_level: ActionImpactLevel,
        approver_roles: tuple[str, ...],
    ) -> None:
        min_role, _ = self._APPROVAL_MATRIX[max_impact_level]
        if min_role not in approver_roles:
            raise PlaybookAuthorizationDenied(
                f"Impact {max_impact_level.value} requires role {min_role}"
            )

    def runtime_authorization_required(
        self, impact_level: ActionImpactLevel
    ) -> str | None:
        return self._RUNTIME_MATRIX[impact_level]

    def assert_runtime_authorized(
        self,
        impact_level: ActionImpactLevel,
        authorizer_roles: tuple[str, ...],
        authorizer_id: str,
        trigger_operator_id: str,
    ) -> None:
        required_role = self.runtime_authorization_required(impact_level)
        if required_role is None:
            return  # auto-execute; no authorization check needed
        if authorizer_id == trigger_operator_id:
            raise SeparationOfDutiesViolation(
                "Runtime authorizer must differ from the operator who triggered execution"
            )
        if required_role not in authorizer_roles:
            raise PlaybookAuthorizationDenied(
                f"Runtime authorization for {impact_level.value} requires role {required_role}"
            )
```

---

### C2 — Kill Switch Mechanism

**Condition from Review:** Define per-tenant kill switch for M35 automation.

#### Decision: Per-Tenant AutomationPolicy Aggregate with KillSwitchState

**`AutomationPolicy` aggregate (introduced in `playbook` context):**

```
AutomationPolicy:
  tenant_id: TenantId                    (aggregate root key)
  kill_switch_state: KillSwitchState     (ARMED | TRIGGERED)
  kill_switch_triggered_at: datetime | None
  kill_switch_triggered_by: str | None
  max_concurrent_executions: int         (default: 5, max: 50)
  max_actions_per_hour: int              (default: 100, max: 1000)
  allowed_connector_types: list[ConnectorType] | None  (None = all allowed)
```

**`KillSwitchState` (enum):** ARMED | TRIGGERED

**Kill switch activation invariants:**
1. Any `PlaybookExecutionWorker` checks `AutomationPolicy.kill_switch_state` before starting each execution — if TRIGGERED, declines with `KillSwitchActive` exception
2. In-progress executions receive `KILL_SWITCH_ACTIVATED` signal; current step is allowed to complete (no mid-action abort); next step is not started
3. `AutomationKillSwitchActivated` domain event published (immutable audit)
4. Deactivation (`ResetKillSwitch` command) requires `incident:ciso` role; publishes `AutomationKillSwitchReset`

**Per-tenant kill switch is independent.** Activating Tenant A's kill switch does not affect Tenant B.

---

### C3 — Connector Failure Handling Contract

**Condition from Review:** Define the complete failure handling contract per connector failure mode.

#### Decision: Typed Failure Modes with Prescribed Handling

```
ConnectorFailureMode enum:
  TIMEOUT           — connector call exceeded max_execution_seconds
  RATE_LIMITED      — HTTP 429 received from external system
  AUTH_FAILURE      — HTTP 401/403 from external system (credential invalid/expired)
  CLIENT_ERROR      — HTTP 400–499 (excluding 401/403/429) — bad request
  SERVER_ERROR      — HTTP 500–599 from external system
  CIRCUIT_OPEN      — circuit breaker is open for this connector
  NETWORK_FAILURE   — connection refused / DNS failure
  PARTIAL_SUCCESS   — multi-resource action partially completed before failure
```

**Prescribed handling per mode (frozen):**

| FailureMode | Retry? | Escalate? | Action Record Status | Circuit Breaker Impact |
|---|---|---|---|---|
| TIMEOUT | Yes, up to 2 | If all retries fail | FAILED | Increment failure count |
| RATE_LIMITED | Yes, backoff (30s, 60s, 120s) | If budget exhausted | FAILED | No (rate limits are expected) |
| AUTH_FAILURE | No | Immediate + alert ops | FAILED | Open circuit (auth invalid = systemic) |
| CLIENT_ERROR | No | No (log only) | FAILED | No |
| SERVER_ERROR | Yes, up to 2 | If all retries fail | FAILED | Increment failure count |
| CIRCUIT_OPEN | No | Immediate | ESCALATED | N/A (circuit already open) |
| NETWORK_FAILURE | Yes, up to 2 | If all retries fail | FAILED | Increment failure count |
| PARTIAL_SUCCESS | No | Immediate | PARTIAL | Increment failure count |

**`ConnectorActionResult` value object (frozen):**
```python
@dataclass(frozen=True, slots=True)
class ConnectorActionResult:
    success: bool
    failure_mode: ConnectorFailureMode | None  # None if success=True
    external_reference: str | None              # external system's confirmation ID
    response_payload: dict[str, object]         # raw connector response (sanitized)
    executed_at: datetime
    duration_ms: int
    rollback_available: bool
    rollback_parameters: dict[str, object]      # parameters needed for rollback call
```

---

### C4 — ACL Contracts for Cross-Context Event Consumption

**Condition from Review:** Confirm payload contracts for `DetectionFindingEscalated` and `IncidentContained` consumption.

#### Decision: ACL Translators in infrastructure/acl with Frozen Input Contracts

**`DetectionFindingEscalated` payload contract (as consumed by M35):**
```python
# M28 publishes; M35 ACL translates to internal TriggerEvent
@dataclass(frozen=True, slots=True)
class DetectionFindingEscalatedPayload:  # ACL input type; not a domain event
    finding_id: str
    tenant_id: str
    severity: str           # M28 FindingSeverity value
    rule_id: str
    asset_ref: str | None   # M22 asset ID
    technique_id: str | None  # ATT&CK technique
    escalated_at: str       # ISO-8601
```

**`IncidentContained` payload contract:**
```python
@dataclass(frozen=True, slots=True)
class IncidentContainedPayload:  # ACL input type
    incident_id: str
    tenant_id: str
    severity: str           # M34 IncidentSeverity value
    contained_at: str       # ISO-8601
```

**ACL translator (contract frozen):**
```python
class M28FindingTriggerTranslator:
    def to_trigger_event(
        self, payload: DetectionFindingEscalatedPayload
    ) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context=TriggerSourceContext.M28_FINDING,
            source_event_id=payload.finding_id,
            tenant_id=payload.tenant_id,
            severity_hint=self._map_severity(payload.severity),
            asset_ref=payload.asset_ref,
        )
```

---

### C5 — PlaybookVersion Content Hashing

**Condition from Review:** Define enforcement of dry-run validity via content hash.

#### Decision: SHA-256 Content Hash on Publication; Dry-Run Bound to Hash

**`PlaybookVersion.content_hash` (frozen):**

When `PlaybookVersion.status` transitions from `DRAFT` to `PUBLISHED`:
1. `content_hash = SHA256(canonical_json(action_steps + trigger_configs))` computed by domain service
2. `content_hash` stored immutably with the version record
3. `PlaybookTestResult` records `playbook_version_content_hash` at time of dry-run
4. Before approving a playbook for production: application service verifies `latest_test_result.content_hash == current_version.content_hash`; if mismatch, approval is rejected with `DryRunHashMismatch`

**Canonical JSON rule:** Keys sorted alphabetically, no trailing whitespace, UTF-8 encoding. Implemented as a pure domain function `canonical_playbook_json(version: PlaybookVersion) -> bytes`.

---

### C6 — Credential Storage Model

**Condition from Review:** Define CredentialRef model; prohibit plaintext credentials in connector registrations.

#### Decision: Opaque CredentialRef with Vault Port Abstraction

**`CredentialRef` value object (frozen):**
```python
@dataclass(frozen=True, slots=True)
class CredentialRef:
    vault_key: str          # opaque key in the credential store
    tenant_id: str          # credential is tenant-scoped
    credential_type: str    # API_KEY | OAUTH_CLIENT | CERTIFICATE | ASSUME_ROLE_ARN
```

**`ICredentialVaultPort` (integration_hub application port — frozen):**
```python
class ICredentialVaultPort(Protocol):
    async def resolve(
        self,
        ref: CredentialRef,
        tenant_id: str,
    ) -> ResolvedCredential: ...

@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    credential_type: str
    secret_value: str       # in-memory only; never logged; never persisted
    expires_at: datetime | None
```

**`ConnectorRegistration` database schema (frozen):**
```sql
CREATE TABLE integration_hub.connector_registrations (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID         NOT NULL,
    connector_type      VARCHAR(50)  NOT NULL,
    status              VARCHAR(30)  NOT NULL DEFAULT 'REGISTERED',
    credential_vault_key TEXT        NOT NULL,   -- opaque vault reference; NOT the credential
    credential_type     VARCHAR(30)  NOT NULL,
    display_name        TEXT         NOT NULL,
    base_url            TEXT,
    configuration       JSONB,                   -- connector-specific non-secret config
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
```

**Hard prohibition (enforced at domain level):**
- `ConnectorRegistration` aggregate MUST NOT contain `api_key`, `secret`, `password`, `token`, or `certificate` columns
- Application service MUST NOT log `ResolvedCredential.secret_value`
- Architecture tests MUST verify no secret field names exist in `connector_registrations` ORM model

---

### C7 — AutomatedActionRecord Outbox Pattern

**Condition from Review:** Prevent orphaned external actions via outbox pattern.

#### Decision: Write-First Outbox in automated_action Execution Worker

**Execution sequence (frozen):**

```
1. BEGIN TRANSACTION
2. INSERT automated_action_records (execution_id, step_number, status=PENDING, connector_type, parameters_hash, attempted_at=now())
3. COMMIT TRANSACTION
4. [Record is now durable — external action can be attempted]
5. connector.execute(parameters)
6. BEGIN TRANSACTION
7. UPDATE automated_action_records SET status=COMPLETED/FAILED, outcome=..., external_reference=..., completed_at=now()
8. COMMIT TRANSACTION
```

**Recovery on worker restart:**
- On startup, `PlaybookExecutionWorker` queries `WHERE status = 'PENDING' AND attempted_at < now() - interval '5 minutes'`
- PENDING records older than 5 minutes are considered abandoned; worker issues a `VerifyActionOutcome` call to the connector
- If connector confirms success: update to COMPLETED
- If connector returns not-found or failure: update to FAILED
- If connector is unreachable: escalate to human

**Idempotency requirement on connectors:** Connector implementations MUST support idempotent re-execution using `execution_id + step_number` as the idempotency key, passed as `X-Idempotency-Key` header (where connector supports it).

---

### C8 — Escalation Pause/Resume Protocol

**Condition from Review:** Define in-flight execution pause and human authorization resume.

#### Decision: AWAITING_AUTHORIZATION State with EscalationRequest Entity

**`AutomationExecution` status transition for escalation (frozen):**

```
RUNNING
  → (step requires HIGH/CRITICAL authorization)
  → AWAITING_AUTHORIZATION
    - EscalationRequest entity created inside AutomationExecution aggregate
    - AutomationEscalated event published
    - Notification sent to required authorizer role
    → (AuthorizeAutomationStep command issued by qualifying operator)
    → RUNNING (resumes from escalated step)
    → (timeout: 30 minutes for HIGH, 60 minutes for CRITICAL)
    → FAILED (reason: ESCALATION_TIMEOUT)
```

**`EscalationRequest` entity (embedded in `AutomationExecution`, frozen):**
```python
@dataclass
class EscalationRequest:
    escalation_id: UUID
    step_number: int
    impact_level: ActionImpactLevel
    required_role: str
    trigger_operator_id: str          # escalation authorizer must differ
    escalated_at: datetime
    expires_at: datetime              # computed: escalated_at + timeout
    authorized_by: str | None = None
    authorized_at: datetime | None = None
    resolution: EscalationResolution | None = None  # AUTHORIZED | EXPIRED | REJECTED

class EscalationResolution(str, Enum):
    AUTHORIZED = "authorized"
    EXPIRED    = "expired"
    REJECTED   = "rejected"
```

**`AuthorizeAutomationStep` command (frozen):**
```python
@dataclass(frozen=True, slots=True)
class AuthorizeAutomationStep:
    tenant_id: TenantId
    execution_id: AutomationExecutionId
    escalation_id: UUID
    authorizer_id: str
    authorizer_roles: tuple[str, ...]
    notes: str | None
```

---

### C9 — Security Graph Edge Ownership

**Condition from Review:** Specify graph edge ownership and write idempotency.

#### Decision: automated_action Context Owns All M35 Graph Writes; Upsert by Stable ID

**Edge write ownership (frozen):**
- `automated_action.infrastructure.events.AutomationKGProjector` is the sole writer of M35 graph nodes and edges
- `playbook` context publishes domain events; `automated_action` KG projector consumes them
- No graph writes occur in `playbook` or `integration_hub` directly

**Idempotency rule (frozen):**
- Node upsert: `INSERT ... ON CONFLICT (node_id) DO UPDATE SET properties = EXCLUDED.properties`
- Edge upsert: `INSERT ... ON CONFLICT (from_node_id, edge_type, to_node_id) DO NOTHING`
- Node IDs computed as: `sha256(node_type + ":" + domain_id)` — stable across replays

---

## 2. Frozen DDD Model

### 2.1 `playbook` Bounded Context — Complete Model

```
┌─────────────────────── playbook ────────────────────────────┐
│                                                               │
│  AGGREGATES                                                   │
│  ──────────                                                   │
│  Playbook                                                     │
│    playbook_id: PlaybookId                                    │
│    tenant_id: TenantId                                        │
│    name: str                                                  │
│    description: str                                           │
│    status: PlaybookStatus (DRAFT|UNDER_REVIEW|APPROVED|DEPRECATED)
│    current_version_number: int                                │
│    max_impact_level: ActionImpactLevel                        │
│    created_by: str                                            │
│    created_at: datetime                                       │
│    approved_by: list[ApprovalRecord]                          │
│    version: int  (optimistic lock)                            │
│                                                               │
│  PlaybookVersion                                              │
│    version_id: PlaybookVersionId                              │
│    tenant_id: TenantId                                        │
│    playbook_id: PlaybookId  (reference)                       │
│    version_number: int                                        │
│    status: VersionStatus (DRAFT|PUBLISHED)                    │
│    content_hash: str  (SHA-256; set on PUBLISHED transition)  │
│    action_steps: list[ActionStepDefinition]  (ordered)        │
│    trigger_configs: list[TriggerCondition]                    │
│    published_by: str | None                                   │
│    published_at: datetime | None                              │
│                                                               │
│  PlaybookTestResult                                           │
│    test_id: PlaybookTestResultId                              │
│    tenant_id: TenantId                                        │
│    playbook_id: PlaybookId                                    │
│    version_id: PlaybookVersionId                              │
│    content_hash_at_test: str  (hash of version at test time)  │
│    outcome: TestOutcome (PASSED|FAILED|PARTIAL)               │
│    steps_tested: int                                          │
│    steps_passed: int                                          │
│    coverage_paths: list[str]  (paths exercised)               │
│    executed_by: str                                           │
│    executed_at: datetime                                       │
│    duration_ms: int                                           │
│                                                               │
│  AutomationPolicy                                             │
│    tenant_id: TenantId  (aggregate key)                       │
│    kill_switch_state: KillSwitchState (ARMED|TRIGGERED)       │
│    kill_switch_triggered_at: datetime | None                  │
│    kill_switch_triggered_by: str | None                       │
│    max_concurrent_executions: int                             │
│    max_actions_per_hour: int                                  │
│    allowed_connector_types: list[ConnectorType] | None        │
│                                                               │
│  VALUE OBJECTS                                                │
│  ─────────────                                                │
│  PlaybookId, PlaybookVersionId, PlaybookTestResultId          │
│  PlaybookStatus, VersionStatus, TestOutcome                   │
│  ActionImpactLevel, KillSwitchState                           │
│  ActionStepDefinition:                                        │
│    step_number: int                                           │
│    action_type: str                                           │
│    connector_type: ConnectorType                              │
│    target_selector: TargetSelectorExpression                  │
│    parameters: dict[str, object]  (no secrets)                │
│    impact_level: ActionImpactLevel                            │
│    rollback_definition: RollbackDefinition | None             │
│    max_execution_seconds: int  (default: 120)                 │
│  TriggerCondition:                                            │
│    source_context: TriggerSourceContext                       │
│    trigger_type: str  (event type name from source context)   │
│    severity_threshold: str | None                             │
│    asset_tag_filter: list[str] | None                         │
│    rate_limit_window_seconds: int  (default: 300)             │
│    rate_limit_max_invocations: int  (default: 1)              │
│  ApprovalRecord:                                              │
│    approved_by: str                                           │
│    approved_at: datetime                                       │
│    role: str                                                  │
│  RollbackDefinition:                                          │
│    rollback_action_type: str                                  │
│    rollback_connector_type: ConnectorType                     │
│    is_reversible: bool                                        │
│    max_rollback_window_hours: int  (default: 24)              │
│  TriggerSourceContext: M28_FINDING | M34_INCIDENT | M32_EXPOSURE | MANUAL
│  ConnectorType: (15 values — see Section 5.3)                 │
│                                                               │
│  DOMAIN SERVICES                                              │
│  ───────────────                                              │
│  PlaybookAuthorizationService                                 │
│  TriggerMatchingService                                       │
│  PlaybookDryRunService                                        │
│  PlaybookContentHashService                                   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

### 2.2 `automated_action` Bounded Context — Complete Model

```
┌────────────────── automated_action ─────────────────────────┐
│                                                               │
│  AGGREGATES                                                   │
│  ──────────                                                   │
│  AutomationExecution                                          │
│    execution_id: AutomationExecutionId                        │
│    tenant_id: TenantId                                        │
│    playbook_ref: PlaybookRef                                  │
│    trigger_ref: TriggerRef                                    │
│    status: ExecutionStatus                                    │
│    started_at: datetime                                       │
│    completed_at: datetime | None                              │
│    operator_id: str  (who triggered; needed for SoD)          │
│    current_step: int                                          │
│    total_steps: int                                           │
│    escalation_request: EscalationRequest | None               │
│    failure_reason: str | None                                 │
│    version: int  (optimistic lock)                            │
│                                                               │
│  AutomatedActionRecord   [append-only]                        │
│    record_id: AutomatedActionRecordId                         │
│    tenant_id: TenantId                                        │
│    execution_id: AutomationExecutionId                        │
│    step_number: int                                           │
│    action_type: str                                           │
│    connector_type: ConnectorType                              │
│    target_resource: str  (asset/resource identifier)          │
│    parameters_hash: str  (SHA-256 of execution params; no PII)│
│    status: ActionRecordStatus (PENDING|COMPLETED|FAILED)      │
│    outcome: ActionOutcome | None                              │
│    external_reference: str | None  (external system's ID)     │
│    failure_mode: ConnectorFailureMode | None                  │
│    attempted_at: datetime                                     │
│    completed_at: datetime | None                              │
│    duration_ms: int | None                                    │
│    rollback_available: bool                                   │
│    rollback_parameters_ref: str | None  (vault ref; not inline)
│                                                               │
│  RollbackRecord   [append-only]                               │
│    rollback_id: RollbackRecordId                              │
│    tenant_id: TenantId                                        │
│    original_record_id: AutomatedActionRecordId                │
│    execution_id: AutomationExecutionId                        │
│    rollback_status: RollbackStatus (PENDING|IN_PROGRESS|COMPLETED|FAILED|NOT_APPLICABLE)
│    initiated_by: str                                          │
│    initiated_at: datetime                                     │
│    completed_at: datetime | None                              │
│    failure_reason: str | None                                 │
│                                                               │
│  ENTITIES (non-root, embedded in AutomationExecution)         │
│  ──────────────────────────────────────────────────────────── │
│  EscalationRequest                                            │
│    escalation_id: UUID                                        │
│    step_number: int                                           │
│    impact_level: ActionImpactLevel                            │
│    required_role: str                                         │
│    trigger_operator_id: str  (SoD: authorizer must differ)    │
│    escalated_at: datetime                                     │
│    expires_at: datetime                                       │
│    authorized_by: str | None                                  │
│    authorized_at: datetime | None                             │
│    resolution: EscalationResolution | None                    │
│                                                               │
│  VALUE OBJECTS                                                │
│  ─────────────                                                │
│  AutomationExecutionId, AutomatedActionRecordId, RollbackRecordId
│  ExecutionStatus: PENDING|RUNNING|AWAITING_AUTHORIZATION|COMPLETED|FAILED|ROLLED_BACK|ESCALATED
│  ActionRecordStatus: PENDING|COMPLETED|FAILED                 │
│  ActionOutcome: SUCCESS|FAILURE|PARTIAL|SKIPPED               │
│  RollbackStatus: PENDING|IN_PROGRESS|COMPLETED|FAILED|NOT_APPLICABLE
│  EscalationResolution: AUTHORIZED|EXPIRED|REJECTED            │
│  ConnectorFailureMode: (8 values — see C3)                    │
│  PlaybookRef: playbook_id, version_number, version_content_hash
│  TriggerRef: source_context, source_event_type, source_event_id
│  ActionEvidence: external_reference, executed_at, duration_ms │
│                                                               │
│  DOMAIN SERVICES                                              │
│  ───────────────                                              │
│  AutomationAuthorizationService                               │
│  RollbackEligibilityService                                   │
│  ExecutionBudgetService                                       │
│  AutomationOutboxService  (manages PENDING record lifecycle)   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

### 2.3 `integration_hub` Bounded Context — Complete Model

```
┌──────────────────── integration_hub ────────────────────────┐
│                                                               │
│  AGGREGATES                                                   │
│  ──────────                                                   │
│  ConnectorRegistration                                        │
│    connector_id: ConnectorId                                  │
│    tenant_id: TenantId                                        │
│    connector_type: ConnectorType                              │
│    display_name: str                                          │
│    status: ConnectorStatus (REGISTERED|HEALTHY|DEGRADED|UNHEALTHY|DISABLED)
│    credential_ref: CredentialRef  (opaque vault key)          │
│    base_url: str | None                                       │
│    configuration: dict[str, object]  (non-secret config)      │
│    created_at: datetime                                       │
│    last_health_check_at: datetime | None                      │
│    circuit_state: CircuitState (CLOSED|OPEN|HALF_OPEN)        │
│    circuit_failure_count: int                                 │
│    circuit_opened_at: datetime | None                         │
│                                                               │
│  ConnectorHealthRecord   [append-only]                        │
│    record_id: ConnectorHealthRecordId                         │
│    tenant_id: TenantId                                        │
│    connector_id: ConnectorId                                  │
│    status: ConnectorHealthStatus (HEALTHY|DEGRADED|UNHEALTHY) │
│    response_time_ms: int | None                               │
│    error_detail: str | None                                   │
│    checked_at: datetime                                       │
│                                                               │
│  PORTS                                                        │
│  ─────                                                        │
│  IActionConnector (Protocol)                                  │
│    execute(action_type, parameters, tenant_id) → ConnectorActionResult
│    rollback(original_action_id, parameters, tenant_id) → ConnectorActionResult
│    health_check(tenant_id) → ConnectorHealthStatus            │
│                                                               │
│  ICredentialVaultPort (Protocol)                              │
│    resolve(ref: CredentialRef, tenant_id) → ResolvedCredential│
│                                                               │
│  VALUE OBJECTS                                                │
│  ─────────────                                                │
│  ConnectorId, ConnectorHealthRecordId                         │
│  ConnectorType: (15 values; see Section 5.3 of review)        │
│  ConnectorStatus, ConnectorHealthStatus                       │
│  CircuitState: CLOSED|OPEN|HALF_OPEN                          │
│  CredentialRef: vault_key, tenant_id, credential_type         │
│  ResolvedCredential: credential_type, secret_value, expires_at│
│  ConnectorActionResult: (see C3 decision)                     │
│                                                               │
│  DOMAIN SERVICES                                              │
│  ───────────────                                              │
│  CircuitBreakerService  (transitions CLOSED→OPEN→HALF_OPEN)   │
│  ConnectorHealthEvaluationService                             │
│  RateLimitTrackingService                                     │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## 3. Frozen Event Contracts

### 3.1 `playbook` Context Events

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookCreated(BasePlaybookEvent):
    playbook_id: str
    tenant_id: str
    name: str
    created_by: str
    created_at: str  # ISO-8601

@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookVersionPublished(BasePlaybookEvent):
    playbook_id: str
    tenant_id: str
    version_id: str
    version_number: int
    content_hash: str
    published_by: str
    published_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookApproved(BasePlaybookEvent):
    playbook_id: str
    tenant_id: str
    version_number: int
    max_impact_level: str
    approved_by: list[str]  # list of approver IDs
    approved_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookDeprecated(BasePlaybookEvent):
    playbook_id: str
    tenant_id: str
    deprecated_by: str
    deprecated_at: str
    reason: str

@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookTestCompleted(BasePlaybookEvent):
    playbook_id: str
    tenant_id: str
    test_id: str
    version_id: str
    content_hash_at_test: str
    outcome: str  # PASSED | FAILED | PARTIAL
    steps_tested: int
    steps_passed: int
    executed_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookTriggered(BasePlaybookEvent):
    playbook_id: str
    tenant_id: str
    version_number: int
    source_context: str   # TriggerSourceContext value
    source_event_id: str
    triggered_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationKillSwitchActivated(BasePlaybookEvent):
    tenant_id: str
    activated_by: str
    activated_at: str
    reason: str

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationKillSwitchReset(BasePlaybookEvent):
    tenant_id: str
    reset_by: str
    reset_at: str
```

### 3.2 `automated_action` Context Events

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionStarted(BaseAutomationEvent):
    execution_id: str
    tenant_id: str
    playbook_id: str
    playbook_version: int
    trigger_source_context: str
    source_event_id: str
    total_steps: int
    max_impact_level: str
    operator_id: str
    started_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionCompleted(BaseAutomationEvent):
    execution_id: str
    tenant_id: str
    playbook_id: str
    playbook_version: int
    steps_completed: int
    steps_failed: int
    completed_at: str
    duration_ms: int

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationExecutionFailed(BaseAutomationEvent):
    execution_id: str
    tenant_id: str
    playbook_id: str
    failure_reason: str
    failed_at_step: int | None
    failed_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomatedActionRecorded(BaseAutomationEvent):
    record_id: str
    execution_id: str
    tenant_id: str
    step_number: int
    action_type: str
    connector_type: str
    target_resource: str
    outcome: str
    recorded_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationEscalated(BaseAutomationEvent):
    execution_id: str
    tenant_id: str
    escalation_id: str
    step_number: int
    impact_level: str
    required_role: str
    expires_at: str
    escalated_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationRolledBack(BaseAutomationEvent):
    execution_id: str
    tenant_id: str
    rollback_id: str
    original_record_id: str
    rolled_back_by: str
    rolled_back_at: str
```

### 3.3 `integration_hub` Context Events

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorRegistered(BaseConnectorEvent):
    connector_id: str
    tenant_id: str
    connector_type: str
    display_name: str
    registered_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealthCheckCompleted(BaseConnectorEvent):
    connector_id: str
    tenant_id: str
    status: str   # HEALTHY | DEGRADED | UNHEALTHY
    response_time_ms: int | None
    checked_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealthDegraded(BaseConnectorEvent):
    connector_id: str
    tenant_id: str
    from_status: str
    to_status: str
    error_detail: str | None
    degraded_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealthRestored(BaseConnectorEvent):
    connector_id: str
    tenant_id: str
    restored_at: str

@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorDisabled(BaseConnectorEvent):
    connector_id: str
    tenant_id: str
    disabled_by: str
    reason: str
    disabled_at: str
```

---

## 4. Frozen Repository Interfaces

### 4.1 `playbook` Context

```python
class IPlaybookRepository(Protocol):
    async def save(self, playbook: Playbook, tenant_id: TenantId) -> None: ...
    async def get(self, playbook_id: PlaybookId, tenant_id: TenantId) -> Playbook | None: ...
    async def find_approved_for_trigger(
        self, tenant_id: TenantId, source_context: TriggerSourceContext
    ) -> list[Playbook]: ...

class IPlaybookVersionRepository(Protocol):
    async def save(self, version: PlaybookVersion, tenant_id: TenantId) -> None: ...
    async def get(
        self, playbook_id: PlaybookId, version_number: int, tenant_id: TenantId
    ) -> PlaybookVersion | None: ...
    async def get_latest(
        self, playbook_id: PlaybookId, tenant_id: TenantId
    ) -> PlaybookVersion | None: ...
    # No update() method — versions are immutable once PUBLISHED

class IPlaybookTestResultRepository(Protocol):
    async def append(self, result: PlaybookTestResult, tenant_id: TenantId) -> None: ...
    async def find_latest_for_version(
        self, playbook_id: PlaybookId, version_id: PlaybookVersionId, tenant_id: TenantId
    ) -> PlaybookTestResult | None: ...
    # No update() method — test results are immutable

class IAutomationPolicyRepository(Protocol):
    async def get_or_create_default(self, tenant_id: TenantId) -> AutomationPolicy: ...
    async def save(self, policy: AutomationPolicy, tenant_id: TenantId) -> None: ...
```

### 4.2 `automated_action` Context

```python
class IAutomationExecutionRepository(Protocol):
    async def save(self, execution: AutomationExecution, tenant_id: TenantId) -> None: ...
    async def get(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> AutomationExecution | None: ...
    async def find_by_status(
        self, tenant_id: TenantId, status: ExecutionStatus, limit: int
    ) -> list[AutomationExecution]: ...
    async def find_pending_recovery(
        self, older_than_minutes: int
    ) -> list[AutomationExecution]: ...  # cross-tenant; used by recovery worker

class IAutomatedActionRecordRepository(Protocol):
    async def append(self, record: AutomatedActionRecord, tenant_id: TenantId) -> None: ...
    async def update_status(
        self,
        record_id: AutomatedActionRecordId,
        tenant_id: TenantId,
        status: ActionRecordStatus,
        outcome: ActionOutcome | None,
        external_reference: str | None,
        failure_mode: ConnectorFailureMode | None,
        completed_at: datetime,
        duration_ms: int,
    ) -> None: ...  # Only status fields mutable; content fields frozen
    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[AutomatedActionRecord]: ...
    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomatedActionRecord]: ...

class IRollbackRecordRepository(Protocol):
    async def append(self, record: RollbackRecord, tenant_id: TenantId) -> None: ...
    async def update_status(
        self,
        rollback_id: RollbackRecordId,
        tenant_id: TenantId,
        status: RollbackStatus,
        completed_at: datetime | None,
        failure_reason: str | None,
    ) -> None: ...
    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[RollbackRecord]: ...
```

### 4.3 `integration_hub` Context

```python
class IConnectorRegistrationRepository(Protocol):
    async def save(self, registration: ConnectorRegistration, tenant_id: TenantId) -> None: ...
    async def get(
        self, connector_id: ConnectorId, tenant_id: TenantId
    ) -> ConnectorRegistration | None: ...
    async def find_healthy_for_action_type(
        self, tenant_id: TenantId, connector_type: ConnectorType
    ) -> list[ConnectorRegistration]: ...
    async def find_all_for_tenant(
        self, tenant_id: TenantId
    ) -> list[ConnectorRegistration]: ...

class IConnectorHealthRecordRepository(Protocol):
    async def append(self, record: ConnectorHealthRecord, tenant_id: TenantId) -> None: ...
    async def find_latest_for_connector(
        self, connector_id: ConnectorId, tenant_id: TenantId, limit: int
    ) -> list[ConnectorHealthRecord]: ...
```

---

## 5. Frozen Command & Query Model

### 5.1 `playbook` Commands

```
CreatePlaybook(tenant_id, name, description, created_by)
PublishPlaybookVersion(tenant_id, playbook_id, action_steps, trigger_configs, published_by)
SubmitPlaybookForApproval(tenant_id, playbook_id, version_number, submitted_by)
ApprovePlaybook(tenant_id, playbook_id, version_number, approved_by, approved_by_role)
DeprecatePlaybook(tenant_id, playbook_id, deprecated_by, reason)
RunPlaybookDryRun(tenant_id, playbook_id, version_id, executed_by)
ActivateKillSwitch(tenant_id, activated_by, reason)
ResetKillSwitch(tenant_id, reset_by)
UpdateAutomationPolicy(tenant_id, updated_by, max_concurrent_executions, max_actions_per_hour)
```

### 5.2 `automated_action` Commands

```
TriggerPlaybookExecution(tenant_id, playbook_id, version_number, trigger_ref, operator_id)
AuthorizeAutomationStep(tenant_id, execution_id, escalation_id, authorizer_id, authorizer_roles, notes)
RequestRollback(tenant_id, execution_id, record_id, initiated_by)
CancelExecution(tenant_id, execution_id, cancelled_by, reason)
```

### 5.3 `integration_hub` Commands

```
RegisterConnector(tenant_id, connector_type, display_name, credential_vault_key, credential_type, configuration, registered_by)
DisableConnector(tenant_id, connector_id, disabled_by, reason)
TriggerHealthCheck(tenant_id, connector_id)
```

### 5.4 Queries

```
GetPlaybook(tenant_id, playbook_id)
ListPlaybooks(tenant_id, status_filter, page, page_size)
GetPlaybookVersion(tenant_id, playbook_id, version_number)
GetPlaybookTestResults(tenant_id, playbook_id, version_id)
GetAutomationPolicy(tenant_id)

GetAutomationExecution(tenant_id, execution_id)
ListAutomationExecutions(tenant_id, status_filter, playbook_id_filter, from_date, to_date, page, page_size)
GetAutomatedActionRecords(tenant_id, execution_id)
GetRollbackRecords(tenant_id, execution_id)
GetPendingEscalations(tenant_id)

GetConnectorRegistration(tenant_id, connector_id)
ListConnectorRegistrations(tenant_id, status_filter)
GetConnectorHealthHistory(tenant_id, connector_id, from_date, to_date)
```

---

## 6. Frozen Read Models

### 6.1 Playbook Effectiveness Dashboard

```python
@dataclass(frozen=True)
class PlaybookEffectivenessReadModel:
    tenant_id: str
    playbook_id: str
    playbook_name: str
    status: str
    total_executions: int
    successful_executions: int
    failed_executions: int
    escalated_executions: int
    avg_execution_duration_ms: float
    avg_mttc_reduction_minutes: float | None   # mean time to containment reduction
    trigger_count_last_30_days: int
    success_rate_percent: float
    last_triggered_at: datetime | None
```

### 6.2 Automated Action History

```python
@dataclass(frozen=True)
class AutomatedActionHistoryReadModel:
    tenant_id: str
    record_id: str
    execution_id: str
    playbook_name: str
    step_number: int
    action_type: str
    connector_type: str
    target_resource: str
    outcome: str
    failure_mode: str | None
    rollback_status: str | None
    attempted_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    authorized_by: str | None   # if escalation was required
    trigger_source: str          # what triggered the playbook
    trigger_event_id: str
```

### 6.3 Playbook Coverage View

```python
@dataclass(frozen=True)
class PlaybookCoverageReadModel:
    tenant_id: str
    total_detection_rule_types: int          # from M28
    detection_rule_types_with_playbook: int
    coverage_percent: float
    uncovered_rule_types: list[str]
    total_incident_trigger_types: int        # from M34
    incident_trigger_types_with_playbook: int
    coverage_by_impact_level: dict[str, int]  # LOW/MEDIUM/HIGH/CRITICAL → playbook count
```

### 6.4 Rollback Tracking View

```python
@dataclass(frozen=True)
class RollbackTrackingReadModel:
    tenant_id: str
    rollback_id: str
    original_record_id: str
    execution_id: str
    action_type: str
    connector_type: str
    target_resource: str
    rollback_status: str
    initiated_by: str
    initiated_at: datetime
    completed_at: datetime | None
    failure_reason: str | None
    max_rollback_window_expires_at: datetime
```

### 6.5 Integration Health Dashboard

```python
@dataclass(frozen=True)
class IntegrationHealthReadModel:
    tenant_id: str
    connector_id: str
    connector_type: str
    display_name: str
    current_status: str
    circuit_state: str
    last_health_check_at: datetime | None
    health_check_success_rate_24h: float
    avg_response_time_ms_24h: float | None
    actions_executed_24h: int
    actions_failed_24h: int
    rate_limit_budget_remaining: int
```

---

## 7. Frozen Migration Plan

### Migration Chain: 0114 → 0130

```
0114_playbooks_core
  Creates schema: playbook
  Tables: playbooks (id, tenant_id, name, description, status, current_version_number,
          max_impact_level, created_by, created_at, updated_at)
  Indexes: (tenant_id, status), (tenant_id, name)

0115_playbook_versions
  Tables: playbook_versions (id, tenant_id, playbook_id→playbooks, version_number, status,
          content_hash, published_by, published_at, created_at)
  Indexes: (playbook_id, version_number) UNIQUE, (tenant_id, status)

0116_playbook_action_steps
  Tables: playbook_action_steps (id, tenant_id, version_id→playbook_versions, step_number,
          action_type, connector_type, target_selector_expr, parameters JSONB,
          impact_level, rollback_definition JSONB, max_execution_seconds)
  Indexes: (version_id, step_number)

0117_playbook_trigger_configs
  Tables: playbook_trigger_configs (id, tenant_id, playbook_id→playbooks, source_context,
          trigger_type, severity_threshold, asset_tag_filter JSONB,
          rate_limit_window_seconds, rate_limit_max_invocations)
  Indexes: (tenant_id, source_context, trigger_type), GIN on asset_tag_filter

0118_playbook_test_results
  Tables: playbook_test_results (id, tenant_id, playbook_id, version_id→playbook_versions,
          content_hash_at_test, outcome, steps_tested, steps_passed, coverage_paths JSONB,
          executed_by, executed_at, duration_ms)
  Indexes: (playbook_id, version_id, executed_at DESC)

0119_automation_policy
  Tables: automation_policy (tenant_id PK, kill_switch_state, kill_switch_triggered_at,
          kill_switch_triggered_by, max_concurrent_executions, max_actions_per_hour,
          allowed_connector_types JSONB, updated_at)

0120_automation_executions
  Creates schema: automated_action
  Tables: automation_executions, PARTITIONED BY RANGE (created_at) monthly
  Columns: (id, tenant_id, playbook_id, playbook_version, playbook_content_hash,
            trigger_source_context, source_event_id, status, operator_id,
            current_step, total_steps, max_impact_level,
            escalation_request JSONB,
            failure_reason, started_at, completed_at, version)
  Indexes: (tenant_id, playbook_id), (tenant_id, status),
           (tenant_id, created_at), (source_event_id)

0121_automated_action_records
  Tables: automated_action_records, PARTITIONED BY HASH (tenant_id) 8 partitions
  Columns: (id, tenant_id, execution_id→automation_executions, step_number,
            action_type, connector_type, target_resource, parameters_hash,
            status, outcome, external_reference, failure_mode,
            attempted_at, completed_at, duration_ms,
            rollback_available, rollback_parameters_ref)
  Indexes: (execution_id), (tenant_id, connector_type),
           (tenant_id, attempted_at), (status, attempted_at) WHERE status='PENDING'

0122_rollback_records
  Tables: rollback_records (id, tenant_id, original_record_id→automated_action_records,
          execution_id, rollback_status, initiated_by, initiated_at,
          completed_at, failure_reason)
  Indexes: (execution_id), (original_record_id), (tenant_id, rollback_status)

0123_automation_kill_switch_log
  Tables: automation_kill_switch_log (id, tenant_id, event_type, actor, reason,
          recorded_at)  -- immutable audit log
  Indexes: (tenant_id, recorded_at)

0124_escalation_records
  Tables: escalation_records (id, tenant_id, execution_id→automation_executions,
          step_number, impact_level, required_role, trigger_operator_id,
          escalated_at, expires_at, authorized_by, authorized_at, resolution)
  Indexes: (execution_id), (tenant_id, resolution) WHERE resolution IS NULL

0125_integration_hub_connectors
  Creates schema: integration_hub
  Tables: connector_registrations (id, tenant_id, connector_type, display_name, status,
          credential_vault_key TEXT, credential_type, base_url, configuration JSONB,
          circuit_state, circuit_failure_count, circuit_opened_at,
          created_at, updated_at, last_health_check_at)
  Indexes: (tenant_id, connector_type), (tenant_id, status)

0126_connector_health_records
  Tables: connector_health_records (id, tenant_id, connector_id→connector_registrations,
          status, response_time_ms, error_detail, checked_at)
  PARTITION BY RANGE (checked_at) monthly
  Indexes: (connector_id, checked_at DESC)

0127_connector_action_audit
  Tables: connector_action_audit (id, tenant_id, connector_id, execution_id,
          record_id, action_type, outcome, duration_ms, executed_at)
  -- Denormalized audit; connector perspective on every action it handled
  PARTITION BY HASH (tenant_id) 4 partitions
  Indexes: (connector_id, executed_at), (tenant_id, executed_at)

0128_rate_limit_tracking
  Tables: connector_rate_limit_tracking (id, tenant_id, connector_id, window_start,
          window_end, action_count, budget_consumed_percent)
  Indexes: (connector_id, window_start DESC)

0129_security_graph_m35_nodes
  Extends security_graph node type enum: adds PLAYBOOK, AUTOMATED_ACTION
  Alters security_graph.edges edge_type enum: adds TRIGGERED_PLAYBOOK, EXECUTED_ACTION,
    ACTION_ON_ASSET, ROLLED_BACK_BY

0130_m35_analytics_projection
  Creates table: analytics.automation_events (event_id, tenant_id, execution_id,
    event_type, playbook_id, outcome, action_count, duration_ms, event_ts, payload JSONB,
    ingested_at)
  PARTITION BY HASH (tenant_id) 8 partitions
  Indexes: (tenant_id, event_ts), (tenant_id, playbook_id, event_ts)
```

---

## 8. Frozen Worker Specifications

### 8.1 `PlaybookTriggerWorker`

```
Purpose: Consumes external domain events; evaluates trigger conditions; starts executions
Trigger: Subscribes to EventBus for: DetectionFindingEscalated, IncidentContained,
         IncidentEradicated, ExposureThresholdBreached
Concurrency: 4 workers per process
Idempotency key: SHA256(trigger_event_id + playbook_id) — prevents double-execution
Rate limit enforcement: Checks TriggerCondition.rate_limit_window before emitting PlaybookTriggered
Kill switch check: Loads AutomationPolicy before any execution; rejects if TRIGGERED
Output: Publishes PlaybookTriggered event; writes AutomationExecution record (PENDING)
```

### 8.2 `PlaybookExecutionWorker`

```
Purpose: Processes AutomationExecution records; executes action steps through connectors
Trigger: Consumes PlaybookTriggered events (or polls automation_executions WHERE status='PENDING')
Concurrency: Per-tenant max_concurrent_executions (default 5)
Execution loop:
  1. Load AutomationExecution; load AutomationPolicy (kill switch check)
  2. Load PlaybookVersion (verify content_hash matches PlaybookRef)
  3. For each ActionStep in order:
     a. Write AutomatedActionRecord (PENDING) — outbox
     b. Check ActionImpactLevel; if HIGH/CRITICAL → create EscalationRequest, set AWAITING_AUTHORIZATION, emit AutomationEscalated, PAUSE
     c. Resolve connector via integration_hub
     d. Execute with timeout; handle ConnectorFailureMode
     e. Update AutomatedActionRecord (COMPLETED/FAILED)
     f. Check circuit breaker; update ConnectorRegistration
  4. On all steps complete: set execution COMPLETED, emit AutomationExecutionCompleted
  5. On step failure: set execution FAILED, emit AutomationExecutionFailed
Max wall time: 10 minutes (configurable); beyond → FAILED with TIMEOUT
```

### 8.3 `EscalationTimeoutWorker`

```
Purpose: Detects expired EscalationRequests; transitions executions to FAILED
Trigger: Scheduled every 5 minutes
Query: escalation_records WHERE resolution IS NULL AND expires_at < now()
Action: AuthorizeAutomationStep not received by deadline → resolve as EXPIRED → execution FAILED
```

### 8.4 `ConnectorHealthWorker`

```
Purpose: Polls registered connectors for health; manages circuit breaker state
Trigger: Scheduled every 60 seconds per connector (staggered)
Concurrency: 1 worker per connector (no parallel health checks per connector)
On success: ConnectorHealthRecord (HEALTHY), reset circuit failure count if > 0
On failure: ConnectorHealthRecord (DEGRADED/UNHEALTHY), increment circuit failure count
Circuit trip: If failure_count >= 5 within 2-minute window → OPEN circuit, emit ConnectorHealthDegraded
Circuit half-open: After 30 seconds OPEN → HALF_OPEN; next health check resolves CLOSED or back to OPEN
```

### 8.5 `OutboxRecoveryWorker`

```
Purpose: Recovers AutomatedActionRecord records stuck in PENDING
Trigger: Scheduled every 5 minutes
Query: automated_action_records WHERE status='PENDING' AND attempted_at < now() - interval '5 minutes'
Action per record:
  1. Call connector.verify_outcome(execution_id, step_number) if connector supports it
  2. On confirmed success: update to COMPLETED
  3. On confirmed failure: update to FAILED
  4. On connector unreachable: emit alert; record remains PENDING with alert count
  5. After 3 consecutive unresolvable: escalate to human; record marked ESCALATED
```

### 8.6 `AutomationKGProjector`

```
Purpose: Projects M35 events into Security Graph
Subscribes to: PlaybookApproved, AutomationExecutionCompleted, AutomationExecutionFailed,
               AutomatedActionRecorded, AutomationRolledBack
Idempotency: All writes are upsert (ON CONFLICT DO NOTHING or DO UPDATE)
Owns: PlaybookNode, AutomatedActionNode, TRIGGERED_PLAYBOOK, EXECUTED_ACTION,
      ACTION_ON_ASSET, ROLLED_BACK_BY edges
Does NOT write: DetectionFindingNode, IncidentNode, AssetNode (those belong to their contexts)
```

---

## 9. Frozen Security Graph Extensions

### Node Types (additions to existing enum)

```python
class NodeType(str, Enum):
    # ... existing values ...
    PLAYBOOK        = "playbook"
    AUTOMATED_ACTION = "automated_action"
```

### Edge Types (additions to existing enum)

```python
class RelationshipType(str, Enum):
    # ... existing values ...
    TRIGGERED_PLAYBOOK  = "triggered_playbook"   # Finding/Incident/Exposure → Playbook
    EXECUTED_ACTION     = "executed_action"       # Playbook → AutomatedAction
    ACTION_ON_ASSET     = "action_on_asset"       # AutomatedAction → Asset
    ROLLED_BACK_BY      = "rolled_back_by"        # AutomatedAction → AutomatedAction (rollback)
```

### Node Properties (frozen)

```
PlaybookNode:
  node_id: sha256("playbook:" + playbook_id)
  node_type: PLAYBOOK
  tenant_id: str
  name: str
  status: str
  max_impact_level: str
  version_count: int
  execution_count: int
  success_rate: float | None

AutomatedActionNode:
  node_id: sha256("automated_action:" + record_id)
  node_type: AUTOMATED_ACTION
  tenant_id: str
  execution_id: str
  action_type: str
  connector_type: str
  target_resource_hash: str  # hashed — no raw resource identifiers in graph
  outcome: str
  executed_at: str  # ISO-8601
  rollback_status: str | None
```

---

## 10. Authorization Model

### API Endpoint Authorization (frozen)

```
playbook:analyst       — list playbooks, get playbook, get test results, view executions
playbook:engineer      — create playbook, publish version, run dry-run, view all
soc:commander          — approve MEDIUM playbooks, authorize HIGH runtime steps
incident:ciso          — approve CRITICAL playbooks, authorize CRITICAL runtime steps, kill switch
integration:admin      — register/disable connectors
automation:operator    — trigger playbook execution (manual trigger)
```

### Route Authorization Matrix (frozen)

```
GET  /playbooks                          → playbook:analyst
POST /playbooks                          → playbook:engineer
GET  /playbooks/{id}                     → playbook:analyst
POST /playbooks/{id}/versions            → playbook:engineer
POST /playbooks/{id}/submit-for-approval → playbook:engineer
POST /playbooks/{id}/approve             → soc:commander | incident:ciso (based on impact)
POST /playbooks/{id}/deprecate           → soc:commander
POST /playbooks/{id}/dry-run             → playbook:engineer
GET  /executions                         → playbook:analyst
GET  /executions/{id}                    → playbook:analyst
GET  /executions/{id}/action-records     → playbook:analyst
POST /executions/{id}/authorize-step     → soc:commander | incident:ciso (based on step impact)
POST /executions/{id}/rollback           → soc:commander
POST /executions/{id}/cancel             → soc:commander
POST /automation-policy/kill-switch      → incident:ciso
DELETE /automation-policy/kill-switch    → incident:ciso
GET  /connectors                         → integration:admin
POST /connectors                         → integration:admin
DELETE /connectors/{id}                  → integration:admin
GET  /connectors/{id}/health             → playbook:analyst
```

---

## 11. ADRs

See `M35_ADR_001_through_007.md` for the complete ADR set. Summary table:

| ADR | Title |
|---|---|
| ADR-M35-001 | Dual-Authorization Model: Design-Time Playbook Approval + Runtime Step Authorization |
| ADR-M35-002 | Outbox Pattern for Connector Action Evidence Integrity |
| ADR-M35-003 | Credential Vault Reference Model for Connector Authentication |
| ADR-M35-004 | Per-Tenant Kill Switch on AutomationPolicy Aggregate |
| ADR-M35-005 | Content Hash Enforcement for PlaybookVersion Dry-Run Validity |
| ADR-M35-006 | Connector Circuit Breaker Integration with Sprint 26 Runtime Infrastructure |
| ADR-M35-007 | ACL Translator Isolation for Cross-Context Event Consumption |

---

## 12. Risk Dispositions (R01–R10)

| Risk ID | Description | Disposition | Mitigation |
|---|---|---|---|
| R01 | Automated actions cause production outage if triggered by false positive detection | MITIGATE | Authorization gate for HIGH/CRITICAL; dry-run requirement; rate limiting per trigger |
| R02 | Connector credential leakage | MITIGATE | CredentialRef model; credential never in DB; secret_value never logged |
| R03 | AutomatedActionRecord orphan (external action applied but not recorded) | MITIGATE | Outbox pattern (C7); OutboxRecoveryWorker |
| R04 | Kill switch unavailability during incident | MITIGATE | AutomationPolicy cached in application layer; kill switch check before each step start |
| R05 | Cross-tenant trigger evaluation | MITIGATE | All trigger evaluation scoped to tenant_id; no cross-tenant trigger matching |
| R06 | Rollback failure leaving infrastructure in inconsistent state | ACCEPT | Rollback is best-effort; failed rollback escalates to human; immutable RollbackRecord |
| R07 | PlaybookVersion deployed without passing dry-run | MITIGATE | Content hash enforcement (C5); dry-run required before approval |
| R08 | Separation of duties bypass (trigger operator self-authorizes escalation) | MITIGATE | `authorizer_id != trigger_operator_id` enforced in AutomationAuthorizationService |
| R09 | Connector circuit breaker not integrated with Sprint 26 runtime | MITIGATE | CircuitBreakerService reuses Sprint 26 patterns; integration tested in Phase 3 |
| R10 | Playbook trigger fan-out storm (one finding triggers N playbooks simultaneously) | MITIGATE | Per-trigger rate limiting in TriggerCondition; max concurrent executions cap |

---

## 13. Frozen Phase Plan

### Phase 1 — Playbook Domain Foundation
**Scope:** `playbook` bounded context — core domain only  
**Bounded Contexts:** `playbook`  
**Aggregates:** `Playbook`, `PlaybookVersion`, `PlaybookTestResult`, `AutomationPolicy`  
**Domain Services:** `PlaybookAuthorizationService`, `PlaybookContentHashService`  
**Events:** `PlaybookCreated`, `PlaybookVersionPublished`, `PlaybookApproved`, `PlaybookDeprecated`, `PlaybookTestCompleted`, `AutomationKillSwitchActivated`, `AutomationKillSwitchReset`  
**Repositories:** `IPlaybookRepository`, `IPlaybookVersionRepository`, `IPlaybookTestResultRepository`, `IAutomationPolicyRepository`  
**Migrations:** 0114–0119  
**Tests:** ≥ 80 unit tests  
**Exit Criteria:**
- All `Playbook` and `PlaybookVersion` state transitions tested
- `PlaybookAuthorizationService` matrix validated (all 4 impact levels)
- Content hash enforcement tested (hash mismatch rejects approval)
- Kill switch activation/reset tested with role enforcement
- Dual-approver requirement tested for HIGH/CRITICAL playbooks

---

### Phase 2 — Integration Hub & Connector Framework
**Scope:** `integration_hub` bounded context  
**Bounded Contexts:** `integration_hub`  
**Aggregates:** `ConnectorRegistration`, `ConnectorHealthRecord`  
**Ports:** `IActionConnector`, `ICredentialVaultPort`  
**Domain Services:** `CircuitBreakerService`, `ConnectorHealthEvaluationService`, `RateLimitTrackingService`  
**Events:** `ConnectorRegistered`, `ConnectorHealthCheckCompleted`, `ConnectorHealthDegraded`, `ConnectorHealthRestored`, `ConnectorDisabled`  
**Workers:** `ConnectorHealthWorker`  
**Migrations:** 0125–0128  
**Tests:** ≥ 60 unit tests; ≥ 15 integration tests  
**Exit Criteria:**
- `IActionConnector` port fully specified and tested with `InMemoryActionConnector` stub
- Circuit breaker state transitions CLOSED → OPEN → HALF_OPEN → CLOSED tested
- `CredentialRef` model verified: no plaintext credentials in any ORM model (architecture test)
- `ConnectorHealthWorker` tested: degradation detection, circuit open, restoration
- All 8 `ConnectorFailureMode` cases handled and tested

---

### Phase 3 — Automated Action Execution Engine
**Scope:** `automated_action` bounded context; `PlaybookTriggerWorker`; `PlaybookExecutionWorker`  
**Bounded Contexts:** `automated_action`  
**Aggregates:** `AutomationExecution`, `AutomatedActionRecord`, `RollbackRecord`  
**Domain Services:** `AutomationAuthorizationService`, `RollbackEligibilityService`, `ExecutionBudgetService`  
**Workers:** `PlaybookTriggerWorker`, `PlaybookExecutionWorker`, `EscalationTimeoutWorker`  
**Migrations:** 0120–0124  
**Tests:** ≥ 100 unit tests; ≥ 20 integration tests  
**Exit Criteria:**
- Complete playbook execution from trigger to completion tested end-to-end
- Outbox pattern tested: PENDING record written before connector call; COMPLETED on success; FAILED on failure
- Escalation pause/resume tested: RUNNING → AWAITING_AUTHORIZATION → RUNNING (resume) and FAILED (timeout)
- Separation of duties enforced: authorizer_id == trigger_operator_id raises `SeparationOfDutiesViolation`
- Kill switch halts in-progress execution (current step completes; next step does not start)
- Rollback lifecycle tested: requested → PENDING → COMPLETED/FAILED
- Tenant isolation: cross-tenant execution access raises TenantMismatch

---

### Phase 4 — API Layer, Read Models, Security Graph
**Scope:** API routes for all 3 contexts; projection workers; Security Graph extension  
**Aggregates:** (no new aggregates)  
**Migrations:** 0129–0130  
**API Routes:** All frozen routes (see Section 10)  
**Read Models:** All 5 read models (see Section 6)  
**Workers:** `AutomationKGProjector`, `AutomationAnalyticsProjector`  
**Tests:** ≥ 40 API tests; ≥ 20 projection tests  
**Exit Criteria:**
- All API routes return correct status codes and payloads
- Authorization enforced at route level (403 for insufficient role)
- Security Graph: `PlaybookNode` and `AutomatedActionNode` upserted correctly
- `TRIGGERED_PLAYBOOK` and `EXECUTED_ACTION` edges created; `ACTION_ON_ASSET` linked to existing asset nodes
- M33 analytics table `automation_events` populated on execution events
- Read model queries return correct data for multi-page results

---

### Phase 5 — Cross-Context ACL, Recovery Workers, Observability
**Scope:** ACL translators; `OutboxRecoveryWorker`; metrics; health endpoints  
**Workers:** `OutboxRecoveryWorker`  
**ACL:** `M28FindingTriggerTranslator`, `M34IncidentTriggerTranslator`, `M32ExposureTriggerTranslator`  
**Tests:** ≥ 30 integration tests  
**Exit Criteria:**
- ACL translators tested: unknown event fields ignored; required fields validated
- `OutboxRecoveryWorker` tested: detects stale PENDING records; resolves via connector verify
- Health endpoint `/health/automation` reflects kill switch state and connector health
- Metrics emitted: `automation.execution.started`, `automation.execution.completed`, `automation.execution.failed`, `automation.escalation.pending`, `connector.health.status`
- All 3 contexts have Prometheus-compatible metric endpoints
- Playbook invocation latency P95 ≤ 30 seconds measured in integration tests

---

## 14. Implementation Readiness Assessment

| Dimension | Status | Notes |
|---|---|---|
| DDD boundary definitions | READY | All 3 contexts frozen |
| Aggregate model | READY | All aggregates, entities, VOs frozen |
| Repository interfaces | READY | All interfaces frozen with method signatures |
| Command/query model | READY | All 20+ commands and 15+ queries defined |
| Event contracts | READY | All domain events frozen with typed fields |
| Authorization matrix | READY | C1 fully resolved |
| Kill switch mechanism | READY | C2 fully resolved |
| Connector failure contract | READY | C3 fully resolved |
| ACL translator contracts | READY | C4 fully resolved |
| Content hash enforcement | READY | C5 fully resolved |
| Credential model | READY | C6 fully resolved |
| Outbox pattern | READY | C7 fully resolved |
| Escalation protocol | READY | C8 fully resolved |
| Graph edge ownership | READY | C9 fully resolved |
| Migration chain | READY | 0114–0130 fully specified |
| Worker specifications | READY | 6 workers fully specified |
| Risk register | READY | 10 risks disposed |
| Test exit criteria | READY | Per-phase criteria defined |
| **Implementation start** | **APPROVED** | **All C1–C9 resolved** |

**Implementation begins at Phase 1. Do not begin Phase 2 until Phase 1 exit criteria are met.**
