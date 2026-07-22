# M35 Architecture Decision Records
## ADR-M35-001 through ADR-M35-007

**Date:** 2026-07-22  
**Status:** FROZEN  

---

## ADR-M35-001: Dual-Authorization Model — Design-Time Playbook Approval + Runtime Step Authorization

**Status:** ACCEPTED

### Context

Automated defensive actions executed against production infrastructure (isolating hosts, revoking credentials, blocking IPs) carry operational risk if triggered incorrectly. M29 established that offensive operations require multi-party engagement approval and scope hashing before any attack begins. M35 must achieve equivalent rigor for defensive automation.

Two distinct authorization events occur in M35:
1. **Design-time**: A security engineer authors a playbook; it requires approval before being marked APPROVED and executable.
2. **Runtime**: An approved playbook is executing; a HIGH or CRITICAL impact step requires in-context human authorization before proceeding.

A naive single-approval model (approve once at design time; execute everything automatically) is insufficient for CRITICAL impact actions in a live incident. A double-approval model on every step is operationally unworkable.

### Decision

Implement a dual-authorization model:

**Layer 1: Design-time approval** — governed by `PlaybookAuthorizationService` using a static matrix keyed on `max(ActionImpactLevel)` across all steps. MEDIUM playbooks require single `soc:commander` approval. HIGH playbooks require two distinct `soc:commander` approvers. CRITICAL playbooks require `soc:commander` + `incident:ciso` dual approval. LOW playbooks require `soc:analyst` single approval.

**Layer 2: Runtime step authorization** — when `PlaybookExecutionWorker` reaches a step with `ActionImpactLevel.HIGH` or `ActionImpactLevel.CRITICAL`, execution transitions to `AWAITING_AUTHORIZATION`. A distinct operator (not the one who triggered execution) with the required role issues `AuthorizeAutomationStep`. After 30 minutes (HIGH) or 60 minutes (CRITICAL) without authorization, the execution fails with `ESCALATION_TIMEOUT`.

**Separation of duties** is enforced at the runtime layer: `authorizer_id != trigger_operator_id` is an invariant checked by `AutomationAuthorizationService.assert_runtime_authorized()`.

### Consequences

**Positive:**
- CRITICAL automated actions always have a human in the loop at execution time, even if the playbook was previously approved
- Separation of duties prevents a single compromised operator account from both triggering and authorizing high-impact actions
- LOW/MEDIUM actions remain fully automated, preserving MTTC reduction for the 80% case

**Negative:**
- Runtime authorization adds latency for HIGH/CRITICAL actions; MTTC reduction benefit is partial for these action types
- Escalation timeout must be tuned per-organization; 30 minutes may be too short for organizations without 24/7 SOC coverage

**Risk mitigations:**
- Escalation timeout is configurable per tenant (within bounds: 5 minutes minimum, 4 hours maximum)
- Playbook designers should structure playbooks to lead with LOW/MEDIUM steps; escalation gate should be a gate, not the entire playbook

---

## ADR-M35-002: Outbox Pattern for Connector Action Evidence Integrity

**Status:** ACCEPTED

### Context

Each step in a playbook execution calls an external connector (AWS API, Okta, CrowdStrike, etc.) and must produce an `AutomatedActionRecord` in the database. The distributed nature of this operation creates a failure window: if the connector call succeeds but the database write fails (or vice versa), the system is inconsistent.

Without evidence integrity, the platform cannot guarantee that every action it claimed to have taken was actually taken, and cannot guarantee that every action it actually took was recorded.

### Decision

Implement the **outbox pattern** for all connector action records:

1. Before calling the connector, write `AutomatedActionRecord` with `status = PENDING` inside the same transaction as `AutomationExecution` step-state update. This record is durable before any external call is made.
2. After the connector returns (success or failure), update the `AutomatedActionRecord` status to `COMPLETED` or `FAILED` with the outcome detail.
3. If the process dies between steps 1 and 2, the `OutboxRecoveryWorker` detects records in `PENDING` status older than 5 minutes and attempts outcome verification.
4. Records that cannot be resolved by the recovery worker are escalated to human review.

`AutomatedActionRecord` rows in `PENDING` status older than 5 minutes represent potential evidence integrity gaps and are treated as alerts, not acceptable operational state.

### Consequences

**Positive:**
- No external action is taken without a durable pre-record
- No external action goes unrecorded after the fact
- Evidence integrity guarantee: the record always exists regardless of process failure

**Negative:**
- Recovery worker requires connectors to support idempotent re-query or outcome verification (not all connectors provide this)
- For connectors without verify support, PENDING records may require manual resolution
- Additional table scan every 5 minutes (mitigated by partial index on `status='PENDING'`)

**Connector requirement added:** All `IActionConnector` implementations must document whether they support idempotent execution and outcome verification. Those that do not are flagged as `verify_support: false` in their `ConnectorRegistration` configuration and generate higher-priority recovery alerts.

---

## ADR-M35-003: Credential Vault Reference Model for Connector Authentication

**Status:** ACCEPTED

### Context

The `integration_hub` connectors must authenticate to 15+ external systems (AWS IAM, Okta API, CrowdStrike OAuth, ServiceNow API keys, etc.). These credentials must not be stored in the `connector_registrations` table in plaintext. They must not appear in application logs. They must be rotated without redeploying the connector configuration.

### Decision

`ConnectorRegistration` stores only a `CredentialRef` — an opaque string referencing a key in the credential vault (managed by a secrets management system, e.g., HashiCorp Vault, AWS Secrets Manager). The `ICredentialVaultPort` port is defined in `integration_hub.application.ports`; its concrete implementation is injected at composition root and is not referenced in domain or application layers.

**Hard prohibitions (enforced by architecture tests):**
1. No column named `api_key`, `secret`, `password`, `token`, `credential`, `private_key`, or `certificate` on the `ConnectorRegistration` ORM model
2. No `ResolvedCredential.secret_value` written to any log handler at any log level
3. No `ResolvedCredential` object passed to any domain or application layer function signature

**Resolution flow:**
```
PlaybookExecutionWorker → needs connector for step N
  → loads ConnectorRegistration → reads credential_ref: CredentialRef
  → calls ICredentialVaultPort.resolve(ref, tenant_id)
  → receives ResolvedCredential (in-memory only; gc'd after connector call)
  → passes secret_value to connector adapter directly
  → ResolvedCredential goes out of scope after connector call
```

### Consequences

**Positive:**
- Credential rotation does not require redeploying the application
- Database dump never contains live credentials
- Log scraping cannot extract credentials

**Negative:**
- Vault availability is a hard dependency for connector execution; if vault is unavailable, connectors cannot execute
- Mitigation: credential vault responses cached in process memory for 5 minutes (with TTL shorter than token expiry) to reduce vault call frequency and tolerate brief vault unavailability

---

## ADR-M35-004: Per-Tenant Kill Switch on AutomationPolicy Aggregate

**Status:** ACCEPTED

### Context

M29's `Engagement` aggregate carries `KillSwitchState` as a first-class field. Activating the kill switch immediately halts all M29 offensive operations for the engagement. M35 automated defensive operations affect production infrastructure; an equivalent halt mechanism is required.

The kill switch must be:
1. Per-tenant (not global; one tenant's automation should not affect another's)
2. Instantly effective (in-progress executions stop before the next action step)
3. Immutably audited (activation is recorded with actor identity and timestamp)
4. Resettable only by `incident:ciso` role

### Decision

`AutomationPolicy` aggregate (in the `playbook` context) carries `kill_switch_state: KillSwitchState`. The `PlaybookExecutionWorker` checks `AutomationPolicy.kill_switch_state` before starting each action step (not each execution — so a kill switch activated mid-execution halts at the current step boundary). The current step is allowed to complete to avoid leaving infrastructure in a partially-configured state.

**Kill switch activation publishes** `AutomationKillSwitchActivated` with actor identity and reason, writing to `automation_kill_switch_log` (append-only table).

**`AutomationPolicy` loading:** Cached in process memory with a 10-second TTL. Maximum lag between kill switch activation and enforcement is 10 seconds (configurable down to 2 seconds for tenants requiring tighter SLAs). This is acceptable given that actions themselves take O(seconds) to O(minutes).

### Consequences

**Positive:**
- CISO can halt all automation with a single API call
- Per-tenant isolation maintained
- In-progress actions complete cleanly (no infrastructure left half-configured)

**Negative:**
- Up to 10-second lag before kill switch takes effect
- An execution started in the lag window may proceed past the kill switch activation; this is documented and the lag window is bounded and observable

---

## ADR-M35-005: Content Hash Enforcement for PlaybookVersion Dry-Run Validity

**Status:** ACCEPTED

### Context

The roadmap success criterion requires that playbook dry-run correctly predicts production execution outcome in ≥95% of test cases. This criterion is meaningless if the dry-run is executed against a different version of the playbook than the one approved for production.

If a security engineer runs a dry-run on version 3 draft content, then modifies the playbook (creating different content still labelled version 3 draft), and then has it approved, the dry-run result is stale. The production execution may differ from what was tested.

### Decision

`PlaybookVersion` carries a `content_hash: str` (SHA-256) computed over the canonical JSON serialization of `action_steps` + `trigger_configs` at the moment of `DRAFT → PUBLISHED` transition.

`PlaybookTestResult` records `content_hash_at_test: str` at the moment the dry-run executes.

**Approval gate (enforced in application service):**
```
Before approving a playbook:
  latest_test = find_latest_for_version(playbook_id, version_id)
  if latest_test is None:
    raise DryRunRequired("playbook version must pass dry-run before approval")
  if latest_test.content_hash_at_test != current_version.content_hash:
    raise DryRunHashMismatch("playbook content changed since last dry-run; re-run required")
  if latest_test.outcome != TestOutcome.PASSED:
    raise DryRunNotPassed(f"last dry-run outcome: {latest_test.outcome.value}")
```

**Canonical JSON:** Keys sorted alphabetically, no trailing whitespace, UTF-8 encoding. Implemented as `PlaybookContentHashService.compute(version: PlaybookVersion) -> str`.

### Consequences

**Positive:**
- Dry-run result is guaranteed to reflect the exact content being approved
- Content modification invalidates previous dry-runs automatically (no manual invalidation required)

**Negative:**
- Any modification to action steps (even a description field change) requires a new dry-run
- Mitigation: description field changes that do not affect execution semantics can be handled via a `PlaybookVersion.description` field that is excluded from the hash computation (non-semantic metadata is outside the hash scope)

**Hash scope (frozen):** Only `action_steps` (including `parameters`) and `trigger_configs` are included in the hash. Fields excluded from hash: `version_number`, `published_by`, `published_at`. Included: all fields under `ActionStepDefinition` and `TriggerCondition`.

---

## ADR-M35-006: Connector Circuit Breaker Integration with Sprint 26 Runtime Infrastructure

**Status:** ACCEPTED

### Context

Sprint 26 introduced `CircuitBreaker` infrastructure (`RuntimeContainer`, `circuitbreaker` module). The `integration_hub` context requires circuit breaker behavior per connector: if a connector is returning errors, the circuit must open to prevent cascading failures.

Two options:
1. Reuse Sprint 26 circuit breaker infrastructure directly
2. Implement a domain-level `CircuitState` on `ConnectorRegistration` aggregate

### Decision

**Hybrid approach:**

The `ConnectorRegistration` aggregate carries `circuit_state: CircuitState` (CLOSED | OPEN | HALF_OPEN) as domain state, persisted in the database. This ensures circuit state survives process restarts.

The Sprint 26 `CircuitBreaker` infrastructure handles the **in-process** circuit evaluation (fast path; no DB round-trip per connector call). On state transitions (CLOSED → OPEN, OPEN → HALF_OPEN, HALF_OPEN → CLOSED), the application service persists the new state to `ConnectorRegistration` and publishes the appropriate domain event.

**Domain `CircuitBreakerService`** manages transition logic:
- `failure_threshold`: 5 failures in a 2-minute sliding window → OPEN
- `half_open_timeout`: 30 seconds after OPEN → try HALF_OPEN (one probe call allowed)
- `recovery_threshold`: 1 successful probe in HALF_OPEN → CLOSED

### Consequences

**Positive:**
- Circuit state is durable; survives worker process restart
- In-process evaluation is fast (no DB call per connector execution)
- Domain event published on state changes enables external observability (alerting, dashboards)

**Negative:**
- Two sources of truth (in-process state + DB state) must stay synchronized
- Mitigation: DB state is authoritative on startup; in-process state is populated from DB on worker initialization; state transitions are always written to DB before taking effect

---

## ADR-M35-007: ACL Translator Isolation for Cross-Context Event Consumption

**Status:** ACCEPTED

### Context

The `playbook` trigger engine consumes events from three external bounded contexts:
- M28 (`detection`): `DetectionFindingEscalated`
- M34 (`incident`): `IncidentContained`, `IncidentEradicated`
- M32 (`exposure`): `ExposureThresholdBreached`

If the `playbook` context imports domain types from these contexts directly (e.g., `from detection.domain.events import DetectionFindingEscalated`), any change to those events breaks the `playbook` context. This violates bounded context isolation.

### Decision

Implement **Anti-Corruption Layer (ACL) translators** in `playbook.infrastructure.acl`:

```
playbook/infrastructure/acl/
  m28_finding_trigger_translator.py   → M28FindingTriggerTranslator
  m34_incident_trigger_translator.py  → M34IncidentTriggerTranslator
  m32_exposure_trigger_translator.py  → M32ExposureTriggerTranslator
```

Each translator receives the raw event payload as a `dict[str, object]` (deserialized from the event bus message) and produces a `AutomationTriggerEvent` internal value object. The `playbook` domain model contains only `AutomationTriggerEvent` — it has no knowledge of M28, M34, or M32 event schemas.

**Key isolation rules:**
1. No import of external bounded context Python modules anywhere in `playbook.domain` or `playbook.application`
2. ACL translators are allowed to import from `playbook.domain.value_objects` only (upward dependency prohibited)
3. Unknown event fields in external payloads are ignored (no validation error for additional fields) — forward compatibility
4. Missing required fields in external payloads cause `ACLTranslationError` (logged; execution not triggered)

### Consequences

**Positive:**
- M28, M34, and M32 can evolve their event schemas without breaking `playbook` context
- ACL translators are the single place where cross-context schema knowledge lives
- ACL translators are independently testable with raw dict payloads

**Negative:**
- Each new trigger source requires a new ACL translator (acceptable; low maintenance cost)
- ACL translation bugs (missing field mapping) cause silent non-triggers; monitoring required
- Mitigation: each ACL translator emits an `acl.translation.success` / `acl.translation.error` metric
