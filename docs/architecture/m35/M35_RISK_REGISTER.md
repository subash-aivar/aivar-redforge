# M35 Risk Register
## Enterprise Security Automation & Orchestration Platform

**Date:** 2026-07-22  
**Status:** FINAL — All risks disposed  

---

## Risk Disposition Legend

| Disposition | Meaning |
|---|---|
| MITIGATE | Risk accepted with specific mitigation controls that reduce likelihood or impact |
| ACCEPT | Risk accepted without mitigation; impact is tolerable or mitigation cost exceeds benefit |
| DEFER | Risk deferred to a future milestone; not blocking M35 |
| REJECT | Risk determined to be non-existent or misidentified after analysis |

---

## R01 — Automated Actions Cause Production Outage via False Positive Trigger

**Category:** Operational Risk  
**Severity:** CRITICAL  
**Likelihood:** MEDIUM (detection false positive rates are non-zero in any real deployment)  
**Impact:** HIGH (automated IP block or account disable affects production users)  

**Root Cause:** M28 detection findings carry `severity` and `confidence` scores. A HIGH severity, LOW confidence finding that triggers a CREDENTIAL_REVOKE playbook would disable a production service account on a false positive.

**Disposition:** MITIGATE  

**Mitigations:**
1. **Rate limiting per trigger condition**: `TriggerCondition.rate_limit_max_invocations` defaults to 1 invocation per 5-minute window per trigger type. A burst of false positives cannot trigger a burst of executions.
2. **Severity threshold filter in trigger condition**: Playbook authors must specify `severity_threshold`; LOW severity findings do not trigger HIGH/CRITICAL impact playbooks by default.
3. **Authorization gate for HIGH/CRITICAL**: Actions with `ActionImpactLevel.HIGH` or `CRITICAL` pause for human authorization (ADR-M35-001). False positive propagation is halted before destructive action.
4. **Dry-run requirement**: Every playbook version must pass dry-run (with content hash enforcement per ADR-M35-005) before approval. Dry-run exercises the full decision path including severity thresholds.
5. **CISO kill switch**: `AutomationPolicy.kill_switch_state` can be TRIGGERED instantly to halt all automation pending investigation of a suspected false positive storm.

**Residual Risk:** LOW/MEDIUM impact actions (ITSM ticket creation, Slack alert) may execute on false positives. This is acceptable — informational actions on false positives cause minor noise, not operational disruption.

---

## R02 — Connector Credential Leakage via Log, Database, or Memory Dump

**Category:** Security Risk  
**Severity:** CRITICAL  
**Likelihood:** LOW (with controls applied)  
**Impact:** CRITICAL (leaked API keys for AWS, Okta, CrowdStrike grant attacker full access to production security controls)  

**Root Cause:** Application code handling credentials is always one bug away from logging or persisting them.

**Disposition:** MITIGATE  

**Mitigations:**
1. **CredentialRef model (ADR-M35-003)**: Database table never contains live credentials; only vault key references.
2. **`ResolvedCredential.secret_value` lifetime**: Credential is resolved immediately before use; goes out of scope after connector call completes. Never stored in aggregate state.
3. **Log sanitization**: Logging middleware must scrub any dict or object containing keys named `secret`, `api_key`, `token`, `password`, `credential` (case-insensitive). Architecture test verifies log format.
4. **Architecture tests**: `test_no_credential_fields_in_orm.py` asserts no `api_key`/`secret`/etc. column names on `ConnectorRegistration` SQLAlchemy model. Fails the build if violated.
5. **Vault TTL**: Vault resolves short-lived tokens where possible (e.g., AWS STS 15-minute tokens rather than long-lived IAM keys).

**Residual Risk:** Memory dump of the running process during a connector call window could expose a credential in memory. Mitigation: process memory dumps are a host-level security control outside M35 scope.

---

## R03 — AutomatedActionRecord Orphan (External Action Applied but Not Recorded)

**Category:** Evidence Integrity Risk / Audit Risk  
**Severity:** HIGH  
**Likelihood:** LOW (process restarts are infrequent; the window is narrow)  
**Impact:** HIGH (audit trail incomplete; rollback decision-making is impaired without the record)  

**Root Cause:** External connector call succeeds but process dies before `AutomatedActionRecord` is updated to COMPLETED.

**Disposition:** MITIGATE  

**Mitigations:**
1. **Outbox pattern (ADR-M35-002)**: `AutomatedActionRecord` is written in PENDING state before the connector call. Record always exists regardless of outcome.
2. **`OutboxRecoveryWorker`**: Detects PENDING records older than 5 minutes; attempts outcome verification via connector; resolves to COMPLETED or FAILED.
3. **Escalation on unresolvable**: After 3 consecutive failed verifications, the record is escalated to `soc:commander` for manual resolution.
4. **Monitoring alert**: Any PENDING record older than 15 minutes triggers a `P3` alert to the operations team.

**Residual Risk:** Connectors without outcome verification support leave unresolvable PENDING records. These are escalated to human resolution. The record exists; only its outcome status is uncertain.

---

## R04 — Kill Switch Unavailability During Critical Incident

**Category:** Operational Risk  
**Severity:** HIGH  
**Likelihood:** LOW  
**Impact:** HIGH (cannot halt automation during a suspected malfunction or runaway execution)  

**Root Cause:** `AutomationPolicy` stored in database; database unavailability could prevent kill switch read, leading to continued automation during a crisis.

**Disposition:** MITIGATE  

**Mitigations:**
1. **In-process cache with fail-safe**: `AutomationPolicy` cached with 10-second TTL. On cache miss + database unavailable: **fail closed** — treat kill switch as TRIGGERED. No automation proceeds when policy cannot be read.
2. **Write propagation**: Kill switch activation writes to database; in-process cache TTL means enforcement within 10 seconds maximum. Cache invalidation notification via event bus provides faster propagation (typically < 1 second).
3. **Alternative activation path**: Kill switch can also be activated by updating an environment variable (`AUTOMATION_KILL_SWITCH=true`) that is checked before database read. This provides a process-level override that does not require database connectivity.

**Residual Risk:** In the 10-second TTL window after activation, a new step may begin. This is bounded and documented. The "fail closed on database unavailability" rule ensures that infrastructure failure causes automation to stop, not continue.

---

## R05 — Cross-Tenant Trigger Evaluation (Tenant A's Finding Triggers Tenant B's Playbook)

**Category:** Security Risk / Multi-Tenancy Risk  
**Severity:** CRITICAL  
**Likelihood:** LOW (with controls applied)  
**Impact:** CRITICAL (Tenant B's production infrastructure is modified based on Tenant A's security events)  

**Root Cause:** `PlaybookTriggerWorker` must evaluate trigger conditions against incoming events. If `tenant_id` scoping is missed, a cross-tenant match is possible.

**Disposition:** MITIGATE  

**Mitigations:**
1. **`tenant_id` on all trigger evaluation calls**: `TriggerMatchingService.find_matching_playbooks(event: AutomationTriggerEvent)` takes `tenant_id` as a required first argument and evaluates only playbooks for that tenant.
2. **`find_approved_for_trigger` requires `tenant_id`**: Repository interface enforces `WHERE tenant_id = :tenant_id` on all trigger queries (no method without `tenant_id`).
3. **Architecture test**: `test_trigger_evaluation_is_tenant_scoped.py` verifies that passing an event with `tenant_id = "A"` never returns playbooks belonging to `tenant_id = "B"`.
4. **`AutomationTriggerEvent.tenant_id` is non-nullable**: ACL translators enforce that every inbound event carries a resolvable `tenant_id`; events without valid `tenant_id` are discarded.

**Residual Risk:** None identified beyond implementation defect, which the architecture test would catch.

---

## R06 — Rollback Failure Leaving Infrastructure in Inconsistent State

**Category:** Operational Risk  
**Severity:** HIGH  
**Likelihood:** MEDIUM (rollback is inherently dependent on external system state which may have changed)  
**Impact:** MEDIUM (inconsistency in external system; not a data loss or security breach)  

**Root Cause:** Rollback attempts to reverse an external system state change. Between the original action and the rollback, another process (human or automated) may have further modified the state. Rollback may partially succeed or silently no-op.

**Disposition:** ACCEPT  

**Justification:** Rollback is inherently a best-effort operation. The platform cannot guarantee that an external system's state is reversible in all cases. Attempting to guarantee it would require distributed transactions across 15+ external systems — which is architecturally infeasible and would prevent shipping.

**Mitigations (reducing likelihood and impact):**
1. **Rollback time window**: `RollbackDefinition.max_rollback_window_hours` (default 24 hours) defines when rollback is eligible. Beyond the window, rollback is blocked as `RollbackStatus.NOT_APPLICABLE`.
2. **`RollbackRecord` captures outcome**: `COMPLETED`, `FAILED`, `NOT_APPLICABLE` states with `failure_reason` provide full audit trail even when rollback fails.
3. **Human escalation on rollback failure**: `RollbackFailed` event triggers `P2` alert to `soc:commander`.
4. **Non-reversible actions classified LOW**: Actions without rollback support (ITSM ticket creation, Slack message) are assigned `ActionImpactLevel.LOW` and do not require HIGH/CRITICAL authorization.

**Residual Risk:** Accepted. Documented in runbook: "Rollback failure requires manual intervention and reconciliation of external system state."

---

## R07 — PlaybookVersion Deployed Without Passing Dry-Run

**Category:** Operational Risk / Quality Risk  
**Severity:** HIGH  
**Likelihood:** LOW (with content hash enforcement)  
**Impact:** HIGH (production execution diverges from tested behavior; unexpected actions taken)  

**Root Cause:** Without content hash verification at approval time, a playbook version that was tested in one form could be approved in a different (modified) form.

**Disposition:** MITIGATE  

**Mitigations:**
1. **Content hash enforcement (ADR-M35-005)**: Approval service verifies `latest_test_result.content_hash == current_version.content_hash`. Mismatch raises `DryRunHashMismatch` and blocks approval.
2. **Dry-run required**: If no test result exists for the current version, `DryRunRequired` blocks approval.
3. **PASSED outcome required**: If the latest test result outcome is `FAILED` or `PARTIAL`, `DryRunNotPassed` blocks approval.

**Residual Risk:** A dry-run may test all paths optimistically (connector stubs always return success). The 95% prediction accuracy criterion requires dry-run stubs to be configurable to simulate failure modes. This is a dry-run fidelity concern, not a content hash concern.

---

## R08 — Separation of Duties Bypass (Trigger Operator Self-Authorizes Escalation)

**Category:** Security Risk / Audit Risk  
**Severity:** HIGH  
**Likelihood:** LOW (requires deliberate bypass attempt)  
**Impact:** HIGH (single operator can trigger and authorize a CRITICAL production action; audit trail integrity broken)  

**Root Cause:** `AuthorizeAutomationStep` command handler could fail to check that the authorizer is different from the trigger operator.

**Disposition:** MITIGATE  

**Mitigations:**
1. **Domain service enforcement**: `AutomationAuthorizationService.assert_runtime_authorized()` raises `SeparationOfDutiesViolation` if `authorizer_id == trigger_operator_id`. This is a domain invariant, not application-layer logic.
2. **Test coverage (mandatory)**: `test_runtime_authorization_self_authorization_rejected.py` in Phase 3 exit criteria.
3. **Audit event**: Both trigger and authorization events include operator IDs; any audit log query can detect SoD violations retrospectively.

**Residual Risk:** A deliberately malicious operator with both trigger capability and authorization capability could attempt a replay or identity substitution attack. This is a threat actor model outside the domain's trust boundary (assumes compromised identity infrastructure).

---

## R09 — Connector Circuit Breaker Not Integrated with Sprint 26 Runtime

**Category:** Integration Risk  
**Severity:** MEDIUM  
**Likelihood:** LOW (Sprint 26 circuit breaker is established infrastructure)  
**Impact:** MEDIUM (cascading connector failures without circuit protection; degraded execution reliability)  

**Root Cause:** Sprint 26 circuit breaker was designed for internal service communication. `integration_hub` connectors call external APIs with different latency and failure characteristics.

**Disposition:** MITIGATE  

**Mitigations:**
1. **Hybrid model (ADR-M35-006)**: `ConnectorRegistration` carries durable `circuit_state`; Sprint 26 in-process logic handles per-call evaluation. State transitions write to DB for durability across process restarts.
2. **Connector-specific thresholds**: Each `ConnectorType` carries default `failure_threshold` and `half_open_timeout` tuned for that external system's observed reliability characteristics.
3. **Phase 3 exit criteria**: Circuit breaker state machine transitions are explicitly tested in integration tests before Phase 3 is declared complete.

**Residual Risk:** A slow connector (high latency but no errors) bypasses the circuit breaker. Mitigation: per-connector timeout enforcement (see C3 decision, TIMEOUT failure mode) causes timeouts to increment the failure counter.

---

## R10 — Playbook Trigger Fan-Out Storm

**Category:** Scalability Risk / Operational Risk  
**Severity:** MEDIUM  
**Likelihood:** LOW-MEDIUM (during a large-scale incident, M28 may produce thousands of escalated findings simultaneously)  
**Impact:** MEDIUM (thousands of concurrent playbook executions; external connector rate limits hit; resource exhaustion)  

**Root Cause:** One large security incident may produce N escalated findings. If N playbooks are configured with matching trigger conditions, N executions start simultaneously.

**Disposition:** MITIGATE  

**Mitigations:**
1. **Per-trigger rate limiting**: `TriggerCondition.rate_limit_window_seconds` (default 300s) and `rate_limit_max_invocations` (default 1) enforce a maximum of 1 trigger per 5 minutes per playbook per trigger type per tenant.
2. **`max_concurrent_executions` cap**: `AutomationPolicy.max_concurrent_executions` (default 5) is checked before starting each new execution. Excess triggers are queued, not dropped.
3. **`max_actions_per_hour` budget**: `AutomationPolicy.max_actions_per_hour` (default 100) limits total action execution rate across all playbooks for a tenant.
4. **Connector rate limit tracking**: `RateLimitTrackingService` tracks action budget per connector; RATE_LIMITED failure mode with exponential backoff prevents API throttling from external systems.

**Residual Risk:** Queue depth growth during a large incident. Monitoring alert when queue depth exceeds `max_concurrent_executions * 10`; operations team can temporarily raise limits or activate kill switch to drain queue selectively.
