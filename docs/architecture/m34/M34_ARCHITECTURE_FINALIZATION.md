# M34 Architecture Finalization
## Enterprise Incident Response Platform

**Status:** FROZEN FOR IMPLEMENTATION  
**Date:** 2026-07-21  
**Precondition:** M34 Architecture Review APPROVED WITH CONDITIONS (C1–C7)  
**Constraint:** Documentation only. No code, no migrations, no repository modifications.

---

## Table of Contents

1. [Final Decisions (C1–C7)](#1-final-decisions-c1c7)
2. [Frozen DDD Model](#2-frozen-ddd-model)
3. [ADRs (ADR-M34-001 through ADR-M34-006)](#3-adrs-adr-m34-001-through-adr-m34-006)
4. [Architecture Corrections](#4-architecture-corrections)
5. [Risk Dispositions (R01–R09)](#5-risk-dispositions-r01r09)
6. [Frozen Phase Plan](#6-frozen-phase-plan)
7. [Implementation Readiness](#7-implementation-readiness)

---

## 1. Final Decisions (C1–C7)

---

### C1 — Incident-Investigation Boundary

**Condition from Review:** The exact boundary between the `Incident` aggregate and M21 Investigation must be frozen. What data is referenced by ID only, what events trigger incident creation, and how the M21 investigation lifecycle relates to the M34 incident lifecycle.

#### Decision: Incident References Investigation; Investigation Does Not Own Incident

The `Incident` aggregate in M34 holds only an `InvestigationRef` value object, which contains:
```
InvestigationRef(VO):
  investigation_id: str   (M21 investigation ID — opaque reference)
  concluded_at: datetime  (timestamp from M21's InvestigationConcluded event)
  conclusion: InvestigationConclusion(Enum): CONFIRMED_THREAT | INCONCLUSIVE | FALSE_POSITIVE
```

The `Incident` aggregate does NOT contain:
- M21 investigation findings
- M21 analyst notes
- M21 timeline entries
- M21 evidence references

These remain in M21. M34 analysts who need full M21 investigation details navigate to M21 via the `investigation_id`. The M34 `IncidentTimeline` has an entry `INVESTIGATION_CONTEXT_LINKED` referencing the `investigation_id`, but no M21 data is duplicated into M34.

**Incident creation triggers (frozen):**

| Trigger | Event Consumed | How Incident is Declared |
|---|---|---|
| Detection finding escalation | `DetectionFindingEscalated(finding_id, severity, asset_ref, rule_id, detected_at)` | Auto-creates `Incident` in DECLARED phase with `EscalatedFindingRef` |
| Investigation conclusion | `InvestigationConcluded(investigation_id, conclusion, confirmed_at)` if conclusion = CONFIRMED_THREAT | Auto-creates `Incident` in CLASSIFIED phase with `InvestigationRef` |
| Manual declaration | `DeclareIncident` command issued by `incident:analyst` or higher | Creates `Incident` in DECLARED phase with `trigger_type = MANUAL_DECLARATION` |
| External notification | `RegisterExternalIncidentNotification` command | Creates `Incident` in DECLARED phase with `trigger_type = EXTERNAL_NOTIFICATION` |

**Relationship rule:** One investigation may be linked to at most one incident. One incident may have at most one investigation ref. This is a 1:1 optional relationship; neither owns the other.

**Phase relationship:**

```
M21 Investigation lifecycle:  OPEN → IN_PROGRESS → CONCLUDED
M34 Incident lifecycle:       DECLARED → CLASSIFIED → CONTAINED → ERADICATED → RECOVERED → CLOSED

These are independent lifecycles. M21 being closed does NOT close M34's Incident.
M34's Incident may exist with no M21 investigation (manual declaration, external notification).
M21's InvestigationConcluded event may trigger M34 Incident creation, but after that,
  M34 manages its own lifecycle independently.
```

---

### C2 — IncidentCommunicationLog Immutability Model

**Condition from Review:** The `IncidentCommunicationLog` immutability model must be frozen: repository interface with only `append()` and `find_by_incident()`; no update or delete; each entry carries immutable `logged_at` and `author`.

#### Decision: Separate Append-Only Entity with Interface-Enforced Immutability

`IncidentCommunicationLogEntry` is a separate entity (not embedded in the `Incident` aggregate) stored in `incident.communication_log_entries`. It is loaded independently from the `Incident` aggregate.

**Frozen repository interface:**

```python
class IIncidentCommunicationLogRepository:
    async def append(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        entry: IncidentCommunicationLogEntry,
    ) -> None: ...

    async def find_by_incident(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        *,
        after: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IncidentCommunicationLogEntry]: ...

    # No update() method. No delete() method.
    # Attempting to modify an entry is a compile-time impossibility at the interface level.
```

**`IncidentCommunicationLogEntry` structure (frozen):**

```
IncidentCommunicationLogEntry:
  entry_id: UUID               (generated at creation; immutable)
  tenant_id: TenantId          (immutable)
  incident_id: IncidentId      (immutable)
  content: str                 (the communication text; immutable after append)
  author: CommunicationAuthor  (who wrote it; immutable)
  recipient_summary: str       (who was notified; immutable)
  communication_type: CommunicationType  (STAKEHOLDER_UPDATE | REGULATORY_NOTIFICATION | INTERNAL | EXTERNAL_AUTHORITY)
  logged_at: datetime          (set by the system at append time; immutable; cannot be specified by caller)
  entry_sequence: int          (monotonically increasing per incident; set by repository on insert)
```

**Immutability enforcement layers:**

1. **Interface layer:** No `update()` or `delete()` method defined on the repository interface
2. **Application service layer:** `LogIncidentCommunication` command creates a new `IncidentCommunicationLogEntry` via `append()`. No "edit communication" command exists.
3. **Database layer:** `logged_at` and `entry_id` columns have `DEFAULT` set server-side (PostgreSQL `DEFAULT now()`, `DEFAULT gen_random_uuid()`); the application cannot override these values
4. **Test layer:** Architecture test verifies no `update` or `delete` method exists on `IIncidentCommunicationLogRepository`

**Why separate from the `Incident` aggregate:** A long-running P1 incident (days or weeks) may generate hundreds of communication log entries. Embedding them in the `Incident` aggregate as a list would require loading all entries every time the `Incident` aggregate is hydrated. A separate entity solves both memory pressure and immutability enforcement.

---

### C3 — Regulatory Notification Automation Prohibition

**Condition from Review:** No automatic submission by timer, event, or automation. Submission is always a human-issued `SubmitRegulatoryNotification` command. Deadline timers trigger alerts only.

#### Decision: Timers Are Alert-Only; Submission Is Human-Commanded; Prohibition Is Domain-Enforced

**What timers do:**
1. Timer fires at configured intervals before deadline (48h, 24h, 12h, 6h, 1h)
2. Timer checks `RegulatoryNotification.status` — if already SUBMITTED, timer is cancelled
3. Timer publishes `RegulatoryDeadlineApproaching(incident_id, regime, deadline_at, hours_remaining)` event
4. Alert is routed to `incident:ciso` and `regulatory:legal` via notification port
5. **Timer does NOT call any submission command. Timer does NOT change aggregate status.**

**What triggers actual submission:**
```python
class SubmitRegulatoryNotification(Command):
    tenant_id: TenantId
    notification_id: RegNotificationId
    submitted_by: str          # actor identity (must be regulatory:legal or incident:ciso role)
    submission_method: str     # e.g., "GDPR_portal_submission", "email_to_DPA"
    reference_number: str      # regulator's acknowledgement number (may be pending initially)
    notes: str | None
```

**Domain invariant (enforced in `RegulatoryNotification.submit()`):**
```python
def submit(self, cmd: SubmitRegulatoryNotification) -> None:
    if self.status == NotificationStatus.SUBMITTED:
        raise AlreadySubmitted(self.notification_id)
    # No check for timer status. Submission can happen before deadline (preferred) or after.
    # Submission requires the actor to supply the regulator reference number.
    # Status transitions: READY_FOR_SUBMISSION → SUBMITTED
    # Publishes RegulatoryNotificationSubmitted (immutable record)
    submission = SubmissionRecord(
        submitted_at=datetime.now(UTC),
        submitted_by=cmd.submitted_by,
        submission_method=cmd.submission_method,
        reference_number=cmd.reference_number,
    )
    self._submission = submission  # immutable value object; set once
    self.status = NotificationStatus.SUBMITTED
```

**What happens if deadline is breached:**
Timer publishes `RegulatoryDeadlineBreached(incident_id, regime, deadline_at)`. This event is a factual record that the deadline was missed. It does NOT auto-submit. It does NOT change the `RegulatoryNotification` status. It triggers:
1. A `CRITICAL` alert to `incident:ciso` and `regulatory:legal`
2. An immutable `DeadlineBreachRecord` appended to the `RegulatoryNotification` aggregate (records the breach for audit purposes)
3. An `IncidentCommunicationLogEntry` created automatically recording the breach fact

**Why:** Platform Invariant 6. Regulatory submissions are legal documents with the organization's name on them. The platform assists the human in meeting the deadline; it does not submit on the human's behalf. An incorrect auto-submission that names the wrong organizational entity or mischaracterizes the breach creates a legal liability greater than the fine for late submission.

---

### C4 — MTTR Pipeline to M33

**Condition from Review:** `analytics.incident_events` table schema in migration `0102`; `IncidentClassified` and `IncidentClosed` event field specifications; M33 `AnalyticsProjectionWorker` subscription configuration.

#### Decision: M34 Migration 0102 Creates the Table; M33 Worker Auto-Activates on New Event Type

**Migration `0102` creates:**

```sql
-- In the analytics schema (M33 owns this schema; M34 extends it with this table)
CREATE TABLE analytics.incident_events (
    event_id        UUID          NOT NULL,
    tenant_id       UUID          NOT NULL,
    incident_id     UUID          NOT NULL,
    event_type      VARCHAR(100)  NOT NULL,  -- 'incident_classified' | 'incident_closed'
    severity        VARCHAR(50),             -- IncidentSeverity value at classification
    classified_at   TIMESTAMPTZ,             -- set on incident_classified events
    closed_at       TIMESTAMPTZ,             -- set on incident_closed events
    resolution_type VARCHAR(50),             -- set on incident_closed events
    event_ts        TIMESTAMPTZ   NOT NULL,
    payload         JSONB         NOT NULL,
    ingested_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
) PARTITION BY HASH (tenant_id);

CREATE TABLE analytics.incident_events_p0 PARTITION OF analytics.incident_events
    FOR VALUES WITH (MODULUS 8, REMAINDER 0);
-- ... p1 through p7

CREATE INDEX ix_incident_events_tenant_id ON analytics.incident_events(tenant_id);
CREATE INDEX ix_incident_events_classified_at ON analytics.incident_events(tenant_id, classified_at)
    WHERE event_type = 'incident_classified';
CREATE INDEX ix_incident_events_closed_at ON analytics.incident_events(tenant_id, closed_at)
    WHERE event_type = 'incident_closed';
```

**`IncidentClassified` event (frozen schema):**

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class IncidentClassified(BaseDomainEvent):
    incident_id: str
    tenant_id: str
    severity: str               # IncidentSeverity.value
    classified_at: str          # ISO-8601 UTC datetime string
    trigger_type: str           # IncidentTriggerType.value
    source_finding_ref: str | None   # M28 finding_id if trigger was detection finding
    source_investigation_ref: str | None  # M21 investigation_id if trigger was investigation
```

**`IncidentClosed` event (frozen schema):**

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class IncidentClosed(BaseDomainEvent):
    incident_id: str
    tenant_id: str
    closed_at: str              # ISO-8601 UTC datetime string
    resolution_type: str        # ResolutionType.value
    classified_at: str          # included for MTTR computation convenience
    incident_duration_hours: float  # pre-computed (closed_at - classified_at) in hours
```

**MTTR computation in M33 `KPIComputationService` (activated by data presence):**

```sql
WITH incidents AS (
  SELECT
    ic.incident_id,
    ic.classified_at,
    icl.closed_at,
    EXTRACT(EPOCH FROM (icl.closed_at - ic.classified_at)) / 3600.0 AS mttr_hours
  FROM analytics.incident_events ic
  JOIN analytics.incident_events icl
    ON  ic.incident_id   = icl.incident_id
    AND ic.tenant_id     = icl.tenant_id
  WHERE ic.event_type    = 'incident_classified'
    AND icl.event_type   = 'incident_closed'
    AND icl.resolution_type NOT IN ('false_positive', 'duplicate')  -- exclude non-incidents
    AND ic.tenant_id     = :tenant_id
    AND icl.closed_at   >= :period_start
    AND icl.closed_at   <  :period_end
)
SELECT
  AVG(mttr_hours)                                             AS mttr_hours,
  PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY mttr_hours)   AS mttr_p50_hours,
  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY mttr_hours)   AS mttr_p95_hours,
  COUNT(*)                                                    AS qualified_incident_count
FROM incidents;
-- Returns REQUIRES_M34_DATA if analytics.incident_events table is empty for tenant
-- Returns INSUFFICIENT_DATA if < 3 qualified incidents in period
-- Returns ACTIVE with computed values once >= 3 incidents present
```

**Activation mechanism:** The `KPIComputationService` checks `COUNT(*) FROM analytics.incident_events WHERE tenant_id = :tenant_id`. If > 0, MTTR moves from `REQUIRES_M34_DATA` to computing normally. No code change required in M33 — the existing `REQUIRES_M34_DATA` check already handles this (if incident_events rows exist, COUNT > 0, MTTR computation proceeds). The M33 `AnalyticsProjectionWorker` adds `incident_classified` and `incident_closed` to its event type routing table in configuration.

---

### C5 — Durable Regulatory Deadline Timers

**Condition from Review:** All regulatory deadlines stored in `regulatory_notification.notification_deadlines` table; `DeadlineAlertingService` reconstitutes on startup; no in-memory-only timers.

#### Decision: PostgreSQL-Persisted Deadline Records + Startup Reconstitution

**Physical deadline storage:**

```sql
CREATE TABLE regulatory_notification.notification_deadlines (
    deadline_id         UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID          NOT NULL,
    notification_id     UUID          NOT NULL
        REFERENCES regulatory_notification.regulatory_notifications(id),
    incident_id         UUID          NOT NULL,
    regime              VARCHAR(50)   NOT NULL,  -- RegulatoryRegime.value
    deadline_at         TIMESTAMPTZ   NOT NULL,
    deadline_hours      INTEGER       NOT NULL,  -- total hours window
    alert_sent_at_48h   TIMESTAMPTZ,             -- NULL until 48h alert sent
    alert_sent_at_24h   TIMESTAMPTZ,
    alert_sent_at_12h   TIMESTAMPTZ,
    alert_sent_at_6h    TIMESTAMPTZ,
    alert_sent_at_1h    TIMESTAMPTZ,
    breach_recorded_at  TIMESTAMPTZ,             -- NULL until deadline passed without submission
    status              VARCHAR(50)   NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE | CANCELLED | MET
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX ix_nd_active_deadlines ON regulatory_notification.notification_deadlines(deadline_at, status)
    WHERE status = 'ACTIVE';
CREATE INDEX ix_nd_tenant ON regulatory_notification.notification_deadlines(tenant_id, status);
```

**`DeadlineAlertingService` startup reconstitution:**

```python
class DeadlineAlertingService:
    async def reconstitute_on_startup(self) -> None:
        """Called at application startup by RuntimeContainer.
        Loads all ACTIVE deadlines from DB.
        Schedules alert tasks for any thresholds not yet sent.
        Immediately evaluates deadlines that should have fired during downtime.
        """
        active_deadlines = await self._repo.find_active_deadlines()
        now = datetime.now(UTC)
        for deadline in active_deadlines:
            # If deadline passed during downtime: record breach immediately
            if deadline.deadline_at < now and deadline.breach_recorded_at is None:
                await self._record_breach(deadline, detected_at=now, note="detected_at_startup")
                continue
            # Schedule remaining unfired alert thresholds
            for threshold_hours, sent_at_attr in [
                (48, "alert_sent_at_48h"), (24, "alert_sent_at_24h"),
                (12, "alert_sent_at_12h"), (6, "alert_sent_at_6h"), (1, "alert_sent_at_1h"),
            ]:
                if getattr(deadline, sent_at_attr) is None:
                    alert_fire_at = deadline.deadline_at - timedelta(hours=threshold_hours)
                    if alert_fire_at > now:
                        self._schedule_alert(deadline.deadline_id, alert_fire_at, threshold_hours)
                    else:
                        # Threshold passed during downtime; send alert immediately
                        await self._send_alert(deadline, hours_remaining=threshold_hours,
                                              note="catchup_after_downtime")
```

**Worker type:** `DeadlineAlertingWorker` — background async task supervised by `RuntimeContainer`. Does not use cron; uses the platform's `DurableScheduledTask` pattern (from Sprint 28) with PostgreSQL-backed scheduling state. The `DurableScheduledTask` table (`redforge.scheduled_tasks`) already exists from M28 infrastructure.

**No in-memory timers rule:** A Python `asyncio.sleep()` call inside a looping coroutine for deadline tracking is explicitly prohibited. It does not survive process restart. The `DeadlineAlertingService` uses `reconstitute_on_startup()` to restore all state from the database on every process boot.

---

### C6 — LessonsLearned Campaign Feedback Design

**Condition from Review:** `CampaignRetargetingSuggested` event schema and pathway must be frozen; no direct M30 write.

#### Decision: Event Bus Advisory with Frozen Event Schema; M30 Subscription Optional

**Event schema (frozen):**

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignRetargetingSuggested(BaseDomainEvent):
    lessons_learned_id: str
    incident_id: str
    tenant_id: str
    confirmed_technique_ids: list[str]  # MITRE ATT&CK technique IDs confirmed in incident
    attack_vector_description: str      # human-readable summary of the attack vector
    suggested_scenario_name: str        # suggested name for the campaign scenario
    suggested_scope: str                # suggested asset scope (e.g., "web_application_servers")
    evidence_refs: list[str]            # EvidenceRef IDs supporting the technique confirmation
    rationale: str                      # why this retarget is suggested
    produced_at: str                    # ISO-8601 UTC
```

**Pathway:**

```
LessonsLearned.finalize() 
  → publishes CampaignRetargetingSuggested to platform event bus
  → M30 campaign context (if subscribed) receives the event
  → M30 event handler creates a ScenarioTemplateDraft (not a full scenario; requires human review)
  → M34 has no visibility into whether M30 acted on the suggestion
```

**Enforcement:**
- `lessons_learned` module has no import from `campaign`, `scenario`, or `taskgraph` modules
- Architecture test: `grep -r "from campaign\|from scenario\|from taskgraph" backend/src/lessons_learned/` must return empty
- `CampaignRetargetingSuggested` event is published to the platform event bus with no response expected
- M30 subscription to `CampaignRetargetingSuggested` is optional; if M30 is not subscribed, the event is unread and no suggestion is created — this is expected and not an error

**Why:** Platform Invariant 7 (AI Suggestion Read-Only at Domain Boundaries) applies here even though M34 is not an AI context. The `lessons_learned` context produces analytical suggestions; it must not implement the suggestions itself. The boundary is enforced at the event bus level.

---

### C7 — Incident Severity Classification Lifecycle

**Condition from Review:** Initial severity source, commander override protocol, severity-change justification, and relationship between severity and containment authorization level must be frozen.

#### Decision: Finding-Derived Initial Classification + Commander Override with Mandatory Justification + Static Authorization Matrix

**Severity mapping from M28 FindingSeverity → IncidentSeverity:**

```
FindingSeverity.CRITICAL → IncidentSeverity.P1_CRITICAL
FindingSeverity.HIGH     → IncidentSeverity.P2_HIGH
FindingSeverity.MEDIUM   → IncidentSeverity.P3_MEDIUM
FindingSeverity.LOW      → IncidentSeverity.P4_LOW
Manual declaration       → IncidentSeverity specified by declarer (requires incident:analyst minimum)
```

**Severity change protocol:**

Severity may change after initial classification ONLY via `ReclassifyIncident` command:
```python
class ReclassifyIncident(Command):
    tenant_id: TenantId
    incident_id: IncidentId
    new_severity: IncidentSeverity
    justification: str  # non-empty; minimum 20 characters
    reclassified_by: str  # must hold incident:commander role
```

Requirements:
1. `incident:commander` role minimum (incident:analyst cannot reclassify)
2. `justification` must be non-empty and ≥ 20 characters (enforced by domain invariant)
3. Every reclassification produces an immutable `IncidentTimelineEntry` recording old severity, new severity, actor, justification, and timestamp
4. Severity may increase (P3 → P1) or decrease (P2 → P4) — both directions permitted with justification

**Authorization matrix (frozen by action type in domain — not configuration):**

| ContainmentActionType | Minimum Required Role | Rationale |
|---|---|---|
| `ALERT_ESCALATION` | `incident:analyst` | Low impact; no production change |
| `TRAFFIC_LOGGING` | `incident:analyst` | Read-only; no disruption |
| `PROCESS_TERMINATION` | `incident:analyst` | Service-local; bounded impact |
| `SERVICE_SUSPENSION` | `incident:commander` | Possible user impact |
| `CREDENTIAL_REVOKE` | `incident:commander` | Identity disruption; production impact |
| `ACCOUNT_DISABLE` | `incident:commander` | Identity disruption; production impact |
| `TRAFFIC_BLOCK` | `incident:commander` | Network-level; broad potential impact |
| `NETWORK_ISOLATION` | `incident:ciso` | Severe business disruption |
| `MASS_CREDENTIAL_REVOKE` | `incident:ciso` | Enterprise-wide disruption; requires CISO sign-off |
| `MANUAL` | Role determined by commander at authorization time | Human judgment required |

The `ContainmentAuthorizationService.required_authorization_level()` method returns the minimum role from this matrix. The matrix is a static, domain-embedded lookup table — not a configuration table. Changing it requires a code change and architectural review.

---

## 2. Frozen DDD Model

### Bounded Context Summary

| Context | Module Path | Role | Aggregates |
|---|---|---|---|
| `incident` | `backend/src/incident/` | Core Domain | Incident, ContainmentAction, EradicationVerification, RecoveryMilestone |
| `regulatory_notification` | `backend/src/regulatory_notification/` | Supporting | RegulatoryNotification, NotificationDraft |
| `lessons_learned` | `backend/src/lessons_learned/` | Supporting | LessonsLearned, PostIncidentReport |

### Frozen Aggregate Specifications

**`incident` context:**

**`Incident` aggregate:**
```
Identity: IncidentId (UUID)
Lifecycle: DECLARED → CLASSIFIED → CONTAINED → ERADICATED → RECOVERED → CLOSED
Key invariants:
  - classified_at set once; immutable after classification
  - CLOSED requires EradicationVerification.VERIFIED OR resolution_type in {FALSE_POSITIVE, DUPLICATE} OR CISO override
  - severity change requires incident:commander + justification
Fields:
  incident_id, tenant_id, title, description, phase, severity,
  classification_method, trigger_type, source_finding_ref, investigation_ref,
  exposure_scope_refs, classified_at, contained_at, eradicated_at, recovered_at,
  closed_at, resolution_type, tags, version
Children (entities, not separate aggregates):
  List[IncidentTimelineEntry]  (ordered phase + action log; append-only)
  List[IncidentTag]            (key-value metadata)
```

**`ContainmentAction` aggregate:**
```
Identity: ContainmentActionId (UUID)
Parent reference: incident_id (not embedded)
Lifecycle: PENDING_AUTH → AUTHORIZED → EXECUTING → COMPLETED | FAILED | ROLLED_BACK
Fields:
  action_id, tenant_id, incident_id, action_type, description, authorization_level_required,
  authorized_by, authorized_at, executed_by, started_at, completed_at,
  evidence_ref, status, failure_reason, rollback_ref
```

**`EradicationVerification` aggregate:**
```
Identity: EradicationVerificationId (UUID)
Parent reference: incident_id (not embedded)
Lifecycle: PENDING → SUBMITTED → VERIFIED | DISPUTED
Two-role attestation: submitted_by (incident:analyst), verified_by (incident:commander)
Fields:
  verification_id, tenant_id, incident_id, assertion, evidence_refs,
  submitted_by, submitted_at, verified_by, verified_at, status, dispute_reason
Invariant: submitted_by ≠ verified_by (same person cannot submit and verify)
```

**`RecoveryMilestone` aggregate:**
```
Identity: RecoveryMilestoneId (UUID)
Parent reference: incident_id (not embedded)
Lifecycle: PENDING → IN_PROGRESS → COMPLETED | DEFERRED
Fields:
  milestone_id, tenant_id, incident_id, title, description, owner,
  target_date, started_at, completed_at, status, completion_notes
```

**`regulatory_notification` context:**

**`RegulatoryNotification` aggregate:**
```
Identity: RegNotificationId (UUID)
Key: (incident_id, regime) — one per (incident, regulation)
Lifecycle: CLOCK_STARTED → DRAFT_IN_PROGRESS → READY_FOR_SUBMISSION → SUBMITTED → ACKNOWLEDGED
Fields:
  notification_id, tenant_id, incident_id, regime, jurisdiction,
  deadline_at, deadline_hours, clock_started_at, status,
  draft_ref, submission_record, deadline_breach_records
Invariant: submission_record is immutable after creation (set once on SUBMIT command)
Invariant: SubmitRegulatoryNotification requires regulatory:legal OR incident:ciso role
```

**`NotificationDraft` aggregate:**
```
Identity: DraftId (UUID)
Parent reference: notification_id
Lifecycle: DRAFT → REVISED → FINAL
Fields:
  draft_id, tenant_id, notification_id, version_number, content,
  authored_by, authored_at, approved_by, approved_at, status
Behavior: REVISED replaces prior draft version (creates new DraftId for each revision)
```

**`lessons_learned` context:**

**`LessonsLearned` aggregate:**
```
Identity: LessonsLearnedId (UUID)
Parent reference: incident_id (one per incident)
Lifecycle: IN_PROGRESS → REVIEWED → FINALIZED
Fields:
  ll_id, tenant_id, incident_id, lessons, action_items, status,
  reviewed_by, reviewed_at, finalized_by, finalized_at,
  campaign_retargeting_suggestion_ref
Behavior: finalize() publishes CampaignRetargetingSuggested if confirmed_technique_ids present
```

**`PostIncidentReport` aggregate:**
```
Identity: PostIncidentReportId (UUID)
Parent reference: lessons_learned_id
Lifecycle: GENERATING → COMPLETE → EXPORTED
Fields:
  report_id, tenant_id, incident_id, lessons_learned_id, format,
  artifact_ref, generated_at, exported_at, exported_to
```

### Frozen Value Objects (Complete)

**`incident` context:**
```
IncidentSeverity(Enum): P1_CRITICAL | P2_HIGH | P3_MEDIUM | P4_LOW
IncidentPhase(Enum): DECLARED | CLASSIFIED | CONTAINED | ERADICATED | RECOVERED | CLOSED
IncidentTriggerType(Enum): DETECTION_FINDING | INVESTIGATION_ESCALATION | MANUAL_DECLARATION | EXTERNAL_NOTIFICATION
SeverityClassificationMethod(Enum): AUTOMATED_FROM_FINDING | INVESTIGATION_CONCLUSION | MANUAL_DECLARATION | COMMANDER_OVERRIDE
ResolutionType(Enum): THREAT_CONTAINED | FALSE_POSITIVE | DUPLICATE | MERGED | ESCALATED_TO_EXTERNAL
ContainmentActionType(Enum): ALERT_ESCALATION | TRAFFIC_LOGGING | PROCESS_TERMINATION | SERVICE_SUSPENSION | CREDENTIAL_REVOKE | ACCOUNT_DISABLE | TRAFFIC_BLOCK | NETWORK_ISOLATION | MASS_CREDENTIAL_REVOKE | MANUAL
ContainmentActionStatus(Enum): PENDING_AUTH | AUTHORIZED | EXECUTING | COMPLETED | FAILED | ROLLED_BACK
ContainmentAuthorizationLevel(Enum): ANALYST | COMMANDER | CISO
EradicationVerificationStatus(Enum): PENDING | SUBMITTED | VERIFIED | DISPUTED
RecoveryMilestoneStatus(Enum): PENDING | IN_PROGRESS | COMPLETED | DEFERRED
TimelineEntryType(Enum): PHASE_TRANSITION | CONTAINMENT_AUTHORIZED | ERADICATION_SUBMITTED | ERADICATION_VERIFIED | RECOVERY_COMPLETED | SEVERITY_RECLASSIFIED | INVESTIGATION_LINKED | COMMUNICATION_LOGGED | INCIDENT_CLOSED

# ACL-translated references (M34-owned; no upstream types)
EscalatedFindingRef(VO): finding_id, severity, asset_ref, rule_id, detected_at, escalated_by
InvestigationRef(VO): investigation_id, concluded_at, conclusion
EvidenceRef(VO): evidence_chain_id, engagement_ref, sealed_at
ExposureScopeRef(VO): asset_ref_id, composite_score, assessed_at
```

**`regulatory_notification` context:**
```
RegulatoryRegime(Enum): GDPR_ART33 | GDPR_ART34 | HIPAA_BREACH | SEC_CYBER | NIS2_EARLY_WARNING | NIS2_NOTIFICATION | NY_DFS_500 | UK_GDPR | PIPEDA
NotificationStatus(Enum): CLOCK_STARTED | DRAFT_IN_PROGRESS | READY_FOR_SUBMISSION | SUBMITTED | ACKNOWLEDGED
DeadlineStatus(Enum): PENDING | APPROACHING | AT_RISK | BREACHED | MET
DraftStatus(Enum): DRAFT | REVISED | FINAL
NotificationDeadline(VO): deadline_at, deadline_hours, regime, clock_started_at
SubmissionRecord(VO, immutable): submitted_at, submitted_by, submission_method, reference_number  [set once]
DeadlineBreachRecord(VO, immutable): breach_detected_at, hours_overdue, notification_submitted_before_breach
RegulatorRef(VO): authority_name, jurisdiction, contact_endpoint
```

**`lessons_learned` context:**
```
LessonCategory(Enum): DETECTION_GAP | RESPONSE_PROCEDURE | COMMUNICATION | TOOL_LIMITATION | THREAT_INTELLIGENCE | PLAYBOOK_DEFICIENCY | CONFIGURATION | OTHER
ActionItemStatus(Enum): OPEN | IN_PROGRESS | COMPLETED | DEFERRED | CANCELLED
ActionItemPriority(Enum): P1_CRITICAL | P2_HIGH | P3_MEDIUM | P4_LOW
ReportFormat(Enum): PDF | HTML | JSON | MARKDOWN
LLStatus(Enum): IN_PROGRESS | REVIEWED | FINALIZED
PostIncidentReportStatus(Enum): GENERATING | COMPLETE | EXPORTED
```

### Frozen Repository Interfaces

All repository methods require `tenant_id` as the first positional argument.

```
IIncidentRepository
  find_by_id(tenant_id, incident_id) → Optional[Incident]
  find_active(tenant_id, *, phase_filter) → List[Incident]
  find_by_severity(tenant_id, severity) → List[Incident]
  find_classified_in_period(tenant_id, start, end) → List[Incident]
  save(tenant_id, incident) → None

IContainmentActionRepository
  find_by_id(tenant_id, action_id) → Optional[ContainmentAction]
  find_by_incident(tenant_id, incident_id) → List[ContainmentAction]
  save(tenant_id, action) → None

IEradicationVerificationRepository
  find_by_incident(tenant_id, incident_id) → Optional[EradicationVerification]
  save(tenant_id, verification) → None

IRecoveryMilestoneRepository
  find_by_incident(tenant_id, incident_id) → List[RecoveryMilestone]
  save(tenant_id, milestone) → None

IIncidentCommunicationLogRepository
  append(tenant_id, incident_id, entry) → None
  find_by_incident(tenant_id, incident_id, *, after, limit, offset) → List[IncidentCommunicationLogEntry]
  # No update(). No delete(). Immutability enforced at interface level.

IRegulatoryNotificationRepository
  find_by_id(tenant_id, notification_id) → Optional[RegulatoryNotification]
  find_by_incident(tenant_id, incident_id) → List[RegulatoryNotification]
  find_by_regime(tenant_id, incident_id, regime) → Optional[RegulatoryNotification]
  find_active_for_alerting(now) → List[RegulatoryNotification]  [cross-tenant; scheduler-only]
  save(tenant_id, notification) → None

INotificationDeadlineRepository
  find_active_deadlines(*, before_deadline) → List[NotificationDeadline]  [cross-tenant; scheduler-only]
  find_by_notification(tenant_id, notification_id) → List[NotificationDeadline]
  mark_alert_sent(deadline_id, threshold_hours, sent_at) → None
  record_breach(deadline_id, detected_at) → None
  cancel_deadline(deadline_id) → None

INotificationDraftRepository
  find_current_draft(tenant_id, notification_id) → Optional[NotificationDraft]
  find_all_drafts(tenant_id, notification_id) → List[NotificationDraft]
  save(tenant_id, draft) → None

ILessonsLearnedRepository
  find_by_id(tenant_id, ll_id) → Optional[LessonsLearned]
  find_by_incident(tenant_id, incident_id) → Optional[LessonsLearned]
  save(tenant_id, ll) → None

IPostIncidentReportRepository
  find_by_id(tenant_id, report_id) → Optional[PostIncidentReport]
  find_by_incident(tenant_id, incident_id) → List[PostIncidentReport]
  save(tenant_id, report) → None
```

### Frozen Outbound Ports (ACL)

**`incident` context ports:**
```
IDetectionFindingEventPort      → event subscription: DetectionFindingEscalated
IInvestigationEventPort         → event subscription: InvestigationConcluded [M21; optional]
IExposureContextPort            → event subscription: ExposureScoreComputed [M32; advisory]
ISecurityGraphWritePort         → write IncidentNode, ContainmentActionNode (append-only)
IITSMNotificationPort           → abstract: ticket creation (advisory; not record of truth)
ICommunicationNotificationPort  → abstract: Slack, Teams, email notification on phase transitions
IAnalyticsIncidentEventPort     → publishes IncidentClassified, IncidentClosed to analytics.incident_events
```

**`regulatory_notification` context ports:**
```
IIncidentEventPort              → event subscription: IncidentClassified (starts clock)
IDeadlineAlertNotificationPort  → abstract: notify regulatory:legal + incident:ciso on deadline approach/breach
```

**`lessons_learned` context ports:**
```
IIncidentEventPort              → event subscription: IncidentClosed (triggers LessonsLearned creation)
IEradicationEventPort           → event subscription: EradicationVerified (provides technique context)
ICampaignRetargetingEventBusPort → publishes CampaignRetargetingSuggested
IReportArtifactStorePort        → abstract: store PostIncidentReport artifact (PDF/HTML/JSON)
IPostIncidentReportDeliveryPort → abstract: deliver report to CISO/legal
```

### Frozen Events

**`incident` produces:**
```
IncidentDeclared(incident_id, tenant_id, trigger_type, severity, declared_at)
IncidentClassified(incident_id, tenant_id, severity, classified_at, classification_method, trigger_type, source_finding_ref, source_investigation_ref)
IncidentReclassified(incident_id, tenant_id, old_severity, new_severity, justification, reclassified_by, reclassified_at)
IncidentContained(incident_id, tenant_id, contained_at)
IncidentEradicated(incident_id, tenant_id, eradicated_at)
IncidentRecovered(incident_id, tenant_id, recovered_at)
IncidentClosed(incident_id, tenant_id, closed_at, resolution_type, classified_at, incident_duration_hours)
ContainmentActionPendingAuthorization(action_id, incident_id, tenant_id, action_type, authorization_level_required)
ContainmentActionAuthorized(action_id, incident_id, tenant_id, authorized_by, authorized_at, action_type)
ContainmentActionCompleted(action_id, incident_id, tenant_id, completed_at, evidence_ref)
ContainmentActionFailed(action_id, incident_id, tenant_id, failure_reason)
EradicationVerificationSubmitted(verification_id, incident_id, tenant_id, submitted_by, submitted_at)
EradicationVerificationVerified(verification_id, incident_id, tenant_id, verified_by, verified_at)
EradicationVerificationDisputed(verification_id, incident_id, tenant_id, dispute_reason)
RecoveryMilestoneCompleted(milestone_id, incident_id, tenant_id, completed_at)
```

**`regulatory_notification` produces:**
```
RegulatoryNotificationClockStarted(notification_id, incident_id, tenant_id, regime, deadline_at, clock_started_at)
RegulatoryDeadlineApproaching(notification_id, incident_id, tenant_id, regime, deadline_at, hours_remaining)
RegulatoryDeadlineBreached(notification_id, incident_id, tenant_id, regime, deadline_at, hours_overdue)
RegulatoryNotificationSubmitted(notification_id, incident_id, tenant_id, regime, submitted_by, submitted_at, reference_number)
RegulatoryNotificationAcknowledged(notification_id, tenant_id, acknowledged_by, acknowledged_at)
```

**`lessons_learned` produces:**
```
LessonsLearnedCreated(ll_id, incident_id, tenant_id, created_at)
LessonsLearnedFinalized(ll_id, incident_id, tenant_id, finalized_by, finalized_at)
CampaignRetargetingSuggested(ll_id, incident_id, tenant_id, confirmed_technique_ids, attack_vector_description, suggested_scenario_name, suggested_scope, evidence_refs, rationale, produced_at)
PostIncidentReportGenerated(report_id, ll_id, incident_id, tenant_id, format, generated_at)
PostIncidentReportExported(report_id, tenant_id, exported_to, exported_at)
```

### RBAC Roles (Canonical)

| Role | Capabilities |
|---|---|
| `incident:viewer` | Read incidents, read containment actions, read timeline |
| `incident:analyst` | `incident:viewer` + declare incident, log communications, submit eradication verification, manage recovery milestones, ANALYST-level containment authorization |
| `incident:commander` | `incident:analyst` + reclassify severity, COMMANDER-level containment authorization, verify eradication, close incident, finalize lessons learned |
| `incident:ciso` | `incident:commander` + CISO-level containment authorization, submit regulatory notifications, override closure requirements |
| `regulatory:officer` | Read regulatory notifications, manage notification drafts |
| `regulatory:legal` | `regulatory:officer` + submit regulatory notifications, acknowledge regulatory responses |
| `lessons_learned:contributor` | Create and update lessons learned, add action items |
| `lessons_learned:approver` | Approve and finalize lessons learned, generate post-incident reports |

---

## 3. ADRs (ADR-M34-001 through ADR-M34-006)

---

### ADR-M34-001 — Incident Is a Lifecycle Aggregate; M21 Investigation Is Referenced, Never Owned

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** M34's `incident` context is triggered by M21 investigation conclusions. The question is whether M34 should embed M21 investigation data into the `Incident` aggregate (simpler for analysts) or reference M21 investigations by ID only.

**Decision:** `Incident` holds an `InvestigationRef` value object containing only `investigation_id`, `concluded_at`, and `conclusion`. No M21 investigation data is embedded in M34. M34 analysts navigate to M21 via the `investigation_id` to see full investigation details.

**Consequences:**

Positive: Domain Purity (Platform Invariant 1) maintained. M34 does not import M21 types. M21 can evolve its data model without breaking M34. Bounded context separation is clear. Avoids the classic "super-aggregate" anti-pattern (Long-Term Architecture §4, Anti-Pattern 1).

Negative: Analysts viewing an incident must navigate between M34 (incident view) and M21 (investigation view) to see the full picture. Mitigated by: the UI layer can compose both views from separate API calls; a "combined incident context view" in the API aggregates both at the read layer without coupling the domain models.

**Rejected alternative:** Embed M21 investigation findings in `Incident` aggregate — violates Domain Purity; makes M34 a consumer of M21 data that changes at M21's cadence.

---

### ADR-M34-002 — CommunicationLog Is a Separate Append-Only Entity, Not Embedded in Incident

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** Stakeholder communication records during an incident must be immutable (legal requirement) and potentially numerous for long-running P1 incidents (hundreds of entries over weeks). The question is whether to embed communication entries in the `Incident` aggregate or manage them as a separate entity.

**Decision:** `IncidentCommunicationLogEntry` is a separate entity stored in `incident.communication_log_entries` with its own repository interface that exposes only `append()` and `find_by_incident()`. The `Incident` aggregate does not load communication log entries in its normal hydration path.

**Rationale:**
1. **Memory pressure:** A P1 incident with 500 communication log entries would require loading all 500 into memory every time the `Incident` aggregate is accessed for any purpose. Separate entity prevents this.
2. **Immutability enforced structurally:** The interface's absence of `update()` and `delete()` makes modification structurally impossible, not just conventionally discouraged.
3. **Audit separation:** Communication logs may need to be read by legal teams with different authorization from incident commanders. A separate repository enables separate access control.

**Consequences:**

Positive: No aggregate size explosion; immutability enforced at interface level; separate read authorization possible.

Negative: Communication entries are not accessible via the `Incident` aggregate directly. Mitigated by: the `IncidentApplicationService` provides a combined query that returns incident + communication summary in one API response.

---

### ADR-M34-003 — Regulatory Notification Submission Is Always Human-Commanded; Timers Are Alert-Only

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** Regulatory deadlines for GDPR, HIPAA, SEC, NIS2, and NY DFS have specific time windows. The question is whether the platform should auto-submit notifications when deadlines approach, to prevent human inaction from causing a missed deadline.

**Decision:** The platform NEVER auto-submits regulatory notifications. Timers produce alerts (`RegulatoryDeadlineApproaching`, `RegulatoryDeadlineBreached`). Submission requires an explicit `SubmitRegulatoryNotification` command from a human actor with `regulatory:legal` or `incident:ciso` role. This is enforced as a domain invariant, not a configuration option.

**Rationale:** Platform Invariant 6. Regulatory notifications are legal documents submitted to government authorities with the organization's name on them. An auto-submitted notification that mischaracterizes the incident, names the wrong organizational entity, or is submitted to the wrong authority creates a legal liability greater than any late-submission fine. Human review is required before submission. This is a regulatory compliance requirement across all major frameworks.

**Consequences:**

Positive: No risk of incorrect auto-submitted regulatory notifications. Full audit trail of who submitted what, when, and via what channel.

Negative: Human inaction can still cause a missed deadline. Mitigated by: increasingly urgent alerts at 48h, 24h, 12h, 6h, and 1h before deadline; breach detection and immediate critical alert; mandatory breach record in aggregate if deadline is missed.

**Rejected alternative:** Auto-submit after deadline approaches — creates legal liability; violates Platform Invariant 6; regulatory authorities may not accept auto-generated notifications without organizational sign-off.

---

### ADR-M34-004 — Durable PostgreSQL-Backed Deadline Timers; No In-Memory Timers for Regulatory Deadlines

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** Regulatory deadlines (GDPR 72h, etc.) must be tracked reliably across process restarts, deployments, and infrastructure events. The question is whether to use in-memory async timers or persistent database-backed scheduling.

**Decision:** All regulatory deadline tracking is persisted in `regulatory_notification.notification_deadlines` PostgreSQL table. On `DeadlineAlertingService.reconstitute_on_startup()`, the service loads all active deadlines from the database and reschedules any unfired alert thresholds. Deadlines that should have fired during downtime are evaluated immediately on startup.

**Consequences:**

Positive: Deadline tracking survives process restart, deployment, and even database failover (deadlines remain in the database after restore from backup). Legal liability from missed deadlines due to platform events is eliminated.

Negative: Startup reconstitution adds a few milliseconds to application startup time. Not a meaningful operational cost.

**Consistency with Sprint 28 Infrastructure:** This follows the `DurableScheduledTask` pattern established in Sprint 28's PostgreSQL DLQ and replay worker infrastructure. The platform already has the operational pattern; M34 applies it to regulatory deadline tracking.

---

### ADR-M34-005 — LessonsLearned Produces Advisory Events; Never Writes to M30 Directly

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** The `lessons_learned` context identifies confirmed attack techniques from eradication evidence and suggests those techniques as targets for new M30 campaign scenarios. The question is whether `lessons_learned` should write directly to M30 aggregates or produce an advisory event.

**Decision:** `LessonsLearned.finalize()` publishes a `CampaignRetargetingSuggested` event to the platform event bus. M30 may optionally subscribe to this event and create a `ScenarioTemplateDraft` for review. M34 has no visibility into whether M30 acted on the suggestion. No M30 type is imported in the `lessons_learned` module.

**Rationale:** Platform Invariant 7 (AI Suggestion Read-Only at Domain Boundaries) applies here even though this is not an AI-generated suggestion. The `lessons_learned` context is an analytical context producing advisory signals. The campaign context is an operational context that requires human review before creating new scenarios. The event bus is the correct boundary. Direct writes would create a deployment dependency: M34 would break if M30 changed its API.

**Rejection of alternatives:**
- Direct M30 repository write from `lessons_learned` — violates Invariant 1 (Domain Purity) and Invariant 7; creates circular architectural dependency
- M34 → M30 synchronous HTTP call — makes `lessons_learned` dependent on M30 availability at lesson finalization time; violates clean architecture boundaries

---

### ADR-M34-006 — Eradication Verification Requires Two-Role Attestation

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** The `EradicationVerification` aggregate asserts that the root cause of an incident has been eliminated. The question is whether a single person can both submit and verify this claim, or whether two-role attestation is required.

**Decision:** `EradicationVerification` requires two distinct actors: the submitter (`incident:analyst`) and the verifier (`incident:commander`). The domain invariant enforces `submitted_by ≠ verified_by`. Self-verification is rejected at the aggregate method level.

**Rationale:** Eradication is a high-stakes claim with legal and regulatory implications. In regulated industries (GDPR, HIPAA, PCI DSS), re-infection after claimed eradication is a material incident escalation. A single-person eradication claim has no internal check. The two-role model follows the same attestation pattern used in M29's evidence sealing (`SealerRoleRequired`) and M30's campaign approval. Consistency with platform patterns makes the governance model predictable.

**Consequences:**

Positive: Eradication claims are peer-reviewed; reduces risk of premature incident closure. Consistent with M29 governance patterns.

Negative: Requires two available authorized individuals during incident closure — may delay closure if the commander is unavailable. Mitigated by: `incident:ciso` can assume the verifier role if the commander is unavailable; explicit override with CISO justification is permitted.

---

## 4. Architecture Corrections

The following corrections apply to `M34_ARCHITECTURE_REVIEW.md` based on decisions C1–C7.

### Correction CC1 — IncidentCommunicationLog Scope Narrowed
The Review listed `IncidentCommunicationLog` as one of seven "Major Domain Concepts" from the roadmap without specifying its storage model. C2 now specifies: `IncidentCommunicationLogEntry` is a separate entity with its own repository, not part of the `Incident` aggregate. The repository interface has no `update()` or `delete()` methods. This replaces the under-specified roadmap description.

### Correction CC2 — IncidentTimeline Scope Clarified
The roadmap listed `IncidentTimeline` as a standalone domain concept. This review corrects: `IncidentTimeline` is an ordered list of `IncidentTimelineEntry` value objects embedded within the `Incident` aggregate. It is not a separate aggregate. Timeline entries are appended as phase transitions and key events occur. They are immutable after appending. This is the correct DDD model (the timeline is a child of the incident lifecycle, not an independent lifecycle).

### Correction CC3 — RegulatoryNotification Cardinality
The roadmap implied one notification per incident. C5 now corrects: one `RegulatoryNotification` aggregate per (incident_id, regime) pair. A global enterprise incident may create 5–7 `RegulatoryNotification` aggregates simultaneously (one per applicable regime). Each tracks its own deadline, draft, and submission independently.

### Correction CC4 — LessonsLearned as Named Module
The Review noted that `lessons_learned` is a supporting context but did not specify its module path. The frozen module path is `backend/src/lessons_learned/`. The M30/M28/M35 suggestion signal goes via the platform event bus to M30 (CampaignRetargetingSuggested), not to M28 or M35 — post-incident lessons primarily inform future campaign targeting, not retroactive rule changes.

---

## 5. Risk Dispositions (R01–R09)

### R01 — Regulatory Deadline Timer Reliability
**Original severity:** CRITICAL  
**Disposition:** MITIGATED  
**Resolution:** C5 specifies PostgreSQL-persisted deadline records with startup reconstitution. `DeadlineAlertingService.reconstitute_on_startup()` is called at every application boot. Deadlines that fired during downtime are evaluated immediately. ADR-M34-004 formalizes this as an architectural decision. No in-memory-only timers for regulatory deadlines.

### R02 — Incident Aggregate Gravity
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** C1 specifies that all upstream data is held as ACL-translated reference value objects (`EscalatedFindingRef`, `InvestigationRef`, `EvidenceRef`, `ExposureScopeRef`). No upstream domain types imported. ADR-M34-001 formalizes the investigation boundary. Architecture test in Phase 5 verifies no upstream type imports.

### R03 — Communication Log Immutability Enforcement by Convention
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** C2 specifies `IIncidentCommunicationLogRepository` interface has only `append()` and `find_by_incident()`. No `update()` or `delete()` method defined anywhere. ADR-M34-002 formalizes this. Architecture test verifies interface shape. Database-level `logged_at` is set by `DEFAULT now()` — the application cannot override it.

### R04 — MTTR Projection Table Schema Ownership
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** C4 specifies that migration `0102` (first M34 migration) creates `analytics.incident_events` in the M33-owned `analytics` schema. Event field schemas for `IncidentClassified` and `IncidentClosed` are frozen with explicit fields required for MTTR computation. Phase 1 exit criterion includes MTTR data appearing in `analytics.incident_events` in integration test.

### R05 — Multi-Jurisdiction Regulatory Complexity
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** C5 and the frozen `RegulatoryNotification` aggregate specify one aggregate per (incident_id, regime) pair. `RegulatoryDeadlineComputationService` creates all applicable regime records on `IncidentClassified`, based on tenant's configured jurisdiction set. Seven regimes defined. Tenant jurisdiction configuration stored in `regulatory_notification.tenant_jurisdiction_config` table.

### R06 — LessonsLearned Campaign Feedback Circular Architecture
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** C6 and ADR-M34-005 specify that `CampaignRetargetingSuggested` is published to the platform event bus. No M30 type imported in `lessons_learned`. Architecture test verifies no M30/scenario/taskgraph imports in `backend/src/lessons_learned/`. M30 subscription is optional; M34 does not verify whether M30 consumed the event.

### R07 — Post-Incident Report Format Proliferation
**Original severity:** LOW  
**Disposition:** MITIGATED  
**Resolution:** Four frozen formats: PDF, HTML, JSON, MARKDOWN. Additional formats require a milestone extension. `IReportArtifactStorePort` abstracts storage. `IPostIncidentReportDeliveryPort` abstracts delivery. No vendor-specific delivery implementations in M34 Phase 1–4; email and webhook added in Phase 5.

### R08 — Containment Action Authorization Level Under-Specification
**Original severity:** LOW  
**Disposition:** MITIGATED  
**Resolution:** C7 provides a frozen, domain-embedded authorization matrix mapping every `ContainmentActionType` to a minimum role. `ContainmentAuthorizationService.required_authorization_level()` implements this as a static lookup table in code, not a configuration table. Changing it requires code change and architectural review.

### R09 — Eradication Verification Evidence Model
**Original severity:** LOW  
**Disposition:** MITIGATED  
**Resolution:** `EradicationVerification` requires at least one `EradicationEvidenceRef`. Two-role attestation (analyst submits, commander verifies) established by ADR-M34-006. Domain invariant `submitted_by ≠ verified_by` enforced. CISO override with justification permitted for operational continuity.

---

## 6. Frozen Phase Plan

### Phase 1 — Incident Lifecycle Foundation + MTTR Pipeline Activation

**Scope:** `incident` bounded context core. `Incident` aggregate with full lifecycle (DECLARED → CLOSED). `IncidentTimeline` embedded entities (append-only). `ContainmentAction` aggregate with full authorization matrix. `IncidentSeverityClassificationService`. `IncidentLifecycleService`. `ContainmentAuthorizationService`. Security Graph integration (`IncidentNode`, `ContainmentActionNode`). `analytics.incident_events` table (migration `0102`) — M33 MTTR pipeline activation. `AnalyticsIncidentEventAdapter` (M33 projection ingestion of `IncidentClassified` and `IncidentClosed`).

**Bounded Contexts:** `incident`

**Aggregates:** `Incident`, `ContainmentAction`

**Domain Services:**
- `IncidentSeverityClassificationService`
- `IncidentLifecycleService` (enforces phase transition invariants)
- `ContainmentAuthorizationService` (applies static authorization matrix)

**API Commands:**
- `DeclareIncident(tenant_id, title, description, trigger_type, severity, source_refs)` — `incident:analyst`
- `ClassifyIncident(tenant_id, incident_id, severity, method)` — `incident:analyst`
- `ReclassifyIncident(tenant_id, incident_id, new_severity, justification)` — `incident:commander`
- `AuthorizeContainmentAction(tenant_id, incident_id, action_type, description)` — role per matrix
- `CompleteContainmentAction(tenant_id, action_id, evidence_ref, completion_notes)` — `incident:analyst`
- `FailContainmentAction(tenant_id, action_id, failure_reason)` — `incident:analyst`

**API Queries:**
- `GetIncident(tenant_id, incident_id)` — full incident + timeline
- `ListIncidents(tenant_id, *, phase_filter, severity_filter, date_range)` — paginated
- `GetIncidentTimeline(tenant_id, incident_id)` — ordered timeline entries
- `ListContainmentActions(tenant_id, incident_id)` — all actions for incident
- `GetActiveIncidentDashboard(tenant_id)` — current P1/P2 incidents with SLA status

**Migrations:** 0102–0104
- `0102_analytics_incident_events.sql` — `analytics.incident_events` (partitioned) + indexes for MTTR
- `0103_incident_core_tables.sql` — `incident` schema, `incidents`, `incident_timeline_entries`, `incident_tags`
- `0104_containment_actions.sql` — `containment_actions` table

**Workers:** None in Phase 1

**Key Tests:**
- Unit: Full incident lifecycle (DECLARED → CLOSED) with correct event sequence
- Unit: Phase transition enforcement (skip-to-CLOSED without eradication requires override)
- Unit: Severity mapping (M28 FindingSeverity → IncidentSeverity all cases)
- Unit: Reclassification requires commander role + justification ≥ 20 chars
- Unit: ContainmentAuthorizationService matrix (all 10 action types × role levels)
- Unit: Multi-tenancy (all repository methods require tenant_id; no cross-tenant)
- Integration: `DetectionFindingEscalated` event → `Incident` auto-declared (ACL adapter)
- Integration: `IncidentClassified` event → `analytics.incident_events` row inserted (MTTR pipeline)
- Integration: `IncidentClosed` event → `analytics.incident_events` row inserted; MTTR queryable
- Architecture: No upstream domain type (DetectionFinding, EvidenceChain, etc.) imported in `backend/src/incident/`

**Phase 1 Exit Criteria:**
- Complete incident lifecycle test end-to-end
- `analytics.incident_events` populated by integration test; MTTR KPI returns non-stub value
- ContainmentAuthorizationService rejects NETWORK_ISOLATION by `incident:analyst` (403)
- Cross-tenant: tenant A's incidents not visible to tenant B's queries
- Ruff check PASS; MyPy --strict PASS on incident BC files

---

### Phase 2 — Regulatory Notification + Durable Deadline Tracking

**Scope:** `regulatory_notification` bounded context. `RegulatoryNotification` aggregate (lifecycle + submission invariant). `NotificationDraft` aggregate. `RegulatoryDeadlineComputationService` (all 7 regimes). `DeadlineAlertingService` with durable PostgreSQL-backed timers. `DeadlineAlertingWorker` with startup reconstitution. Multi-jurisdiction support. Human-commanded submission enforcement. `IDeadlineAlertNotificationPort` (alert dispatch abstraction).

**Bounded Contexts:** `regulatory_notification`

**Aggregates:** `RegulatoryNotification`, `NotificationDraft`

**Domain Services:**
- `RegulatoryDeadlineComputationService` (7 regime × jurisdiction → deadline records)
- `DeadlineAlertingService` (timer scheduling + startup reconstitution)
- `JurisdictionMappingService` (tenant jurisdiction config → applicable regimes)

**API Commands:**
- `StartRegulatoryNotificationClock(tenant_id, incident_id, applicable_regimes)` — `incident:ciso` [typically auto-called on IncidentClassified]
- `CreateNotificationDraft(tenant_id, notification_id, content)` — `regulatory:officer`
- `ReviseNotificationDraft(tenant_id, notification_id, revised_content)` — `regulatory:officer`
- `FinalizeNotificationDraft(tenant_id, notification_id)` — `regulatory:legal`
- `SubmitRegulatoryNotification(tenant_id, notification_id, submitted_by, submission_method, reference_number)` — `regulatory:legal` or `incident:ciso`
- `AcknowledgeRegulatoryResponse(tenant_id, notification_id, acknowledged_by)` — `regulatory:legal`
- `ConfigureTenantJurisdictions(tenant_id, jurisdiction_set)` — `incident:ciso`

**API Queries:**
- `GetRegulatoryNotification(tenant_id, notification_id)`
- `ListRegulatoryNotifications(tenant_id, incident_id)` — all regimes for an incident
- `GetRegulatoryDeadlineDashboard(tenant_id)` — all active deadlines with status + time remaining
- `GetNotificationDraftHistory(tenant_id, notification_id)` — all draft versions

**Migrations:** 0105–0107
- `0105_regulatory_notification_schema.sql` — `regulatory_notification` schema creation
- `0106_regulatory_notifications_and_drafts.sql` — `regulatory_notifications`, `notification_drafts`, `tenant_jurisdiction_config`
- `0107_notification_deadlines.sql` — `notification_deadlines` table (durable timer state) + indexes

**Workers:** `DeadlineAlertingWorker` (background; startup reconstitution)

**Key Tests:**
- Unit: GDPR Art.33 deadline computation (72h from classified_at, UTC)
- Unit: NIS2 early warning (24h) + notification (72h) created as two separate RegulatoryNotification records
- Unit: SubmissionRecord is immutable after creation (attempt to modify → domain error)
- Unit: SubmitRegulatoryNotification rejected if not regulatory:legal or incident:ciso role (403)
- Unit: Auto-submission prohibited — timer does NOT call any submission method
- Unit: Multi-regime creation (incident with GDPR + HIPAA → 2 separate notification aggregates)
- Integration: `IncidentClassified` event → all applicable regime `RegulatoryNotification` aggregates created
- Integration: DeadlineAlertingWorker startup reconstitution (simulate process restart; verify alert still fires)
- Integration: `RegulatoryDeadlineApproaching` event published at 24h threshold
- Integration: Deadline breach recorded if not submitted by deadline
- Integration: Manual submission produces immutable `SubmissionRecord`; status → SUBMITTED
- Security: Submission attempt by incident:analyst → rejected; regulatory:legal → accepted

**Phase 2 Exit Criteria:**
- GDPR 72h deadline tracked, alerted at 48h/24h/12h/6h/1h, breach detected if not submitted
- Startup reconstitution: simulate restart mid-countdown; verify correct alert scheduling on re-up
- Multi-jurisdiction: incident triggers GDPR + HIPAA + SEC notifications simultaneously
- Human-submission-only: no code path exists that calls `submit()` without an explicit human command
- Ruff check PASS; MyPy --strict PASS on regulatory_notification BC files

---

### Phase 3 — Eradication, Recovery, Communication Log, Incident Closure

**Scope:** `EradicationVerification` aggregate (two-role attestation). `RecoveryMilestone` aggregate. `IncidentCommunicationLogEntry` entity with append-only repository. Incident closure invariant (requires VERIFIED eradication or explicit override). `ICommunicationNotificationPort` (Slack/Teams/email adapters for phase transition notifications). `IITSMNotificationPort` (abstract; no vendor implementations in M34 Phase 3).

**Bounded Contexts:** `incident` (extended)

**New Aggregates:** `EradicationVerification`, `RecoveryMilestone`

**New Entity:** `IncidentCommunicationLogEntry` (separate storage; append-only repository)

**New Ports:** `ICommunicationNotificationPort`, `IITSMNotificationPort`

**API Commands:**
- `SubmitEradicationVerification(tenant_id, incident_id, assertion, evidence_refs, submitted_by)` — `incident:analyst`
- `VerifyEradication(tenant_id, verification_id, verified_by)` — `incident:commander` (submitted_by ≠ verified_by enforced)
- `DisputeEradication(tenant_id, verification_id, dispute_reason)` — `incident:commander`
- `CloseIncident(tenant_id, incident_id, resolution_type, notes)` — `incident:commander`
- `ForceCloseIncident(tenant_id, incident_id, justification)` — `incident:ciso` [overrides eradication requirement]
- `AddRecoveryMilestone(tenant_id, incident_id, title, description, owner, target_date)` — `incident:analyst`
- `CompleteRecoveryMilestone(tenant_id, milestone_id, completion_notes)` — `incident:analyst`
- `LogCommunication(tenant_id, incident_id, content, communication_type, recipient_summary)` — `incident:analyst`

**API Queries:**
- `GetEradicationVerification(tenant_id, incident_id)` — current verification status
- `ListRecoveryMilestones(tenant_id, incident_id)` — all milestones + status
- `GetCommunicationLog(tenant_id, incident_id, *, after, limit, offset)` — paginated; chronological
- `GetIncidentClosureSummary(tenant_id, incident_id)` — full lifecycle summary for reporting

**Migrations:** 0108–0110
- `0108_eradication_verification.sql` — `eradication_verifications` table
- `0109_recovery_milestones.sql` — `recovery_milestones` table
- `0110_communication_log.sql` — `incident_communication_log_entries` table (append-only; no UPDATE/DELETE grants to application role)

**Key Tests:**
- Unit: EradicationVerification two-role invariant (submitted_by = verified_by → domain error)
- Unit: Incident closure blocked without VERIFIED eradication (unless FALSE_POSITIVE/DUPLICATE)
- Unit: CISO force-close permitted with justification (records override in timeline)
- Unit: IIncidentCommunicationLogRepository has no update() or delete() methods (interface test)
- Unit: LoggedAt set by system; caller cannot specify logged_at (domain enforces this)
- Unit: RecoveryMilestone DEFERRED requires reason
- Integration: Full incident lifecycle: declare → classify → contain → eradicate (two-role) → recover → close
- Integration: Communication log append round-trip; paginated retrieval; chronological order
- Architecture: `IIncidentCommunicationLogRepository` method count = 2 (append + find_by_incident)
- Security: Communication log read requires incident:viewer minimum (403 for unauthenticated)
- Database: Verify no UPDATE or DELETE privilege granted to application DB role on communication_log_entries table

**Phase 3 Exit Criteria:**
- End-to-end full incident lifecycle (declare → close) passes including eradication two-role attestation
- Communication log immutability verified at interface and database grant levels
- Incident closure blocked without eradication (unless override with CISO justification)
- Ruff check PASS; MyPy --strict PASS

---

### Phase 4 — Lessons Learned and Post-Incident Reports

**Scope:** `lessons_learned` bounded context. `LessonsLearned` aggregate with structured capture (lesson categories, action items). `PostIncidentReport` aggregate with four-format generation (PDF, HTML, JSON, MARKDOWN). `PostIncidentReportGenerationService` (compiles from `LessonsLearned` + `IncidentTimeline` read model). `CampaignRetargetingAdvisoryService` (publishes `CampaignRetargetingSuggested` advisory event). `IReportArtifactStorePort` (abstract). `IPostIncidentReportDeliveryPort` (abstract; email and webhook in Phase 5).

**Bounded Contexts:** `lessons_learned`

**Aggregates:** `LessonsLearned`, `PostIncidentReport`

**Domain Services:**
- `PostIncidentReportGenerationService` (template-driven; four formats)
- `CampaignRetargetingAdvisoryService` (technique extraction + event publishing)

**API Commands:**
- `CreateLessonsLearned(tenant_id, incident_id)` — `lessons_learned:contributor` [auto-created on IncidentClosed]
- `AddLesson(tenant_id, ll_id, category, description, impact_summary)` — `lessons_learned:contributor`
- `AddActionItem(tenant_id, ll_id, title, description, owner, priority, due_date)` — `lessons_learned:contributor`
- `UpdateActionItemStatus(tenant_id, action_item_id, status, notes)` — `lessons_learned:contributor`
- `ReviewLessonsLearned(tenant_id, ll_id, reviewed_by)` — `lessons_learned:approver`
- `FinalizeLessonsLearned(tenant_id, ll_id, finalized_by)` — `lessons_learned:approver`
- `GeneratePostIncidentReport(tenant_id, ll_id, format)` — `lessons_learned:approver`
- `ExportPostIncidentReport(tenant_id, report_id, destination)` — `lessons_learned:approver`

**API Queries:**
- `GetLessonsLearned(tenant_id, incident_id)` — full lessons learned record
- `GetPostIncidentReport(tenant_id, report_id)` — report metadata + artifact download link
- `ListPostIncidentReports(tenant_id, *, date_range)` — paginated

**Migrations:** 0111–0112
- `0111_lessons_learned_tables.sql` — `lessons_learned` schema, `lessons_learned_records`, `lesson_items`, `action_items`
- `0112_post_incident_reports.sql` — `post_incident_reports` table

**Workers:** None (report generation is synchronous; large reports are background tasks via platform worker)

**Key Tests:**
- Unit: `LessonsLearned.finalize()` → `CampaignRetargetingSuggested` event produced if confirmed_technique_ids present
- Unit: `CampaignRetargetingSuggested` not published if no confirmed techniques (graceful empty path)
- Unit: `PostIncidentReportGenerationService` produces all four formats from same input
- Unit: Auto-creation of `LessonsLearned` on `IncidentClosed` event
- Integration: Full lessons learned lifecycle (create → add lessons → add action items → review → finalize → report)
- Integration: `CampaignRetargetingSuggested` event on bus after finalization
- Architecture: No import from `campaign`, `scenario`, `taskgraph`, or `ml_pipeline` in `backend/src/lessons_learned/`
- Architecture: No import from `detection`, `engagement`, `execution`, `evidence` in lessons_learned (all cross-context refs are value object IDs only)
- Report: PDF generation produces a parseable PDF artifact; JSON matches frozen schema

**Phase 4 Exit Criteria:**
- Full `lessons_learned` lifecycle end-to-end including post-incident report in all 4 formats
- `CampaignRetargetingSuggested` event published with correct technique IDs from eradication evidence
- No M30 imports in lessons_learned module (architecture test passes)
- Report generation < 30 seconds for typical incident (< 500 timeline entries)

---

### Phase 5 — Security Graph Completion, RBAC Hardening, MTTR Validation

**Scope:** Full Security Graph wiring (all M34 node types and edge types). Complete RBAC enforcement across all three M34 contexts. `IPostIncidentReportDeliveryPort` implementations (email, webhook). `IITSMNotificationPort` implementations (ServiceNow stub, Jira stub — not production integrations; abstract adapters only). MTTR KPI end-to-end integration test (from `IncidentClassified` through `analytics.incident_events` to `KPIComputationService` returning MTTR value). Complete M34 test suite hardening. Cross-tenant security audit.

**Migrations:** 0113
- `0113_incident_operational_metrics.sql` — operational metrics tables (phase transition timing, regulatory deadline health, lessons quality score)

**Workers:** Final wiring of `DeadlineAlertingWorker` startup reconstitution in `RuntimeContainer`.

**Key Tests:**
- Unit: All RBAC roles enforce correct command access (viewer cannot declare; analyst cannot submit regulatory notification; etc.)
- Unit: Security Graph `IncidentNode` writes only edges from incident-owned nodes (no edge written to M28 FindingNode)
- Integration: MTTR KPI full pipeline (IncidentClassified → analytics.incident_events → KPIComputationService → ACTIVE status with value)
- Integration: M33 `KPIStatus.REQUIRES_M34_DATA` transitions to `ACTIVE` after first incident events in analytics schema
- Integration: Post-incident report delivery (email adapter, webhook adapter)
- Security: Cross-tenant isolation — 50 concurrent sessions from different tenants; no cross-tenant incident data visible
- Security: CommunicationLog — authenticated as incident:ciso for tenant A cannot read tenant B's log
- Architecture: All three M34 contexts have zero imports from each other's domain types (inter-M34-context isolation)
- Architecture: `incident` context has zero imports from M21, M28, M29, M32, M33 domain types
- Performance: `GetActiveIncidentDashboard` query < 100ms for tenant with 100 active incidents
- Regression: All M33 tests still pass (no M33 behavior changed by M34's `analytics.incident_events` addition)

**Phase 5 Exit Criteria:**
- All Phase 1–5 tests passing
- Ruff check PASS; Ruff format --check PASS; MyPy --strict PASS on all three M34 BC files
- MTTR KPI transitions from `REQUIRES_M34_DATA` to computed value in M33 integration test
- Security Graph traversal: incident → affected asset nodes → correct results
- Cross-tenant isolation verified across all three contexts
- Regulatory deadline reconstitution verified (process restart mid-countdown test)
- M34 Final Repository Validation Report produced

---

## 7. Implementation Readiness

### Boundary Verification

| Context | Module Path | Aggregate Roots | Core Services |
|---|---|---|---|
| `incident` | `backend/src/incident/` | Incident, ContainmentAction, EradicationVerification, RecoveryMilestone | IncidentSeverityClassificationService, IncidentLifecycleService, ContainmentAuthorizationService |
| `regulatory_notification` | `backend/src/regulatory_notification/` | RegulatoryNotification, NotificationDraft | RegulatoryDeadlineComputationService, DeadlineAlertingService, JurisdictionMappingService |
| `lessons_learned` | `backend/src/lessons_learned/` | LessonsLearned, PostIncidentReport | PostIncidentReportGenerationService, CampaignRetargetingAdvisoryService |

### Migration Sequence

| Migration | Description | Alembic Chain |
|---|---|---|
| 0102 | `analytics.incident_events` — MTTR pipeline (M33 schema extension) | 0101 → 0102 |
| 0103 | `incident` schema, incidents, incident_timeline_entries, tags | 0102 → 0103 |
| 0104 | containment_actions | 0103 → 0104 |
| 0105 | `regulatory_notification` schema | 0104 → 0105 |
| 0106 | regulatory_notifications, notification_drafts, tenant_jurisdiction_config | 0105 → 0106 |
| 0107 | notification_deadlines (durable timer state) | 0106 → 0107 |
| 0108 | eradication_verifications | 0107 → 0108 |
| 0109 | recovery_milestones | 0108 → 0109 |
| 0110 | incident_communication_log_entries (append-only; application role has no UPDATE/DELETE) | 0109 → 0110 |
| 0111 | `lessons_learned` schema, lessons_learned_records, lesson_items, action_items | 0110 → 0111 |
| 0112 | post_incident_reports | 0111 → 0112 |
| 0113 | incident_operational_metrics | 0112 → 0113 |

Current head: `0101`. M34 migrations: `0102`–`0113` (12 migrations across 5 phases). Single Alembic head throughout.

### Platform Invariant Compliance

| Invariant | M34 Compliance |
|---|---|
| Invariant 1: Domain Purity | All upstream context data held as M34-owned reference value objects (EscalatedFindingRef, InvestigationRef, EvidenceRef, ExposureScopeRef). No upstream domain types imported. Verified by architecture test in Phase 1 and Phase 5. |
| Invariant 2: Multi-Tenancy Non-Negotiable | All repository methods require tenant_id. Cross-tenant queries permitted only in scheduler-only methods (DeadlineAlertingService.find_active_deadlines) with explicit supervisor-only access control. |
| Invariant 3: Security Graph Append-Only | IncidentNode and ContainmentActionNode are deactivated (is_active = false) on incident close, never deleted. Physical deletion is compliance engineering only. |
| Invariant 4: Evidence and Journals Immutable | IncidentCommunicationLogEntry: interface has no update/delete; database grants exclude UPDATE/DELETE for application role. IncidentTimelineEntry: embedded append-only value object list in Incident aggregate. SubmissionRecord: value object set once in RegulatoryNotification; no mutation path. |
| Invariant 5: Kill Switch Is Domain Invariant | M34 does not introduce automated infrastructure actions (that is M35). ContainmentActions are authorized human actions tracked by the platform; they are not automated executions. Kill switch does not apply to in-flight human-authorized containment actions (stopping an active incident response because a kill switch fired would worsen the incident). |
| Invariant 6: Human Approval Gates | Two gates: (1) RegulatoryNotification submission requires human SubmitRegulatoryNotification command — no auto-submit; (2) ContainmentAction authorization requires human command per role matrix. Both enforced at domain service layer, not configurable. |
| Invariant 7: AI Suggestion Read-Only | LessonsLearned publishes CampaignRetargetingSuggested event — advisory only. No direct M30 write. M34 has no AI components; this invariant applies to the campaign retargeting pathway which is analogous. |

### Pre-Implementation Checklist

Before Phase 1 begins, verify:

- [ ] Current Alembic head confirmed as `0101` (`alembic current` in `/backend/`)
- [ ] `backend/src/incident/` module namespace does not conflict with any existing module
- [ ] `backend/src/regulatory_notification/` module namespace does not conflict
- [ ] `backend/src/lessons_learned/` module namespace does not conflict
- [ ] `analytics.incident_events` partition strategy consistent with M33's partition pattern (HASH 8 partitions for this smaller table)
- [ ] Platform `DurableScheduledTask` infrastructure from Sprint 28 is available for `DeadlineAlertingWorker`
- [ ] M33 `AnalyticsProjectionWorker` event routing configuration extensible (can add `incident_classified`, `incident_closed` event types without code change — config-driven routing)
- [ ] `ISecurityGraphWritePort` available from `redforge` platform infrastructure (used by M32, M33)
- [ ] `ICommunicationNotificationPort` distinct from M29/M30 notification ports (M34 creates its own port abstraction)
- [ ] Evidence context (`evidence` BC) EvidenceChain reference model reviewed — M34 references evidence chains by ID only

### Outstanding Items (Post-M34)

| Item | Priority | Notes |
|---|---|---|
| ServiceNow production adapter (IITSMNotificationPort) | Medium | Stub defined in M34; production adapter is post-M34 |
| Jira production adapter (IITSMNotificationPort) | Medium | Same as above |
| M35 authorization model pre-design | HIGH | Strategic Dependencies §9 Finding 2: M35 authorization must be designed during M34. PostIncidentReport → M35 playbook synthesis pathway requires M35 `PlaybookAuthorization` design to be settled before M35 Phase 1 begins |
| MTTR trend visualization in M33 reporting | Low | M33 KPI activated; dashboard integration is M33 reporting configuration, not M34 work |
| LessonsLearned → M36 playbook synthesis signal | — | M36 will subscribe to `CampaignRetargetingSuggested` and potentially `LessonsLearnedFinalized` for AI playbook synthesis; no M34 code change required |

### Critical Pre-M35 Work (Flagged per Strategic Dependencies Finding 2)

The Strategic Dependencies document (§9, Finding 2) explicitly states: *"During M34, include an architecture review session specifically for M35 authorization design. The M35 `PlaybookAuthorization` aggregate and `AutomationAuthorizationService` should be architecturally defined before M35 implementation begins."*

This M34 Architecture Finalization confirms this finding. Before M35 Phase 1 begins, the following must be architecturally defined:
1. `PlaybookAuthorization` aggregate: what constitutes an authorized defensive automation action
2. `AutomationAuthorizationService`: the authorization enforcement service equivalent to M29's `ExecutionAuthorizationService`
3. M35 kill switch: the defensive automation kill switch equivalent to M29's `KillSwitchState` aggregate
4. Rollback authorization: who can authorize a rollback, and what evidence is required

These design decisions should be captured in `M35_PRE_DESIGN_NOTES.md` before M34 Phase 3 begins, not after M34 closes.

---

M34 Architecture Freeze Complete.

**Architecture status:** FROZEN FOR IMPLEMENTATION  
**Bounded contexts:** `incident`, `regulatory_notification`, `lessons_learned`  
**Module paths:** `backend/src/incident/`, `backend/src/regulatory_notification/`, `backend/src/lessons_learned/`  
**Migrations:** 0102–0113 (12 migrations across 5 phases)  
**ADRs:** ADR-M34-001 through ADR-M34-006 (complete)  
**Risks:** R01–R09 all dispositioned (R01–R04 Mitigated as CRITICAL/HIGH; R05–R09 Mitigated)  
**Conditions:** C1–C7 all resolved  
**Implementation phases:** 5 phases frozen with scope, aggregates, services, events, migrations, tests, exit criteria  
**Pending:** Implementation authorization required before Phase 1 begins

STOP. Do NOT implement code. Do NOT create migrations. Do NOT modify repository.
