# M34 Architecture Review
## Enterprise Incident Response Platform

**Status:** REVIEW — PENDING APPROVAL  
**Date:** 2026-07-21  
**Reviewer:** Architecture Review Process  
**Precondition:** M33 RELEASED (2026-07-21) — commit `4a3e7edac28276f1602dc40b1f30bcb0629095ba`  
**Constraint:** Documentation only. No code, no migrations, no repository modifications.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Assessment](#2-architecture-assessment)
3. [Bounded Context Review](#3-bounded-context-review)
4. [Integration Review](#4-integration-review)
5. [Risk Assessment](#5-risk-assessment)
6. [Conditions for Implementation Approval](#6-conditions-for-implementation-approval)
7. [Implementation Phase Plan](#7-implementation-phase-plan)
8. [Architecture Verdict](#8-architecture-verdict)

---

## 1. Executive Summary

M34 is the **Enterprise Incident Response Platform**. Its mission is to transform the detection-to-resolution lifecycle from a manual, tool-hopping exercise into a governed, auditable, platform-native discipline — with legally defensible evidence, regulatory deadline tracking, and closed-loop signal feedback to improve future detection and campaign coverage.

M34 introduces three bounded contexts:

| Context | Role | Classification |
|---|---|---|
| `incident` | Incident lifecycle, severity, containment authorization, eradication verification | Core Domain |
| `regulatory_notification` | Notification obligation deadlines, drafts, submission records | Supporting Domain |
| `lessons_learned` | Post-incident structured capture, platform signal feedback | Supporting Domain |

**Module paths following M26–M33 convention:**
- `backend/src/incident/`
- `backend/src/regulatory_notification/`
- `backend/src/lessons_learned/`

**Migration sequence:** Current head `0101` → M34 starts at `0102`.

**Key observations from this review:**

1. The three-context design correctly separates incident lifecycle (operational), regulatory compliance (legal/time-bound), and lessons capture (strategic feedback). The boundary logic is sound.
2. The `incident` context boundary relative to M21 Investigation is the most critical design risk. Incident must reference M21 investigations, never own their data. Aggregate gravity toward a "super-context" that absorbs M21, M28, and M29 data must be architecturally prevented.
3. `IncidentCommunicationLog` must be an append-only, separately-stored entity (not an embedded list in the Incident aggregate) to prevent memory pressure on long-running incidents and enforce immutability at the repository layer.
4. Regulatory notification submission is a human-commanded operation per Platform Invariant 6. Deadline timers notify; they never auto-submit. This must be frozen as an immutable architectural constraint.
5. Regulatory deadline timers must use the platform's durable scheduler infrastructure, not in-memory async timers. An in-process timer is destroyed when the process restarts; a missed GDPR notification is a legal liability.
6. The `LessonsLearned` context's campaign re-targeting signal must be modeled as an advisory event on the platform event bus, not as a direct write to M30 campaign aggregates. Platform Invariant 7 applies.
7. The MTTR KPI in M33 currently returns `KPIStatus.REQUIRES_M34_DATA`. When M34's `IncidentClassified` and `IncidentResolved` events are published, the M33 `AnalyticsProjectionWorker` must ingest them into `analytics.incident_events`. The MTTR computation then activates automatically without any M33 code change.
8. A single incident may be subject to multiple regulatory regimes simultaneously (GDPR + HIPAA + SEC). The `regulatory_notification` context must model one `RegulatoryNotification` aggregate per applicable regulation per incident.

**Conditions for implementation approval:** Seven conditions (C1–C7) are identified below. All must be resolved in the Architecture Finalization document before Phase 1 begins.

---

## 2. Architecture Assessment

### 2.1 Domain-Driven Design Assessment

**Context Isolation:** The three M34 contexts are internally coherent and correctly separated by concern:
- `incident` = lifecycle ownership (what is happening, who is responding, what has been done)
- `regulatory_notification` = time-bound legal obligations (what must be reported, to whom, by when)
- `lessons_learned` = retrospective intelligence (what can be improved, what signals should be fed back)

These are three genuinely distinct subdomains with different lifecycle lengths, different stakeholders, and different change rates. The separation is correct.

**Domain Purity (Platform Invariant 1):**  
M34 has the most complex integration web of any milestone so far. `incident` must consume events from M28 (detection), M21 (investigation), M29 (evidence), M32 (exposure), and M33 (analytics). The risk of importing upstream types directly is higher here than in any prior milestone.

Resolution: All upstream data is accessed via ACL ports only. The `incident` context does not import `DetectionFinding`, `InvestigationFinding`, `EvidenceChain`, or any other upstream type. It consumes events from the platform event bus and translates them at ACL boundaries. When a `DetectionFindingEscalated` event arrives, M34's ACL adapter translates it into an `EscalatedFindingRef` value object (owned by M34) before it touches any M34 aggregate.

**Multi-Tenancy (Platform Invariant 2):**  
Incident records aggregate information about active attacks on a tenant's infrastructure. Cross-tenant leakage of incident data is catastrophically sensitive. All three M34 contexts enforce `TenantId` as a non-nullable first argument on all repository methods.

**Evidence Immutability (Platform Invariant 4 — Extension):**  
`IncidentCommunicationLog` entries must be append-only with tamper detection. This follows the same philosophy as M29's `ExecutionJournal`. Log entries are created once and never modified. The `IIncidentCommunicationLogRepository` defines only `append()` and `find_by_incident()` — no update or delete operations.

**Kill Switch Extension (Platform Invariant 5):**  
M34 does not introduce new automated execution against infrastructure (that is M35). However, `ContainmentAction` records that authorize manual containment steps must track their authorization status. If a kill switch event fires during an active incident, in-progress containment authorizations are not cancelled (an active incident is never stopped by a kill switch — that would worsen the incident). This distinction must be explicit in the authorization model.

**Human Approval Gates (Platform Invariant 6):**  
Two human approval gates in M34:
1. `RegulatoryNotification` submission — no timer fires a submission; only an explicit `SubmitRegulatoryNotification` command issued by an authorized actor submits.
2. `ContainmentAction` authorization — a containment action at CRITICAL severity requires `incident:commander` role authorization before it is logged as authorized.

**AI Suggestion Boundary (Platform Invariant 7):**  
`LessonsLearned.suggest_campaign_retarget()` produces a `CampaignRetargetingSuggested` event on the platform event bus. M30 consumes this event as advisory input. M34 does not write directly to any M30 aggregate. This is the correct boundary.

### 2.2 Incident Lifecycle Model

The M34 incident lifecycle follows PICERL (Preparation / Identification / Containment / Eradication / Recovery / Lessons Learned), which is the industry-standard IR framework. The phases map to M34's domain model as follows:

| PICERL Phase | M34 Domain Concept | Trigger |
|---|---|---|
| Preparation | (Covered by M35 playbooks and M30 campaign scenarios; not M34) | — |
| Identification | `Incident` declared; `IncidentClassified` event | `DetectionFindingEscalated` or manual declaration |
| Containment | `ContainmentAction` authorized and executed | `incident:commander` command |
| Eradication | `EradicationVerification` evidence submitted | `incident:analyst` command + evidence reference |
| Recovery | `RecoveryMilestone` tracked | `incident:analyst` command |
| Lessons Learned | `LessonsLearned` structured capture; `PostIncidentReport` generated | Manual after incident closure |

### 2.3 MTTR Integration with M33

The M33 codebase contains the following stub:

```python
# analytics/domain/services/kpi_computation_service.py
return KPIComputationResult(KPIType.MTTR, None, "hours", KPIStatus.REQUIRES_M34_DATA)

# analytics/domain/value_objects/enums.py
class KPIStatus(StrEnum):
    REQUIRES_M34_DATA = "RequiresM34Data"
```

The activation pathway when M34 is released:

```
M34 publishes:  IncidentClassified(incident_id, tenant_id, classified_at, severity, source_finding_ref)
M34 publishes:  IncidentClosed(incident_id, tenant_id, closed_at, resolution_type)

M33 AnalyticsProjectionWorker ingests → analytics.incident_events table

KPIComputationService.compute_mttr():
  SELECT AVG(EXTRACT(EPOCH FROM (closed_at - classified_at))) / 3600.0 AS mttr_hours
  FROM analytics.incident_events i_closed
  JOIN analytics.incident_events i_open ON i_closed.incident_id = i_open.incident_id
  WHERE i_closed.event_type = 'incident_closed'
    AND i_open.event_type = 'incident_classified'
    AND i_closed.tenant_id = :tenant_id
    AND i_closed.closed_at >= :period_start
  -- Minimum 3 incidents for statistical validity; otherwise INSUFFICIENT_DATA
```

No M33 code change is required. The M33 `AnalyticsProjectionWorker` receives the new event types and adds a row to `analytics.incident_events`. The `KPIComputationService` detects the presence of incident data and computes MTTR automatically on the next daily run.

The `analytics.incident_events` table must be created in M34 migration `0102` as part of the M33 analytics schema extension. This is M34's responsibility — extending the `analytics` schema that M33 owns.

### 2.4 Security Graph Extensions

Per the Capability Matrix, M34 introduces:
- `IncidentNode` (linked to `DetectionFindingNode`, `AssetNode`)
- `ContainmentActionNode` (linked to `IncidentNode`)
- Edges: `CONTAINED_BY`, `ERADICATED_VIA`, `INCIDENT_AFFECTED`, `LESSON_LEARNED_FROM`

Ownership rules (per REDFORGE_LONG_TERM_ARCHITECTURE.md, Section 8 cross-milestone risk mitigation):
- The `incident` context writes `IncidentNode` and `ContainmentActionNode` to the Security Graph via `ISecurityGraphWritePort`
- The `incident` context does NOT write edges to M28's `DetectionFindingNode` (those nodes are M28's; M28 owns the edges from its nodes)
- Instead, the `incident` context writes: `IncidentNode -[TRIGGERED_BY]→ {finding_ref}` from its own node only
- This follows the rule: "edges from a node are written by the owning context of the source node"

---

## 3. Bounded Context Review

### 3.1 `incident` — Core Domain

**Aggregate Roots:**

| Aggregate | Identity | Lifecycle |
|---|---|---|
| `Incident` | `IncidentId` (UUID) | DECLARED → CLASSIFIED → CONTAINED → ERADICATED → RECOVERED → CLOSED |
| `ContainmentAction` | `ContainmentActionId` (UUID) | PENDING_AUTH → AUTHORIZED → EXECUTING → COMPLETED / FAILED |
| `EradicationVerification` | `EradicationVerificationId` (UUID) | PENDING → SUBMITTED → VERIFIED / DISPUTED |
| `RecoveryMilestone` | `RecoveryMilestoneId` (UUID) | PENDING → IN_PROGRESS → COMPLETED |

**Value Objects:**
```
IncidentSeverity(Enum): P1_CRITICAL | P2_HIGH | P3_MEDIUM | P4_LOW
IncidentPhase(Enum): DECLARED | CLASSIFIED | CONTAINED | ERADICATED | RECOVERED | CLOSED
IncidentTriggerType(Enum): DETECTION_FINDING | INVESTIGATION_ESCALATION | MANUAL_DECLARATION | EXTERNAL_NOTIFICATION
SeverityClassificationMethod(Enum): AUTOMATED_FROM_FINDING | COMMANDER_OVERRIDE | MANUAL_DECLARATION
EscalatedFindingRef(VO): finding_id, tenant_id, severity, detected_at, rule_id  [M34-owned translation of M28 data]
InvestigationRef(VO): investigation_id, tenant_id, confirmed_at  [M34-owned translation of M21 data]
EvidenceRef(VO): evidence_chain_id, engagement_ref  [M34-owned reference to M29 evidence]
ContainmentActionType(Enum): NETWORK_ISOLATION | CREDENTIAL_REVOKE | PROCESS_TERMINATION | ACCOUNT_DISABLE | TRAFFIC_BLOCK | MANUAL
ContainmentAuthorizationLevel(Enum): ANALYST | COMMANDER | CISO
EradicationEvidenceRef(VO): artifact_id, evidence_type, submitted_at
ResolutionType(Enum): THREAT_CONTAINED | FALSE_POSITIVE | DUPLICATE | MERGED | ESCALATED
```

**Domain Services:**
- `IncidentSeverityClassificationService` — computes initial severity from finding severity + exposure context; accepts commander override with justification
- `IncidentLifecycleService` — enforces phase transition rules and invariants
- `ContainmentAuthorizationService` — determines required authorization level based on action type and impact scope

**Entities (child of Incident aggregate, not separate aggregate roots):**
- `IncidentTimelineEntry` — ordered, immutable event record; each phase transition + human action is a timeline entry
- `IncidentTag` — key-value metadata attached to incident by analysts

**Separate Entity (repository-managed, append-only, not loaded with Incident aggregate):**
- `IncidentCommunicationLogEntry` — stakeholder communications log; stored separately to prevent aggregate size explosion; append-only at repository level; every entry is immutable after creation

**Invariants:**
1. `Incident.classified_at` is set once, never changed. MTTR clock starts here.
2. Phase transitions are strictly ordered: DECLARED → CLASSIFIED → CONTAINED → ERADICATED → RECOVERED → CLOSED. CONTAINED and ERADICATED may be skipped only with explicit justification if the incident is reclassified as false_positive or duplicate.
3. `ContainmentAction` at `ContainmentActionType.CREDENTIAL_REVOKE` or `ContainmentActionType.NETWORK_ISOLATION` requires `ContainmentAuthorizationLevel.COMMANDER` minimum.
4. An `Incident` can only move to CLOSED state after either: (a) `EradicationVerification` is in VERIFIED state, OR (b) `resolution_type` is `FALSE_POSITIVE` or `DUPLICATE`, OR (c) CISO explicitly authorizes early closure with justification.

### 3.2 `regulatory_notification` — Supporting Domain

**Aggregate Roots:**

| Aggregate | Identity | Lifecycle |
|---|---|---|
| `RegulatoryNotification` | `RegNotificationId` (UUID) | CLOCK_STARTED → DRAFT_IN_PROGRESS → READY_FOR_SUBMISSION → SUBMITTED → ACKNOWLEDGED |
| `NotificationDraft` | `DraftId` (UUID) | DRAFT → REVISED → FINAL (one draft per notification; revised replaces the previous) |

**Value Objects:**
```
RegulatoryRegime(Enum): GDPR_ART33 | GDPR_ART34 | HIPAA_BREACH | SEC_CYBER | NIS2_EARLY_WARNING | NIS2_NOTIFICATION | NY_DFS_500 | UK_GDPR | PIPEDA
NotificationDeadline(VO): deadline_at (UTC), regime, business_days_or_calendar, hours_window
DeadlineStatus(Enum): PENDING | APPROACHING (< 25% buffer) | AT_RISK (< 10% buffer) | BREACHED | MET
RegulatorRef(VO): authority_name, jurisdiction, contact_endpoint  [reference only; no auto-submission]
SubmissionRecord(VO): submitted_at, submitted_by, submission_method, reference_number [immutable after creation]
```

**Deadline Definitions (frozen):**

| Regime | Clock Start | Deadline | Auto-Submit? |
|---|---|---|---|
| GDPR Art.33 | `IncidentClassified.classified_at` | 72 calendar hours | NEVER |
| GDPR Art.34 | `EradicationVerification.verified_at` | Reasonable time (platform marks ADVISORY) | NEVER |
| HIPAA Breach Notification | `IncidentClassified.classified_at` | 60 calendar days | NEVER |
| SEC Form 8-K Cyber | Materiality determination (`ContainmentAction.authorized_at` for first action) | 4 business days | NEVER |
| NIS2 Early Warning | `IncidentClassified.classified_at` | 24 calendar hours | NEVER |
| NIS2 Incident Notification | `IncidentClassified.classified_at` | 72 calendar hours | NEVER |
| NY DFS 23 NYCRR 500 | `IncidentClassified.classified_at` | 72 calendar hours | NEVER |

**Domain Services:**
- `RegulatoryDeadlineComputationService` — given incident classified_at, jurisdiction set, and regime list → computes all applicable deadlines with timezone handling
- `DeadlineAlertingService` — checks approaching/breached deadlines; publishes `RegulatoryDeadlineApproaching` and `RegulatoryDeadlineBreached` events

**Critical Invariant:** `SubmissionRecord` is immutable after creation. A submitted notification cannot be "un-submitted" in the domain model. If a submission is in error, a new `RegulatoryNotification` record is created for the corrective notification.

### 3.3 `lessons_learned` — Supporting Domain

**Aggregate Roots:**

| Aggregate | Identity | Lifecycle |
|---|---|---|
| `LessonsLearned` | `LessonsLearnedId` (UUID) | IN_PROGRESS → REVIEWED → FINALIZED |
| `PostIncidentReport` | `PostIncidentReportId` (UUID) | GENERATING → COMPLETE → EXPORTED |

**Value Objects:**
```
LessonCategory(Enum): DETECTION_GAP | RESPONSE_PROCEDURE | COMMUNICATION | TOOL_LIMITATION | THREAT_INTELLIGENCE | PLAYBOOK_DEFICIENCY | CONFIGURATION | OTHER
ActionItemStatus(Enum): OPEN | IN_PROGRESS | COMPLETED | DEFERRED | CANCELLED
ActionItemPriority(Enum): P1_CRITICAL | P2_HIGH | P3_MEDIUM | P4_LOW
CampaignRetargetingSuggestionRef(VO): incident_id, confirmed_technique_ids, attack_vector_description [advisory; fed to event bus]
ReportFormat(Enum): PDF | HTML | JSON | MARKDOWN
```

**Domain Services:**
- `PostIncidentReportGenerationService` — compiles report from `LessonsLearned` + `IncidentTimeline` read model + regulatory notification outcomes
- `CampaignRetargetingAdvisoryService` — analyses confirmed attack techniques from EradicationVerification evidence → publishes `CampaignRetargetingSuggested` event (advisory only; M30 decides whether to create a new scenario)

**Platform Invariant 7 compliance:** `CampaignRetargetingAdvisoryService` publishes events; it never calls M30 repositories or commands directly. The event contains structured data (confirmed_technique_ids, attack_vector_description) that M30's event consumer can use to create a campaign scenario suggestion. This is an advisory pathway, not a write pathway.

---

## 4. Integration Review

### 4.1 Upstream Integration Ports (ACL — Read-Only from M34's Perspective)

| Port | Source Context | Purpose | Integration Method |
|---|---|---|---|
| `IDetectionFindingPort` | M28 `detection` | Receive escalated findings as incident triggers | Event subscription: `DetectionFindingEscalated` |
| `IInvestigationContextPort` | M21 `investigation` (external) | Receive investigation conclusions | Event subscription: `InvestigationConcluded` |
| `IEvidenceChainQueryPort` | M29 `evidence` | Reference evidence chain IDs in containment/eradication | Event subscription: `EvidenceChainSealed` (reference only) |
| `IExposureContextPort` | M32 `exposure` | Retrieve blast-radius assets for scope assessment | Event subscription: `ExposureScoreComputed` (advisory) |
| `IAnalyticsAnomalyPort` | M33 `analytics` | Ingest anomaly signals that may indicate IR-relevant activity | Event subscription: `AnomalyDetected` |

**Critical: M34 does not query M21, M28, M29, or M32 operational databases directly.** All cross-context data arrives via event subscription and is translated at the ACL boundary before touching any M34 aggregate.

### 4.2 Downstream Outbound (M34 Produces)

| Destination | Event Produced | Purpose |
|---|---|---|
| M33 `analytics` via event bus | `IncidentClassified` | Starts MTTR clock; feeds `analytics.incident_events` |
| M33 `analytics` via event bus | `IncidentClosed` | Ends MTTR clock; feeds `analytics.incident_events` |
| M30 `campaign` via event bus | `CampaignRetargetingSuggested` | Advisory: confirmed technique IDs for new scenario consideration |
| Security Graph | `IncidentNode`, `ContainmentActionNode` | Via `ISecurityGraphWritePort` |
| ITSM via port | `IITSMNotificationPort` | Ticket creation on incident declaration (advisory; not record of truth) |
| Communication platform via port | `ICommunicationNotificationPort` | Stakeholder notification on phase transitions |

### 4.3 MTTR Projection Table

M34 introduces the `analytics.incident_events` table in migration `0102`. This table is physically located in the `analytics` PostgreSQL schema (owned by M33) but its population is M34's responsibility — M34 publishes the events; M33's `AnalyticsProjectionWorker` ingests them.

The M34 architecture finalization must confirm that:
1. `IncidentClassified` and `IncidentClosed` events contain `classified_at` / `closed_at` timestamps as first-class event fields
2. M33's `AnalyticsProjectionWorker` event subscription list includes these two M34 event types
3. The `analytics.incident_events` table schema is defined in migration `0102`

### 4.4 Security Graph Integration

```
IncidentNode attributes:
  id: IncidentId
  tenant_id: TenantId
  severity: IncidentSeverity
  phase: IncidentPhase
  classified_at: datetime
  closed_at: datetime | None
  trigger_type: IncidentTriggerType
  is_active: bool

ContainmentActionNode attributes:
  id: ContainmentActionId
  tenant_id: TenantId
  action_type: ContainmentActionType
  authorization_level: ContainmentAuthorizationLevel
  status: ContainmentActionStatus
  authorized_by: str
  authorized_at: datetime

Edges (written by incident context from its own nodes):
  IncidentNode -[TRIGGERED_BY]→ {finding_ref} [reference ID; not a graph traversal node lookup]
  IncidentNode -[HAS_CONTAINMENT]→ ContainmentActionNode
  IncidentNode -[INCIDENT_AFFECTED]→ {asset_ref} [reference ID; asset nodes owned by M22]
  ContainmentActionNode -[REFERENCES_EVIDENCE]→ {evidence_ref} [reference ID only]
```

The `incident` context does not write edges from nodes owned by other contexts. M28 is responsible for any edge from `DetectionFindingNode`. M22 is responsible for edges from `AssetNode`. M34 writes only edges from the nodes it owns.

---

## 5. Risk Assessment

### R01 — Regulatory Deadline Timer Reliability
**Severity:** CRITICAL  
**Impact:** If regulatory deadline timers run in-memory and the platform process restarts, timers are destroyed. A GDPR 72-hour notification deadline missed due to platform restart is a legal liability with potential fines up to 4% of global annual revenue.  
**Recommendation:** All regulatory deadline tracking must use the platform's durable scheduler (`DurableScheduledTask` pattern from Sprint 28 PostgreSQL DLQ infrastructure). Deadline records are stored in `regulatory_notification.notification_deadlines` table. On startup, the `DeadlineAlertingService` loads all active deadlines from the database and reconstitutes alert schedules. No deadline is stored only in memory.

### R02 — Incident Aggregate Gravity (Aggregate Boundary Erosion)
**Severity:** HIGH  
**Impact:** The `Incident` aggregate is a natural target for accumulating all security context: M28 finding details, M21 investigation timeline, M29 evidence items, M32 exposure scope. If developers embed upstream types directly into the Incident aggregate, the context becomes a super-aggregate that owns investigation, detection, and evidence data — violating Domain Purity and creating an unmaintainable monolith.  
**Recommendation:** Strict ACL enforcement: `EscalatedFindingRef`, `InvestigationRef`, and `EvidenceRef` are M34-owned value objects containing only reference identifiers and timestamps. The Incident aggregate holds these references but never the full upstream objects. Architecture tests must verify no import of `DetectionFinding`, `EvidenceChain`, or any M21 type in any M34 module.

### R03 — Communication Log Immutability Enforcement by Convention
**Severity:** HIGH  
**Impact:** If `IncidentCommunicationLogEntry` immutability is enforced only by developer convention (no update/delete calls in the codebase), future developers may accidentally add update operations, creating legally defensible evidence that was silently modified.  
**Recommendation:** The `IIncidentCommunicationLogRepository` interface defines only `append()` and `find_by_incident()`. No `update()` or `delete()` method exists anywhere in the interface. Attempting to modify an entry is a compile-time impossibility at the repository layer, not a runtime check.

### R04 — MTTR Projection Table Schema Ownership
**Severity:** HIGH  
**Impact:** The `analytics.incident_events` table lives in M33's `analytics` schema but must be created in M34's migration. If this ownership is unclear, the table may not be created before M34 publishes events, causing silent data loss (events with no projection table to insert into).  
**Recommendation:** Migration `0102` is the first M34 migration and creates `analytics.incident_events`. M33's `AnalyticsProjectionWorker` event subscription list (configured in application startup) includes `IncidentClassified` and `IncidentClosed` event types. The M34 Architecture Finalization must document this explicitly as a Phase 1 exit criterion.

### R05 — Multi-Jurisdiction Regulatory Complexity
**Severity:** MEDIUM  
**Impact:** A single incident at a global enterprise may trigger GDPR (EU operations), HIPAA (healthcare division), SEC (publicly-traded company), and NIS2 (EU member state infrastructure) simultaneously. If the `regulatory_notification` context models only one notification per incident, it cannot handle multi-regime compliance.  
**Recommendation:** One `RegulatoryNotification` aggregate per (incident_id, regime) pair. An incident has a `List[RegulatoryNotification]`. Each aggregate tracks its own clock, deadline, draft, and submission independently. The `RegulatoryDeadlineComputationService` creates all applicable `RegulatoryNotification` records when an incident is classified, based on the tenant's configured jurisdiction set.

### R06 — LessonsLearned Campaign Feedback Creates Circular Architecture Risk
**Severity:** MEDIUM  
**Impact:** If `lessons_learned` directly calls M30 application services to create campaign scenarios, it creates a write dependency from M34 → M30. This violates the one-directional dependency model and makes M34 deployment contingent on M30 API compatibility.  
**Recommendation:** Platform Invariant 7 enforced: `LessonsLearned.finalized()` publishes a `CampaignRetargetingSuggested` event on the platform event bus. M30 has an optional event subscription for this event type. No direct M30 call from M34. Architecture test verifies no M30 import in `lessons_learned` module.

### R07 — Post-Incident Report Format Proliferation
**Severity:** LOW  
**Impact:** Organizations requesting M34 post-incident reports will demand different formats: PDF for legal, JSON for integration, Markdown for documentation platforms. Without a frozen format strategy, each customer request drives a new code path.  
**Recommendation:** `PostIncidentReportGenerationService` supports four frozen formats: PDF, HTML, JSON, MARKDOWN. Additional formats require a milestone extension. `IPostIncidentReportDeliveryPort` abstracts delivery mechanism. Report artifact stored in blob storage reference (`IReportArtifactStore` port) — same pattern as M33 `reporting` context.

### R08 — Containment Action Authorization Level Under-Specification
**Severity:** LOW  
**Impact:** The roadmap states containment actions require "authorization" but does not specify what authorization level is required for which action types. Without explicit rules, authorization becomes convention-based.  
**Recommendation:** Authorization levels are frozen by action type in the domain (not configuration). `ContainmentAuthorizationService` applies a hard-coded authorization matrix: ANALYST-authorized for low-impact actions (traffic logging, alert escalation), COMMANDER-authorized for medium-impact (process termination, service suspension), CISO-authorized for high-impact (network segment isolation, credential mass-revoke).

### R09 — Eradication Verification Evidence Model
**Severity:** LOW  
**Impact:** "Proving" that an attacker has been eradicated is operationally complex. Without a clear evidence model for `EradicationVerification`, the aggregate becomes a checkbox with no substance.  
**Recommendation:** `EradicationVerification` requires at minimum one `EradicationEvidenceRef` (a reference to either a platform `EvidenceChain` item or an analyst-submitted artifact). The verification is submitted by `incident:analyst`, reviewed by `incident:commander`, and marked VERIFIED by the commander. This follows the same two-role attestation pattern used in M29's evidence sealing.

---

## 6. Conditions for Implementation Approval

| ID | Condition | Severity | Impact if Unresolved |
|---|---|---|---|
| C1 | Freeze the exact boundary between `Incident` aggregate and M21 Investigation: what data is referenced (by ID only), what events trigger incident creation, and how the investigation lifecycle relates to the incident lifecycle | CRITICAL | Aggregate gravity pulls M21 data into M34; context becomes monolith |
| C2 | Freeze the `IncidentCommunicationLog` immutability model: repository interface with only `append()` and `find_by_incident()`; no update or delete; each entry carries immutable `logged_at` and `author` | HIGH | Tampered communication records undermine legal defensibility |
| C3 | Freeze the regulatory notification submission rule: no automatic submission by any timer, event, or automation; submission is always a human-issued `SubmitRegulatoryNotification` command; deadline timers trigger alerts only | HIGH | Auto-submission creates legal liability; regulatory submissions require human review |
| C4 | Freeze the MTTR pipeline: `analytics.incident_events` table schema in migration `0102`; `IncidentClassified` and `IncidentClosed` event field specifications; M33 `AnalyticsProjectionWorker` subscription configuration | HIGH | MTTR KPI stub never activates; M33 KPI dashboard permanently incomplete |
| C5 | Freeze the durable deadline timer implementation: all regulatory deadlines stored in `regulatory_notification.notification_deadlines` table; `DeadlineAlertingService` reconstitutes on startup; no in-memory-only timers | HIGH | Platform restart loses regulatory deadline tracking; legal liability |
| C6 | Freeze the `LessonsLearned` → M30 advisory pathway: `CampaignRetargetingSuggested` event published on platform event bus with frozen event schema; no direct M30 write | MEDIUM | Circular architecture dependency; M34 deployment contingent on M30 API |
| C7 | Freeze the incident severity classification lifecycle: initial severity source (M28 finding severity), commander override protocol, severity-change justification requirement, and relationship between severity and containment authorization level | MEDIUM | Severity changes without justification; authorization level mismatch with action impact |

---

## 7. Implementation Phase Plan

### Phase 1 — Incident Foundation

**Scope:** `incident` bounded context core. `Incident` aggregate lifecycle (DECLARED → CLOSED). `IncidentTimeline` (append-only phase transition log). `ContainmentAction` aggregate with authorization model. Security Graph integration (`IncidentNode`, `ContainmentActionNode`). `analytics.incident_events` table creation (migration `0102`). MTTR pipeline activation: `IncidentClassified` and `IncidentClosed` events consumed by M33 `AnalyticsProjectionWorker`.

**Bounded Contexts:** `incident`  
**Migrations:** 0102–0104  
**Exit Criteria:** Incident declared from `DetectionFindingEscalated` event; full lifecycle to CLOSED; MTTR data appearing in `analytics.incident_events`; cross-tenant isolation verified

### Phase 2 — Regulatory Notification

**Scope:** `regulatory_notification` bounded context. `RegulatoryNotification` aggregate. `NotificationDraft` aggregate. `DeadlineAlertingService` with durable PostgreSQL-backed timers. All seven regulatory regimes frozen. Multi-jurisdiction support (multiple notifications per incident). `RegulatoryDeadlineApproaching` and `RegulatoryDeadlineBreached` events. Human-commanded submission.

**Bounded Contexts:** `regulatory_notification`  
**Migrations:** 0105–0107  
**Exit Criteria:** GDPR 72h deadline tracked and alerting correctly; deadline persists across simulated process restart; manual submission command produces immutable `SubmissionRecord`; auto-submission prevented at domain level

### Phase 3 — Eradication, Recovery, Communication Log

**Scope:** `EradicationVerification` aggregate with two-role attestation model. `RecoveryMilestone` tracking. `IncidentCommunicationLog` entity with append-only repository. `IITSMNotificationPort` (abstract only; no vendor implementations in M34). `ICommunicationNotificationPort` (Slack/Teams/email adapters).

**Bounded Contexts:** `incident` (extended)  
**Migrations:** 0108–0110  
**Exit Criteria:** Eradication verification requires commander attestation; communication log append-only enforced at interface level; incident closure blocked without verified eradication OR explicit override; no update/delete methods on log repository

### Phase 4 — Lessons Learned & Post-Incident Reports

**Scope:** `lessons_learned` bounded context. `LessonsLearned` aggregate with structured capture. `PostIncidentReport` aggregate with four format support (PDF, HTML, JSON, MARKDOWN). `CampaignRetargetingAdvisoryService` publishing advisory events. `PostIncidentReportGenerationService` compiling from `LessonsLearned` + `IncidentTimeline` read model.

**Bounded Contexts:** `lessons_learned`  
**Migrations:** 0111–0112  
**Exit Criteria:** Post-incident report generated in < 30 seconds from incident closure; `CampaignRetargetingSuggested` event published with correct technique IDs; no M30 type imported in `lessons_learned` module; report artifact stored via `IReportArtifactStore` port

### Phase 5 — Security Graph Completion, RBAC, Hardening

**Scope:** Full Security Graph wiring (all M34 nodes and edges). Complete RBAC model (`incident:viewer`, `incident:analyst`, `incident:commander`, `incident:ciso`, `regulatory:officer`, `regulatory:legal`). API hardening. Complete M34 test suite including security tests. `PostIncidentReport` export to BI/document store via port. MTTR KPI activated in M33 integration test.

**Migrations:** 0113  
**Exit Criteria:** All Phase 1–5 tests passing; Ruff PASS; MyPy --strict PASS; MTTR KPI returns actual values (not `REQUIRES_M34_DATA`) after incident events in integration test; Security Graph traversal from `IncidentNode` to affected assets produces correct results; cross-tenant isolation across all three contexts verified

---

## 8. Architecture Verdict

The M34 architecture is **APPROVED WITH CONDITIONS C1–C7**.

The three-context design (`incident`, `regulatory_notification`, `lessons_learned`) is correct and appropriately scoped. The bounded context boundaries are coherent and non-overlapping. The integration model follows the platform's established event-driven ACL pattern.

Seven conditions must be resolved in the Architecture Finalization document before Phase 1 begins. The most critical are C1 (incident-investigation boundary), C3 (regulatory automation prohibition), and C5 (durable timers). These three conditions are not implementation details — they are architectural decisions with legal and compliance consequences.

**M34 Architecture Approved for Implementation — with Conditions C1 through C7.**
