# AIVAR RedForge — Master Platform Evolution Architecture

**Date**: 2026-07-11
**Status**: Architecture assessment only. No implementation authorized by this
document. Written after Sprint 42–43 closure (see `SPRINT_4243_REPORT.md`).

This document assesses how the existing RedForge codebase should evolve
toward the target vision: an **Enterprise Autonomous Security Validation,
Exposure, and Red Team Operations Platform**, with AI red teaming as the
initial and continuing differentiator rather than an isolated module.

---

## 1. Current Architecture Reuse Assessment

RedForge is already a mature Clean Architecture / DDD system with ~24
bounded contexts under `backend/src/redforge/{application,domain}/`:

`identity`, `organizations`, `ai_targets`, `providers`, `connectors`,
`inventory`, `red_team`, `campaigns`, `attack_library`, `planning`,
`payloads`, `execution`, `evidence`, `findings`, `posture` (risk),
`intelligence`, `knowledge` (graph), `policies`, `agents`, `conversations`,
`validations`, `platform` (runtime/event infra), `invitations`,
`memberships`.

This is not a toy scanner with a thin UI bolted on — it is a proper
event-sourced platform with a projection registry, DLQ, circuit breakers,
health engine, and a real knowledge graph. The vision in this document does
**not** require a rewrite. It requires:

1. Extending several existing bounded contexts to be provider/domain-agnostic
   rather than AI-specific where the underlying concept generalizes (e.g.
   `inventory`, `connectors`, `findings`, `posture`, `knowledge`).
2. Adding a **platform control plane** alongside the existing **tenant
   (organization) control plane** — currently the codebase has no concept of
   a platform-level actor at all.
3. Adding new bounded contexts for domains RedForge does not yet touch
   (network, identity/directory, cloud, controlled offensive operations,
   compliance).

## 2. Bounded Contexts That Should Remain As-Is

- `red_team`, `attack_library`, `payloads`, `planning`, `execution` — this is
  the AI red-team execution core. It is the product's differentiator and
  should not be diluted by premature generalization. Other domains
  (network, cloud) get their **own** planning/execution contexts that share
  infrastructure (see Section 8), not a forced merge into `red_team`.
- `platform` — the runtime/event/projection/DLQ infrastructure is
  domain-agnostic by design already and needs no change to support new
  bounded contexts; new projections simply register into the existing
  `ProjectionRegistry`.
- `organizations`, `memberships`, `invitations` — the organization-level RBAC
  primitives are sound and are the foundation Section 6 builds on.

## 3. Bounded Contexts Requiring Extension

- **`inventory`** — currently models AI assets (`AIAsset ≠ AITarget`, per
  Sprint 22). This is the natural home for a **unified asset inventory**
  spanning network hosts, cloud resources, identities, and applications —
  but only by extending its asset-type taxonomy, not by building a second
  inventory system (Section 8 makes this explicit, since the prompt
  specifically warns against a second inventory).
- **`connectors`** — currently used for AI system discovery (Sprint 23). This
  becomes the extension point for identity/directory connectors and
  multi-cloud connectors. The connector abstraction (discover → normalize →
  ingest into inventory) already generalizes; it needs new connector
  *implementations*, not a new *pattern*.
- **`findings` / `posture` (risk) / `evidence`** — these are already
  domain-agnostic in shape (a finding has a title, severity, evidence,
  recommendation regardless of whether the underlying issue came from an AI
  red-team run or a network scan). Extension needed: a `source_domain`
  discriminator so a finding can be traced back to AI / network / cloud /
  application without conflating pipelines.
- **`knowledge`** (the Knowledge Graph) — already ingests `AIAsset` and
  execution data as projections (Sprint 24's KGProjection). This is the
  correct foundation for the **unified security graph** (Section 11); it
  needs new node/edge types added incrementally per new domain, not a
  redesign.
- **`identity`** (domain, RBAC) — currently org-scoped only (`Role`:
  OWNER/ADMIN/SECURITY_MANAGER/ANALYST/MEMBER/VIEWER, `Permission` enum).
  Needs a platform-role layer added alongside, not replacing, the existing
  organization-role layer (Section 6).

## 4. Genuinely New Bounded Contexts

- `platform_identity` — Platform Super Admin bootstrap, platform roles,
  platform-wide audit (Section 6).
- `network_security` — authorized network discovery, host/IP/port
  inventory, passive monitoring, separated explicitly from active
  validation (Section 9).
- `directory_identity` — identity/directory connector ingestion (users,
  groups, privileged identities, service identities) as inventory +
  graph data, not an IAM system of record (Section 10).
- `cloud_security` — multi-cloud connector ingestion, cloud asset/exposure
  data feeding the same `inventory`/`findings`/`knowledge` contexts
  (Section 11).
- `offensive_operations` — the controlled red-team/PT operations boundary:
  authorization scope, approval gates, kill switch, operator permissions,
  execution provenance (Section 12). This context defines *policy and
  boundary* only in the near term; it does not include a C2/Metasploit
  adapter implementation until its own dedicated milestone.
- `compliance` — control catalog, framework mapping, evidence-to-control
  linkage, posture status (Section 13). Depends on `findings`/`posture`
  already existing; does not duplicate them.

## 5. Platform Control Plane vs Tenant Control Plane

Two distinct authorization planes must coexist without conflation:

| | Platform control plane | Tenant control plane |
|---|---|---|
| Actor | Platform Super Admin / platform operator | Organization Admin / org user |
| Scope | All organizations, all tenants | One organization |
| Current state | **Does not exist** | Exists (`Role`, `Permission`, `TenantContext`) |
| Data visibility | Cross-tenant (governance only, never tenant secrets) | Single-tenant, enforced by `organization_id` from JWT |
| Enforced by | New `PlatformContext` + `require_platform_permission()` | Existing `TenantContext` + `require_permission()` |

**Hard rule carried forward from Sprint 42–43**: platform-level visibility
must never leak tenant credential material, resolved secrets, or another
tenant's evidence/finding content. Platform visibility is governance and
health data (org exists, org is active, org's runtime health), not tenant
security data.

## 6. Super Admin Bootstrap and Platform RBAC Architecture

**Anti-pattern to avoid explicitly**: `if user.email == "subash@..."` anywhere
in domain or application code. This must never exist.

**Correct pattern** — bootstrap-then-authoritative:

1. A new `platform_super_admins` table (or a `platform_role` column on
   `users`, decision deferred to the implementing milestone) starts empty.
2. A one-time, environment-gated bootstrap procedure (CLI command or a
   startup check gated by `REDFORGE_BOOTSTRAP_SUPER_ADMIN_EMAIL`, read from
   configuration/secrets — never hardcoded in source) promotes exactly one
   existing registered user to platform Super Admin, and only if the
   platform has zero Super Admins. This mirrors how many platforms handle
   "first admin" bootstrap (e.g., initial cluster admin patterns) without
   baking an identity into code.
3. After bootstrap, all platform-role assignment is backend-authoritative
   and requires an existing Super Admin to grant further platform roles.
   No self-registration path to a platform role can exist.
4. Organization Admins must not be able to escalate to a platform role
   through any org-scoped endpoint — this is enforced by keeping
   `PlatformContext` and `TenantContext` as separate, non-overlapping
   dependency-injected security contexts (mirroring how `TenantContext` is
   already isolated from raw JWT parsing today).
5. Every platform-role grant/revoke is an immutable audit event through the
   existing `platform_events` event store (Sprint 25) — this table already
   exists and already supports append-only audit; it does not need a new
   audit mechanism, only a new event type.

## 7. Organization RBAC Evolution

Current: `Role` enum (OWNER/ADMIN/SECURITY_MANAGER/ANALYST/MEMBER/VIEWER) +
`Permission` enum (resource:action pairs) + `require_permission()`. This is
already a permission-oriented design, not a hardcoded 3-role UI switch — the
prompt's concern ("do not reduce future RBAC to three hardcoded UI roles")
is already satisfied structurally. The evolution needed is additive:

- Extend `Permission` per new bounded context as it's built (e.g.
  `NETWORK_READ`, `CLOUD_READ`, `COMPLIANCE_MANAGE`) rather than
  overloading existing permissions across domains.
- Keep the frontend permission model UX-only (already true — the frontend
  has zero authorization logic beyond what the backend returns); this
  principle must hold as new domains add UI surfaces.

## 8. Asset/Inventory Unification Strategy

**Explicit anti-pattern to avoid**: building a second inventory system for
network/cloud assets because "AI assets are special." They are a subtype.

Extension path:
1. `inventory`'s asset model already distinguishes `AIAsset` from `AITarget`
   (Sprint 22) — the pattern of "typed asset kinds sharing a common
   inventory shell" is proven. Add `NetworkAsset`, `CloudResource`,
   `IdentityAsset`, `ApplicationAsset` as sibling asset kinds under the same
   inventory bounded context, not parallel systems.
2. `connectors` already models "discover externally → normalize → ingest."
   Each new domain (network, cloud, directory) gets a connector
   *implementation*, reusing the existing discovery→ingest pipeline shape.
3. Do not let asset-kind-specific fields leak into a shared base type;
   follow the `AIAsset`/`AITarget` precedent of type-specific DTOs behind a
   common `Asset` identity (id, organization_id, kind, name, tags,
   created_at) for cross-domain queries and graph projection.

## 9. Identity/Directory Connector Architecture

New `directory_identity` bounded context. Do not assume Active Directory is
the only system — model a `DirectoryConnectorPort` protocol (mirroring the
existing `CredentialResolverPort` pattern from Sprint 42–43) with pluggable
implementations (LDAP/AD, Okta, Azure AD/Entra ID, Google Workspace, generic
SCIM). Each connector implementation:
- Discovers users, groups, privileged identities, service identities.
- Normalizes into `IdentityAsset` inventory records + graph nodes
  (`Identity`, `Group`) and edges (`MEMBER_OF`, `AUTHENTICATES_TO`).
- Never persists directory credentials in RedForge's own store beyond an
  `auth_ref`-style reference, following the exact Sprint 42–43 credential
  boundary pattern (`CredentialResolverPort` → environment/secret-store
  resolver → adapter, secret never returned to any API response).
- Read-only by default; no write-back to the source directory in the first
  milestone.

## 10. Network Discovery/Monitoring Architecture

New `network_security` bounded context, with a **hard separation** the
prompt explicitly requires:

- **Passive discovery** (asset/host/IP/port inventory, topology) —
  low-risk, always-on, feeds `inventory` and `knowledge`.
- **Active validation** (vulnerability scanning, exploitation attempts) —
  requires the same authorization-scope model as `offensive_operations`
  (Section 12): explicit target ownership/scope validation before any
  active check runs, approval gates for anything beyond passive discovery,
  and a kill switch.

This context must not silently escalate from passive to active; the
distinction is a first-class field on every network operation
(`operation_mode: passive | active`), and active mode requires the same
approval-gate infrastructure `offensive_operations` defines, shared rather
than duplicated.

## 11. Application/URL Security Workflow

The existing pipeline —
`ai_targets → planning → payloads → execution → evaluation (intelligence) →
evidence → findings → posture (risk)` — already implements exactly the
workflow the prompt describes for generic URL/application validation:
`DISCOVER → INVENTORY → ATTACK SURFACE → PLAN → VALIDATE → EVALUATE →
EVIDENCE → FINDING → RISK`. Extension needed:
- Generalize `AITarget` intake to accept a generic `ApplicationTarget` /
  `URLTarget` (a new `inventory` asset kind, Section 8) so the same
  planning/execution/evaluation pipeline can validate a REST API or web app,
  not only an AI system endpoint.
- Attack-surface discovery for non-AI targets (endpoint enumeration, auth
  surface mapping) becomes a new `planning` capability, not a parallel
  scanner.
- Do **not** build a second execution/evaluation/evidence pipeline. Reuse.

## 12. Multi-Cloud Connector Strategy

New `cloud_security` bounded context, built on the `connectors` +
`inventory` pattern (Section 8), not a new inventory. Per-provider
connectors (AWS/Azure/GCP first, extensible) each:
- Discover cloud assets, IAM/identity posture, public attack surface,
  configuration posture into `inventory` (`CloudResource` asset kind) and
  `knowledge` (graph nodes: `Cloud Account`, `Cloud Resource`; edges:
  `CAN_ASSUME`, `TRUSTS`, `EXPOSES`).
- Feed `findings`/`posture` using the existing finding/risk pipeline
  (misconfiguration = finding, same as an AI jailbreak = finding).
- Attack-path computation (identity → workload → data) is a `knowledge`
  graph traversal capability (Section 15), not a cloud-specific feature —
  it must compose with AI/network/identity edges from day one architecturally,
  even if the cloud milestone itself only populates cloud-specific nodes.

## 13. AI Security Integration Strategy

No structural change needed — this is already the platform's strongest,
most mature capability set (Sprints 36–43: adaptive intelligence,
evaluation-driven control loop, campaign persistence, credential boundary).
The explicit requirement is architectural discipline going forward: every
new domain (network, cloud, identity) must project into the **same**
`knowledge` graph, the **same** `findings`/`posture` pipeline, and the
**same** `evidence` store that AI red-teaming already uses — AI security
must never become a disconnected module as new domains are added around it.

## 14. Controlled Red-Team Operations Integration Boundary

New `offensive_operations` bounded context. **This milestone defines policy
and boundary only** — no C2/Metasploit/external-framework adapter is built
here or authorized by this document.

Required boundary elements, modeled before any adapter exists:
- `AuthorizationScope` value object: explicit target ownership/scope
  validation, expiry, and revocability — an operation cannot start without
  an active, unexpired scope record.
- `OperatorPermission` — distinct from organization `Permission`; controls
  who may initiate offensive actions, separate from who may merely view
  results.
- `ApprovalGate` — a required human/policy approval step before any
  offensive action beyond RedForge's existing AI red-team execution
  (which already has its own evaluation/policy enforcement from Sprint 40).
- `KillSwitch` / pause / cancel — must be a runtime capability on any future
  execution adapter, mirroring the existing `GracefulShutdownCoordinator`
  and circuit-breaker patterns already in `platform`.
- **Credential isolation** — any future operator-framework credential
  (e.g., a C2 API token) follows the exact `CredentialResolverPort` pattern
  from Sprint 42–43. No exceptions.
- **Immutable audit** — every offensive action's provenance (who, when,
  scope, approval chain) goes through `platform_events`, same as platform
  RBAC changes (Section 6).
- **Tenant isolation** — scope, approval, and execution records are
  organization-scoped exactly like campaigns today.

## 15. Compliance/Control Evidence Architecture

New `compliance` bounded context: `ControlCatalog → Framework →
ControlRequirement → TechnicalEvidence → Finding/Risk → ControlStatus →
Posture`. Built on top of existing `findings`/`posture`/`evidence` — a
control requirement maps to one or more findings/evidence records, it does
not duplicate them.

**Hard rule**: the system must never render or return the literal string
`CERTIFIED` or `COMPLIANT`. `ControlStatus` must be one of: `mapped`,
`evidence_available`, `technically_validated`, `partially_satisfied`,
`failed`, `not_assessed`, `requires_human_evidence`. This is a UI/API
contract constraint that must be enforced at the response-schema level
(an enum, not a free-text field), the same way Sprint 42–43 enforced "no
raw credential field" at the schema level.

## 16. Unified Security Graph Evolution

`knowledge`'s existing `KGProjection` (Sprint 24/31) is the correct
foundation. Evolution is incremental, not a redesign:
- Add node types per new bounded context as it ships (Identity, Group,
  Device, Network, Cloud Account, Cloud Resource, Control), not all at once.
- Add edge types the same way, driven by what each new domain's connector
  actually produces (`MEMBER_OF`, `CAN_ACCESS`, `CAN_ASSUME`, `TRUSTS`,
  `MAPS_TO_CONTROL`, `ATTACK_PATH_TO`), reviewed each time against the
  existing ontology to avoid duplicate/overlapping edge semantics.
- Cross-domain attack-path queries (`INTERNET → EXPOSED APPLICATION →
  CLOUD WORKLOAD → OVERPRIVILEGED IDENTITY → AI AGENT → SENSITIVE DATA`)
  are a graph-traversal capability that becomes meaningful only once at
  least two of {network, cloud, identity, AI} domains have real data in the
  graph — do not build path-finding UI before there is more than one domain
  to path across.

## 17. Live Operation/Event UX Data Architecture

The `platform` context already has real event/projection/read-model
infrastructure (event store, projections, DLQ, checkpoints). Live operation
UX (`DISCOVERY → INVENTORY → PLANNING → VALIDATION → EXECUTION →
EVALUATION → EVIDENCE → FINDING → RISK`) must be built by reading real
projected read-model state, the same pattern `CampaignProjection` already
uses for red-team campaigns. **Explicit anti-pattern**: fabricated progress
bars or synthetic "live" events not backed by a real persisted state
transition. If a step hasn't produced a real event, the UI must show its
last-known real state, not a simulated one.

## 18. Concise Finding/Reporting Contract

Target structure: `PROBLEM / AFFECTED ASSET / EVIDENCE / RISK / ATTACK PATH
/ REMEDIATION`. This is largely satisfied today by `Finding` (title,
description, severity, risk_score, evidence_ids, recommendation) plus
`RiskIncident` (affected_targets, finding_ids). The gap: no `attack_path`
field yet, and recommendation text should remain structured/concise, not
AI-generated prose that could obscure the actual technical issue (an
explicit product-quality guardrail, not a technical one).

## 19. Audit and Governance Requirements

- Platform-level privilege changes: immutable, via `platform_events`
  (Section 6).
- Tenant-level significant actions (campaign launch, provider
  register/disable, offensive-operation authorization) already have or must
  gain the same event-sourced audit trail — this is a natural extension of
  existing `platform_events` usage, not a new subsystem.
- Every new bounded context's write path must answer: "if an auditor asks
  who did this and when, can we answer from an immutable log?" If not, it
  is not ready to ship.

## 20. Threat Model for Platform-Wide Administration

- **Compromised platform Super Admin credential**: highest-impact single
  point of failure in the entire system. Mitigations: MFA requirement at
  the identity layer (out of scope for this architecture doc, but a hard
  prerequisite before Super Admin capabilities ship), immutable audit of
  every platform action, and no platform action that can directly read a
  tenant's resolved secrets (platform visibility is governance/health data
  only, per Section 5).
- **Privilege escalation from org-admin to platform-admin**: prevented
  structurally by keeping `PlatformContext` and `TenantContext` as
  non-overlapping security dependencies (Section 6) — an org-scoped
  endpoint physically cannot construct a `PlatformContext`.
- **Cross-tenant data exposure via platform tooling**: any platform
  dashboard/API that aggregates across tenants must be reviewed against
  the same sentinel-leak testing discipline established in Sprint 42–43
  (`test_credential_leak.py` pattern) before shipping.

## 21. Tenant Isolation Implications

Every new bounded context must answer, before its first endpoint ships:
"is `organization_id` derived exclusively from JWT `TenantContext`, never
from request body or query parameters?" This is already the enforced
pattern for `red_team`/`ai_targets`/`findings`/`risk_incidents`; it must
hold with zero exceptions for `network_security`, `cloud_security`,
`directory_identity`, `offensive_operations`, and `compliance` as they are
built. The one deliberate, explicitly-flagged exception in the current
codebase is `providers` (platform-wide by design, Sprint 42–43 Section 8
finding) — any future non-tenant-scoped resource must be an equally
deliberate, documented decision, never an oversight.

## 22. Data Retention and Evidence Integrity Considerations

- `evidence` records (network scan results, cloud misconfguration snapshots,
  offensive-operation logs) are forensic/compliance-relevant data. Retention
  policy (how long, immutability guarantees, tenant-controlled deletion vs.
  platform-mandated retention for audit) must be decided per new evidence
  type before the first milestone that produces it, not retrofitted later.
- Evidence integrity: consider content-hashing evidence records at capture
  time so tampering (accidental or malicious) is detectable — relevant
  especially for `offensive_operations` provenance and `compliance`
  evidence, where auditors may later need to trust the record.

## 23. Build-vs-Integrate Decision Principles

- **Build**: anything that is core differentiation (AI red-team execution,
  the unified security graph, the finding/risk/evidence pipeline, the
  credential-boundary pattern). This is RedForge's IP.
- **Integrate**: identity/directory systems (don't build an IAM), cloud
  provider APIs (don't build a cloud), offensive execution frameworks
  (don't build a C2 — integrate with authorized, purpose-built ones behind
  the `offensive_operations` boundary), compliance framework definitions
  (don't invent MITRE ATT&CK or NIST CSF — map to the canonical published
  control catalogs).
- Default to integration via a narrow port/adapter (mirroring
  `CredentialResolverPort`, `DirectoryConnectorPort`) so a vendor swap never
  requires touching application or domain logic.

## 24. Architecture Risks and Anti-Patterns to Avoid

- **Hardcoded platform-admin identity** (Section 6) — must never appear in
  code.
- **Second inventory system** for network/cloud assets (Section 8) —
  extend `inventory`, do not parallel it.
- **AI security as a disconnected module** as new domains are added
  (Section 13) — every domain must share graph/findings/evidence/risk.
- **Fabricated live-operation state** (Section 17) — UI must reflect real
  projected state only.
- **Claiming `CERTIFIED`/`COMPLIANT`** (Section 15) — must be structurally
  impossible via the response schema, not just a copywriting guideline.
- **Building offensive-framework adapters before the authorization boundary
  exists** (Section 14) — boundary first, adapter later, enforced as a
  milestone dependency order in the companion roadmap document.
- **Silent tenant-scoping gaps** (Section 21) — the `providers` finding from
  Sprint 42–43 must not repeat in new bounded contexts; each new context's
  first PR must include a tenant-isolation test analogous to
  `test_credential_leak.py`.
- **Treating platform visibility as tenant visibility** (Section 5) — the
  platform control plane must never become a backdoor to tenant secrets or
  tenant-specific evidence.

---

See `MASTER_PLATFORM_ROADMAP.md` for the ordered milestone sequence derived
from this assessment.
