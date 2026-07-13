# AIVAR RedForge — Master Platform Roadmap

**Date**: 2026-07-11
**Status**: Milestone sequence only. Implementation of any milestone below
requires its own dedicated session/sprint and is **not** authorized by this
document. Companion to `MASTER_PLATFORM_EVOLUTION_ARCHITECTURE.md`.

This roadmap intentionally deviates in places from the dependency order
suggested in the originating prompt, with the deviation explained at each
milestone where it applies. The prompt's suggested order treated "AI red
team unification" and "compliance evidence" as late-stage; this roadmap
instead treats AI red-team's existing pipeline as the reusable foundation
other domains build on from Milestone 3 onward, since it already exists and
is production-grade (3,383 tests passing as of Sprint 42–43).

---

## Milestone 1 — Platform Identity & Super Admin Bootstrap

**Business capability**: Establish a platform-level actor distinct from
organization-level actors, with a secure, non-hardcoded bootstrap path for
the first Super Admin (Subash), and immutable audit of all platform-role
changes.

- **Bounded context ownership**: new `platform_identity` context.
- **Architectural prerequisites**: none — this is the first new context and
  has no dependency on later milestones.
- **Security prerequisites**: MFA at the identity layer should be evaluated
  before this ships (Super Admin is the single highest-impact credential in
  the system per the threat model, Architecture doc Section 20). If MFA
  infrastructure doesn't exist yet, this milestone must explicitly flag that
  gap rather than silently shipping Super Admin without it.
- **Backend scope**: `platform_identity` domain/application/infrastructure
  layers; `PlatformContext` security dependency (parallel to, never merged
  with, `TenantContext`); bootstrap procedure gated by
  `REDFORGE_BOOTSTRAP_SUPER_ADMIN_EMAIL` config value, only usable when zero
  Super Admins exist; platform-role grant/revoke endpoints, Super-Admin-only;
  audit via `platform_events`.
- **Frontend/product scope**: none in this milestone. No platform dashboard
  yet — that is Milestone 2's UX, built once the roles it displays exist.
- **Data model impact**: new `platform_super_admins` (or equivalent) table
  and migration; new `platform_role_granted` / `platform_role_revoked` event
  types in the existing event store.
- **Tenant/RBAC implications**: zero change to existing organization RBAC.
  `PlatformContext` and `TenantContext` must be provably non-overlapping
  (an org-scoped endpoint cannot construct a `PlatformContext` and vice
  versa) — this is the single most important structural guarantee in this
  milestone.
- **Required principal review**: yes — this milestone creates the platform's
  highest-privilege actor. Review must specifically adversarially attempt
  privilege escalation from an org-admin token before sign-off.
- **Acceptance boundary**: bootstrap procedure creates exactly one Super
  Admin from a known-good state (zero existing Super Admins); a second
  bootstrap attempt is rejected; an org-admin JWT cannot be used to construct
  or satisfy `PlatformContext`; every grant/revoke produces an immutable
  audit event.
- **What must NOT be implemented yet**: no platform dashboard UI, no
  cross-tenant data visibility of any kind, no org-lifecycle actions
  (suspend/delete an org) beyond what's needed to prove the RBAC boundary.

---

## Milestone 2 — Platform RBAC / Tenant Governance Control Plane

**Business capability**: Give the platform Super Admin visibility into
tenant lifecycle, registered users, and platform-wide health — the minimum
viable platform control-plane UX.

- **Bounded context ownership**: `platform_identity` (extended) +
  read-only projections from `organizations`/`memberships`/`platform`.
- **Architectural prerequisites**: Milestone 1 (Platform Identity) complete.
- **Security prerequisites**: every cross-tenant read in this milestone must
  be reviewed against the Sprint 42–43 sentinel-leak testing discipline —
  no tenant secret, resolved credential, or tenant-specific finding/evidence
  content may appear in any platform-level response.
- **Backend scope**: read-only platform endpoints — organization list
  (governance metadata only: name, status, created_at, member count — not
  tenant security data), registered-user list, platform runtime/health
  aggregation (reusing the existing `RuntimeHealthEngine`), platform audit
  log query (reading `platform_events`).
- **Frontend/product scope**: first platform control-plane UI screen
  (Architecture doc Section "Platform Super Admin Control Plane") — org
  list, user list, tenant health, audit activity. This is the first genuinely
  new UX surface in the roadmap; keep it data-table-simple in this
  milestone, not the full "category-leading" experience (that's a later,
  dedicated UX milestone once there's more platform data to show).
- **Data model impact**: none beyond Milestone 1 — this milestone is
  read-only projections of existing data plus platform-role gating.
- **Tenant/RBAC implications**: platform visibility must remain strictly
  governance/health data. Any temptation to surface tenant findings/evidence
  "for support purposes" must be explicitly rejected or explicitly
  re-scoped with its own security review — not bundled into this milestone.
- **Required principal review**: yes — specifically a sentinel-leak-style
  adversarial pass on every new platform endpoint.
- **Acceptance boundary**: Super Admin can see org list, user list, and
  platform health; a sentinel value planted in a tenant's provider/finding/
  evidence data never appears in any platform-level response.
- **What must NOT be implemented yet**: organization suspension/deletion
  actions, platform-level policy administration, integration governance UI.

---

## Milestone 3 — Unified Asset & Connector Foundation

**Business capability**: Extend the existing `inventory` and `connectors`
bounded contexts to support non-AI asset kinds, without building a second
inventory system — the foundation every later domain (network, cloud,
identity, application) builds on.

- **Bounded context ownership**: `inventory` (extended), `connectors`
  (extended).
- **Architectural prerequisites**: none beyond current state — this
  milestone deliberately does not depend on Milestones 1–2, since asset
  modeling is orthogonal to platform RBAC. It can run in parallel with
  Milestone 2 if resourcing allows, though this roadmap lists it
  sequentially for clarity.
- **Security prerequisites**: none new — inherits existing tenant-isolation
  requirements (Architecture doc Section 21).
- **Backend scope**: extend the `inventory` asset-kind taxonomy (currently
  `AIAsset`/`AITarget`) to add `NetworkAsset`, `CloudResource`,
  `IdentityAsset`, `ApplicationAsset` as sibling kinds behind a common
  `Asset` identity shape (id, organization_id, kind, name, tags,
  created_at); extend `connectors`' discover→normalize→ingest pipeline to be
  domain-parameterized rather than AI-specific; add a
  `DirectoryConnectorPort`-shaped protocol precedent (implementation comes
  in Milestone 6) so later milestones have a proven pattern to follow.
- **Frontend/product scope**: extend the existing asset/target list UI to
  filter/display by asset kind. No new domain-specific UI yet (no network
  topology view, no cloud resource view) — those come with their own
  milestones once real data exists.
- **Data model impact**: schema/migration extending the inventory tables (or
  document-store JSON shape, matching the existing `providers`-style
  document store precedent) to carry a `kind` discriminator plus per-kind
  metadata.
- **Tenant/RBAC implications**: none new — all new asset kinds are
  organization-scoped by default, following the existing `AITarget`/
  `AIAsset` precedent (in contrast to the deliberately-flagged
  `providers` exception).
- **Required principal review**: yes, focused narrowly on confirming this
  milestone does not create a second inventory system in practice (review
  the actual schema/queries, not just the intent).
- **Acceptance boundary**: a new asset kind can be created, listed, and
  tenant-isolated using the exact same code paths as `AITarget` today,
  proven by an analogous regression-test suite to
  `test_targets_api.py`.
- **What must NOT be implemented yet**: no real connector implementations
  for network/cloud/directory sources yet — this milestone proves the
  pattern with the existing AI connector as the only real implementation.

---

## Milestone 4 — Security Graph Evolution (Phase 1: Node/Edge Types)

**Business capability**: Extend the existing `KGProjection` to model the
node/edge types needed for cross-domain queries later, incrementally and
only as far ahead as Milestone 3's new asset kinds require.

- **Bounded context ownership**: `knowledge` (extended).
- **Architectural prerequisites**: Milestone 3 (new asset kinds exist to
  project).
- **Security prerequisites**: none new.
- **Backend scope**: add graph node types (`Identity`, `Group`, `Device`,
  `Network`, `Cloud Account`, `Cloud Resource` — added only as their owning
  milestone approaches, not all at once) and edge types (`MEMBER_OF`,
  `CAN_ACCESS`, `EXPOSES`) to the existing `ProjectionRegistry` /
  `KGProjection` pattern.
- **Frontend/product scope**: none — no graph UI change in this milestone,
  since there isn't yet enough cross-domain data to make a graph view
  meaningful (Architecture doc Section 16 explicitly warns against building
  path-finding UI before there's more than one domain to path across).
- **Data model impact**: graph schema/ontology extension only — no new
  relational tables.
- **Tenant/RBAC implications**: graph queries must remain organization-
  scoped, matching every other read path.
- **Required principal review**: light — an ontology review to avoid
  duplicate/overlapping edge semantics (Architecture doc Section 16).
- **Acceptance boundary**: new node/edge types round-trip through the
  existing projection pipeline without regressing `KGProjection`'s existing
  AI-asset projection behavior (verified by the existing KG test suite plus
  new node/edge-specific tests).
- **What must NOT be implemented yet**: cross-domain attack-path
  computation/UI (needs at least two real domains populated first — see
  Milestone 8+).

---

## Milestone 5 — Live Operation State (Read Model + UX)

**Business capability**: Replace the current simple campaign-only progress
display with a domain-agnostic "live operation" read model
(`DISCOVERY → INVENTORY → PLANNING → VALIDATION → EXECUTION → EVALUATION →
EVIDENCE → FINDING → RISK`) so every future domain's in-progress work has a
truthful, non-fabricated UX from day one.

- **Bounded context ownership**: `platform` (extended read-model/projection
  usage), no new bounded context.
- **Architectural prerequisites**: Milestone 3 (asset foundation) so the
  read model can reference any asset kind, not only AI targets.
- **Security prerequisites**: none new.
- **Backend scope**: a generalized "operation state" projection built the
  same way `CampaignProjection` already works, parameterized by operation
  type rather than hardcoded to red-team campaigns.
- **Frontend/product scope**: a reusable "live operation" component
  replacing the campaign-specific progress UI, consuming only real
  projected state — explicitly no fabricated progress bars or synthetic
  events (Architecture doc Section 17).
- **Data model impact**: new read-model table/projection, no change to
  existing campaign persistence (`campaign_results` continues to work
  as-is; the new projection is additive).
- **Tenant/RBAC implications**: none new.
- **Required principal review**: light — confirm no operation stage can be
  displayed as "in progress" or "complete" without a corresponding real
  persisted event.
- **Acceptance boundary**: the existing red-team campaign UI is migrated to
  the new generalized component with zero behavior regression (verified by
  the existing campaign UI test suite from Sprint 42–43, extended).
- **What must NOT be implemented yet**: no new domain actually running
  through this yet (network/cloud execution doesn't exist until later
  milestones) — this milestone only proves the pattern generalizes using
  the existing AI red-team pipeline as the reference implementation.

---

## Milestone 6 — Identity/Directory Visibility

**Business capability**: Ingest identity/directory data (users, groups,
privileged/service identities) as read-only inventory + graph data via
authorized connectors.

- **Bounded context ownership**: new `directory_identity` context, building
  on `connectors`/`inventory` from Milestone 3.
- **Architectural prerequisites**: Milestones 3–4 (asset foundation + graph
  node types for Identity/Group).
- **Security prerequisites**: connector credentials follow the exact
  `CredentialResolverPort` pattern from Sprint 42–43 — no exceptions, no new
  credential-handling pattern invented for this milestone.
- **Backend scope**: `DirectoryConnectorPort` protocol + first
  implementation (one provider — LDAP/AD or a modern IdP, decided at
  implementation time); ingestion into `IdentityAsset` inventory + graph.
- **Frontend/product scope**: identity/directory list view under the
  existing asset-browsing UX pattern (extends Milestone 3's UI, no new UX
  paradigm).
- **Data model impact**: new inventory asset-kind records (already schema-
  supported by Milestone 3); no schema change beyond that.
- **Tenant/RBAC implications**: connector configuration is organization-
  scoped (an org configures its own directory connector), in contrast to
  the deliberately-shared `providers` design — this should be a conscious,
  documented choice at implementation time, not a repeat of the ambiguity
  flagged in Sprint 42–43.
- **Required principal review**: yes — first credential-handling connector
  since Sprint 42–43; must include a sentinel-leak test analogous to
  `test_credential_leak.py`.
- **Acceptance boundary**: directory data ingests read-only; connector
  credential never appears in any API response, log, or exception (proven
  by sentinel test); disabling/removing a connector stops ingestion without
  deleting already-ingested inventory.
- **What must NOT be implemented yet**: write-back to the source directory;
  automated identity risk scoring (that's a `findings`/`posture` capability
  to add once there's enough directory data to score against).

---

## Milestone 7 — Network Discovery & Passive Monitoring

**Business capability**: Authorized passive network asset discovery (hosts,
IPs, ports/services, topology) — explicitly **not** active
scanning/exploitation in this milestone.

- **Bounded context ownership**: new `network_security` context.
- **Architectural prerequisites**: Milestones 3–4 (asset foundation, graph
  node types for Network/Device).
- **Security prerequisites**: `operation_mode: passive` is a mandatory,
  enforced field on every operation this context can perform in this
  milestone — there is no active mode yet, so this is trivially satisfied
  by only implementing passive discovery, but the field must exist now so
  Milestone 9's active mode is additive rather than requiring a schema
  migration and re-review of every existing operation.
- **Backend scope**: passive discovery connector(s), ingestion into
  `NetworkAsset` inventory + graph (`Network`, `Device`, `Service` nodes;
  `CONNECTED_TO`, `RUNS_ON` edges).
- **Frontend/product scope**: network asset/topology list view (table-first,
  not a fancy topology visualization yet — that's a later UX investment
  once there's enough real topology data to justify it).
- **Data model impact**: new inventory asset-kind records (Milestone 3
  pattern); graph edges from Milestone 4's ontology.
- **Tenant/RBAC implications**: organization-scoped, no exceptions.
- **Required principal review**: yes — first bounded context with any
  potential for active-mode escalation later; review must confirm
  `operation_mode` is genuinely enforced, not just present as an unused
  field.
- **Acceptance boundary**: passive discovery populates inventory/graph;
  attempting to set `operation_mode: active` is rejected (feature doesn't
  exist yet — reject, don't silently ignore).
- **What must NOT be implemented yet**: any active scanning, exploitation,
  or vulnerability validation — that is Milestone 9, gated on the
  authorization-boundary work in Milestone 9 itself, not on this milestone.

---

## Milestone 8 — Multi-Cloud Exposure (Read-Only)

**Business capability**: Cloud asset inventory, IAM/identity risk, public
attack surface, and configuration posture for AWS/Azure/GCP via connectors —
read-only exposure visibility, not active cloud red-teaming.

- **Bounded context ownership**: new `cloud_security` context, on
  `connectors`/`inventory` (Milestone 3).
- **Architectural prerequisites**: Milestones 3–4, and ideally Milestone 6
  (identity) since cloud IAM risk is meaningfully an identity + cloud
  cross-domain concern — this is the first milestone where the unified
  graph (Milestone 4) starts to pay off with real cross-domain queries
  (identity → cloud workload).
- **Security prerequisites**: cloud provider credentials via
  `CredentialResolverPort`, same as every prior connector.
- **Backend scope**: per-provider connector (start with one), ingestion into
  `CloudResource` inventory + graph (`Cloud Account`, `Cloud Resource`
  nodes; `CAN_ASSUME`, `TRUSTS`, `EXPOSES` edges); misconfiguration findings
  feed the existing `findings`/`posture` pipeline unchanged.
- **Frontend/product scope**: cloud asset/exposure list view; first simple
  cross-domain attack-path query UI becomes viable here (identity →
  cloud), per Architecture doc Section 16's "at least two domains populated"
  threshold.
- **Data model impact**: new inventory asset-kind records; no new pipeline.
- **Tenant/RBAC implications**: organization-scoped.
- **Required principal review**: yes — cloud IAM data is sensitive; review
  must confirm no cloud credential or resolved secret ever appears in
  findings/evidence/API responses (sentinel test required).
- **Acceptance boundary**: cloud misconfiguration produces a real `Finding`
  through the existing pipeline, unmodified; a sentinel cloud credential
  never leaks; a real (even if simple) identity→cloud attack-path query
  returns correct graph traversal results.
- **What must NOT be implemented yet**: active cloud exploitation/red-team
  execution — that depends on Milestone 9's authorization boundary plus
  its own cloud-specific execution adapter, out of scope here.

---

## Milestone 9 — Controlled PT / Red-Team Operations Boundary

**Business capability**: Build the authorization/approval/audit boundary
for controlled offensive operations (network active-mode, future C2/PT
framework integration) — **boundary only, no offensive framework adapter**.

- **Bounded context ownership**: new `offensive_operations` context.
- **Architectural prerequisites**: Milestone 1 (platform audit
  infrastructure pattern), Milestone 7 (network passive mode exists as the
  first consumer of this boundary's active-mode gate).
- **Security prerequisites**: this milestone *is* the security prerequisite
  for everything after it — `AuthorizationScope`, `OperatorPermission`,
  `ApprovalGate`, kill switch, credential isolation (via
  `CredentialResolverPort`, no exceptions), immutable audit via
  `platform_events`, tenant isolation matching campaigns today.
- **Backend scope**: the boundary primitives listed above, plus wiring
  Milestone 7's `operation_mode: active` gate to require a satisfied
  `AuthorizationScope` + `ApprovalGate` before any active network operation
  can run. No C2/Metasploit/external-framework adapter is built or
  integrated in this milestone.
- **Frontend/product scope**: authorization-scope request/approval UI
  (who requests, who approves, expiry) — minimal, workflow-focused.
- **Data model impact**: new tables for `AuthorizationScope`,
  `ApprovalGate` records, operator permissions; audit via existing event
  store.
- **Tenant/RBAC implications**: organization-scoped scope/approval records;
  a new `OperatorPermission` layer distinct from viewing permissions.
- **Required principal review**: yes — mandatory, adversarial. Attempt to
  start an active operation without an approved scope; attempt to reuse an
  expired scope; attempt cross-tenant scope reuse. All must fail.
- **Acceptance boundary**: an active network operation cannot start without
  an active, unexpired, approved `AuthorizationScope`; kill switch halts a
  running operation; every scope/approval/execution event is immutably
  audited; a sentinel operator credential never leaks.
- **What must NOT be implemented yet**: any actual C2 orchestration,
  Metasploit integration, or external red-team framework adapter — those
  are future milestones, individually reviewed, that plug into this
  boundary once it exists and is proven.

---

## Milestone 10 — AI Red Team Graph/Compliance Unification

**Business capability**: Ensure AI red-teaming's existing findings/evidence/
risk data participates fully in the now-multi-domain graph and becomes
mappable to compliance controls, closing the loop the Architecture doc
warns about (AI security must never be a disconnected module).

- **Bounded context ownership**: `red_team`/`findings`/`posture` (minor
  extension: `source_domain` discriminator), `knowledge` (graph edges
  linking AI findings to the same node types other domains use), new
  `compliance` context begins here.
- **Architectural prerequisites**: Milestones 3–4 (asset/graph foundation
  now populated by multiple domains), Milestone 8 (at least cloud+AI+
  identity domains exist for meaningful cross-domain compliance mapping).
- **Security prerequisites**: none new.
- **Backend scope**: add `source_domain` to `Finding`; begin the
  `compliance` context (`ControlCatalog`, `Framework`,
  `ControlRequirement`) mapping existing findings to a first framework
  (e.g., OWASP or MITRE ATT&CK, chosen at implementation time) with the
  enum-constrained `ControlStatus` (never free-text `CERTIFIED`/
  `COMPLIANT`).
- **Frontend/product scope**: control-mapping/posture view — the first
  compliance UX surface, deliberately minimal (one framework, read-only
  status) rather than all frameworks at once.
- **Data model impact**: new `compliance` schema (control catalog, control-
  to-finding mapping); `source_domain` column/field on `Finding`.
- **Tenant/RBAC implications**: organization-scoped compliance posture.
- **Required principal review**: yes — specifically confirm the
  `ControlStatus` enum is enforced at the schema/response level such that
  returning a free-text "certified" claim is structurally impossible, not
  merely discouraged by convention.
- **Acceptance boundary**: an AI red-team finding and a cloud
  misconfiguration finding can both map to the same control requirement and
  both display through the same UI component; no response can contain the
  literal string "CERTIFIED" or "COMPLIANT".
- **What must NOT be implemented yet**: multi-framework support, auditor
  workflow/sign-off tooling, automated control remediation.

---

## Milestone 11 — Advanced Enterprise Control-Plane UX

**Business capability**: The category-leading control-plane experience
(platform overview, organization security overview, live operations,
concise findings, graph-driven attack-path investigation) the current
simple dashboard does not yet provide.

- **Bounded context ownership**: frontend-primarily; consumes all prior
  bounded contexts' read models. No new backend bounded context.
- **Architectural prerequisites**: all of Milestones 1–10 — this is
  deliberately last. A polished control-plane UX built before enough real
  domains/data exist would be decorating an empty platform; the roadmap
  prioritizes foundations first per the architecture assessment's explicit
  guidance.
- **Security prerequisites**: none new — this milestone only surfaces data
  that already passed its own domain's security review.
- **Backend scope**: aggregation/read-model endpoints for dashboard
  summaries (org security overview counts, critical findings, attack-path
  highlights) — thin aggregation over existing projections, no new business
  logic.
- **Frontend/product scope**: the full experience described in the
  originating vision — platform control plane, organization security
  overview, live operations (using Milestone 5's generalized component),
  concise findings UX (Section 18 structure), graph-driven attack-path
  investigation (using Milestone 4/8's graph capability). Must not copy
  proprietary code, branding, or product text from any named vendor —
  architectural/interaction patterns only.
- **Data model impact**: none beyond read aggregation.
- **Tenant/RBAC implications**: none new — pure presentation over
  already-authorized data.
- **Required principal review**: standard UX/product review; security
  review only needed if new aggregation endpoints expose data in
  combinations not previously reviewed together (e.g., cross-domain summary
  counts) — check for unintended inference leaks even in aggregate data.
- **Acceptance boundary**: dashboard reflects real data from at least
  network, cloud, identity, and AI domains simultaneously; no fabricated
  data anywhere; no vendor-copied assets.
- **What must NOT be implemented yet**: nothing further — this is the
  terminal milestone of this roadmap. Future capability domains (additional
  cloud providers, additional compliance frameworks, C2 framework adapters
  under Milestone 9's boundary) become their own follow-on roadmaps.

---

## Dependency Graph Summary

```
M1 Platform Identity/Super Admin
  └─> M2 Platform RBAC / Governance Control Plane
M3 Unified Asset & Connector Foundation (parallel-capable with M1/M2)
  └─> M4 Security Graph Evolution (node/edge types)
  └─> M5 Live Operation State (read model + UX)
  └─> M6 Identity/Directory Visibility
  └─> M7 Network Discovery (passive only)
        └─> M9 Controlled PT/Red-Team Boundary (also needs M1's audit pattern)
  └─> M8 Multi-Cloud Exposure (benefits from M6 identity data)
        └─> M10 AI Red Team Graph/Compliance Unification (needs M3/M4/M8)
M1..M10 ──────────────────────────────────────────> M11 Advanced Control-Plane UX
```

Milestones 3 and 1 can run in parallel (asset modeling is independent of
platform RBAC). Milestone 11 is strictly last — it has no independent value
without the domains it visualizes.
