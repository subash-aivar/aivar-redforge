# ADR-0009: Product Edition Architecture (Full RedForge + Network Defense Edition)

## Status

Accepted (design only — not implemented in this phase)

## Date

2026-09-08

## Context

A repository-first audit (Network Defense Edition Phase 0) confirmed no
product-edition or deployment-profile concept exists anywhere today:

- **RBAC** (`redforge.domain.identity`/`platform_identity`) is a single
  `role -> frozenset[Permission]` table (`ROLE_PERMISSIONS`), explicitly
  documented as the *only* authorization mechanism in the system, with no
  per-deployment/edition variation axis.
- **Backend router registration** (`app.py`'s `_register_routers` ->
  `api/v1/__init__.py`) unconditionally includes all ~96 bounded-context
  routers. Zero precedent for conditional/settings-driven inclusion
  exists anywhere in `app.py`.
- **Frontend navigation** (`frontend/src/components/navigation/navConfig.ts`)
  is already a single declarative `NAV_GROUPS: NavGroup[]` array of
  `{label, href, icon, perm?}`, filtered through one `can()` closure in
  `frontend/src/app/(app)/layout.tsx` — permission-based hiding already
  exists as a pattern, but no edition-based filtering does.
- **CI/CD** is one workflow (`.github/workflows/ci.yml`) producing one
  backend Docker image tag and no frontend build/test job at all.
- **Deployment** is a single `docker-compose.yml`/two `Dockerfile`s
  (backend, frontend), no Kubernetes/Helm manifests anywhere, no
  build-arg-driven image variants.
- **Database migrations** are a single strictly linear Alembic chain
  (confirmed: one `down_revision` per file, current head `0168`), with
  no branching.

The mission requires one repository to produce two separately
deployable products — Full RedForge and RedForge Network Defense
Edition — reusing the canonical shared core (identity/RBAC, evidence,
asset inventory, investigation, connector framework, audit/observability,
response/governance, and Threat Intelligence per ADR-0007) without
forking any of it.

## Decision

Introduce exactly one new, explicit concept: **`product_edition`**, with
values `full` and `network_defense` (e.g. a `Settings.product_edition:
Literal["full", "network_defense"]`, driven by an environment variable
such as `REDFORGE_PRODUCT_EDITION`, default `full`).

This single concept is the only new primitive, and it controls exactly
these five things — no more:

1. **Backend router exposure** — a single, explicit allow-list constant
   (e.g. `NETWORK_DEFENSE_ROUTERS: frozenset[str]`) checked once inside
   `_register_routers`/`api/v1/__init__.py`'s registration flow, not 96
   scattered `if` statements at each router's own call site. When
   `product_edition == "network_defense"`, only allow-listed routers
   (identity/RBAC, evidence, investigation, asset inventory, connector
   framework, `ddos`/`behavior`/`network_security`/`telemetry`, the M51
   Threat Intelligence suite, response/governance) are mounted.
2. **Frontend shell/navigation** — extend `NavItem`/`NavGroup` with an
   optional `editions?: ("full" | "network_defense")[]` field, filtered
   alongside the existing `can()` permission check in the same place.
   Absence of the field means "all editions" (mirrors how absence of
   `perm` today means "no permission gate").
3. **Build artifact** — one `backend/Dockerfile` family, parameterized by
   a build arg (e.g. `ARG PRODUCT_EDITION=full`) that bakes
   `REDFORGE_PRODUCT_EDITION` as the image's default environment value;
   likewise one `frontend/Dockerfile` parameterized by
   `NEXT_PUBLIC_PRODUCT_EDITION`. Two image tags result
   (`redforge-backend:full`, `redforge-backend:network_defense`, and
   equivalent frontend tags) from one Dockerfile each — not two
   Dockerfiles, not two repositories.
4. **Deployment configuration** — a Network Defense Edition deployment
   sets `REDFORGE_PRODUCT_EDITION=network_defense` (and the matching
   frontend build-time variable) and otherwise uses the same deployment
   shape (Docker Compose today; Kubernetes/Helm if/when that is built —
   itself a separate future decision, not addressed by this ADR).
5. **CI artifact generation** — extend the existing single `ci.yml`
   workflow with a build matrix (`edition: [full, network_defense]`) on
   the existing `docker` job, rather than a second workflow file duplicating
   lint/typecheck/test.

## What this must NOT become

- **Not a second RBAC system.** `ROLE_PERMISSIONS` stays exactly as it
  is; a Network Defense Edition user simply never reaches a route/nav
  item their edition doesn't expose. Permission semantics are identical
  across editions — edition only changes *what surface exists to check
  permissions against*, never *how permissions are evaluated*.
- **Not hundreds of scattered feature-flag checks.** Exactly one
  allow-list on the backend, one filter field on the frontend nav — both
  centralized, both reusing an existing single-checkpoint pattern
  (`_register_routers`'s one registration flow; `layout.tsx`'s one
  `can()` closure) rather than introducing per-call-site conditionals
  throughout the 96 router modules or the nav tree.
- **Not a forked database migration chain.** Both editions run migrations
  against the same single linear Alembic chain. Any Network Defense
  Edition-specific schema (if ever needed) is an additive migration like
  any other, on the same chain, never a branch.
- **Not a copied repository.** One repository, one `main`, one shared
  core (per ADR-0006/0007/0008 for the network-specific pieces of that
  core) — confirmed as the mission's explicit non-negotiable constraint
  and reaffirmed here.

## Consequences

- Full RedForge is unaffected by default (`product_edition` defaults to
  `full`, preserving exactly today's behavior with zero opt-in).
- A Network Defense Edition build is smaller in both API surface and
  navigable UI, satisfying "avoid exposing unnecessary product surfaces
  where technically practical" without a second RBAC model or a
  maintenance-heavy scattered-flag approach.
- The two centralization points (one router allow-list, one nav filter
  field) mean future edition-scoping decisions have one obvious place to
  be made, not a growing list of ad hoc conditionals discovered later.
- This ADR records the *design* only. No code implementing
  `product_edition`, the router allow-list, or the nav filter field is
  written in this phase (Phase 0/1) — implementation is deliberately a
  separate, later step per the mission's phased sequencing.

## Alternatives Considered

- **Per-router-module settings check** (96 individual `if settings...`
  guards at each `include_router` call site) — rejected: exactly the
  "hundreds of scattered feature-flag checks" the mission explicitly
  rules out; a single allow-list is equivalent in effect and far less
  error-prone to maintain as new bounded contexts are added.
- **A second, edition-specific RBAC permission set** — rejected: doubles
  the authorization model the identity ADR/docstrings already assert is
  singular; edition-based route/nav filtering achieves the same product
  goal without touching authorization semantics at all.
- **Two separate Dockerfiles / two separate repositories** — rejected:
  the mission explicitly rules out a copied repository, and two
  Dockerfiles would immediately drift (base image patches, dependency
  bumps, security fixes applied to one and forgotten in the other);
  one parameterized Dockerfile family avoids that by construction.
- **A forked migration chain** (edition-specific migration branches) —
  rejected: reintroduces exactly the kind of schema drift risk a single
  linear chain exists to prevent, for a problem (edition-specific UI/API
  surface) that doesn't actually require schema divergence to solve.
