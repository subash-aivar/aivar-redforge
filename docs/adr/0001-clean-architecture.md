# ADR-0001: Clean Architecture with Domain-Driven Boundaries

## Status

Accepted

## Date

2025-01-01

## Context

AIVAR RedForge is a long-lived enterprise platform that will be maintained by hundreds of engineers over a decade. The platform requires clear separation of concerns to support independent evolution of business logic, infrastructure adapters, and transport layers.

## Decision

We adopt Clean Architecture with the following layering:

- **core/** — Configuration, exceptions, logging. Zero external dependencies. Everything else depends on core.
- **domain/** — Pure Python business logic. Depends only on core. Never imports from infrastructure or api.
- **shared/** — Cross-domain primitives (base entities, value objects, domain events) shared between bounded contexts.
- **infrastructure/** — Framework adapters (database, middleware, external services). Depends inward on core.
- **api/** — HTTP transport. Thin orchestration layer. Depends on core and domain.

The dependency rule is strictly enforced: dependencies point inward only.

## Consequences

- Business logic is framework-independent and trivially testable.
- Infrastructure can be swapped without touching domain code.
- Each bounded context can be extracted to a microservice with minimal refactoring.
- New engineers must understand the layering rules before contributing.
- More files and packages than a flat structure, but each has a clear responsibility.

## Alternatives Considered

- **Flat module structure** — Simpler initially but becomes unmaintainable at scale.
- **Feature-slice architecture** — Good for small teams, but doesn't enforce the separation needed for 100+ engineers.
