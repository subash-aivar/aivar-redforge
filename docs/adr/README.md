# Architecture Decision Records

This folder contains Architecture Decision Records (ADRs) for AIVAR RedForge.

ADRs document significant architectural decisions with their context, rationale, and consequences. They serve as a historical record that helps current and future engineers understand why the system is designed the way it is.

## Format

Each ADR follows this structure:

- **Status** — Proposed, Accepted, Deprecated, or Superseded.
- **Date** — When the decision was made.
- **Context** — The problem or situation that motivated the decision.
- **Decision** — What was decided.
- **Consequences** — The resulting trade-offs.
- **Alternatives Considered** — What else was evaluated.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-clean-architecture.md) | Clean Architecture with Domain-Driven Boundaries | Accepted |
| [0002](0002-async-first.md) | Async-First Backend Architecture | Accepted |
| [0003](0003-evidence-immutability.md) | Evidence Immutability as Architectural Constraint | Accepted |
| [0004](0004-plugin-based-attack-engine.md) | Plugin-Based Attack Engine | Accepted |
| [0005](0005-canonical-identifier-strategy.md) | Canonical Identifier Strategy — ULID via Shared EntityId | Accepted |
| [0006](0006-network-defense-detection-pipeline-ownership.md) | Network Defense Detection/Alerting Pipeline Ownership (Family A vs. siem_*) | Accepted |
| [0007](0007-threat-intelligence-ownership-for-new-product-work.md) | Threat Intelligence Ownership for New Product Work (M51 Native Suite vs. Legacy) | Accepted |
| [0008](0008-network-sensor-product-boundary.md) | Network Sensor Product Boundary (BYO + Future RedForge-Managed Sensor) | Accepted (boundary only) |
| [0009](0009-product-edition-architecture.md) | Product Edition Architecture (Full RedForge + Network Defense Edition) | Accepted (design only) |
