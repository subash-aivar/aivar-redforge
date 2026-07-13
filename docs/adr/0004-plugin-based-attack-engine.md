# ADR-0004: Plugin-Based Attack Engine

## Status

Accepted

## Date

2025-01-01

## Context

RedForge must support hundreds of attack types across multiple AI system categories (LLMs, agents, RAG, MCP servers). New attack types will be contributed by different teams and potentially by enterprise customers themselves.

## Decision

The attack engine will be plugin-based:

- Each attack type is a self-contained module implementing a common interface.
- Attacks are discovered and loaded at runtime via a plugin registry.
- Attacks declare their target type compatibility, required configuration, and output schema.
- The validation engine orchestrates attacks without knowing their implementation details.

The plugin interface will be defined when the attack engine milestone is reached. The current architecture supports this by keeping `domain/attacks/` as an independent bounded context.

## Consequences

- New attacks can be added without modifying existing code (Open/Closed Principle).
- Attacks can be packaged and distributed independently.
- Enterprise customers can develop custom attack packs.
- Plugin interface must be stable — breaking changes affect all attack authors.
- Plugin discovery and validation adds a small startup cost.

## Alternatives Considered

- **Hardcoded attack registry** — Simpler but doesn't scale to hundreds of attacks.
- **External scripting (Python exec)** — Security risk, harder to type-check and test.
