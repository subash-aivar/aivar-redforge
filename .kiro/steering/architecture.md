---
inclusion: auto
---

# AIVAR RedForge — Architecture & Engineering Standards

This document governs all architectural decisions for the AIVAR RedForge platform.
It is authoritative and must not be contradicted by any code generation.

## Product Identity

- **Product:** AIVAR RedForge
- **Mission:** Build the world's most trusted Continuous AI Security Validation Platform.
- **Philosophy:** Evidence First. Evidence is immutable. Evidence is the source of truth.

## Supported AI Targets

- LLM Applications
- AI Agents
- RAG Systems
- MCP Servers
- AI APIs
- Autonomous Agent Systems
- Future AI Platforms

## Architecture Style

- Clean Architecture
- Domain Driven Design
- Hexagonal Architecture (Ports & Adapters)
- SOLID Principles
- Dependency Injection (manual, constructor-based)
- Repository Pattern
- Unit of Work
- CQRS where appropriate
- Event Driven Design where appropriate
- Secure by Design
- API First
- Testability First
- Observability First

## Layering Rules

- Business logic must NEVER depend on frameworks (FastAPI, SQLAlchemy, etc.)
- Frameworks are implementation details (outer ring)
- The domain layer must remain pure Python
- Every layer has a single responsibility
- Dependencies point inward only

## Scale Assumptions

- Millions of validation executions per day
- Thousands of enterprise customers
- Hundreds of contributing engineers
- Hundreds of AI providers
- Hundreds of attack plugins
- Hundreds of future integrations

## Code Quality Standards

- Strict typing (mypy strict mode)
- Meaningful naming
- Comprehensive docstrings where appropriate
- Small focused classes
- Small focused modules
- High cohesion, low coupling
- Readable code over clever code
- Composition over inheritance
- No circular dependencies
- No hidden coupling
- No god objects / giant services
- No duplicated logic
- No framework leakage into business logic

## Security Requirements

- Secure by default
- Validate every input
- Never trust external systems
- Audit every important operation
- Support RBAC
- Support API Keys
- Support future SSO
- Support future Multi-Tenant architecture
- Support future Compliance frameworks
- Never hardcode secrets

## Observability Requirements

- Structured logging (JSON)
- Correlation IDs
- Request IDs
- Health endpoints
- Readiness endpoints
- Metrics-ready architecture
- Tracing-ready architecture
- OpenTelemetry ready

## Testing Requirements

Architecture must naturally support:
- Unit Tests
- Integration Tests
- API Tests
- Repository Tests
- Validation Tests
- Attack Tests
- Evidence Tests
- End-to-End Tests

## Development Rules

- Never generate unnecessary code
- Never over-engineer
- Never introduce infrastructure before it is needed
- Every feature should be independently deployable
- Explain architectural decisions before writing code
- Explain trade-offs
- Mention future extension points
- Wait for approval before moving to the next milestone
