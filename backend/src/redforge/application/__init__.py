"""Application Layer — use case orchestration.

Coordinates repositories, unit of work, domain behavior, and event
publishing. Every transport adapter (REST, CLI, GraphQL, MCP, workers)
calls application services. Controllers contain zero logic.
"""
