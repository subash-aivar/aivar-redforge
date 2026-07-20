"""Thin engagement projection façade — delegates to execution red-team projections.

Engagement owns EngagementNode / CONTAINS_OPERATION graph writes via its
ISecurityGraphWritePort; read models are owned by the shared red-team
projection coordinator under execution (M29_M30_INTEGRATION_ARCHITECTURE).
"""

from __future__ import annotations

from engagement.infrastructure.graph.in_memory_security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)

__all__ = ["InMemorySecurityGraphWriteAdapter"]
