"""Thin operation projection façade — delegates to execution red-team projections.

Operation owns OperationNode / EXECUTED_ACTION graph writes via its
ISecurityGraphWritePort; timeline read models are owned by the shared
red-team projection coordinator under execution.
"""

from __future__ import annotations

from operation.infrastructure.graph.in_memory_security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)

__all__ = ["InMemorySecurityGraphWriteAdapter"]
