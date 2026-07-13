"""Evidence bounded context.

Evidence is the immutable source of truth in RedForge. Every security check
against an AI target produces evidence — the raw request, response, result,
and supporting artifacts. Findings are always generated FROM evidence and
can be regenerated at any time.

Public API:
    - Evidence: Aggregate root (immutable after finalization).
    - EvidenceRepository: Persistence interface (append-only).
    - Value objects: EvidenceResult, Confidence, RequestPayload, etc.
    - Events: EvidenceRecorded, EvidenceFinalized, etc.
    - Exceptions: EvidenceImmutableError, etc.
"""

from redforge.domain.evidence.entity import Evidence
from redforge.domain.evidence.repository import EvidenceRepository
from redforge.domain.evidence.value_objects import (
    Artifact,
    AttackReference,
    Confidence,
    EvidenceResult,
    ExecutionMetadata,
    RequestPayload,
    ResponsePayload,
    TestCaseReference,
    TraceMetadata,
)

__all__ = [
    "Artifact",
    "AttackReference",
    "Confidence",
    "Evidence",
    "EvidenceRepository",
    "EvidenceResult",
    "ExecutionMetadata",
    "RequestPayload",
    "ResponsePayload",
    "TestCaseReference",
    "TraceMetadata",
]
