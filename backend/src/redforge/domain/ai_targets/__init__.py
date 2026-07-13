"""AI Target bounded context.

Represents AI systems under continuous security validation. Every validation
run, evidence artifact, and finding relates to an AI Target.

Public API:
    - AITarget: Aggregate root with lifecycle behavior.
    - AITargetRepository: Persistence interface (Protocol).
    - Value objects: TargetName, EndpointUrl, Provider, TargetType, TargetStatus, Tag.
    - Events: TargetRegistered, TargetActivated, etc.
    - Exceptions: TargetNotFoundError, TargetArchivedError, etc.
"""

from redforge.domain.ai_targets.entity import AITarget
from redforge.domain.ai_targets.repository import AITargetRepository
from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    Tag,
    TargetMetadata,
    TargetName,
    TargetStatus,
    TargetType,
    ValidationPolicyReference,
)

__all__ = [
    "AITarget",
    "AITargetRepository",
    "EndpointUrl",
    "Provider",
    "Tag",
    "TargetMetadata",
    "TargetName",
    "TargetStatus",
    "TargetType",
    "ValidationPolicyReference",
]
