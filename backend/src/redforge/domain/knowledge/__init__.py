"""Knowledge bounded context.

Reusable AI security knowledge: attack definitions, validation packs,
compliance rules, detection logic, provider profiles. The Execution Engine
consumes published Knowledge Items to perform security validations.

Public API:
    - KnowledgeItem: Aggregate root with lifecycle behavior.
    - KnowledgeRepository: Persistence interface (Protocol).
    - Value objects: KnowledgeCategory, KnowledgeStatus, KnowledgeVersion, etc.
"""

from redforge.domain.knowledge.entity import KnowledgeItem
from redforge.domain.knowledge.repository import KnowledgeRepository
from redforge.domain.knowledge.value_objects import (
    KnowledgeCategory,
    KnowledgeReference,
    KnowledgeSource,
    KnowledgeStatus,
    KnowledgeVersion,
)

__all__ = [
    "KnowledgeCategory",
    "KnowledgeItem",
    "KnowledgeReference",
    "KnowledgeRepository",
    "KnowledgeSource",
    "KnowledgeStatus",
    "KnowledgeVersion",
]
