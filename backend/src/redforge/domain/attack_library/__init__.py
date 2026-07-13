"""Attack Library bounded context.

Enterprise knowledge catalog of AI security techniques. Defines every
attack RedForge understands. Execution engines consume these definitions.
Designed to scale to 10,000+ attack definitions.

Public API:
    - AttackDefinition: Aggregate root with lifecycle behavior.
    - AttackLibraryRepository: Persistence interface (Protocol).
    - Value objects: AttackCategory, AttackTechnique, AttackSeverity, etc.
    - AttackTaxonomyNode / AttackTaxonomyRepository: the hierarchical,
      unlimited-depth classification tree (taxonomy.py) — see that
      module's docstring for how it relates to AttackCategory.
"""

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.repository import AttackLibraryRepository
from redforge.domain.attack_library.taxonomy import (
    AttackTaxonomyNode,
    AttackTaxonomyRepository,
    TaxonomyNodeKey,
)
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackPrerequisite,
    AttackReference,
    AttackRelationship,
    AttackRelationshipType,
    AttackSeverity,
    AttackStatus,
    AttackTechnique,
    AttackVersion,
    Capability,
    CvssMetadata,
    EvaluationRequirement,
    ExecutionStrategy,
    ExpectedOutcome,
    FrameworkMapping,
    ProviderCompatibility,
    SafetyClassification,
)

__all__ = [
    "AttackCategory",
    "AttackDefinition",
    "AttackLibraryRepository",
    "AttackMaturity",
    "AttackPrerequisite",
    "AttackReference",
    "AttackRelationship",
    "AttackRelationshipType",
    "AttackSeverity",
    "AttackStatus",
    "AttackTaxonomyNode",
    "AttackTaxonomyRepository",
    "AttackTechnique",
    "AttackVersion",
    "Capability",
    "CvssMetadata",
    "EvaluationRequirement",
    "ExecutionStrategy",
    "ExpectedOutcome",
    "FrameworkMapping",
    "ProviderCompatibility",
    "SafetyClassification",
    "TaxonomyNodeKey",
]
