"""ISecurityGraphWritePort — outbound port for Security Graph campaign ontology writes.

Writes campaign evaluation nodes and edges to the Security Graph after evaluation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import MitreAttackRef


class ISecurityGraphWritePort(ABC):
    """Write campaign evaluation ontology to the Security Graph.

    All writes are idempotent under event replay (graph nodes are upserted).
    """

    @abstractmethod
    async def upsert_campaign_evaluation_node(
        self,
        tenant_id: str,
        evaluation_id: str,
        campaign_instance_id: str,
        composite_outcome: str,
        detection_coverage_pct: float,
    ) -> None:
        """Create or update a CampaignEvaluationNode in the Security Graph."""

    @abstractmethod
    async def upsert_covered_technique_edges(
        self,
        tenant_id: str,
        evaluation_id: str,
        technique_refs: list[MitreAttackRef],
        detected_technique_ids: frozenset[str],
        succeeded_technique_ids: frozenset[str],
    ) -> None:
        """Create or update COVERED_TECHNIQUE edges from CampaignEvaluationNode
        to each MitreAttackTechniqueNode, with detected/success flags.
        """

    @abstractmethod
    async def upsert_evaluated_by_edge(
        self,
        tenant_id: str,
        campaign_instance_id: str,
        evaluation_id: str,
    ) -> None:
        """Create or update EVALUATED_BY edge from CampaignInstanceNode to
        CampaignEvaluationNode.
        """
