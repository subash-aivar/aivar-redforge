"""Stub ACL adapters for evaluation — testing without live M28/M29/M24."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evaluation.domain.ports.i_attack_action_query_port import IAttackActionQueryPort
from evaluation.domain.ports.i_compliance_query_port import IComplianceQueryPort
from evaluation.domain.ports.i_detection_finding_query_port import IDetectionFindingQueryPort
from evaluation.domain.ports.i_evidence_query_port import IEvidenceQueryPort
from evaluation.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import (
        AttackActionRecord,
        ComplianceMappingResult,
        DetectionFindingRecord,
        EvidenceRecord,
        MitreAttackRef,
    )


class StubAttackActionQueryAdapter(IAttackActionQueryPort):
    def __init__(self, actions: list[AttackActionRecord] | None = None) -> None:
        self._actions = list(actions or [])

    async def list_by_campaign_instance(
        self, campaign_instance_id: str, tenant_id: str
    ) -> list[AttackActionRecord]:
        return list(self._actions)

    async def list_by_technique(
        self, campaign_instance_id: str, tenant_id: str, technique_id: str
    ) -> list[AttackActionRecord]:
        return [a for a in self._actions if a.technique_id == technique_id]


class StubDetectionFindingQueryAdapter(IDetectionFindingQueryPort):
    def __init__(self, findings: list[DetectionFindingRecord] | None = None) -> None:
        self._findings = list(findings or [])

    async def list_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: str,
        started_at: str,
        completed_at: str,
    ) -> list[DetectionFindingRecord]:
        return list(self._findings)

    async def list_by_technique(
        self, campaign_instance_id: str, tenant_id: str, technique_id: str
    ) -> list[DetectionFindingRecord]:
        return [f for f in self._findings if f.technique_id == technique_id]


class StubEvidenceQueryAdapter(IEvidenceQueryPort):
    def __init__(self, evidence: list[EvidenceRecord] | None = None) -> None:
        self._evidence = list(evidence or [])

    async def list_by_campaign_instance(
        self, campaign_instance_id: str, tenant_id: str
    ) -> list[EvidenceRecord]:
        return list(self._evidence)


class StubComplianceQueryAdapter(IComplianceQueryPort):
    def __init__(self, mappings: list[ComplianceMappingResult] | None = None) -> None:
        self._mappings = list(mappings or [])

    async def map_objectives(
        self, campaign_id: str, tenant_id: str, objective_ids: list[str]
    ) -> list[ComplianceMappingResult]:
        return [m for m in self._mappings if m.objective_id in objective_ids]


class StubSecurityGraphWriteAdapter(ISecurityGraphWritePort):
    def __init__(self) -> None:
        self.nodes: list[dict[str, object]] = []
        self.technique_edges: list[dict[str, object]] = []
        self.evaluated_by_edges: list[dict[str, object]] = []

    async def upsert_campaign_evaluation_node(
        self,
        tenant_id: str,
        evaluation_id: str,
        campaign_instance_id: str,
        composite_outcome: str,
        detection_coverage_pct: float,
    ) -> None:
        key = (tenant_id, evaluation_id)
        self.nodes = [n for n in self.nodes if (n["tenant_id"], n["evaluation_id"]) != key]
        self.nodes.append(
            {
                "tenant_id": tenant_id,
                "evaluation_id": evaluation_id,
                "campaign_instance_id": campaign_instance_id,
                "composite_outcome": composite_outcome,
                "detection_coverage_pct": detection_coverage_pct,
            }
        )

    async def upsert_covered_technique_edges(
        self,
        tenant_id: str,
        evaluation_id: str,
        technique_refs: list[MitreAttackRef],
        detected_technique_ids: frozenset[str],
        succeeded_technique_ids: frozenset[str],
    ) -> None:
        self.technique_edges = [
            e
            for e in self.technique_edges
            if not (e["tenant_id"] == tenant_id and e["evaluation_id"] == evaluation_id)
        ]
        for ref in technique_refs:
            self.technique_edges.append(
                {
                    "tenant_id": tenant_id,
                    "evaluation_id": evaluation_id,
                    "technique_id": ref.technique_id,
                    "detected": ref.technique_id in detected_technique_ids,
                    "success": ref.technique_id in succeeded_technique_ids,
                }
            )

    async def upsert_evaluated_by_edge(
        self,
        tenant_id: str,
        campaign_instance_id: str,
        evaluation_id: str,
    ) -> None:
        key = (tenant_id, campaign_instance_id, evaluation_id)
        self.evaluated_by_edges = [
            e
            for e in self.evaluated_by_edges
            if (e["tenant_id"], e["campaign_instance_id"], e["evaluation_id"]) != key
        ]
        self.evaluated_by_edges.append(
            {
                "tenant_id": tenant_id,
                "campaign_instance_id": campaign_instance_id,
                "evaluation_id": evaluation_id,
            }
        )
