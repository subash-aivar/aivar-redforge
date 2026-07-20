"""ISecurityGraphWritePort — outbound port for execution Security Graph projection."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISecurityGraphWritePort(ABC):
    """Writes red-team execution ontology nodes/edges. Never queries the graph."""

    @abstractmethod
    async def project_attack_action_node(
        self,
        *,
        organization_id: str,
        action_id: str,
        technique_ref: str | None = None,
        state: str | None = None,
        timestamp: str | None = None,
        action_hash: str | None = None,
        operation_id: str | None = None,
        engagement_id: str | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_execution_worker_node(
        self,
        *,
        organization_id: str,
        worker_id: str,
        worker_type: str | None = None,
        trust_level: str | None = None,
        capabilities: list[str] | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_executed_action(
        self,
        *,
        organization_id: str,
        operation_id: str,
        action_id: str,
        sequence_number: int | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_used_technique(
        self,
        *,
        organization_id: str,
        action_id: str,
        technique_id: str,
        success: bool | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_executed_by(
        self,
        *,
        organization_id: str,
        action_id: str,
        worker_id: str,
        worker_trust_level: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_targeted(
        self,
        *,
        organization_id: str,
        action_id: str,
        asset_id: str,
        impact_observed: str | None = None,
        asset_kind: str = "asset",
    ) -> None: ...

    @abstractmethod
    async def project_used_payload(
        self,
        *,
        organization_id: str,
        action_id: str,
        payload_id: str,
        payload_version: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_caught_by_detection(
        self,
        *,
        organization_id: str,
        action_id: str,
        rule_id: str,
        detected_at: str | None = None,
        finding_id: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_evaded_detection(
        self,
        *,
        organization_id: str,
        action_id: str,
        rule_id: str,
        evaluated_at: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_produced_finding(
        self,
        *,
        organization_id: str,
        action_id: str,
        finding_id: str,
        finding_type: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_payload_node(
        self,
        *,
        organization_id: str,
        payload_id: str,
        payload_type: str | None = None,
        impact_ceiling: str | None = None,
        version: str | None = None,
    ) -> str | None: ...
