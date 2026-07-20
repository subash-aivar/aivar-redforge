"""ISecurityGraphWritePort — outbound port for Detection Security Graph projection."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISecurityGraphWritePort(ABC):
    """Writes detection ontology nodes/edges. Never queries the graph."""

    @abstractmethod
    async def project_detection_rule(
        self,
        *,
        organization_id: str,
        rule_id: str,
        rule_key: str,
        severity: str,
        confidence: str,
        lifecycle_state: str,
        version: str | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_detection_pack(
        self,
        *,
        organization_id: str,
        pack_id: str,
        pack_key: str,
        pack_category: str,
        version: str,
    ) -> str | None: ...

    @abstractmethod
    async def project_detection_finding(
        self,
        *,
        organization_id: str,
        finding_id: str,
        state: str,
        severity: str,
        detected_at: str,
        mitre_technique: str | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_telemetry_source(
        self,
        *,
        organization_id: str,
        source_id: str,
        source_type: str,
        health_status: str,
    ) -> str | None: ...

    @abstractmethod
    async def project_mitre_technique(
        self,
        *,
        organization_id: str,
        technique_id: str,
        tactic: str | None = None,
        name: str | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_detects(
        self,
        *,
        organization_id: str,
        rule_id: str,
        technique_id: str,
        confidence: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_covers(
        self,
        *,
        organization_id: str,
        pack_id: str,
        rule_id: str,
        version: str | None = None,
        added_at: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_produced(
        self,
        *,
        organization_id: str,
        rule_id: str,
        finding_id: str,
        version: str | None = None,
        execution_ref: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_finding_on(
        self,
        *,
        organization_id: str,
        finding_id: str,
        asset_id: str,
        observed_at: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_finding_involves(
        self,
        *,
        organization_id: str,
        finding_id: str,
        identity_id: str,
        actor_role: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_finding_correlates(
        self,
        *,
        organization_id: str,
        finding_id: str,
        instance_id: str,
        correlation_strength: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_finding_attributed(
        self,
        *,
        organization_id: str,
        finding_id: str,
        threat_actor_id: str,
        confidence: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_queries(
        self,
        *,
        organization_id: str,
        rule_id: str,
        source_id: str,
        query_type: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def project_escalated_to(
        self,
        *,
        organization_id: str,
        finding_id: str,
        investigation_id: str,
        escalated_at: str | None = None,
    ) -> None: ...
