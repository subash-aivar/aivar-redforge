"""IDetectionEvidenceRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.aggregates.detection_evidence import DetectionEvidence
    from detection.domain.value_objects.identifiers import (
        DetectionEvidenceId,
        DetectionExceptionId,
        DetectionFindingId,
        TenantId,
    )


class IDetectionEvidenceRepository(ABC):
    @abstractmethod
    async def save(self, evidence: DetectionEvidence) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        evidence_id: DetectionEvidenceId,
        tenant_id: TenantId,
    ) -> DetectionEvidence | None: ...

    @abstractmethod
    async def find_by_finding(
        self,
        finding_id: DetectionFindingId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionEvidence]: ...

    @abstractmethod
    async def find_by_exception(
        self,
        exception_id: DetectionExceptionId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionEvidence]: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionEvidence]: ...
