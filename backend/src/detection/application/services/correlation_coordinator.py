"""CorrelationCoordinator — async enrichment with retry; never blocks produce."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from detection.application._validation import validate_uuid
from detection.application.exceptions import (
    ApplicationNotFoundError,
)
from detection.domain.services.correlation import CorrelationService
from detection.domain.value_objects.enums import CorrelationStatus
from detection.domain.value_objects.identifiers import DetectionFindingId, TenantId

if TYPE_CHECKING:
    from collections.abc import Callable

    from detection.application.ports.i_unit_of_work import IUnitOfWork
    from detection.application.services.correlation_publisher import CorrelationPublisher
    from detection.domain.aggregates.detection_finding import DetectionFinding

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAY_S = 0.05


class CorrelationCoordinator:
    """
    Orchestrates asynchronous finding correlation.

    - Never invoked synchronously from ProduceFinding.
    - Retries transient failures.
    - Graceful degradation via CorrelationService.
    - No Security Graph writes.
    """

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        correlation_service: CorrelationService,
        publisher: CorrelationPublisher,
        *,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        self._uow_factory = uow_factory
        self._correlation = correlation_service
        self._publisher = publisher
        self._max_retries = max_retries

    async def correlate_finding(
        self,
        *,
        tenant_uuid: UUID,
        finding_id: UUID,
        refresh: bool = False,
    ) -> dict[str, object]:
        validate_uuid(tenant_uuid, "tenant_id")
        validate_uuid(finding_id, "finding_id")

        tenant_id = tenant_uuid
        finding_id_vo = DetectionFindingId(finding_id)
        await self._publisher.started(
            tenant_id=tenant_id, finding_id=str(finding_id_vo)
        )

        last_error: str | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                result = await self._run_once(
                    tenant_id=tenant_id,
                    finding_id=finding_id_vo,
                    refresh=refresh,
                )
                status = str(result["status"])
                succeeded = result["sources_succeeded"]
                failed = result["sources_failed"]
                assert isinstance(succeeded, int)
                assert isinstance(failed, int)
                await self._publisher.completed(
                    tenant_id=tenant_id,
                    finding_id=str(finding_id_vo),
                    status=status,
                    sources_succeeded=succeeded,
                    sources_failed=failed,
                )
                return result
            except ApplicationNotFoundError:
                raise
            except Exception as exc:
                last_error = str(exc)
                logger.warning(
                    "correlation_retry",
                    extra={"attempt": attempt, "error": last_error},
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(_RETRY_DELAY_S * attempt)

        reason = last_error or "correlation failed"
        await self._publisher.failed(
            tenant_id=tenant_id,
            finding_id=str(finding_id_vo),
            reason=reason,
        )
        return {
            "finding_id": str(finding_id_vo),
            "status": CorrelationStatus.FAILED.value,
            "sources_succeeded": 0,
            "sources_failed": 0,
            "error": reason,
        }

    async def _run_once(
        self,
        *,
        tenant_id: TenantId,
        finding_id: DetectionFindingId,
        refresh: bool,
    ) -> dict[str, object]:
        async with self._uow_factory() as uow:
            finding = await uow.detection_findings.find_by_id(finding_id, tenant_id)
            if finding is None:
                raise ApplicationNotFoundError("DetectionFinding", str(finding_id))
            if finding.correlation.enriched and not refresh:
                return {
                    "finding_id": str(finding_id),
                    "status": CorrelationStatus.COMPLETED.value,
                    "sources_succeeded": 0,
                    "sources_failed": 0,
                    "skipped": True,
                }

            siblings = await self._sibling_refs(uow, finding, tenant_id)
            corr_result = await self._correlation.correlate(
                finding,
                tenant_id,
                sibling_finding_refs=siblings,
                now=datetime.now(UTC),
            )
            finding.enrich_correlation(
                tenant_id=tenant_id,
                correlation=corr_result.correlation,
                now=datetime.now(UTC),
            )
            await uow.detection_findings.save(finding)
            await uow.commit()
            return {
                "finding_id": str(finding_id),
                "status": corr_result.status.value,
                "sources_succeeded": corr_result.sources_succeeded,
                "sources_failed": corr_result.sources_failed,
                "errors": list(corr_result.errors),
                "correlation_id": corr_result.correlation.correlation_id,
            }

    async def _sibling_refs(
        self,
        uow: IUnitOfWork,
        finding: DetectionFinding,
        tenant_id: TenantId,
    ) -> tuple[str, ...]:
        siblings = await uow.detection_findings.find_by_asset(
            finding.asset_ref.asset_id,
            tenant_id,
            limit=10,
            offset=0,
        )
        return tuple(
            str(s.finding_id)
            for s in siblings
            if s.finding_id != finding.finding_id
        )[:5]

    def schedule_correlate(
        self,
        *,
        tenant_uuid: UUID,
        finding_id: UUID,
    ) -> asyncio.Task[dict[str, object]]:
        """Fire-and-forget async correlation (does not block finding creation)."""
        return asyncio.create_task(
            self.correlate_finding(tenant_uuid=tenant_uuid, finding_id=finding_id)
        )
