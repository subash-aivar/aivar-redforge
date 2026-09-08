"""SecurityOperationsSummaryService — M15.

Every count here is a real backend query (or, where noted, a bounded
list-length over an already-established 1000-row cap matching the
precedent M14 itself documented for its own 500-row org-wide
correlation lookup) — never a fabricated number, never a client-side
percentage/trend, never a "security score."

Deliberately DOES NOT report "recently resolved conditions" — the
brief's own suggested metric list includes it, but `security_conditions`
(M8) has no dedicated resolution timestamp (only `last_observed_at`,
which is stamped on every fresh OBSERVATION, not on resolve()). Rather
than fabricate an approximation that would silently misrepresent when
a condition was actually resolved, this metric is omitted — see
docs/M15_SECURITY_OPERATIONS_COMMAND_CENTER_REPORT.md for the full
reconnaissance note.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from redforge.domain.continuous_validation.value_objects import PolicyLifecycle
from redforge.domain.security_operations.value_objects import (
    BoundedPeriod,
    bounded_period_seconds,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.ai_targets import AITargetService
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService
    from redforge.application.security_correlation.service import TenantSecurityCorrelationService
    from redforge.application.validation_execution.execution_service import (
        ValidationExecutionService,
    )
    from redforge.core.config import ProductEdition

_BOUNDED_LIST_CAP = 1000
_RUNNING_STATUSES = frozenset({"policy_checking", "authorized", "running"})


@dataclass(frozen=True, slots=True)
class SecurityOperationsSummaryDTO:
    period: str
    canonical_assets: int
    critical_high_conditions: int
    active_correlations: int
    runtime_unhealthy_components: int
    # Full-only fields (ai_targets / continuous_validation / validation_execution
    # bounded contexts have zero Network Defense relevance) — `None` for the
    # network_defense edition, a real int for full. Never fabricated as 0.
    active_targets: int | None = None
    active_continuous_validation_policies: int | None = None
    validations_running: int | None = None
    validations_blocked_in_period: int | None = None
    validations_failed_in_period: int | None = None
    drift_events_in_period: int | None = None


class SecurityOperationsSummaryService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        ai_target_service: AITargetService,
        tenant_asset_service: TenantAssetService,
        execution_service: ValidationExecutionService,
        condition_service: TenantSecurityConditionService,
        correlation_service: TenantSecurityCorrelationService,
        runtime_unhealthy_count_fn: Callable[[], Awaitable[int]],
        edition: ProductEdition = "full",
    ) -> None:
        self._session_factory = session_factory
        self._ai_target_service = ai_target_service
        self._tenant_asset_service = tenant_asset_service
        self._execution_service = execution_service
        self._condition_service = condition_service
        self._correlation_service = correlation_service
        self._runtime_unhealthy_count_fn = runtime_unhealthy_count_fn
        self._edition = edition

    async def get_summary(
        self, organization_id: str, period: BoundedPeriod = BoundedPeriod.TWENTY_FOUR_HOURS,
    ) -> SecurityOperationsSummaryDTO:
        is_full = self._edition == "full"

        since = datetime.now(UTC) - timedelta(seconds=bounded_period_seconds(period))
        org_id = EntityId.from_string(organization_id)

        # ND-valid fields — always computed, both editions.
        assets = await self._tenant_asset_service.list_for_org(
            organization_id, limit=_BOUNDED_LIST_CAP,
        )
        condition_summary = await self._condition_service.get_summary_for_org(organization_id)
        critical_high = condition_summary.by_severity.get("critical", 0) + (
            condition_summary.by_severity.get("high", 0)
        )
        active_correlations = await self._correlation_service.list_for_org(
            organization_id, evidence_state="active", limit=_BOUNDED_LIST_CAP,
        )
        unhealthy = await self._runtime_unhealthy_count_fn()

        if not is_full:
            # network_defense: skip every Full-only repository/service call
            # entirely — never fetch-then-discard.
            return SecurityOperationsSummaryDTO(
                period=str(period),
                canonical_assets=len(assets),
                critical_high_conditions=critical_high,
                active_correlations=len(active_correlations),
                runtime_unhealthy_components=unhealthy,
            )

        from redforge.infrastructure.database.repositories.continuous_validation.drift_repository import (  # noqa: E501
            SqlAlchemySecurityDriftEventRepository,
        )
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )
        from redforge.infrastructure.database.repositories.validation_execution.repository import (
            SqlAlchemyValidationExecutionRepository,
        )

        targets = await self._ai_target_service.list_by_organization(organization_id)

        all_time_status_counts = await self._execution_service.summary(organization_id)
        running = sum(all_time_status_counts.get(s, 0) for s in _RUNNING_STATUSES)

        async with self._session_factory() as session:
            policy_repo = SqlAlchemyContinuousValidationPolicyRepository(session)
            active_policies = await policy_repo.count_for_organization(
                org_id, PolicyLifecycle.ACTIVE,
            )

            execution_repo = SqlAlchemyValidationExecutionRepository(session)
            period_status_counts = await execution_repo.count_by_status_since(org_id, since)

            drift_repo = SqlAlchemySecurityDriftEventRepository(session)
            drift_count = await drift_repo.count_for_organization_since(org_id, since)

        return SecurityOperationsSummaryDTO(
            period=str(period),
            canonical_assets=len(assets),
            critical_high_conditions=critical_high,
            active_correlations=len(active_correlations),
            runtime_unhealthy_components=unhealthy,
            active_targets=len(targets),
            active_continuous_validation_policies=active_policies,
            validations_running=running,
            validations_blocked_in_period=period_status_counts.get("denied", 0),
            validations_failed_in_period=period_status_counts.get("failed", 0),
            drift_events_in_period=drift_count,
        )
