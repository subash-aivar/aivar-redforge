"""AnalyticsApplicationService — the Analytics Engine's single
application-layer entrypoint (M44F).

Orchestrates, in order: authorization, query validation (grouping/
filters/schema version — `query_validation.py`), provider selection
(`IAnalyticsProviderRegistry`), and execution (`IAnalyticsProvider`).
This service is read-only by construction: it holds no state between
calls, has no outbound "writer" port at all (there is nothing to
persist — analytics never mutates anything), and never builds
dashboards, executive reports, or risk scores — only what a single
`IAnalyticsProvider.aggregate()` call returns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_analytics.application import _auth
from siem_analytics.application.dtos.analytics_outcome import (
    AnalyticsFailure,
    AnalyticsOutcome,
    AnalyticsStatus,
    BatchAnalyticsResult,
)
from siem_analytics.application.exceptions import (
    ApplicationValidationError,
    EmptyBatchAnalyticsError,
    ProviderSelectionError,
)
from siem_analytics.application.services import query_validation
from siem_analytics.domain.exceptions.domain_exceptions import SiemAnalyticsDomainError
from siem_analytics.domain.value_objects.enums import AnalyticsRole
from siem_shared.domain.exceptions.domain_exceptions import SiemSharedDomainError
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from siem_analytics.application.commands.analytics_queries import (
        AnalyticsBatchQuery,
        AnalyticsQuery,
    )
    from siem_analytics.application.ports.i_analytics_provider_registry import (
        IAnalyticsProviderRegistry,
    )

_VALIDATION_ERRORS = (ApplicationValidationError, SiemAnalyticsDomainError, SiemSharedDomainError)


def _to_failure(stage: str, exc: Exception) -> AnalyticsFailure:
    return AnalyticsFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class AnalyticsApplicationService:
    def __init__(self, provider_registry: IAnalyticsProviderRegistry) -> None:
        self._registry = provider_registry

    def aggregate(self, query: AnalyticsQuery) -> AnalyticsOutcome:
        _auth.require_at_least(query.actor_roles, AnalyticsRole.VIEWER)
        return self._execute(query)

    def aggregate_batch(self, cmd: AnalyticsBatchQuery) -> BatchAnalyticsResult:
        _auth.require_at_least(cmd.actor_roles, AnalyticsRole.VIEWER)
        if not cmd.queries:
            raise EmptyBatchAnalyticsError()

        outcomes = tuple(self._execute(query) for query in cmd.queries)
        succeeded = sum(1 for o in outcomes if o.status == AnalyticsStatus.SUCCEEDED)

        if succeeded == len(outcomes):
            overall = AnalyticsStatus.SUCCEEDED
        elif succeeded == 0:
            overall = AnalyticsStatus.FAILED
        else:
            overall = AnalyticsStatus.PARTIALLY_SUCCEEDED

        return BatchAnalyticsResult(status=overall, outcomes=outcomes)

    def _execute(self, query: AnalyticsQuery) -> AnalyticsOutcome:
        try:
            query_validation.validate_filters(query.filters)
            query_validation.validate_group_by(query.group_by)
            schema_version = SchemaVersion.parse(query.schema_version_raw)
        except _VALIDATION_ERRORS as exc:
            return AnalyticsOutcome(
                status=AnalyticsStatus.REJECTED, failures=(_to_failure("validation", exc),)
            )

        try:
            provider = self._registry.resolve(query.entity_type, schema_version)
        except ProviderSelectionError as exc:
            return AnalyticsOutcome(
                status=AnalyticsStatus.UNSUPPORTED_PROVIDER,
                failures=(_to_failure("provider_selection", exc),),
            )

        try:
            result = provider.aggregate(
                tenant_id=query.tenant_id,
                time_range=query.time_range,
                aggregation_type=query.aggregation_type,
                group_by=query.group_by,
                filters=query.filters,
            )
        except Exception as exc:
            # An untrusted provider's execution failure must never
            # crash the pipeline (same discipline as M44A-M44E) — caught
            # broadly and deliberately.
            return AnalyticsOutcome(
                status=AnalyticsStatus.FAILED, failures=(_to_failure("execution", exc),)
            )

        return AnalyticsOutcome(status=AnalyticsStatus.SUCCEEDED, result=result)
