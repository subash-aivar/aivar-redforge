"""EnterpriseRiskProfileRepository — an async ABC port for
tenant-scoped persistence of `EnterpriseRiskProfile` aggregates
(M48C, converted from a sync `Protocol` to an async `ABC` in the
M48C contract correction authorized alongside M48E — see
`docs/architecture/m48/M48E_ADR.md` for the original deviation this
resolves). `get`/`list` are tenant-scoped: `get` returns `None` for a
`profile_id` that exists but under a different tenant, never leaking
cross-tenant existence.

Judgment call: `score_history` is not called for verbatim by the task
spec's port list, but `GetRiskTimelineQuery`'s handler
(`RiskTimelineApplicationService`) must feed a `Sequence[
CompositeRiskScore]` into `RiskTrendAnalysisService.analyze_trend`, and
the aggregate itself only ever holds its *current* `composite_score` —
history is a persistence concern this milestone does not implement
but must still declare a contract for, since "fetched via repository
port" is explicit in the spec. Declared here rather than as a fourth
port to keep the timeline read colocated with the aggregate it reads
history for.

`ABC` (not `Protocol`) matches every mature bounded context's
repository port exactly — e.g. `operation.domain.repositories.
i_operation_repository.IOperationRepository`,
`detection.domain.repositories.i_detection_rule_repository.
IDetectionRuleRepository`, `ai_posture.domain.repositories.
i_ai_compliance_mapping_repository.IAIComplianceMappingRepository` —
all `ABC` with `@abstractmethod async def`."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId


class EnterpriseRiskProfileRepository(ABC):
    @abstractmethod
    async def save(self, profile: EnterpriseRiskProfile) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> EnterpriseRiskProfile | None: ...

    @abstractmethod
    async def list(
        self, tenant_id: TenantId, **filters: object
    ) -> Sequence[EnterpriseRiskProfile]: ...

    @abstractmethod
    async def score_history(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> Sequence[CompositeRiskScore]:
        """Chronologically ordered `CompositeRiskScore` snapshots for
        this profile, oldest first. Tenant-scoped like `get`/`list`."""
        ...
