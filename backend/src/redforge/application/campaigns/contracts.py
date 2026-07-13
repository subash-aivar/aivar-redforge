"""Protocol contracts for the Campaign bounded context.

All collaborators injected into CampaignEngine are defined here as
@runtime_checkable Protocols. No concrete implementations are imported
in this module — this is the seam layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.campaigns.entity import Campaign


@runtime_checkable
class CampaignRepositoryPort(Protocol):
    """Persistence boundary for Campaign aggregates."""

    async def save(self, campaign: Campaign) -> None:
        """Persist a Campaign (insert or update)."""
        ...

    async def get(self, campaign_id: str) -> Campaign | None:
        """Retrieve a Campaign by id string. Returns None if not found."""
        ...


@runtime_checkable
class TargetSelectorPort(Protocol):
    """Resolves a set of concrete target IDs from a policy scope.

    CampaignEngine calls this once per campaign to convert
    ValidationPolicy.scope (TargetScope) into the concrete EntityId set
    that Campaign.target_ids is initialised from.
    """

    async def select(
        self,
        organization_id: str,
        policy_id: str,
    ) -> list[str]:
        """Return resolved target ID strings for the given org + policy.

        Returns an empty list when the scope resolves to zero targets
        (callers treat that as an error condition).
        """
        ...


@runtime_checkable
class CampaignKnowledgeProjectorPort(Protocol):
    """Projects Campaign lifecycle events into the Knowledge Graph."""

    def project_campaign(self, campaign: Campaign) -> int:
        """Project campaign node + edges. Returns number of nodes added."""
        ...


@runtime_checkable
class ExecutionPolicyDecisionResult(Protocol):
    """Structural shape of an ExecutionPolicyService.evaluate() result —
    see application.authorization.execution_policy_service.ExecutionPolicyResultDTO,
    which satisfies this Protocol without CampaignEngine importing that
    bounded context directly."""

    decision: str
    reason_code: str
    decision_id: str


@runtime_checkable
class ExecutionPolicyPort(Protocol):
    """The mandatory M10 execution-authorization gate. Every active
    execution dispatch boundary MUST call evaluate() before dispatching
    and MUST NOT proceed unless decision == "allow" — see
    CampaignEngine.execute_campaign()/trigger() for the enforcement
    point, and domain.authorization.exceptions.ExecutionNotAuthorizedError
    for what is raised otherwise.

    This parameter is REQUIRED (no default) on CampaignEngine's
    constructor specifically so that no caller can construct a working
    engine without wiring a real policy decision — see
    tests/unit/test_campaign_engine.py::test_cannot_construct_without_execution_policy_service
    for the regression test proving this.
    """

    async def evaluate(
        self,
        *,
        organization_id: str,
        actor_user_id: str,
        action_class: str,
        entity_refs: list[tuple[str, str]],
    ) -> ExecutionPolicyDecisionResult:
        ...


@runtime_checkable
class BaselineCampaignPort(Protocol):
    """Reads baseline campaign data needed for drift detection.

    Separated from CampaignRepositoryPort because the baseline data
    (finding counts, vulnerability rates) is a read-only analytical
    view — it does not need to be the same store as the write-side
    campaign repository.
    """

    async def get_findings_summary(
        self, campaign_id: str
    ) -> dict[str, int]:
        """Return {target_id: findings_count} for an earlier campaign."""
        ...

    async def get_vulnerability_rates(
        self, campaign_id: str
    ) -> dict[str, float]:
        """Return {target_id: vulnerability_rate} for an earlier campaign."""
        ...
