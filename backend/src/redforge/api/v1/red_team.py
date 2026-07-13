"""Red Team Campaigns REST API.

Route: POST /api/v1/red-team/campaigns

Credential security boundary (Sprint 42/43):
- The browser NEVER submits a raw provider API key.
- Campaign requests reference a registered provider by provider_id.
- The server resolves the provider's auth_ref (an env var name) to the
  actual credential using CredentialResolverPort at the infrastructure
  boundary — never earlier, never returned to the client.
- organization_id comes exclusively from the caller's verified TenantContext
  (JWT). It is never accepted from the request body or query parameters.
- The full evaluation control loop is wired into every orchestrator produced
  by the factory (EvaluationPipeline → ConsensusEngine →
  EvaluationPolicyEnforcer → EvaluationDrivenIntelligenceAdapter →
  CampaignIntelligenceService).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_campaign_query_service, get_runtime_container
from redforge.api.security import TenantContext, require_permission
from redforge.application.red_team.orchestrator import (
    RedTeamRequest,
    RedTeamResult,
)
from redforge.core.exceptions import CredentialResolutionError, NotFoundError
from redforge.domain.identity.value_objects import Permission
from redforge.domain.red_team.value_objects import AttackObjective, BudgetConstraint, CampaignGoal
from redforge.infrastructure.providers.openai_adapter import OpenAIAdapter, OpenAIConfig

if TYPE_CHECKING:
    from redforge.application.red_team.campaign_query_service import (
        CampaignDetailDTO,
        CampaignQueryService,
        CampaignSummaryDTO,
    )

router = APIRouter(prefix="/red-team", tags=["red-team"])


# ─── Request / Response models ────────────────────────────────────────────────


class LaunchCampaignRequest(BaseModel):
    """Request body for POST /red-team/campaigns.

    organization_id is intentionally NOT a field — it comes from the caller's
    verified TenantContext (JWT). This is enforced at this layer.

    provider_id references a registered provider whose credentials are
    resolved server-side. Raw API keys are never accepted from the browser.
    """

    target_id: str = Field(..., description="AITarget entity ID")
    target_name: str = Field(..., min_length=1, max_length=200)
    target_endpoint: str = Field(..., description="Base URL of the AI target")
    model: str = Field(default="gpt-4o-mini")
    target_system_prompt: str = Field(default="You are a helpful assistant.")
    provider_id: str = Field(
        ...,
        description=(
            "ID of a registered provider configuration. "
            "The server resolves the provider's credential reference (auth_ref) "
            "to the actual API key. Raw keys are never accepted here."
        ),
    )
    goal: str = Field(
        default="jailbreak",
        description="Campaign goal: jailbreak | data_extraction | prompt_injection | "
                    "goal_hijacking | sensitive_disclosure | policy_violation",
    )
    max_attacks_per_category: int = Field(default=2, ge=1, le=10)
    severity_minimum: str = Field(
        default="medium",
        pattern=r"^(low|medium|high|critical)$",
    )
    max_parallel_nodes: int = Field(default=3, ge=1, le=10)
    max_duration_s: int | None = Field(default=None, ge=10, le=3600)
    campaign_id: str = Field(default="")


_GOAL_CATEGORIES: dict[str, frozenset[str]] = {
    "jailbreak": frozenset({"jailbreak", "prompt_injection"}),
    "data_extraction": frozenset({"data_extraction", "information_leakage"}),
    "prompt_injection": frozenset({"prompt_injection"}),
    "goal_hijacking": frozenset({"goal_hijacking", "jailbreak"}),
    "sensitive_disclosure": frozenset({"information_leakage", "sensitive_disclosure"}),
    "policy_violation": frozenset({"policy_violation", "content_safety"}),
}


def _make_campaign_goal(goal_name: str) -> CampaignGoal:
    categories = _GOAL_CATEGORIES[goal_name]
    return CampaignGoal(
        objective=AttackObjective(
            name=goal_name,
            description=f"Red team campaign targeting: {goal_name}",
            target_categories=categories,
        ),
        budget=BudgetConstraint(),
    )


class CampaignResultResponse(BaseModel):
    """Response from POST /red-team/campaigns."""

    graph_id: str
    campaign_id: str
    organization_id: str
    state: str
    goal_achieved: bool
    objective_name: str
    total_nodes: int
    nodes_executed: int
    completed_nodes: int
    failed_nodes: int
    blocked_nodes: int
    injected_nodes: int
    intelligence_confidence: float
    duration_ms: int
    failure_reason: str | None = None

    @classmethod
    def from_result(cls, result: RedTeamResult) -> CampaignResultResponse:
        return cls(
            graph_id=result.graph_id,
            campaign_id=result.campaign_id,
            organization_id=result.organization_id,
            state=result.state,
            goal_achieved=result.goal_achieved,
            objective_name=result.objective_name,
            total_nodes=result.total_nodes,
            nodes_executed=result.nodes_executed,
            completed_nodes=result.completed_nodes,
            failed_nodes=result.failed_nodes,
            blocked_nodes=result.blocked_nodes,
            injected_nodes=result.injected_nodes,
            intelligence_confidence=result.intelligence_confidence,
            duration_ms=result.duration_ms,
            failure_reason=result.failure_reason,
        )


# ─── Launch endpoint ──────────────────────────────────────────────────────────


@router.post(
    "/campaigns",
    response_model=CampaignResultResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Launch an AI red team campaign",
    description=(
        "Runs a complete adaptive red team campaign against an AI target. "
        "organization_id is derived exclusively from the caller's JWT. "
        "provider credentials are resolved server-side from the registered "
        "provider's auth_ref — raw API keys are never accepted from the browser."
    ),
)
async def launch_campaign(
    body: LaunchCampaignRequest,
    request: Request,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_RUN)),
) -> CampaignResultResponse:
    """Launch an adaptive red team campaign.

    Credential resolution path:
        browser → provider_id (opaque UUID, no secret)
        server → ProviderService.get_by_id(provider_id) → ProviderDTO.auth_ref
        server → CredentialResolver.resolve(auth_ref) → raw_api_key
        raw_api_key → OpenAIAdapter (never returned to client, never persisted)
    """
    container = get_runtime_container(request)
    factory = container.red_team_factory
    if factory is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Red team factory not initialized. Application startup incomplete.",
        )

    if body.goal not in _GOAL_CATEGORIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown campaign goal: {body.goal!r}",
        )
    goal = _make_campaign_goal(body.goal)

    # ── Resolve provider and credential server-side ────────────────────────
    from redforge.api.dependencies import get_provider_service

    provider_service = get_provider_service()
    try:
        # M2: organization_id scoping — a provider owned by a different
        # tenant (or a legacy pre-M2 row with no owner) 404s identically
        # to a nonexistent provider_id. tenant.organization_id comes only
        # from the verified JWT, never from this request body.
        provider_dto = await provider_service.get_by_id(
            body.provider_id, tenant.organization_id,
        )
    except NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Provider '{body.provider_id}' not found. Register a provider first.",
        ) from exc

    if not provider_dto.enabled:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Provider '{provider_dto.name}' is disabled.",
        )

    # Resolve credential server-side — never from the browser
    credential_resolver = container.credential_resolver
    if credential_resolver is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential resolver not initialized. Application startup incomplete.",
        )
    try:
        resolved_api_key = credential_resolver.resolve(provider_dto.auth_ref)
    except CredentialResolutionError as exc:
        # auth_ref (env var name) is safe to include — it is NOT the secret value
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.message,
        ) from exc

    provider_adapter = _build_provider_adapter(
        provider_type=provider_dto.provider_type,
        api_key=resolved_api_key,
        base_url=provider_dto.base_url or body.target_endpoint,
        model=body.model,
    )
    # resolved_api_key is now held only in the local stack frame and the adapter —
    # it is not assigned to any field that persists beyond this request

    orchestrator = factory.build(
        provider_adapter=provider_adapter,
        uow_factory=container.session_factory,
        knowledge_graph=container.knowledge_graph,
    )

    red_team_request = RedTeamRequest(
        organization_id=tenant.organization_id,  # EXCLUSIVELY from JWT
        target_id=body.target_id,
        target_endpoint=provider_dto.base_url or body.target_endpoint,
        target_provider=provider_dto.provider_type,
        target_name=body.target_name,
        model=body.model,
        target_system_prompt=body.target_system_prompt,
        goal=goal,
        correlation_id=str(uuid.uuid4()),
        campaign_id=body.campaign_id,
        max_attacks_per_category=body.max_attacks_per_category,
        severity_minimum=body.severity_minimum,
        max_parallel_nodes=body.max_parallel_nodes,
        max_duration_s=body.max_duration_s,
    )

    result: RedTeamResult = await orchestrator.execute(red_team_request)

    await _persist_campaign_result(
        result=result,
        organization_id=tenant.organization_id,
        target_id=body.target_id,
        session_factory=container.session_factory,
    )

    return CampaignResultResponse.from_result(result)


async def _persist_campaign_result(
    result: RedTeamResult,
    organization_id: str,
    target_id: str,
    session_factory: Any,
) -> None:
    """Write a terminal campaign result record after execution completes.

    This is a best-effort write. The campaign execution has already succeeded;
    a persistence failure here degrades queryability but does not roll back the run.
    """
    try:
        from redforge.infrastructure.database.repositories.campaign_result_repository import (
            CampaignResultRepository,
            campaign_result_from_red_team_result,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(session_factory) as uow:
            repo = CampaignResultRepository(uow.session)
            record = campaign_result_from_red_team_result(
                result=result,
                organization_id=organization_id,
                target_id=target_id,
            )
            await repo.save(record)
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "campaign_result_persist_failed", exc_info=True,
        )


# ─── Campaign Query Endpoints ─────────────────────────────────────────────────


class CampaignSummaryResponse(BaseModel):
    """Response for GET /red-team/campaigns list."""

    campaign_id: str
    organization_id: str
    target_id: str
    state: str
    goal_achieved: bool
    objective_name: str
    total_nodes: int
    nodes_executed: int
    completed_nodes: int
    failed_nodes: int
    blocked_nodes: int
    injected_nodes: int
    intelligence_confidence: float
    duration_ms: int
    failure_reason: str | None = None
    created_at: str

    @classmethod
    def from_dto(cls, dto: CampaignSummaryDTO) -> CampaignSummaryResponse:
        import dataclasses
        return cls(**dataclasses.asdict(dto))


class CampaignDetailResponse(BaseModel):
    """Response for GET /red-team/campaigns/{campaign_id}."""

    campaign_id: str
    organization_id: str
    target_id: str
    state: str
    goal_achieved: bool
    objective_name: str
    total_nodes: int
    nodes_executed: int
    completed_nodes: int
    failed_nodes: int
    blocked_nodes: int
    injected_nodes: int
    intelligence_confidence: float
    duration_ms: int
    failure_reason: str | None = None
    graph_nodes: list[dict[str, Any]]
    graph_edges: list[dict[str, Any]]
    created_at: str

    @classmethod
    def from_dto(cls, dto: CampaignDetailDTO) -> CampaignDetailResponse:
        import dataclasses
        return cls(**dataclasses.asdict(dto))


@router.get(
    "/campaigns",
    response_model=list[CampaignSummaryResponse],
    summary="List red team campaigns for the caller's organization",
)
async def list_campaigns(
    limit: int = 50,
    offset: int = 0,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    query_service: CampaignQueryService = Depends(get_campaign_query_service),
) -> list[CampaignSummaryResponse]:
    """List completed red team campaigns scoped to the caller's organization."""
    dtos = await query_service.list_campaigns(
        organization_id=tenant.organization_id,
        limit=limit,
        offset=offset,
    )
    return [CampaignSummaryResponse.from_dto(d) for d in dtos]


@router.get(
    "/campaigns/{campaign_id}",
    response_model=CampaignDetailResponse,
    summary="Get red team campaign detail",
)
async def get_campaign(
    campaign_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.VALIDATIONS_READ)),
    query_service: CampaignQueryService = Depends(get_campaign_query_service),
) -> CampaignDetailResponse:
    """Get detail for a specific campaign scoped to the caller's organization."""
    dto = await query_service.get_campaign(
        campaign_id=campaign_id,
        organization_id=tenant.organization_id,
    )
    if dto is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign {campaign_id!r} not found.",
        )
    return CampaignDetailResponse.from_dto(dto)


def _build_provider_adapter(
    provider_type: str,
    api_key: str,
    base_url: str,
    model: str,
) -> Any:
    """Construct the LLM provider adapter from a server-resolved credential.

    api_key is the resolved secret — it must not be logged or returned.
    """
    if provider_type in ("openai", "cloud"):
        return OpenAIAdapter(
            config=OpenAIConfig(
                api_key=api_key,
                base_url=base_url,
                model=model,
            )
        )
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"Provider type '{provider_type}' adapter not yet implemented.",
    )
