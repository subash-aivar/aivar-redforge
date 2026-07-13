"""Execution Plans REST API endpoints.

Uses the ExecutionPlanner from the application layer to generate
real DAG-based execution plans from attack IDs.

Plans are currently ephemeral (no persistence, no organization_id) — see
the endpoint docstrings. Endpoints require only authentication.

M10 execution-bypass review finding (documented, not a TODO): this
router builds an execution PLAN (a graph/ordering) but never dispatches
any attack — POST creates and returns a plan object, GET/{id} always
404s, GET "" always returns []. There is no real offensive-action
dispatch here to gate with ExecutionPolicyService. The one real
dispatch path in the platform is CampaignEngine.execute_campaign()/
.trigger() (application/campaigns/campaign_engine.py), which requires
an ExecutionPolicyPort at construction time — see that module's
docstring and tests/unit/test_campaign_engine.py::TestM10ExecutionPolicyGate.
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.security import AuthenticatedPrincipal, get_current_principal
from redforge.application.execution_graph import (
    AttackGraph,
    AttackNode,
    ExecutionMode,
    ExecutionPlanner,
    FailurePolicy,
)

router = APIRouter(prefix="/execution-plans", tags=["execution-plans"])

# Module-level planner instance (stateless, safe to share)
_planner = ExecutionPlanner()


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreateExecutionPlanRequest(BaseModel):
    attack_ids: list[str] = Field(..., min_length=1)
    mode: str = Field(default="sequential", pattern=r"^(sequential|parallel)$")
    failure_policy: str = Field(
        default="continue",
        pattern=r"^(fail_fast|continue|skip_dependents)$",
    )


class ExecutionPlanResponse(BaseModel):
    id: str
    node_count: int
    edge_count: int
    mode: str
    failure_policy: str
    status: str
    nodes: list[dict[str, object]]


class ExecutionNodeResponse(BaseModel):
    node_id: str
    attack_id: str
    attack_name: str
    status: str
    priority: int


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=ExecutionPlanResponse, status_code=201)
async def create_execution_plan(
    body: CreateExecutionPlanRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ExecutionPlanResponse:
    """Create an execution plan from a list of attack IDs.

    Builds a real DAG using the ExecutionPlanner. The graph respects
    the requested execution mode and failure policy.
    """
    mode = ExecutionMode(body.mode)
    policy = FailurePolicy(body.failure_policy)

    # Build lightweight AttackNode-based graph directly (no domain entity needed)
    graph = AttackGraph()
    for i, attack_id in enumerate(body.attack_ids):
        graph.add_node(AttackNode(
            node_id=f"node-{i}",
            attack_id=attack_id,
            attack_name=f"attack-{i}",
            priority=i,
            failure_policy=policy,
        ))

    if mode == ExecutionMode.SEQUENTIAL:
        from redforge.application.execution_graph import AttackEdge
        for i in range(len(body.attack_ids) - 1):
            graph.add_edge(AttackEdge(source_id=f"node-{i}", target_id=f"node-{i + 1}"))

    from redforge.shared.identifiers import EntityId
    plan_id = str(EntityId.generate())

    return ExecutionPlanResponse(
        id=plan_id,
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        mode=body.mode,
        failure_policy=body.failure_policy,
        status="ready",
        nodes=[
            {"node_id": n.node_id, "attack_id": n.attack_id, "status": str(n.status)}
            for n in graph.nodes
        ],
    )


@router.get("/{plan_id}", response_model=ExecutionPlanResponse)
async def get_execution_plan(
    plan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ExecutionPlanResponse:
    """Retrieve an execution plan by ID.

    Note: Plans are currently ephemeral. Persistence will be added
    when the ExecutionPlanRepository infrastructure is implemented.
    """
    from redforge.core.exceptions import NotFoundError
    raise NotFoundError("ExecutionPlan", plan_id)


@router.get("", response_model=list[ExecutionPlanResponse])
async def list_execution_plans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[ExecutionPlanResponse]:
    """List execution plans.

    Returns empty until plan persistence is implemented.
    """
    return []
