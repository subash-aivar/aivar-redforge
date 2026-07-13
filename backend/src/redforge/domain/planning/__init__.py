"""Attack Planning & Strategy bounded context.

Decides WHAT to execute, WHEN, WHY, and in WHICH ORDER — the planning
brain that sits between the Attack Library/Taxonomy (knowledge of what
attacks exist) and the Execution bounded context (runtime dispatch of
an already-decided order). Produces no payloads and executes nothing
itself.

Public API:
    - AttackPlan: Aggregate root — the immutable output of planning.
    - AttackPlanner: Default PlannerProtocol implementation (the
      pipeline orchestrator).
    - Protocols: PlannerProtocol, StrategyProtocol, SelectionPolicy,
      OrderingPolicy, DependencyResolver, CapabilityResolver.
    - Value objects: PlanningStrategy, RiskAppetite, AttackPriority,
      AttackSequence, AttackDependencyGraph, etc.
"""

from redforge.domain.planning.entity import AttackPlan
from redforge.domain.planning.planner import AttackPlanner
from redforge.domain.planning.protocols import (
    CapabilityResolver,
    DependencyResolver,
    OrderingPolicy,
    PlannerProtocol,
    SelectionPolicy,
    StrategyProtocol,
)
from redforge.domain.planning.repository import AttackPlanRepository
from redforge.domain.planning.value_objects import (
    AttackDependencyGraph,
    AttackPriority,
    AttackSequence,
    EstimatedCost,
    EstimatedDuration,
    PlannedAttackStep,
    PlanningStrategy,
    PlanStatus,
    RiskAppetite,
    SelectionCriteria,
    SuccessCriteria,
)

__all__ = [
    "AttackDependencyGraph",
    "AttackPlan",
    "AttackPlanRepository",
    "AttackPlanner",
    "AttackPriority",
    "AttackSequence",
    "CapabilityResolver",
    "DependencyResolver",
    "EstimatedCost",
    "EstimatedDuration",
    "OrderingPolicy",
    "PlanStatus",
    "PlannedAttackStep",
    "PlannerProtocol",
    "PlanningStrategy",
    "RiskAppetite",
    "SelectionCriteria",
    "SelectionPolicy",
    "StrategyProtocol",
    "SuccessCriteria",
]
