"""Red Team domain — Sprint 34/35.

Goal-Oriented AI Red Team Orchestration bounded context.

Concepts introduced here:
- AttackObjective: what the red team is trying to achieve
- CampaignGoal: termination criteria + budget constraints
- AttackGraph: DAG of attack nodes with dependency edges
- AttackNode: single node in the graph with a state machine
- GoalCriteria: when to stop (first finding, threshold, coverage, all-complete)

This bounded context extends the existing Campaign and Validation bounded
contexts — it does NOT replace them. The AttackGraph is the runtime execution
state; the Campaign aggregate remains the lifecycle owner.
"""
