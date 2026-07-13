"""Runtime Execution — application-layer orchestration.

Coordinates existing domain objects (Policy, Attack, ExecutionPlan,
ValidationRun, Evidence, Finding) into a working execution pipeline.

This is NOT a new bounded context. It is thin orchestration glue
that wires together domain aggregates for runtime execution.

Components:
- ValidationOrchestrator: coordinates the full lifecycle
- InProcessDispatcher: traverses ExecutionPlan DAG sequentially
- StepExecutor (protocol): executes one step → Evidence
- ResponseClassifier (protocol): classifies Evidence → result
"""
