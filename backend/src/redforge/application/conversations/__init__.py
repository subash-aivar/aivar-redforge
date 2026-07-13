"""Enterprise Adaptive Multi-turn AI Red Team Engine — application layer.

Layer ownership:
  ConversationEngine    (here) — adaptive loop, turn orchestration, memory
  ConversationStrategy          — produces the next attack payload per turn
  DecisionEngine                — rule-based: Continue|Escalate|Pivot|Retry|Terminate
  TerminationPolicy             — budget enforcement
  ConversationSession  (domain) — aggregate root, turn records, lifecycle

The ConversationEngine does NOT call ValidationService. It directly uses the
StepExecutor protocol for turn-level execution, giving it fine-grained control
over the accumulated message list. ValidationService handles single-target
single-run validations; ConversationEngine handles adaptive multi-turn sessions.

Nothing here implements autonomous agents. The decision engine is rule-based.
"""
