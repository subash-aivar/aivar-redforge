"""Enterprise Adaptive Multi-turn AI Red Team Engine — domain layer.

A ConversationSession is the aggregate root for one adaptive attack
conversation. It tracks the full lifecycle of an adversarial dialogue
against an AI target: turn-by-turn execution, decision history, budget
accounting, and final outcome.

Key distinctions:
- ConversationSession ≠ ValidationRun: a ValidationRun is single-step.
  A ConversationSession spans N turns with adaptive decision-making between
  them. They are sibling aggregates at the same abstraction level.
- NOT autonomous: the decision engine is rule-based. No LLM judges.
- NOT a continuous validation: a ConversationSession has a defined budget
  and terminates when the budget is exhausted or a terminal decision is made.

Domain layer — imports only redforge.domain.*, redforge.shared.*,
redforge.core.exceptions (ADR-0001).
"""
