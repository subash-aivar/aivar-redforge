"""Attack Execution Engine — defines HOW attacks behave.

Sits between domain (AttackDefinition, PayloadTemplate) and
runtime execution (StepContext → StepExecutor → StepEvidence).

Components:
- AttackExecutionStrategy: determines attack flow and sequencing
- PayloadGenerator: selects/creates payloads for an attack
- PromptRenderer: renders templates into executable content
- ConversationBuilder: constructs message arrays for providers
- AttackExecutionContext: immutable context for one attack execution

Architecture: Each component is protocol-based and independently replaceable.
"""
