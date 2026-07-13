"""Advanced AI Validation — Sprint 32/33.

Extends the existing Validation Engine with advanced modes:
- Multi-turn conversation validation with memory persistence checks
- Long-context window stress testing
- Multi-model / multi-provider comparative evaluation
- Prompt chain integrity validation
- Agent workflow validation (tool use + orchestration)
- MCP tool permission validation

All validators compose existing engines (ConversationEngine,
AgentValidationEngine, MCPValidationEngine, EvaluationEngine).
No new engine is introduced — only a coordinator that routes
requests to the right existing engine with an appropriate mode.
"""

from redforge.application.advanced_validation.coordinator import (
    AdvancedValidationCoordinator,
    AdvancedValidationRequest,
    AdvancedValidationResult,
)

__all__ = [
    "AdvancedValidationCoordinator",
    "AdvancedValidationRequest",
    "AdvancedValidationResult",
]
