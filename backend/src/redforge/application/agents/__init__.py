"""Enterprise Agent & MCP Security Validation Framework — application layer.

Layer ownership:
  AgentValidationEngine   — orchestrates tool/MCP attack sessions
  MCPValidationEngine     — orchestrates MCP-protocol-specific attacks
  AgentStrategy           — produces the next attack payload per step
  ToolInvocationPolicy    — decides Allow | Block | Escalate for a tool call
  ToolValidator           — validates tool schemas and permissions
  MCPInspector            — introspects MCP servers (tools/resources/prompts)
  MCPTransport            — sends MCP protocol messages (fake or real)
  AgentSession  (domain)  — aggregate root; records invocations and events

Architecture invariant:
  AgentValidationEngine does NOT call ValidationService.
  It uses StepExecutor (via ChatCompletionExecutor) for LLM turns, and
  MCPTransport for MCP wire-protocol calls — the same way ConversationEngine
  uses StepExecutor directly for fine-grained message control.

Nothing here implements autonomous agents.
"""
