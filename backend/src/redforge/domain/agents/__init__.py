"""Enterprise Agent & MCP Security Validation — domain bounded context.

Canonical domain models for validating AI systems that use:
- Tool Calling / Function Calling
- MCP Servers (Model Context Protocol)
- Browser Tools / Computer Use
- External APIs
- Multi-agent workflows

Bounded context owns:
  Agent               — registered agent under test (target metadata)
  AgentSession        — one validation session against an agent
  Tool                — a tool definition the agent can invoke
  ToolInvocation      — one recorded tool call within a session
  MCPServer           — an MCP server registered for validation
  MCPSession          — one validation session against an MCP server

Domain layer — imports only domain.*, shared.*, core.exceptions (ADR-0001).
"""
