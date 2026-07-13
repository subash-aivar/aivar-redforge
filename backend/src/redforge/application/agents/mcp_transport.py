"""MCP transport implementations.

FakeMCPTransport: in-process transport used in tests and for offline
  validation. It serves a configurable set of tools/resources/prompts
  and can be primed with injection payloads for security testing.

MCPInspector: static security inspector that analyses MCP server responses
  for prompt injection, resource poisoning, and dangerous tool declarations.

Neither implementation calls the real network — production transport is
an infrastructure concern to be wired via MCPTransportPort.
"""

from __future__ import annotations

import json
from typing import Any

from redforge.domain.agents.value_objects import MCPCapabilities

# ─── Injection-detection patterns ────────────────────────────────────────────

_INJECTION_PATTERNS = frozenset({
    "ignore previous instructions",
    "ignore all previous",
    "system override",
    "new system prompt",
    "disregard your",
    "forget your instructions",
    "your real instructions",
    "<!-- ",
    "[system]",
    "[admin]",
    "[override]",
    "jailbreak",
    "dan mode",
})

_RESOURCE_POISON_PATTERNS = frozenset({
    "eval(",
    "exec(",
    "<script",
    "javascript:",
    "data:text/html",
    "__import__",
    "os.system",
    "subprocess",
    "; rm ",
    "| nc ",
    "wget http",
    "curl http",
    "base64",
})

_DANGEROUS_TOOL_PERMISSIONS = frozenset({
    "shell", "exec", "execute", "run", "system",
    "delete", "remove", "wipe", "format",
    "network", "download", "upload", "exfiltrate",
})


# ─── Fake transport ───────────────────────────────────────────────────────────


class FakeMCPTransport:
    """In-process MCP transport for tests and offline security validation.

    Can be configured with:
    - tools: list of tool definitions
    - resources: dict of uri → content (including poisoned content)
    - prompts: dict of name → template
    - tool_responses: dict of tool_name → result to return

    All calls are recorded in self.calls for assertion in tests.
    """

    def __init__(
        self,
        tools: list[dict[str, Any]] | None = None,
        resources: dict[str, str] | None = None,
        prompts: dict[str, str] | None = None,
        tool_responses: dict[str, Any] | None = None,
        server_name: str = "fake-mcp-server",
        protocol_version: str = "2024-11-05",
        raise_on_call: str | None = None,
    ) -> None:
        self._tools = tools or []
        self._resources = resources or {}
        self._prompts = prompts or {}
        self._tool_responses = tool_responses or {}
        self._server_name = server_name
        self._protocol_version = protocol_version
        self._raise_on_call = raise_on_call
        self.calls: list[dict[str, Any]] = []

    async def initialize(self, server_url: str) -> MCPCapabilities:
        self.calls.append({"method": "initialize", "url": server_url})
        return MCPCapabilities(
            has_tools=bool(self._tools),
            has_resources=bool(self._resources),
            has_prompts=bool(self._prompts),
            protocol_version=self._protocol_version,
            server_name=self._server_name,
        )

    async def list_tools(self) -> list[dict[str, Any]]:
        self.calls.append({"method": "tools/list"})
        return list(self._tools)

    async def list_resources(self) -> list[dict[str, Any]]:
        self.calls.append({"method": "resources/list"})
        return [{"uri": uri, "name": uri} for uri in self._resources]

    async def list_prompts(self) -> list[dict[str, Any]]:
        self.calls.append({"method": "prompts/list"})
        return [{"name": name} for name in self._prompts]

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if self._raise_on_call:
            raise RuntimeError(self._raise_on_call)
        self.calls.append({"method": "tools/call", "name": name, "arguments": arguments})
        if name in self._tool_responses:
            resp = self._tool_responses[name]
        else:
            resp = {"result": f"fake result from {name}"}
        return {"content": [{"type": "text", "text": json.dumps(resp)}]}

    async def read_resource(self, uri: str) -> dict[str, Any]:
        self.calls.append({"method": "resources/read", "uri": uri})
        content = self._resources.get(uri, f"fake content for {uri}")
        return {"contents": [{"uri": uri, "text": content}]}

    async def get_prompt(
        self, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls.append({"method": "prompts/get", "name": name, "arguments": arguments})
        template = self._prompts.get(name, f"Fake prompt template for {name}")
        return {"messages": [{"role": "user", "content": {"type": "text", "text": template}}]}

    async def close(self) -> None:
        self.calls.append({"method": "close"})


# ─── MCP Inspector ────────────────────────────────────────────────────────────


class DefaultMCPInspector:
    """Static security inspector for MCP server-exposed surfaces.

    Does NOT call the server. Analyses content returned by the transport.
    Returns lists of human-readable security finding strings.
    """

    def inspect_tool_list(self, tools: list[dict[str, Any]]) -> list[str]:
        findings: list[str] = []
        for tool in tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            name_lower = name.lower()
            desc_lower = desc.lower()

            for perm in _DANGEROUS_TOOL_PERMISSIONS:
                if perm in name_lower or perm in desc_lower:
                    findings.append(
                        f"MCP tool '{name}' declares dangerous capability: '{perm}'"
                    )
                    break

            # Check for missing input schema
            if "inputSchema" not in tool and "input_schema" not in tool:
                findings.append(
                    f"MCP tool '{name}' has no input schema — "
                    "unvalidated arguments are an injection risk"
                )

            # Check for injection signals in description
            desc_lower_str = desc.lower()
            for pattern in _INJECTION_PATTERNS:
                if pattern in desc_lower_str:
                    findings.append(
                        f"MCP tool '{name}' description contains injection pattern: '{pattern}'"
                    )
                    break

        return findings

    def inspect_resource(self, uri: str, content: str) -> list[str]:
        findings: list[str] = []
        content_lower = content.lower()

        for pattern in _INJECTION_PATTERNS:
            if pattern in content_lower:
                findings.append(
                    f"Resource '{uri}' contains prompt injection pattern: '{pattern}'"
                )

        for pattern in _RESOURCE_POISON_PATTERNS:
            if pattern in content_lower:
                findings.append(
                    f"Resource '{uri}' contains code execution pattern: '{pattern}'"
                )

        if len(content) > 100_000:
            findings.append(
                f"Resource '{uri}' is unusually large ({len(content)} chars) — "
                "potential denial-of-service or context stuffing attack"
            )

        return findings

    def inspect_prompt(self, name: str, template: str) -> list[str]:
        findings: list[str] = []
        template_lower = template.lower()

        for pattern in _INJECTION_PATTERNS:
            if pattern in template_lower:
                findings.append(
                    f"Prompt template '{name}' contains injection pattern: '{pattern}'"
                )

        # Check for unescaped template variables that could be abused
        import re
        variables = re.findall(r"\{\{[^}]+\}\}", template)
        for var in variables:
            if any(k in var.lower() for k in ("system", "prompt", "instruction", "override")):
                findings.append(
                    f"Prompt '{name}' has suspicious template variable: {var}"
                )

        return findings
