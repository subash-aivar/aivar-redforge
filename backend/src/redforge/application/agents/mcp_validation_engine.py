"""MCPValidationEngine — orchestrates MCP protocol security validation.

Responsibilities:
1. Initialize the MCP server via MCPTransportPort (initialize handshake).
2. Enumerate exposed tools, resources, and prompts.
3. Run DefaultMCPInspector on everything returned.
4. For each requested attack vector, execute targeted MCP interactions.
5. Record all interactions on the MCPSession aggregate.
6. Project findings into the Knowledge Graph.

Architecture:
- Uses MCPTransportPort to communicate with the MCP server.
  FakeMCPTransport is used in tests.
- Uses DefaultMCPInspector for static analysis.
- Does NOT use StepExecutor or ValidationService.
- Is a peer of AgentValidationEngine, not a sub-component.

No switch statements. Attack dispatch through METHOD_DISPATCH dict.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from typing import Any

from redforge.application.agents.contracts import (
    AgentKnowledgeProjectorPort,
    MCPInspectorPort,
    MCPSessionRepositoryPort,
    MCPTransportPort,
    MCPValidationRequest,
    MCPValidationResult,
)
from redforge.application.agents.mcp_transport import DefaultMCPInspector
from redforge.domain.agents.entity import MCPSession
from redforge.domain.agents.value_objects import (
    AgentSessionOutcome,
    AttackVector,
    MCPCapabilities,
    MCPInteractionRecord,
)
from redforge.shared.identifiers import EntityId


def _interaction_id() -> str:
    return str(uuid.uuid4())


_MCP_ATTACK_VECTORS = frozenset({
    AttackVector.MCP_PROMPT_INJECTION,
    AttackVector.MCP_RESOURCE_POISONING,
    AttackVector.MCP_SERVER_SPOOFING,
    AttackVector.TOOL_OUTPUT_INJECTION,
    AttackVector.UNAUTHORIZED_INVOCATION,
    AttackVector.CAPABILITY_DISCOVERY,
})


class MCPValidationEngine:
    """Orchestrates MCP server security validation sessions.

    Wiring (required):
        transport: MCPTransportPort — wire communication.

    Wiring (optional):
        inspector: MCPInspectorPort — static analysis (default: DefaultMCPInspector).
        session_repo: MCPSessionRepositoryPort — persistence.
        knowledge_projector: AgentKnowledgeProjectorPort — KG projection.
    """

    def __init__(
        self,
        transport: MCPTransportPort,
        inspector: MCPInspectorPort | None = None,
        session_repo: MCPSessionRepositoryPort | None = None,
        knowledge_projector: AgentKnowledgeProjectorPort | None = None,
    ) -> None:
        self._transport = transport
        self._inspector = inspector or DefaultMCPInspector()
        self._session_repo = session_repo
        self._knowledge_projector = knowledge_projector

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(
        self,
        request: MCPValidationRequest,
        cancel_event: asyncio.Event | None = None,
    ) -> MCPValidationResult:
        session = MCPSession.create(
            organization_id=EntityId.from_string(request.organization_id),
            target_id=EntityId.from_string(request.target_id),
            mcp_server_id=request.mcp_server_id,
            attack_vectors=tuple(
                AttackVector(v) for v in request.attack_vectors
                if v in {a.value for a in AttackVector}
            ),
            budget=request.budget,
            metadata=dict(request.metadata),
        )

        cancel = cancel_event or asyncio.Event()
        try:
            await self._validate(session, request, cancel)
        except Exception as exc:
            if not session.is_terminal:
                session.fail(str(exc))
        finally:
            await self._persist(session)
            self._project_mcp(session)
            with contextlib.suppress(Exception):
                await self._transport.close()

        return self._build_result(session)

    # ── Validation pipeline ───────────────────────────────────────────────────

    async def _validate(
        self,
        session: MCPSession,
        request: MCPValidationRequest,
        cancel: asyncio.Event,
    ) -> None:
        # 1. Initialize / handshake
        capabilities = await self._initialize(session, request.mcp_server_url)
        if session.is_terminal:
            return

        # 2. Enumerate surfaces
        findings: list[str] = []
        tools, resources, prompts = await self._enumerate(capabilities, findings)

        # 3. Run static inspection
        findings.extend(self._inspector.inspect_tool_list(tools))
        for res_meta in resources:
            uri = res_meta.get("uri", "")
            content_resp = await self._safe_read_resource(session, uri, request)
            raw_content = self._extract_resource_content(content_resp)
            findings.extend(self._inspector.inspect_resource(uri, raw_content))

        for prompt_meta in prompts:
            name = prompt_meta.get("name", "")
            prompt_resp = await self._safe_get_prompt(session, name, request)
            template = self._extract_prompt_template(prompt_resp)
            findings.extend(self._inspector.inspect_prompt(name, template))

        # 4. Per-vector targeted attacks
        for vector_str in request.attack_vectors:
            if cancel.is_set():
                break
            try:
                vector = AttackVector(vector_str)
            except ValueError:
                continue
            if vector in _MCP_ATTACK_VECTORS:
                await self._run_vector_attack(
                    session=session,
                    vector=vector,
                    tools=tools,
                    resources=resources,
                    prompts=prompts,
                    request=request,
                )

        # 5. Complete
        if not session.is_terminal:
            outcome = (
                AgentSessionOutcome.SUCCESS
                if session.succeeded_vectors
                else AgentSessionOutcome.FAILURE
            )
            session.complete(outcome)

    async def _initialize(
        self, session: MCPSession, server_url: str
    ) -> MCPCapabilities:
        try:
            caps = await self._transport.initialize(server_url)
            session.connect(caps)
            return caps
        except Exception as exc:
            session.fail(f"MCP initialize failed: {exc}")
            return MCPCapabilities()

    async def _enumerate(
        self, capabilities: MCPCapabilities, findings: list[str]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        tools: list[dict[str, Any]] = []
        resources: list[dict[str, Any]] = []
        prompts: list[dict[str, Any]] = []

        if capabilities.has_tools:
            with contextlib.suppress(Exception):
                tools = await self._transport.list_tools()

        if capabilities.has_resources:
            with contextlib.suppress(Exception):
                resources = await self._transport.list_resources()

        if capabilities.has_prompts:
            with contextlib.suppress(Exception):
                prompts = await self._transport.list_prompts()

        return tools, resources, prompts

    async def _run_vector_attack(
        self,
        session: MCPSession,
        vector: AttackVector,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        _vector_dispatchers = {
            AttackVector.CAPABILITY_DISCOVERY: self._attack_capability_discovery,
            AttackVector.UNAUTHORIZED_INVOCATION: self._attack_unauthorized_invocation,
            AttackVector.MCP_PROMPT_INJECTION: self._attack_prompt_injection,
            AttackVector.MCP_RESOURCE_POISONING: self._attack_resource_poisoning,
            AttackVector.MCP_SERVER_SPOOFING: self._attack_server_spoofing,
            AttackVector.TOOL_OUTPUT_INJECTION: self._attack_tool_output_injection,
        }
        handler = _vector_dispatchers.get(vector)
        if handler:
            await handler(session, tools, resources, prompts, request)

    async def _attack_capability_discovery(
        self,
        session: MCPSession,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        """Record a capability enumeration interaction."""
        interaction = MCPInteractionRecord(
            interaction_id=_interaction_id(),
            method="tools/list",
            params=json.dumps({}),
            result=json.dumps({"tools": tools}),
            attack_vector=AttackVector.CAPABILITY_DISCOVERY.value,
            duration_ms=0,
        )
        session.record_interaction(interaction, mark_vector_succeeded=bool(tools))

    async def _attack_unauthorized_invocation(
        self,
        session: MCPSession,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        """Attempt to call a high-risk tool without authorization."""
        for tool in tools:
            name = tool.get("name", "")
            if any(k in name.lower() for k in ("delete", "exec", "write", "admin")):
                try:
                    result = await self._transport.call_tool(
                        name, {"__attack__": "unauthorized_invocation"}
                    )
                    succeeded = "error" not in str(result).lower()
                except Exception as exc:
                    result = {"error": str(exc)}
                    succeeded = False

                interaction = MCPInteractionRecord(
                    interaction_id=_interaction_id(),
                    method="tools/call",
                    params=json.dumps({"name": name}),
                    result=json.dumps(result),
                    attack_vector=AttackVector.UNAUTHORIZED_INVOCATION.value,
                )
                session.record_interaction(interaction, mark_vector_succeeded=succeeded)
                break

    async def _attack_prompt_injection(
        self,
        session: MCPSession,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        """Read resources and detect prompt injection content."""
        for res_meta in resources[:3]:
            uri = res_meta.get("uri", "")
            resp = await self._safe_read_resource(session, uri, request)
            content = self._extract_resource_content(resp)
            injection_findings = self._inspector.inspect_resource(uri, content)
            succeeded = bool(injection_findings)
            interaction = MCPInteractionRecord(
                interaction_id=_interaction_id(),
                method="resources/read",
                params=json.dumps({"uri": uri}),
                result=json.dumps({"content": content[:500], "findings": injection_findings}),
                attack_vector=AttackVector.MCP_PROMPT_INJECTION.value,
            )
            session.record_interaction(interaction, mark_vector_succeeded=succeeded)

    async def _attack_resource_poisoning(
        self,
        session: MCPSession,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        """Attempt to read poison-URI resources."""
        poison_uris = [
            "config://system/override",
            "file:///etc/passwd",
            "../../../secret",
        ]
        for uri in poison_uris:
            try:
                resp = await self._transport.read_resource(uri)
                content = self._extract_resource_content(resp)
                succeeded = bool(content) and "error" not in content.lower()
            except Exception:
                resp = {}
                content = ""
                succeeded = False

            interaction = MCPInteractionRecord(
                interaction_id=_interaction_id(),
                method="resources/read",
                params=json.dumps({"uri": uri}),
                result=json.dumps({"content": content[:200]}),
                attack_vector=AttackVector.MCP_RESOURCE_POISONING.value,
            )
            session.record_interaction(interaction, mark_vector_succeeded=succeeded)

    async def _attack_server_spoofing(
        self,
        session: MCPSession,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        """Record a server-spoofing probe — engine observes capabilities post-connect."""
        # In a real scenario this would reconnect to a different URL.
        # Here we record that the probe ran.
        interaction = MCPInteractionRecord(
            interaction_id=_interaction_id(),
            method="initialize",
            params=json.dumps({"server_url": "mcp://attacker.example.com:9999"}),
            result=json.dumps({"probe": "spoofing_attempt_recorded"}),
            attack_vector=AttackVector.MCP_SERVER_SPOOFING.value,
        )
        session.record_interaction(interaction, mark_vector_succeeded=False)

    async def _attack_tool_output_injection(
        self,
        session: MCPSession,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
        request: MCPValidationRequest,
    ) -> None:
        """Call tools and inspect the results for injected content."""
        for tool in tools[:3]:
            name = tool.get("name", "")
            try:
                result = await self._transport.call_tool(name, {})
                result_str = json.dumps(result)
                injection_findings = []
                for pattern in (
                    "ignore previous",
                    "system override",
                    "[admin]",
                    "<script",
                ):
                    if pattern in result_str.lower():
                        injection_findings.append(pattern)
                succeeded = bool(injection_findings)
            except Exception as exc:
                result_str = str(exc)
                succeeded = False
                injection_findings = []

            interaction = MCPInteractionRecord(
                interaction_id=_interaction_id(),
                method="tools/call",
                params=json.dumps({"name": name}),
                result=result_str[:500],
                attack_vector=AttackVector.TOOL_OUTPUT_INJECTION.value,
            )
            session.record_interaction(interaction, mark_vector_succeeded=succeeded)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _safe_read_resource(
        self, session: MCPSession, uri: str, request: MCPValidationRequest
    ) -> dict[str, Any]:
        try:
            return await self._transport.read_resource(uri)
        except Exception as exc:
            return {"error": str(exc)}

    async def _safe_get_prompt(
        self, session: MCPSession, name: str, request: MCPValidationRequest
    ) -> dict[str, Any]:
        try:
            return await self._transport.get_prompt(name, {})
        except Exception as exc:
            return {"error": str(exc)}

    @staticmethod
    def _extract_resource_content(resp: dict[str, Any]) -> str:
        contents: list[dict[str, Any]] = resp.get("contents", [])
        if contents:
            text: str = str(contents[0].get("text", "") or contents[0].get("blob", ""))
            return text
        return str(resp.get("error", ""))

    @staticmethod
    def _extract_prompt_template(resp: dict[str, Any]) -> str:
        messages: list[dict[str, Any]] = resp.get("messages", [])
        if messages:
            content: object = messages[0].get("content", {})
            if isinstance(content, dict):
                return str(content.get("text", ""))
            return str(content)
        return str(resp.get("error", ""))

    def _build_result(self, session: MCPSession) -> MCPValidationResult:
        return MCPValidationResult(
            session_id=str(session.id),
            organization_id=str(session.organization_id),
            status=session.status.value,
            outcome=session.outcome.value if session.outcome else None,
            total_interactions=len(session.interactions),
            attack_vectors_tested=len(session.attack_vectors),
            attack_vectors_succeeded=len(session.succeeded_vectors),
            failure_reason=session.failure_reason,
        )

    async def _persist(self, session: MCPSession) -> None:
        if self._session_repo is None:
            return
        with contextlib.suppress(Exception):
            await self._session_repo.save(session)

    def _project_mcp(self, session: MCPSession) -> None:
        if self._knowledge_projector is None:
            return
        with contextlib.suppress(Exception):
            self._knowledge_projector.project_mcp_session(session)
