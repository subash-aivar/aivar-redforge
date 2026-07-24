"""ai_security — AI Security bounded context (M47A).

An entirely new, independent bounded context providing the domain and
application architecture foundation for securing AI systems (targets,
deployments, and guardrail policy metadata). Does not import from
`cloud_security`, `vulnerability_engine`, any `siem_*` package, or the
unrelated `ai_agent_governance`/`ai_posture`/`ai_supply_chain`
packages — only the shared kernel (`redforge.shared`) is a legitimate
cross-context dependency.

M47A scope is domain + application architecture only: identifiers,
enums, value objects, aggregates, domain events, application commands/
queries/dtos/ports, and one minimal in-memory registry for validation.
No prompt injection detection, no jailbreak detection, no prompt
scanning, no guardrail enforcement/evaluation logic, no model
evaluation, no AI red teaming, no agent security, no RAG security, no
MCP security, no risk scoring, no real infrastructure, and no HTTP API
are implemented in this milestone.
"""

from __future__ import annotations
