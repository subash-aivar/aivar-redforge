"""Remediation plan generation — produces concrete, ordered steps per category.

RemediationPlanner is stateless. It dispatches on RecommendationCategory
to produce a tuple of RemediationSteps. No switch statements — rule
dispatch is a dict.

Steps are category-specific. Each step has effort, order, and an
automation_available flag (True where RedForge can trigger it).
"""

from __future__ import annotations

from collections.abc import Callable

from redforge.domain.intelligence.value_objects import (
    RecommendationCategory,
    RemediationEffort,
    RemediationStep,
)

# Planner signature: () -> tuple[RemediationStep, ...]
_PlanFn = Callable[[], tuple[RemediationStep, ...]]


class RemediationPlanner:
    """Stateless service: produce ordered remediation steps for a category.

    Usage:
        planner = RemediationPlanner()
        steps = planner.plan(RecommendationCategory.PROMPT_SECURITY)
    """

    def __init__(self) -> None:
        self._plans: dict[RecommendationCategory, _PlanFn] = {
            RecommendationCategory.CRITICAL_SECURITY_RISK: _plan_critical_risk,
            RecommendationCategory.COVERAGE_GAP: _plan_coverage_gap,
            RecommendationCategory.PROMPT_SECURITY: _plan_prompt_security,
            RecommendationCategory.AGENT_SECURITY: _plan_agent_security,
            RecommendationCategory.TOOL_SECURITY: _plan_tool_security,
            RecommendationCategory.MCP_SECURITY: _plan_mcp_security,
            RecommendationCategory.MEMORY_SECURITY: _plan_memory_security,
            RecommendationCategory.RAG_SECURITY: _plan_rag_security,
            RecommendationCategory.PROVIDER_SECURITY: _plan_provider_security,
            RecommendationCategory.MODEL_UPGRADE: _plan_model_upgrade,
            RecommendationCategory.CONFIGURATION_DRIFT: _plan_configuration_drift,
            RecommendationCategory.POLICY_WEAKNESS: _plan_policy_weakness,
            RecommendationCategory.OPERATIONAL_IMPROVEMENT: _plan_operational_improvement,
            RecommendationCategory.COMPLIANCE_GAP: _plan_compliance_gap,
        }

    def plan(self, category: RecommendationCategory) -> tuple[RemediationStep, ...]:
        """Return ordered remediation steps for the given category."""
        fn = self._plans.get(category, _plan_generic)
        return fn()


# ─── Category-specific plans ─────────────────────────────────────────────────


def _plan_critical_risk() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Immediately disable affected target in production",
            description=(
                "Suspend or route traffic away from the affected AI component "
                "until the vulnerability is confirmed and addressed."
            ),
            effort=RemediationEffort.IMMEDIATE,
            automation_available=True,
        ),
        RemediationStep(
            order=2,
            title="Run targeted re-validation to confirm exploit",
            description=(
                "Execute a focused RedForge campaign against the reported attack "
                "vector to confirm reproducibility and capture fresh evidence."
            ),
            effort=RemediationEffort.IMMEDIATE,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Apply emergency guardrails or input/output filters",
            description=(
                "Deploy prompt-level and output-level filters as a stopgap "
                "while structural remediation is underway."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=4,
            title="Conduct root cause analysis",
            description=(
                "Review system prompt, model configuration, tool permissions, "
                "and access controls to identify the root cause."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=5,
            title="Re-enable with full regression test suite",
            description=(
                "After structural fix is applied, run the full RedForge campaign "
                "and verify vulnerability rate returns below baseline."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )


def _plan_coverage_gap() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Identify highest-risk uncovered attack categories",
            description=(
                "Review the AttackCoverageGap report and prioritize categories "
                "relevant to the target's capabilities (RAG, tool use, memory)."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Create a targeted campaign for missing categories",
            description=(
                "Configure a RedForge campaign with only the missing attack "
                "categories to measure current exposure efficiently."
            ),
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Update validation policy to include all relevant categories",
            description=(
                "Expand the default ValidationPolicy to ensure future scheduled "
                "campaigns cover the full attack surface."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )


def _plan_prompt_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Audit and harden the system prompt",
            description=(
                "Review the system prompt for injection vectors. Add explicit "
                "role boundary instructions and denial of impersonation."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Implement input sanitization layer",
            description=(
                "Add a pre-processing step that detects and blocks known "
                "injection patterns before they reach the LLM."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=3,
            title="Deploy output filtering for sensitive content",
            description=(
                "Add a post-processing output filter that catches leaked PII, "
                "credentials, or policy violations before returning to users."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=4,
            title="Enable structured output constraints where supported",
            description=(
                "Use JSON mode or tool-only output to restrict the LLM to "
                "structured responses, reducing free-form injection risk."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
        RemediationStep(
            order=5,
            title="Schedule monthly prompt injection regression tests",
            description=(
                "Configure a RedForge scheduled campaign targeting "
                "PROMPT_INJECTION and JAILBREAK categories."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )


def _plan_agent_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Implement tool permission allow-listing",
            description=(
                "Replace implicit tool access with an explicit allow-list "
                "per agent role. Deny tools not required for the task."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Add agent loop detection and budget limits",
            description=(
                "Configure RedForge LoopDetectionPolicy and DepthLimitPolicy "
                "to prevent runaway agent execution."
            ),
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Implement human-in-the-loop gates for high-risk tools",
            description=(
                "For tools that write, delete, or exfiltrate data, require "
                "explicit confirmation before agent execution."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
        RemediationStep(
            order=4,
            title="Run full AgentValidation campaign against updated agent",
            description=(
                "Execute a RedForge AgentValidationEngine campaign covering "
                "all 16 attack vectors."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )


def _plan_tool_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Audit tool schemas and restrict sensitive parameters",
            description=(
                "Review tool schemas for over-broad parameter types. "
                "Add parameter validation and reject malformed inputs."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Implement tool output sanitization",
            description=(
                "Add a layer that validates tool outputs before returning "
                "them to the agent context. Block injected instructions."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=3,
            title="Apply least-privilege to tool access controls",
            description=(
                "Scope tool permissions to the minimum required for each "
                "agent role and execution context."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
    )


def _plan_mcp_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Validate MCP server provenance and integrity",
            description=(
                "Verify the MCP server's identity, certificate chain, and "
                "expected resource/tool signatures before connection."
            ),
            effort=RemediationEffort.IMMEDIATE,
        ),
        RemediationStep(
            order=2,
            title="Restrict MCP resource access to allow-listed schemas",
            description=(
                "Define an explicit resource allow-list. Reject resource URIs "
                "not matching expected patterns."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=3,
            title="Sanitize all MCP resource content before agent ingestion",
            description=(
                "Add a content inspection layer that strips prompt-injection "
                "patterns from MCP resources before they enter the agent context."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=4,
            title="Run MCPValidation campaign with full attack vector coverage",
            description=(
                "Execute a RedForge MCPValidationEngine campaign covering "
                "CAPABILITY_DISCOVERY, UNAUTHORIZED_INVOCATION, MCP_PROMPT_INJECTION, "
                "MCP_RESOURCE_POISONING, MCP_SERVER_SPOOFING, TOOL_OUTPUT_INJECTION."
            ),
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
    )


def _plan_memory_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Implement memory store access controls",
            description="Restrict read/write to memory stores by agent identity and session scope.",
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Sanitize content before persisting to memory",
            description="Scan memory writes for injected instructions before storage.",
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=3,
            title="Implement memory TTL and isolation per tenant",
            description="Enforce time-to-live on memory entries and strict tenant isolation.",
            effort=RemediationEffort.MEDIUM_TERM,
        ),
    )


def _plan_rag_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Audit retrieval corpus for injected content",
            description=(
                "Scan the RAG document corpus for prompt injection patterns. "
                "Remove or quarantine malicious documents."
            ),
            effort=RemediationEffort.IMMEDIATE,
        ),
        RemediationStep(
            order=2,
            title="Implement chunk-level content inspection before retrieval",
            description="Add a pre-retrieval filter that scores and filters out malicious chunks.",
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=3,
            title="Restrict retrieval to verified document sources",
            description="Allow-list document sources and validate provenance before ingestion.",
            effort=RemediationEffort.MEDIUM_TERM,
        ),
    )


def _plan_provider_security() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Validate provider API credentials and key rotation",
            description=(
                "Rotate API keys. Verify credentials are scoped to minimum required permissions."
            ),
            effort=RemediationEffort.IMMEDIATE,
        ),
        RemediationStep(
            order=2,
            title="Enable provider-specific safety filters",
            description=(
                "Turn on content filtering, output monitoring, and rate limiting at provider level."
            ),
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Evaluate provider alternatives for vulnerable models",
            description="If vulnerabilities are provider-specific, evaluate alternative providers.",
            effort=RemediationEffort.LONG_TERM,
        ),
    )


def _plan_model_upgrade() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Identify model versions with known security improvements",
            description=(
                "Check provider release notes for security patches relevant to observed attack types."  # noqa: E501
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Test new model version in staging environment",
            description=(
                "Run a full RedForge campaign against the upgraded model before production rollout."
            ),
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Deploy upgraded model with canary rollout",
            description=(
                "Roll out the new model version to a subset of traffic. Monitor vulnerability rate."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
    )


def _plan_configuration_drift() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Review configuration changes against known change log",
            description=(
                "Identify what changed (model, provider, prompt, tools) by comparing "
                "ConfigurationFingerprints. Verify changes were intentional."
            ),
            effort=RemediationEffort.IMMEDIATE,
        ),
        RemediationStep(
            order=2,
            title="Run re-validation against post-drift configuration",
            description=(
                "Execute a RedForge campaign against the current configuration "
                "to measure the security impact of the drift."
            ),
            effort=RemediationEffort.IMMEDIATE,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Establish new baseline if drift was intentional",
            description=(
                "If the configuration change was planned, promote a new "
                "ValidationBaseline after confirming acceptable vulnerability rate."
            ),
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=4,
            title="Implement configuration change review process",
            description=(
                "Require that any change to model, provider, or system prompt "
                "triggers an automatic RedForge validation before deployment."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
    )


def _plan_policy_weakness() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Review ValidationPolicy attack category coverage",
            description="Expand the policy's attack_categories to cover all relevant threat vectors.",  # noqa: E501
            effort=RemediationEffort.SHORT_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=2,
            title="Increase campaign frequency for high-risk targets",
            description=(
                "Change campaign interval from monthly to weekly for CRITICAL/HIGH-risk targets."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=3,
            title="Add regression policy trigger on configuration change",
            description=(
                "Configure a REGRESSION campaign type that auto-fires on any "
                "ConfigurationFingerprint change."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )


def _plan_operational_improvement() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Review and remediate open findings older than 30 days",
            description=(
                "Triage all OPEN findings. Close, accept-risk, or create remediation tickets."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Schedule regular validation campaigns for all targets",
            description="Ensure every AI target has at least one scheduled campaign per month.",
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )


def _plan_compliance_gap() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Map open findings to compliance requirements",
            description=(
                "For each open finding, identify which SOC2, ISO 27001, or NIST "
                "requirements are impacted using the Finding compliance references."
            ),
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Expand attack coverage to include compliance-relevant categories",
            description=(
                "Ensure the validation policy includes attack categories that "
                "map to your compliance framework's AI security controls."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
        RemediationStep(
            order=3,
            title="Generate compliance evidence artifacts",
            description=(
                "Use RedForge Evidence records as audit artifacts for compliance reviews. "
                "Ensure Evidence is retained per your framework's retention requirements."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
    )


def _plan_generic() -> tuple[RemediationStep, ...]:
    return (
        RemediationStep(
            order=1,
            title="Investigate and reproduce the security finding",
            description="Review the finding evidence and attempt to reproduce the condition.",
            effort=RemediationEffort.SHORT_TERM,
        ),
        RemediationStep(
            order=2,
            title="Apply targeted remediation",
            description=(
                "Based on findings, apply the appropriate security control or configuration change."
            ),
            effort=RemediationEffort.MEDIUM_TERM,
        ),
        RemediationStep(
            order=3,
            title="Re-validate after remediation",
            description="Run a focused RedForge campaign to confirm the vulnerability is resolved.",
            effort=RemediationEffort.MEDIUM_TERM,
            automation_available=True,
        ),
    )
