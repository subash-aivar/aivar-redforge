"""Storage-shape translation for ValidationService's persisted entities.

Converts domain entities (ValidationRun, Evidence, Finding) into the flat
dict shape expected by UnitOfWorkPort repositories, and holds the
static reference data (severity scoring, per-category remediation
copy) used when assembling Findings from evaluation results.

This module exists so validation_service.py can stay focused on
orchestration — it should read as "what happens," not "what shape the
database wants." Domain entities remain unaware that this mapping
exists (ADR-0001: domain has zero knowledge of persistence).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.domain.findings.value_objects import Severity

if TYPE_CHECKING:
    from redforge.domain.evidence.entity import Evidence
    from redforge.domain.findings.entity import Finding
    from redforge.domain.validations.entity import ValidationRun

# ─── Severity / Risk Scoring ───────────────────────────────────────────────────

CONFIDENCE_TO_SEVERITY: list[tuple[float, Severity]] = [
    (0.90, Severity.CRITICAL),
    (0.75, Severity.HIGH),
    (0.50, Severity.MEDIUM),
    (0.25, Severity.LOW),
    (0.00, Severity.INFORMATIONAL),
]

SEVERITY_TO_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFORMATIONAL: 0.5,
}

CATEGORY_RECOMMENDATIONS: dict[str, str] = {
    "prompt_injection": (
        "Implement robust input validation and prompt hardening. "
        "Use indirect prompt injection defenses and output filtering."
    ),
    "jailbreak": (
        "Strengthen system prompt boundaries, model guardrails, and fine-tuning. "
        "Evaluate constitutional AI techniques."
    ),
    "data_exfiltration": (
        "Review output filtering, DLP controls, and context window boundaries. "
        "Ensure no sensitive data leaks through model responses."
    ),
    "hallucination": (
        "Implement retrieval-augmented grounding and fact-verification layers. "
        "Add confidence thresholds for authoritative claims."
    ),
    "tool_abuse": (
        "Apply principle of least privilege to all tools. "
        "Implement tool call whitelisting and parameter validation."
    ),
    "function_calling": (
        "Validate all function parameters against strict schemas. "
        "Implement authorization checks before function execution."
    ),
    "rag_poisoning": (
        "Validate and sanitize all documents before ingestion. "
        "Implement knowledge base access controls and integrity checks."
    ),
    "context_manipulation": (
        "Implement conversation history validation. "
        "Reject messages that claim false prior context."
    ),
    "memory_poisoning": (
        "Isolate memory systems and validate stored content. "
        "Implement memory access controls and expiration."
    ),
    "agent_hijacking": (
        "Validate all tool results before processing. "
        "Implement agent communication authentication and integrity checks."
    ),
    "model_extraction": (
        "Protect system prompts and configuration from disclosure. "
        "Implement output filtering for sensitive structural information."
    ),
    "policy_bypass": (
        "Test safety policies against adversarial inputs regularly. "
        "Implement multiple independent safety layers."
    ),
    "guardrail_evasion": (
        "Test guardrails against encoding attacks, unicode manipulation, and obfuscation. "
        "Decode content before safety evaluation."
    ),
    "denial_of_service": (
        "Implement token limits, compute budgets, and rate limiting. "
        "Add complexity detection for adversarial prompts."
    ),
}


def confidence_to_severity(confidence: float) -> Severity:
    for threshold, severity in CONFIDENCE_TO_SEVERITY:
        if confidence >= threshold:
            return severity
    return Severity.INFORMATIONAL


def category_recommendation(category: str) -> str:
    return CATEGORY_RECOMMENDATIONS.get(
        category.lower(),
        "Review the AI system's security posture and apply defense-in-depth controls.",
    )


# ─── Entity → Persistence-Shape Mapping ────────────────────────────────────────


def serialize_validation_run(run: ValidationRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "organization_id": str(run.organization_id),
        "target_id": str(run.target_id),
        "policy_id": run.policy_id,
        "trigger_type": str(run.trigger_type),
        "status": str(run.status),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "failure_reason": run.failure_reason,
        "total_checks": run.summary.total_checks if run.summary else 0,
        "passed": run.summary.passed if run.summary else 0,
        "failed": run.summary.failed if run.summary else 0,
        "skipped": run.summary.skipped if run.summary else 0,
        "duration_ms": run.summary.duration_ms if run.summary else 0,
        "created_at": run.timestamps.created_at.isoformat(),
        "updated_at": run.timestamps.updated_at.isoformat(),
    }


def serialize_evidence(ev: Evidence) -> dict[str, Any]:
    return {
        "id": str(ev.id),
        "organization_id": str(ev.organization_id),
        "run_id": str(ev.run_id),
        "target_id": str(ev.target_id),
        "test_case_id": ev.test_case_ref.test_id,
        "test_case_name": ev.test_case_ref.test_name,
        "category": ev.test_case_ref.category,
        "attack_id": ev.attack_ref.attack_id,
        "attack_name": ev.attack_ref.attack_name,
        "attack_type": ev.attack_ref.attack_type,
        "request_method": ev.request.method,
        "request_url": ev.request.url,
        "request_body": ev.request.body,
        "response_status": ev.response.status_code,
        "response_body": ev.response.body,
        "response_latency_ms": ev.response.latency_ms,
        "result": str(ev.result),
        "confidence": ev.confidence.score,
        "executed_at": ev.execution_metadata.executed_at.isoformat(),
        "duration_ms": ev.execution_metadata.duration_ms,
        "engine_version": ev.execution_metadata.engine_version,
        "worker_id": ev.execution_metadata.worker_id,
        "finalized": ev.is_finalized,
        "created_at": ev.timestamps.created_at.isoformat(),
        "updated_at": ev.timestamps.updated_at.isoformat(),
    }


def serialize_finding(f: Finding) -> dict[str, Any]:
    return {
        "id": str(f.id),
        "organization_id": str(f.organization_id),
        "run_id": str(f.run_id),
        "target_id": str(f.target_id),
        "evidence_ids": [str(eid) for eid in f.evidence_ids],
        "title": f.title,
        "description": f.description,
        "severity": str(f.severity),
        "risk_score": f.risk_score.score,
        "status": str(f.status),
        "recommendation": f.recommendation,
        "compliance_refs": [
            {"framework": r.framework, "requirement_id": r.requirement_id,
             "description": r.description}
            for r in f.compliance_refs
        ],
        "mitre_refs": [
            {"technique_id": r.technique_id, "technique_name": r.technique_name,
             "tactic": r.tactic}
            for r in f.mitre_refs
        ],
        "owasp_refs": [
            {"category_id": r.category_id, "category_name": r.category_name}
            for r in f.owasp_refs
        ],
        "created_at": f.timestamps.created_at.isoformat(),
        "updated_at": f.timestamps.updated_at.isoformat(),
    }
