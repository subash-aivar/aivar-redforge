"""Attack-category → security-framework taxonomy mapping.

Static, table-driven, replaceable defaults mapping RedForge's attack
categories (see application/runtime/attacks/library_resolver.py) onto:

  - OWASP Top 10 for LLM Applications (2025) control IDs
  - MITRE ATLAS tactics/techniques
  - Stable "security objective" tags (see about-product.md §7 — the
    Security Objective Framework itself, e.g. a ThreatCoverageResolver
    that dynamically maps objectives → categories, is a separate,
    not-yet-built milestone per ADR-0002. This module intentionally does
    NOT implement that framework — it only emits the stable objective
    *tags* an evaluator's finding is evidence for, as a plain string,
    so the framework has something real to consume once it exists.)

ACCURACY CAVEAT: MITRE ATLAS technique IDs evolve as the matrix is
updated. The mappings below reflect the well-established, stable
entries (prompt injection, jailbreak) with higher confidence; several
others are best-effort category-level mappings pending review by
RedForge's security research team. Treat this table as a maintained
default, not a certified compliance mapping — enterprise customers
requiring certified mappings should override via their own
ExplainabilityProvider implementation.

This module has zero I/O and zero side effects — pure lookup tables.
"""

from __future__ import annotations

from redforge.application.runtime.evaluation.models import (
    MitreTechniqueMatch,
    OwaspControlMatch,
)

# ─── OWASP Top 10 for LLM Applications (2025) ──────────────────────────────────

_OWASP_LLM_TOP_10: dict[str, tuple[str, str]] = {
    "LLM01": ("LLM01", "Prompt Injection"),
    "LLM02": ("LLM02", "Sensitive Information Disclosure"),
    "LLM03": ("LLM03", "Supply Chain"),
    "LLM04": ("LLM04", "Data and Model Poisoning"),
    "LLM05": ("LLM05", "Improper Output Handling"),
    "LLM06": ("LLM06", "Excessive Agency"),
    "LLM07": ("LLM07", "System Prompt Leakage"),
    "LLM08": ("LLM08", "Vector and Embedding Weaknesses"),
    "LLM09": ("LLM09", "Misinformation"),
    "LLM10": ("LLM10", "Unbounded Consumption"),
}

CATEGORY_TO_OWASP: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("LLM01",),
    "jailbreak": ("LLM01",),
    "data_exfiltration": ("LLM02", "LLM07"),
    "hallucination": ("LLM09",),
    "tool_abuse": ("LLM06",),
    "function_calling": ("LLM06",),
    "rag_poisoning": ("LLM04", "LLM08"),
    "context_manipulation": ("LLM01",),
    "memory_poisoning": ("LLM04",),
    "agent_hijacking": ("LLM06",),
    "model_extraction": ("LLM02", "LLM03"),
    "policy_bypass": ("LLM01",),
    "guardrail_evasion": ("LLM01", "LLM05"),
    "denial_of_service": ("LLM10",),
    # Sprint 34/35 — new categories
    "indirect_prompt_injection": ("LLM01",),
    "system_prompt_extraction": ("LLM07",),
    "role_escalation": ("LLM01", "LLM06"),
    "instruction_override": ("LLM01",),
    "secret_leakage": ("LLM02", "LLM07"),
    "mcp_tool_abuse": ("LLM06",),
    "agent_escalation": ("LLM06",),
    "cross_agent_attacks": ("LLM06",),
    "multi_agent_collaboration_abuse": ("LLM06",),
    "conversation_hijacking": ("LLM01",),
    "reasoning_manipulation": ("LLM01", "LLM09"),
    "long_context_abuse": ("LLM01", "LLM10"),
    "model_confusion": ("LLM09",),
    "cross_provider_behavior": ("LLM09",),
    "function_calling_abuse": ("LLM06",),
    "hallucination_safety": ("LLM09",),
}

# ─── MITRE ATLAS (best-effort category-level mapping; see caveat above) ────────

_MITRE_ATLAS: dict[str, tuple[str, str, str]] = {
    # (technique_id, technique_name, tactic)
    "prompt_injection": ("AML.T0051", "LLM Prompt Injection", "ML Attack Staging"),
    "jailbreak": ("AML.T0054", "LLM Jailbreak", "Defense Evasion"),
    "data_exfiltration": ("AML.T0057", "LLM Data Leakage", "Exfiltration"),
    "hallucination": ("AML.T0048", "External Harms", "Impact"),
    "tool_abuse": ("AML.T0053", "LLM Plugin Compromise", "Execution"),
    "function_calling": ("AML.T0053", "LLM Plugin Compromise", "Execution"),
    "rag_poisoning": ("AML.T0070", "RAG Poisoning", "ML Attack Staging"),
    "context_manipulation": ("AML.T0051", "LLM Prompt Injection", "ML Attack Staging"),
    "memory_poisoning": ("AML.T0018", "Backdoor ML Model", "Persistence"),
    "agent_hijacking": ("AML.T0053", "LLM Plugin Compromise", "Execution"),
    "model_extraction": ("AML.T0024", "Exfiltration via ML Inference API", "Exfiltration"),
    "policy_bypass": ("AML.T0054", "LLM Jailbreak", "Defense Evasion"),
    "guardrail_evasion": ("AML.T0054", "LLM Jailbreak", "Defense Evasion"),
    "denial_of_service": ("AML.T0029", "Denial of ML Service", "Impact"),
}

# ─── Security Objective tags (stable, decade-scale — see about-product.md §7) ──

CATEGORY_TO_SECURITY_OBJECTIVES: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("prompt_integrity",),
    "jailbreak": ("prompt_integrity", "policy_adherence"),
    "data_exfiltration": ("data_confidentiality",),
    "hallucination": ("output_reliability",),
    "tool_abuse": ("tool_safety",),
    "function_calling": ("tool_safety",),
    "rag_poisoning": ("data_confidentiality", "output_reliability"),
    "context_manipulation": ("prompt_integrity",),
    "memory_poisoning": ("data_confidentiality", "output_reliability"),
    "agent_hijacking": ("tool_safety", "policy_adherence"),
    "model_extraction": ("data_confidentiality",),
    "policy_bypass": ("policy_adherence",),
    "guardrail_evasion": ("policy_adherence",),
    "denial_of_service": ("availability",),
}

# ─── Lookup functions ──────────────────────────────────────────────────────────


def owasp_controls_for_category(category: str) -> tuple[OwaspControlMatch, ...]:
    """Return the OWASP LLM Top 10 controls a given attack category is
    evidence for. Empty tuple for unknown categories — callers should
    treat that as "no known mapping," not "definitely no match."
    """
    ids = CATEGORY_TO_OWASP.get(category, ())
    return tuple(
        OwaspControlMatch(category_id=cid, category_name=_OWASP_LLM_TOP_10[cid][1])
        for cid in ids
        if cid in _OWASP_LLM_TOP_10
    )


def mitre_technique_for_category(category: str) -> MitreTechniqueMatch | None:
    """Return the best-effort MITRE ATLAS technique for a category, or
    None if this table has no mapping for it.
    """
    entry = _MITRE_ATLAS.get(category)
    if entry is None:
        return None
    technique_id, technique_name, tactic = entry
    return MitreTechniqueMatch(
        technique_id=technique_id, technique_name=technique_name, tactic=tactic,
    )


def security_objectives_for_category(category: str) -> tuple[str, ...]:
    """Return the stable security-objective tags a category maps to."""
    return CATEGORY_TO_SECURITY_OBJECTIVES.get(category, ())


def threat_coverage_for_category(category: str) -> tuple[str, ...]:
    """Return threat-coverage tags for a category.

    Threat coverage today is represented as the attack category itself
    (it IS the volatile technique-level taxonomy — see about-product.md
    §7's Security Domain → Objectives → Threat Coverage → Categories
    hierarchy). Kept as a distinct function, rather than reusing the
    category string directly at call sites, so a future
    ThreatCoverageResolver can replace this single function without
    touching any evaluator or the ExplainabilityProvider.
    """
    return (category,) if category and category != "unknown" else ()
