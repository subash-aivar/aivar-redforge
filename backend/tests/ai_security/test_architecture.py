from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "ai_security"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|siem_\w+|"
    r"ai_agent_governance|ai_posture|ai_supply_chain)\b",
    re.M,
)


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "domain" / "events").is_dir()
    assert (ROOT / "domain" / "exceptions").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_domain_layer_has_no_infrastructure_imports() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_application_layer_has_no_infrastructure_imports() -> None:
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka|"
        r"elasticsearch|opensearchpy)\b",
        re.M,
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_context_does_not_import_forbidden_bounded_contexts() -> None:
    """M47A's explicit boundary: ai_security is an entirely new,
    independent bounded context — it must never import from
    `cloud_security`, any `siem_*` context, or
    the unrelated `ai_agent_governance`/`ai_posture`/`ai_supply_chain`
    packages (only the truly-shared `redforge.shared` is legitimate to
    reuse)."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_infrastructure_and_api_layers_remain_empty_stubs() -> None:
    for layer in ("infrastructure", "api"):
        files = sorted(p.name for p in (ROOT / layer).rglob("*.py"))
        assert files == ["__init__.py"], f"{layer}/ is no longer an empty stub: {files}"


def test_no_out_of_scope_vocabulary() -> None:
    """M47A's explicit scope guard: no prompt injection detection, no
    jailbreak detection, no prompt scanning, no guardrail
    enforcement/evaluation logic, no model evaluation, no AI red
    teaming, no agent security, no RAG security, no MCP security, and
    no risk scoring may appear anywhere in this bounded context's
    source, as functional code (docstrings explaining what is *not*
    implemented are fine and are excluded from this scan)."""
    banned = re.compile(
        r"\b(prompt_?injection|jailbreak|guardrail_?evaluat\w*|guardrail_?enforc\w*|"
        r"red_?team_?attack|risk_?score|model_?evaluat\w*)\b",
        re.IGNORECASE,
    )
    for path in ROOT.rglob("*.py"):
        lines = path.read_text().splitlines()
        in_docstring = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                # Toggle docstring state; a line that both opens and
                # closes a docstring (single-line) does not change state.
                marker = stripped[:3]
                if stripped.count(marker) < 2:
                    in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            match = banned.search(line)
            if match:
                raise AssertionError(f"{path}: references out-of-scope vocabulary: {match.group()}")


def test_registry_is_tenant_isolated() -> None:
    """`InMemoryAiTargetRegistry` must scope every lookup by
    `tenant_id` — verified structurally by requiring `tenant_id` in
    every public read method's signature."""
    text = (ROOT / "application" / "registry" / "in_memory_ai_target_registry.py").read_text()
    for method in ("def get(", "def list("):
        idx = text.index(method)
        signature_end = text.index(")", idx)
        signature = text[idx:signature_end]
        assert "tenant_id" in signature, f"{method} does not take tenant_id: {signature}"


def test_no_scan_or_execution_implementations_exist() -> None:
    """No concrete AI-provider SDK calls and no execution
    implementations — extension points (Protocols) only in this
    milestone."""
    banned = re.compile(
        r"\b(openai\.|anthropic\.|subprocess\.run|socket\.connect|requests\.(get|post))\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(
                f"{path} references a concrete provider/execution call: {match.group()}"
            )
