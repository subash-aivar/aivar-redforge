from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "attack_pattern_intel"

_FORBIDDEN_DOMAIN_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.threat_intel\.(attack_technique_entity|"
    r"fusion_entity)\b",
    re.M,
)


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_acl_adapter_never_imports_legacy_domain_aggregate() -> None:
    """The ACL adapter may import the infra-level ORM model
    (`redforge.infrastructure.database.models.threat_intel_reference_data`)
    but must NEVER import `threat_intel`'s domain aggregate classes —
    the M51.3 ACL-over-legacy-identity architecture decision's central
    boundary."""
    for path in (ROOT / "infrastructure" / "acl").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_DOMAIN_IMPORT.search(text):
            raise AssertionError(f"{path} imports threat_intel's domain aggregate classes")


def test_acl_adapter_only_reads_attack_techniques_table() -> None:
    adapter_file = ROOT / "infrastructure" / "acl" / "mitre_technique_identity_adapter.py"
    text = adapter_file.read_text()
    assert "AttackTechniqueModel" in text
    assert "insert(" not in text.lower()
    assert "update(" not in text.lower()
    assert "delete(" not in text.lower()
