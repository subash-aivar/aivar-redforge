"""CSPM policy loader + inheritance tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redforge.infrastructure.cloud_security.cspm.policy_loader import (
    _merge_rules,
    load_cspm_policies,
)


def test_load_packaged_policies_at_least_25() -> None:
    policies = load_cspm_policies()
    assert len(policies) >= 25
    ids = {str(p.id) for p in policies}
    assert "CSPM-AWS-S3-001" in ids
    assert "CSPM-AZURE-STORAGE-001" in ids
    assert "CSPM-GCP-GCS-001" in ids


def test_loaded_policy_fields() -> None:
    policies = {str(p.id): p for p in load_cspm_policies()}
    p = policies["CSPM-AWS-S3-001"]
    assert p.severity.value == "CRITICAL"
    assert "AWS" in p.provider_types
    assert "S3_BUCKET" in p.asset_types
    assert p.rule["op"] == "eq"
    assert p.compliance_mapping


def test_inheritance_merges_rules(tmp_path: Path) -> None:
    aws = tmp_path / "aws"
    aws.mkdir()
    (aws / "PARENT.json").write_text(
        json.dumps(
            {
                "id": "PARENT",
                "rule_id": "PARENT",
                "title": "Parent",
                "description": "p",
                "severity": "LOW",
                "version": "1.0.0",
                "provider_types": ["AWS"],
                "asset_types": ["S3_BUCKET"],
                "metadata": {"category": "storage"},
                "remediation": {"description": "r"},
                "compliance_mapping": [],
                "rule": {"op": "eq", "path": "a", "value": 1},
                "enabled": True,
            }
        ),
        encoding="utf-8",
    )
    (aws / "CHILD.json").write_text(
        json.dumps(
            {
                "id": "CHILD",
                "rule_id": "CHILD",
                "title": "Child",
                "description": "c",
                "severity": "HIGH",
                "version": "1.0.0",
                "provider_types": ["AWS"],
                "asset_types": ["S3_BUCKET"],
                "metadata": {"category": "storage", "tags": ["child"]},
                "remediation": {"description": "r2"},
                "compliance_mapping": [
                    {"framework_key": "soc2_type2", "requirement_ref": "CC6.1"}
                ],
                "inherits_from": "PARENT",
                "rule": {"op": "eq", "path": "b", "value": 2},
                "enabled": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "azure").mkdir()
    (tmp_path / "gcp").mkdir()
    policies = {str(p.id): p for p in load_cspm_policies(tmp_path)}
    child = policies["CHILD"]
    assert child.severity.value == "HIGH"
    assert "all" in child.rule
    assert len(child.rule["all"]) == 2
    assert child.inherits_from == "PARENT"
    assert child.metadata.tags == ("child",)


def test_merge_rules_helpers() -> None:
    assert _merge_rules({}, {"op": "eq", "path": "x", "value": 1})["op"] == "eq"
    assert _merge_rules({"op": "always_true"}, {})["op"] == "always_true"
    merged = _merge_rules({"op": "always_true"}, {"op": "always_false"})
    assert merged["all"][0]["op"] == "always_true"


def test_circular_inheritance_raises(tmp_path: Path) -> None:
    aws = tmp_path / "aws"
    aws.mkdir()
    (tmp_path / "azure").mkdir()
    (tmp_path / "gcp").mkdir()
    for pid, parent in (("A", "B"), ("B", "A")):
        (aws / f"{pid}.json").write_text(
            json.dumps(
                {
                    "id": pid,
                    "rule_id": pid,
                    "title": pid,
                    "description": "d",
                    "severity": "LOW",
                    "version": "1.0.0",
                    "provider_types": ["AWS"],
                    "asset_types": ["S3_BUCKET"],
                    "metadata": {"category": "x"},
                    "remediation": {"description": "r"},
                    "compliance_mapping": [],
                    "inherits_from": parent,
                    "rule": {"op": "always_true"},
                    "enabled": True,
                }
            ),
            encoding="utf-8",
        )
    from redforge.domain.cloud_security.cspm.exceptions import InvalidCSPMArgumentError

    with pytest.raises((ValueError, KeyError, TypeError, InvalidCSPMArgumentError)):
        load_cspm_policies(tmp_path)


def test_applies_to_filter() -> None:
    policies = load_cspm_policies()
    aws_s3 = [p for p in policies if p.applies_to(provider_type="AWS", asset_type="S3_BUCKET")]
    assert aws_s3
    assert all(p.enabled for p in aws_s3)
