"""Load CSPM policies from the packaged YAML policy library."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from redforge.domain.cloud_security.cspm.entities import RemediationReference
from redforge.domain.cloud_security.cspm.exceptions import InvalidCSPMArgumentError
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import ComplianceRef, RuleMetadata

_DEFAULT_POLICIES_ROOT = (
    Path(__file__).resolve().parents[1] / "cspm_policies"
)


def _load_definition_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        raise InvalidCSPMArgumentError("policy_file", f"unsupported suffix {path.suffix}")
    if not isinstance(data, dict):
        raise InvalidCSPMArgumentError("policy_file", f"invalid root object in {path.name}")
    return data


def _merge_rules(parent_rule: dict[str, Any], child_rule: dict[str, Any]) -> dict[str, Any]:
    if not parent_rule:
        return deepcopy(child_rule)
    if not child_rule:
        return deepcopy(parent_rule)
    return {"all": [deepcopy(parent_rule), deepcopy(child_rule)]}


def _merge_definitions(
    parent: dict[str, Any], child: dict[str, Any]
) -> dict[str, Any]:
    merged = deepcopy(parent)
    for key, value in child.items():
        if key == "inherits_from":
            continue
        if key == "rule":
            merged["rule"] = _merge_rules(
                dict(parent.get("rule") or {}),
                dict(value) if isinstance(value, dict) else {},
            )
            continue
        if key in {"metadata", "remediation"} and isinstance(value, dict):
            base = dict(merged.get(key) or {})
            base.update(value)
            merged[key] = base
            continue
        if key == "compliance_mapping" and isinstance(value, list):
            existing = list(merged.get("compliance_mapping") or [])
            existing.extend(value)
            merged["compliance_mapping"] = existing
            continue
        merged[key] = value
    return merged


def _resolve_inheritance(
    definitions: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    resolved: dict[str, dict[str, Any]] = {}
    visiting: set[str] = set()

    def resolve(policy_id: str) -> dict[str, Any]:
        if policy_id in resolved:
            return resolved[policy_id]
        if policy_id in visiting:
            raise InvalidCSPMArgumentError(
                "inherits_from", f"circular inheritance at {policy_id}"
            )
        raw = definitions.get(policy_id)
        if raw is None:
            raise InvalidCSPMArgumentError("inherits_from", f"missing parent {policy_id}")
        parent_id = raw.get("inherits_from")
        if not parent_id:
            resolved[policy_id] = deepcopy(raw)
            return resolved[policy_id]
        visiting.add(policy_id)
        parent = resolve(str(parent_id))
        visiting.discard(policy_id)
        merged = _merge_definitions(parent, raw)
        merged["id"] = raw["id"]
        merged["inherits_from"] = str(parent_id)
        resolved[policy_id] = merged
        return merged

    for pid in definitions:
        resolve(pid)
    return resolved


def _to_policy(data: dict[str, Any]) -> CSPMPolicy:
    metadata_raw = data.get("metadata") or {}
    if not isinstance(metadata_raw, dict):
        metadata_raw = {}
    remediation_raw = data.get("remediation") or {}
    if not isinstance(remediation_raw, dict):
        remediation_raw = {}
    compliance_raw = data.get("compliance_mapping") or []
    compliance: list[ComplianceRef] = []
    if isinstance(compliance_raw, list):
        for item in compliance_raw:
            if isinstance(item, dict):
                compliance.append(ComplianceRef.from_dict(item))
    version = data.get("version", "1.0.0")
    if isinstance(version, dict):
        version = (
            f"{version.get('major', 1)}.{version.get('minor', 0)}.{version.get('patch', 0)}"
        )
    return CSPMPolicy.from_definition(
        policy_id=str(data["id"]),
        rule_id=str(data.get("rule_id") or data["id"]),
        title=str(data.get("title", "")),
        description=str(data.get("description", "")),
        severity=str(data.get("severity", "MEDIUM")),
        version=str(version),
        provider_types=[str(x) for x in (data.get("provider_types") or [])],
        asset_types=[str(x) for x in (data.get("asset_types") or [])],
        metadata=RuleMetadata.from_dict(metadata_raw),
        remediation=RemediationReference.from_dict(remediation_raw),
        compliance_mapping=compliance,
        rule=dict(data.get("rule") or {}),
        inherits_from=str(data["inherits_from"]) if data.get("inherits_from") else None,
        enabled=bool(data.get("enabled", True)),
        evaluation_strategy=str(data.get("evaluation_strategy", "boolean")),
    )


def load_cspm_policies(policies_root: Path | None = None) -> list[CSPMPolicy]:
    """Load all YAML (or JSON) policies under aws/azure/gcp/kubernetes."""
    root = policies_root or _DEFAULT_POLICIES_ROOT
    definitions: dict[str, dict[str, Any]] = {}
    for provider_dir in ("aws", "azure", "gcp", "kubernetes"):
        directory = root / provider_dir
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*")):
            if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
                continue
            data = _load_definition_file(path)
            policy_id = str(data.get("id") or path.stem)
            data["id"] = policy_id
            definitions[policy_id] = data
    resolved = _resolve_inheritance(definitions)
    policies = [_to_policy(resolved[pid]) for pid in sorted(resolved)]
    return policies
