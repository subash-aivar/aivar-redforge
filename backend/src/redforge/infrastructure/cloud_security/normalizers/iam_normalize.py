"""RawIAMPrincipal → NormalizedIAMPrincipalDraft normalizers (AWS / Azure / GCP)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from redforge.domain.cloud_security.entities import PolicyAttachment, TrustRelationship
from redforge.domain.cloud_security.exceptions import InvalidCloudArgumentError
from redforge.domain.cloud_security.ports import RawIAMPrincipal
from redforge.domain.cloud_security.value_objects import IAMPrincipalType, PolicyAttachmentType
from redforge.infrastructure.cloud_security.normalizers.iam_types import NormalizedIAMPrincipalDraft


def _str(value: object | None, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _parse_datetime(value: object | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _account_from_arn(arn: str) -> str | None:
    parts = arn.split(":")
    if len(parts) >= 5 and parts[0] == "arn":
        account = parts[4]
        return account or None
    return None


def _principals_from_statement(principal: object) -> list[str]:
    if principal is None or principal == "*":
        return ["*"] if principal == "*" else []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        out: list[str] = []
        for key in ("AWS", "Federated", "Service", "CanonicalUser"):
            value = principal.get(key)
            if value is None:
                continue
            if isinstance(value, list):
                out.extend(str(v) for v in value if v is not None)
            else:
                out.append(str(value))
        return out
    if isinstance(principal, list):
        nested: list[str] = []
        for item in principal:
            nested.extend(_principals_from_statement(item))
        return nested
    return [str(principal)]


def _parse_conditions(condition: object | None) -> tuple[tuple[str, str], ...]:
    if not isinstance(condition, dict):
        return ()
    pairs: list[tuple[str, str]] = []
    for op, nested in condition.items():
        if not isinstance(nested, dict):
            pairs.append((str(op), str(nested)))
            continue
        for key, value in nested.items():
            pairs.append((f"{op}:{key}", str(value)))
    return tuple(pairs[:100])


def _trust_from_aws_statement(
    statement: dict[str, Any], account_id: str
) -> list[TrustRelationship]:
    effect = _str(statement.get("Effect"), "Allow")
    if effect.lower() != "allow":
        return []
    action = statement.get("Action") or statement.get("NotAction")
    actions = (
        [str(a) for a in action]
        if isinstance(action, list)
        else ([str(action)] if action is not None else [])
    )
    trust_type = "AssumeRole"
    if any("AssumeRoleWithSAML" in a for a in actions):
        trust_type = "AssumeRoleWithSAML"
    elif any("AssumeRoleWithWebIdentity" in a for a in actions):
        trust_type = "AssumeRoleWithWebIdentity"
    elif any("sts:AssumeRole" in a or a == "sts:*" for a in actions):
        trust_type = "AssumeRole"
    conditions = _parse_conditions(statement.get("Condition"))
    trusts: list[TrustRelationship] = []
    for principal_id in _principals_from_statement(statement.get("Principal")):
        if not principal_id:
            continue
        trusted_account = (
            _account_from_arn(principal_id) if principal_id.startswith("arn:") else None
        )
        is_cross = bool(
            account_id
            and trusted_account
            and trusted_account != account_id
            and trusted_account != ""
        )
        if principal_id == "*" and account_id:
            is_cross = True
        trusts.append(
            TrustRelationship.create(
                trusted_principal_provider_id=principal_id,
                trust_type=trust_type,
                is_cross_account=is_cross,
                conditions=conditions,
            )
        )
    return trusts


def _parse_aws_trust_policy(payload: dict[str, Any], account_id: str) -> list[TrustRelationship]:
    raw = payload.get("trust_policy") or payload.get("AssumeRolePolicyDocument")
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, dict):
        return []
    statements = raw.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    trusts: list[TrustRelationship] = []
    for stmt in statements:
        if isinstance(stmt, dict):
            trusts.extend(_trust_from_aws_statement(stmt, account_id))
    return trusts[:200]


def _policy_attachment_from_dict(item: dict[str, Any]) -> PolicyAttachment | None:
    policy_id = _str(
        item.get("policy_provider_id")
        or item.get("arn")
        or item.get("PolicyArn")
        or item.get("role_definition_id")
        or item.get("role")
        or item.get("id")
    )
    policy_name = _str(
        item.get("policy_name")
        or item.get("name")
        or item.get("PolicyName")
        or item.get("role_name")
        or item.get("display_name")
        or policy_id
    )
    if not policy_id or not policy_name:
        return None
    raw_type = _str(item.get("attachment_type") or item.get("type"), "MANAGED").upper()
    try:
        attachment_type = PolicyAttachmentType(raw_type)
    except ValueError:
        attachment_type = PolicyAttachmentType.MANAGED
    is_inline = bool(item.get("is_inline", attachment_type is PolicyAttachmentType.INLINE))
    return PolicyAttachment.create(
        policy_provider_id=policy_id,
        policy_name=policy_name,
        attachment_type=attachment_type,
        is_inline=is_inline,
        attachment_id=_str(item.get("attachment_id")) or str(uuid4()),
    )


def _parse_attached_policies(payload: dict[str, Any]) -> list[PolicyAttachment]:
    policies: list[PolicyAttachment] = []
    for key in (
        "attached_policies",
        "policies",
        "role_assignments",
        "iam_bindings",
        "inline_policies",
    ):
        raw = payload.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            if not isinstance(item, dict):
                continue
            if key == "inline_policies" and "attachment_type" not in item:
                item = {
                    **item,
                    "attachment_type": PolicyAttachmentType.INLINE.value,
                    "is_inline": True,
                    "policy_provider_id": item.get("policy_provider_id")
                    or item.get("name")
                    or item.get("PolicyName")
                    or f"inline:{item.get('name', uuid4())}",
                }
            if key == "role_assignments" and "attachment_type" not in item:
                item = {
                    **item,
                    "attachment_type": PolicyAttachmentType.ROLE_ASSIGNMENT.value,
                    "policy_provider_id": item.get("role_definition_id")
                    or item.get("policy_provider_id")
                    or item.get("id"),
                    "policy_name": item.get("role_name")
                    or item.get("policy_name")
                    or item.get("display_name"),
                }
            if key == "iam_bindings" and "attachment_type" not in item:
                role = _str(item.get("role"))
                attachment_type = (
                    PolicyAttachmentType.CUSTOM_ROLE
                    if role.startswith("projects/")
                    else PolicyAttachmentType.IAM_BINDING
                )
                if role.startswith("roles/"):
                    attachment_type = PolicyAttachmentType.PREDEFINED_ROLE
                item = {
                    **item,
                    "attachment_type": attachment_type.value,
                    "policy_provider_id": role or item.get("policy_provider_id"),
                    "policy_name": role.rsplit("/", 1)[-1] if role else item.get("policy_name"),
                }
            att = _policy_attachment_from_dict(item)
            if att is not None:
                policies.append(att)
    return policies[:500]


def _parse_trust_relationships(payload: dict[str, Any], account_id: str) -> list[TrustRelationship]:
    trusts = _parse_aws_trust_policy(payload, account_id)
    raw_list = payload.get("trust_relationships")
    if isinstance(raw_list, list):
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            trusted = _str(
                item.get("trusted_principal_provider_id")
                or item.get("principal_id")
                or item.get("trusted_principal")
            )
            if not trusted:
                continue
            trusted_account = (
                _account_from_arn(trusted)
                if trusted.startswith("arn:")
                else _str(item.get("trusted_account_id")) or None
            )
            is_cross = bool(item.get("is_cross_account"))
            if account_id and trusted_account and trusted_account != account_id:
                is_cross = True
            trusts.append(
                TrustRelationship.create(
                    trusted_principal_provider_id=trusted,
                    trust_type=_str(item.get("trust_type"), "Trust"),
                    is_cross_account=is_cross,
                    conditions=_parse_conditions(item.get("conditions"))
                    if isinstance(item.get("conditions"), dict)
                    else (),
                )
            )
    return trusts[:200]


def _resolve_principal_type(raw: RawIAMPrincipal) -> IAMPrincipalType:
    text = _str(raw.principal_type).upper()
    if not text:
        raise InvalidCloudArgumentError("principal_type", "required")
    try:
        return IAMPrincipalType(text)
    except ValueError as exc:
        raise InvalidCloudArgumentError(
            "principal_type", f"unknown type: {raw.principal_type}"
        ) from exc


def normalize_raw_iam_principal(raw: RawIAMPrincipal) -> NormalizedIAMPrincipalDraft:
    """Normalize a provider RawIAMPrincipal into a domain-ready draft."""
    provider_id = _str(raw.provider_id) or _str(raw.payload.get("provider_id"))
    if not provider_id:
        raise InvalidCloudArgumentError("provider_id", "required")
    display_name = _str(raw.display_name) or provider_id
    principal_type = _resolve_principal_type(raw)
    payload = dict(raw.payload) if raw.payload else {}
    account_id = _str(payload.get("account_id") or payload.get("AccountId"))
    is_federated = bool(payload.get("is_federated", False))
    is_human = bool(payload.get("is_human", principal_type is IAMPrincipalType.USER))
    if principal_type in {
        IAMPrincipalType.ROLE,
        IAMPrincipalType.SERVICE_PRINCIPAL,
        IAMPrincipalType.SERVICE_ACCOUNT,
        IAMPrincipalType.MANAGED_IDENTITY,
        IAMPrincipalType.POLICY,
        IAMPrincipalType.GROUP,
    }:
        is_human = bool(payload.get("is_human", False))
    return NormalizedIAMPrincipalDraft(
        principal_type=principal_type,
        provider_id=provider_id,
        display_name=display_name,
        attached_policies=_parse_attached_policies(payload),
        trust_relationships=_parse_trust_relationships(payload, account_id),
        is_federated=is_federated,
        is_human=is_human,
        last_activity_at=_parse_datetime(
            payload.get("last_activity_at") or payload.get("PasswordLastUsed")
        ),
    )
