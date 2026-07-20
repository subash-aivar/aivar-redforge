"""RuleLogic / RuleCondition / related VO ↔ JSON helpers.

Timedeltas are persisted as integer seconds (``*_seconds`` keys).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from detection.domain.value_objects.enums import (
    ConditionOperator,
    FieldDataType,
    LogicConnector,
    RuleLogicType,
    SourceHealthStatus,
)
from detection.domain.value_objects.execution_finding import (
    AnalystNote,
    CorrelationContext,
    EscalationRef,
    ExecutionError,
    ExecutionStats,
    FindingCorrelation,
    MitreAttackRef,
)
from detection.domain.value_objects.keys import (
    AssetScopeFilter,
    ExternalRuleRef,
    FalsePositiveProfile,
    RuleKey,
    RuleTag,
    TelemetrySourceRef,
    ThrottlePolicy,
)
from detection.domain.value_objects.rule_logic import (
    NormalizedFieldRef,
    RuleCondition,
    RuleLogic,
)
from detection.domain.value_objects.telemetry import (
    ConnectionConfig,
    FieldDefinition,
    SourceHealth,
    SourceSchema,
)


def rule_condition_to_dict(condition: RuleCondition) -> dict[str, Any]:
    return {
        "field": condition.field.path,
        "operator": condition.operator.value,
        "value": condition.value,
        "connector": condition.connector.value if condition.connector is not None else None,
        "children": [rule_condition_to_dict(child) for child in condition.children],
    }


def rule_condition_from_dict(data: dict[str, Any]) -> RuleCondition:
    connector_raw = data.get("connector")
    children_raw = data.get("children") or []
    return RuleCondition(
        field=NormalizedFieldRef(str(data["field"])),
        operator=ConditionOperator(str(data["operator"])),
        value=data.get("value"),
        connector=LogicConnector(str(connector_raw)) if connector_raw is not None else None,
        children=tuple(rule_condition_from_dict(child) for child in children_raw),
    )


def rule_logic_to_dict(logic: RuleLogic) -> dict[str, Any]:
    return {
        "logic_type": logic.logic_type.value,
        "conditions": [rule_condition_to_dict(c) for c in logic.conditions],
        "sequence_window_seconds": (
            int(logic.sequence_window.total_seconds())
            if logic.sequence_window is not None
            else None
        ),
        "aggregation_field": logic.aggregation_field,
        "threshold_count": logic.threshold_count,
        "threshold_window_seconds": (
            int(logic.threshold_window.total_seconds())
            if logic.threshold_window is not None
            else None
        ),
        "correlation_refs": [str(ref) for ref in logic.correlation_refs],
        "normalized_field_refs": [ref.path for ref in logic.normalized_field_refs],
    }


def rule_logic_from_dict(data: dict[str, Any]) -> RuleLogic:
    seq_seconds = data.get("sequence_window_seconds")
    thresh_seconds = data.get("threshold_window_seconds")
    refs_raw = data.get("normalized_field_refs") or []
    corr_raw = data.get("correlation_refs") or []
    return RuleLogic(
        logic_type=RuleLogicType(str(data["logic_type"])),
        conditions=tuple(
            rule_condition_from_dict(item) for item in (data.get("conditions") or [])
        ),
        sequence_window=(
            timedelta(seconds=int(seq_seconds)) if seq_seconds is not None else None
        ),
        aggregation_field=data.get("aggregation_field"),
        threshold_count=data.get("threshold_count"),
        threshold_window=(
            timedelta(seconds=int(thresh_seconds)) if thresh_seconds is not None else None
        ),
        correlation_refs=tuple(RuleKey(str(ref)) for ref in corr_raw),
        normalized_field_refs=tuple(NormalizedFieldRef(str(path)) for path in refs_raw),
    )


def telemetry_sources_to_json(refs: list[TelemetrySourceRef]) -> list[dict[str, Any]]:
    return [
        {"source_id": ref.source_id, "source_type": ref.source_type}
        for ref in refs
    ]


def telemetry_sources_from_json(data: list[Any] | None) -> list[TelemetrySourceRef]:
    if not data:
        return []
    return [
        TelemetrySourceRef(
            source_id=str(item["source_id"]),
            source_type=item.get("source_type"),
        )
        for item in data
    ]


def asset_scope_to_json(scope: AssetScopeFilter | None) -> dict[str, Any] | None:
    if scope is None:
        return None
    return {
        "asset_types": list(scope.asset_types),
        "tags": list(scope.tags),
    }


def asset_scope_from_json(data: dict[str, Any] | None) -> AssetScopeFilter | None:
    if data is None:
        return None
    return AssetScopeFilter(
        asset_types=tuple(str(t) for t in (data.get("asset_types") or ())),
        tags=tuple(str(t) for t in (data.get("tags") or ())),
    )


def throttle_to_json(policy: ThrottlePolicy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {
        "window_seconds": policy.window_seconds,
        "max_count": policy.max_count,
    }


def throttle_from_json(data: dict[str, Any] | None) -> ThrottlePolicy | None:
    if data is None:
        return None
    return ThrottlePolicy(
        window_seconds=int(data["window_seconds"]),
        max_count=int(data["max_count"]),
    )


def fp_profile_to_json(profile: FalsePositiveProfile | None) -> dict[str, Any] | None:
    if profile is None:
        return None
    return {
        "fp_rate": profile.fp_rate,
        "total_findings": profile.total_findings,
        "fp_count": profile.fp_count,
        "last_calculated_at": profile.last_calculated_at,
    }


def fp_profile_from_json(data: dict[str, Any] | None) -> FalsePositiveProfile | None:
    if data is None:
        return None
    return FalsePositiveProfile(
        fp_rate=float(data["fp_rate"]),
        total_findings=int(data["total_findings"]),
        fp_count=int(data["fp_count"]),
        last_calculated_at=data.get("last_calculated_at"),
    )


def tags_to_json(tags: list[RuleTag]) -> list[str]:
    return [tag.value for tag in tags]


def tags_from_json(data: list[Any] | None) -> list[RuleTag]:
    if not data:
        return []
    return [RuleTag(str(item)) for item in data]


def external_refs_to_json(refs: list[ExternalRuleRef]) -> list[dict[str, str]]:
    return [{"system": ref.system, "external_id": ref.external_id} for ref in refs]


def external_refs_from_json(data: list[Any] | None) -> list[ExternalRuleRef]:
    if not data:
        return []
    return [
        ExternalRuleRef(system=str(item["system"]), external_id=str(item["external_id"]))
        for item in data
    ]


# --- TelemetrySource serialization ---


def source_schema_to_json(schema: SourceSchema) -> dict[str, Any]:
    return {
        "schema_version": schema.schema_version,
        "contract_name": schema.contract_name,
        "fields": [
            {
                "path": f.field_ref.path,
                "data_type": f.data_type.value,
                "required": f.required,
                "description": f.description,
            }
            for f in schema.fields
        ],
    }


def source_schema_from_json(data: dict[str, Any]) -> SourceSchema:
    fields_raw = data.get("fields") or []
    return SourceSchema(
        schema_version=str(data["schema_version"]),
        contract_name=str(data.get("contract_name") or "NormalizedTelemetry"),
        fields=tuple(
            FieldDefinition(
                field_ref=NormalizedFieldRef(str(item["path"])),
                data_type=FieldDataType(str(item["data_type"])),
                required=bool(item.get("required", False)),
                description=str(item.get("description") or ""),
            )
            for item in fields_raw
        ),
    )


def connection_to_json(config: ConnectionConfig) -> dict[str, Any]:
    return {
        "adapter_key": config.adapter_key,
        "tenant_scope_assertion": config.tenant_scope_assertion,
        "credential_vault_ref": (
            str(config.credential_vault_ref) if config.credential_vault_ref else None
        ),
        "endpoint_url": config.endpoint_url,
        "options": dict(config.options),
    }


def connection_from_json(data: dict[str, Any]) -> ConnectionConfig:
    from uuid import UUID

    vault = data.get("credential_vault_ref")
    return ConnectionConfig(
        adapter_key=str(data["adapter_key"]),
        tenant_scope_assertion=str(data["tenant_scope_assertion"]),
        credential_vault_ref=UUID(str(vault)) if vault else None,
        endpoint_url=data.get("endpoint_url"),
        options={str(k): str(v) for k, v in (data.get("options") or {}).items()},
    )


def health_to_json(health: SourceHealth) -> dict[str, Any]:
    return {
        "status": health.status.value,
        "last_checked_at": (
            health.last_checked_at.isoformat() if health.last_checked_at else None
        ),
        "last_success_at": (
            health.last_success_at.isoformat() if health.last_success_at else None
        ),
        "last_failure_at": (
            health.last_failure_at.isoformat() if health.last_failure_at else None
        ),
        "last_error": health.last_error,
        "consecutive_failures": health.consecutive_failures,
    }


def health_from_json(data: dict[str, Any]) -> SourceHealth:
    from datetime import datetime

    def _parse_dt(raw: Any) -> datetime | None:
        if raw is None:
            return None
        if isinstance(raw, datetime):
            return raw
        return datetime.fromisoformat(str(raw))

    return SourceHealth(
        status=SourceHealthStatus(str(data["status"])),
        last_checked_at=_parse_dt(data.get("last_checked_at")),
        last_success_at=_parse_dt(data.get("last_success_at")),
        last_failure_at=_parse_dt(data.get("last_failure_at")),
        last_error=data.get("last_error"),
        consecutive_failures=int(data.get("consecutive_failures") or 0),
    )


# --- Execution / Finding serialization ---


def execution_stats_to_json(stats: ExecutionStats) -> dict[str, Any]:
    return {
        "telemetry_records_evaluated": stats.telemetry_records_evaluated,
        "findings_produced": stats.findings_produced,
        "duration_ms": stats.duration_ms,
        "cpu_ms": stats.cpu_ms,
    }


def execution_stats_from_json(data: dict[str, Any] | None) -> ExecutionStats:
    if not data:
        return ExecutionStats()
    return ExecutionStats(
        telemetry_records_evaluated=int(data.get("telemetry_records_evaluated") or 0),
        findings_produced=int(data.get("findings_produced") or 0),
        duration_ms=float(data.get("duration_ms") or 0.0),
        cpu_ms=float(data.get("cpu_ms") or 0.0),
    )


def execution_error_to_json(error: ExecutionError | None) -> dict[str, Any] | None:
    if error is None:
        return None
    return {
        "error_type": error.error_type,
        "error_message": error.error_message,
        "stack_ref": error.stack_ref,
    }


def execution_error_from_json(data: dict[str, Any] | None) -> ExecutionError | None:
    if not data:
        return None
    return ExecutionError(
        error_type=str(data["error_type"]),
        error_message=str(data["error_message"]),
        stack_ref=data.get("stack_ref"),
    )


def mitre_ref_to_json(ref: MitreAttackRef | None) -> dict[str, Any] | None:
    if ref is None:
        return None
    return {
        "tactic": ref.tactic,
        "technique_id": ref.technique_id,
        "sub_technique_id": ref.sub_technique_id,
    }


def mitre_ref_from_json(data: dict[str, Any] | None) -> MitreAttackRef | None:
    if not data:
        return None
    return MitreAttackRef(
        tactic=data.get("tactic"),
        technique_id=data.get("technique_id"),
        sub_technique_id=data.get("sub_technique_id"),
    )


def correlation_to_json(corr: FindingCorrelation) -> dict[str, Any]:
    ctx = corr.context
    return {
        "correlation_id": corr.correlation_id,
        "enriched": corr.enriched,
        "context": {
            "asset_metadata": dict(ctx.asset_metadata),
            "vulnerability_instances": list(ctx.vulnerability_instances),
            "cloud_context": dict(ctx.cloud_context),
            "identity_ref": ctx.identity_ref,
            "threat_actor_refs": list(ctx.threat_actor_refs),
            "compliance_controls": list(ctx.compliance_controls),
            "sibling_finding_refs": list(ctx.sibling_finding_refs),
            "correlated_at": (
                ctx.correlated_at.isoformat() if ctx.correlated_at else None
            ),
        },
    }


def correlation_from_json(data: dict[str, Any] | None) -> FindingCorrelation:
    if not data:
        return FindingCorrelation.placeholder()
    from datetime import datetime

    ctx_raw = data.get("context") or {}
    corr_at = ctx_raw.get("correlated_at")
    context = CorrelationContext(
        asset_metadata=dict(ctx_raw.get("asset_metadata") or {}),
        vulnerability_instances=tuple(
            str(x) for x in (ctx_raw.get("vulnerability_instances") or ())
        ),
        cloud_context=dict(ctx_raw.get("cloud_context") or {}),
        identity_ref=ctx_raw.get("identity_ref"),
        threat_actor_refs=tuple(
            str(x) for x in (ctx_raw.get("threat_actor_refs") or ())
        ),
        compliance_controls=tuple(
            str(x) for x in (ctx_raw.get("compliance_controls") or ())
        ),
        sibling_finding_refs=tuple(
            str(x) for x in (ctx_raw.get("sibling_finding_refs") or ())
        ),
        correlated_at=(
            datetime.fromisoformat(str(corr_at)) if corr_at else None
        ),
    )
    return FindingCorrelation(
        correlation_id=data.get("correlation_id"),
        context=context,
        enriched=bool(data.get("enriched", False)),
    )


def analyst_note_to_json(note: AnalystNote | None) -> dict[str, Any] | None:
    if note is None:
        return None
    return {"text": note.text, "author": note.author}


def analyst_note_from_json(data: dict[str, Any] | None) -> AnalystNote | None:
    if not data:
        return None
    return AnalystNote(text=str(data["text"]), author=data.get("author"))


def escalation_to_json(ref: EscalationRef | None) -> dict[str, Any] | None:
    if ref is None:
        return None
    return {
        "investigation_id": ref.investigation_id,
        "escalated_at": (
            ref.escalated_at.isoformat() if ref.escalated_at else None
        ),
    }


def escalation_from_json(data: dict[str, Any] | None) -> EscalationRef | None:
    if not data:
        return None
    from datetime import datetime

    raw = data.get("escalated_at")
    return EscalationRef(
        investigation_id=str(data["investigation_id"]),
        escalated_at=datetime.fromisoformat(str(raw)) if raw else None,
    )


# --- Phase 4 pack / exception / evidence helpers ---

def pack_maintainer_to_json(m: object) -> dict[str, object]:
    return {"identity": m.identity, "display_name": m.display_name}  # type: ignore[attr-defined]


def pack_maintainer_from_json(data: dict[str, Any] | None) -> Any:
    from detection.domain.value_objects.pack import PackMaintainer
    if not data:
        raise ValueError("maintainer required")
    return PackMaintainer(
        identity=str(data["identity"]),
        display_name=data.get("display_name"),
    )


def subscription_to_json(scope: object) -> dict[str, object]:
    return {"tenant_ids": list(scope.tenant_ids)}  # type: ignore[attr-defined]


def subscription_from_json(data: dict[str, Any] | None) -> Any:
    from detection.domain.value_objects.pack import PackSubscriptionScope
    if not data:
        return PackSubscriptionScope()
    return PackSubscriptionScope(tenant_ids=tuple(data.get("tenant_ids") or ()))


def compliance_fw_to_json(ref: object | None) -> dict[str, object] | None:
    if ref is None:
        return None
    return {"framework_id": ref.framework_id, "framework_name": ref.framework_name}  # type: ignore[attr-defined]


def compliance_fw_from_json(data: dict[str, Any] | None) -> Any:
    from detection.domain.value_objects.pack import ComplianceFrameworkRef
    if not data:
        return None
    return ComplianceFrameworkRef(
        framework_id=str(data["framework_id"]),
        framework_name=data.get("framework_name"),
    )


def coverage_to_json(matrix: object) -> dict[str, Any]:
    payload: dict[str, Any] = matrix.to_dict()  # type: ignore[attr-defined]
    return payload


def coverage_from_json(data: dict[str, Any] | None) -> Any:
    from datetime import datetime

    from detection.domain.value_objects.pack import CoverageMatrix, CoverageMatrixEntry
    if not data:
        return CoverageMatrix.empty()
    entries = tuple(
        CoverageMatrixEntry(
            technique_id=str(e["technique_id"]),
            rule_count=int(e["rule_count"]),
            rule_ids=tuple(e.get("rule_ids") or ()),
        )
        for e in (data.get("entries") or [])
    )
    computed = data.get("computed_at")
    computed_at = datetime.fromisoformat(computed) if computed else None
    return CoverageMatrix(entries=entries, computed_at=computed_at)


def pack_metadata_to_json(meta: object) -> dict[str, Any]:
    return {
        "description": meta.description,  # type: ignore[attr-defined]
        "tags": list(meta.tags),  # type: ignore[attr-defined]
        "extra": dict(meta.extra),  # type: ignore[attr-defined]
    }


def pack_metadata_from_json(data: dict[str, Any] | None) -> Any:
    from detection.domain.value_objects.pack import PackMetadata
    if not data:
        return PackMetadata()
    return PackMetadata(
        description=str(data.get("description") or ""),
        tags=tuple(data.get("tags") or ()),
        extra=dict(data.get("extra") or {}),
    )
