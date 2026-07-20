"""Detection rule API routers."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from detection.api.dependencies import (
    PrincipalIdDep,
    RuleServiceDep,
    TelemetryServiceDep,
    TenantIdDep,
)
from detection.api.schemas.rule_schemas import (
    AuthorDetectionRuleRequest,
    DemoteRuleRequest,
    DetectionRuleResponse,
    ListRulesResponse,
    PromoteRuleRequest,
    PublishRuleVersionRequest,
    RuleTestSuiteResponse,
    UpdateRuleRequest,
    ValidateRuleResponse,
)
from detection.api.schemas.telemetry_schemas import (
    SchemaValidationResponse,
    SimulateRuleRequest,
    SimulationResultResponse,
    ValidateRuleAgainstSchemaRequest,
)
from detection.application.commands.rule_commands import (
    AuthorDetectionRule,
    DemoteRule,
    PromoteRule,
    PublishRuleVersion,
    RunRuleTestSuite,
    UpdateRule,
    ValidateRule,
)
from detection.application.queries.rule_queries import GetRule, ListRules
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

rules_router = APIRouter()


@rules_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=DetectionRuleResponse,
)
async def author_detection_rule(
    body: AuthorDetectionRuleRequest,
    response: Response,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionRuleResponse:
    dto = await svc.author_detection_rule(
        AuthorDetectionRule(
            tenant_id=tenant_id,
            rule_key=body.rule_key,
            title=body.title,
            description=body.description,
            category=body.category,
            severity=body.severity,
            confidence=body.confidence,
            author_identity=str(principal_id),
            logic=body.logic.to_dict(),
            telemetry_sources=[
                {"source_id": s.source_id, "source_type": s.source_type}
                for s in body.telemetry_sources
            ],
            asset_scope=(
                {"asset_types": body.asset_scope.asset_types, "tags": body.asset_scope.tags}
                if body.asset_scope is not None
                else None
            ),
            throttle=(
                {
                    "window_seconds": body.throttle.window_seconds,
                    "max_count": body.throttle.max_count,
                }
                if body.throttle is not None
                else None
            ),
            tags=list(body.tags),
            external_refs=[
                {"system": r.system, "external_id": r.external_id}
                for r in body.external_refs
            ],
            test_cases=[
                {
                    "name": t.name,
                    "input_payload": t.input_payload,
                    "expected_match": t.expected_match,
                    "description": t.description,
                }
                for t in body.test_cases
            ],
        )
    )
    response.headers["Location"] = f"/api/v1/detection-rules/{dto.rule_id}"
    return DetectionRuleResponse.from_dto(dto)


@rules_router.get("", response_model=ListRulesResponse)
async def list_detection_rules(
    tenant_id: TenantIdDep,
    svc: RuleServiceDep,
    lifecycle_state: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> ListRulesResponse:
    page = await svc.list_rules(
        ListRules(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            lifecycle_state=lifecycle_state,
        )
    )
    return ListRulesResponse(
        items=[DetectionRuleResponse.from_dto(item) for item in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )


@rules_router.get("/{rule_id}", response_model=DetectionRuleResponse)
async def get_detection_rule(
    rule_id: UUID,
    tenant_id: TenantIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> DetectionRuleResponse:
    dto = await svc.get_rule(GetRule(tenant_id=tenant_id, rule_id=rule_id))
    return DetectionRuleResponse.from_dto(dto)


@rules_router.patch("/{rule_id}", response_model=DetectionRuleResponse)
async def update_detection_rule(
    rule_id: UUID,
    body: UpdateRuleRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionRuleResponse:
    dto = await svc.update_rule(
        UpdateRule(
            tenant_id=tenant_id,
            rule_id=rule_id,
            title=body.title,
            description=body.description,
            severity=body.severity,
            confidence=body.confidence,
            throttle=(
                {
                    "window_seconds": body.throttle.window_seconds,
                    "max_count": body.throttle.max_count,
                }
                if body.throttle is not None
                else None
            ),
            tags=list(body.tags) if body.tags is not None else None,
            test_cases=(
                [
                    {
                        "name": t.name,
                        "input_payload": t.input_payload,
                        "expected_match": t.expected_match,
                        "description": t.description,
                    }
                    for t in body.test_cases
                ]
                if body.test_cases is not None
                else None
            ),
            actor=str(principal_id),
        )
    )
    return DetectionRuleResponse.from_dto(dto)


@rules_router.post("/{rule_id}/publish", response_model=DetectionRuleResponse)
async def publish_rule_version(
    rule_id: UUID,
    body: PublishRuleVersionRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionRuleResponse:
    dto = await svc.publish_rule_version(
        PublishRuleVersion(
            tenant_id=tenant_id,
            rule_id=rule_id,
            change_summary=body.change_summary,
            published_by=str(principal_id),
            semver=body.semver,
            logic=body.logic.to_dict() if body.logic is not None else None,
        )
    )
    return DetectionRuleResponse.from_dto(dto)


@rules_router.post("/{rule_id}/promote", response_model=DetectionRuleResponse)
async def promote_rule(
    rule_id: UUID,
    body: PromoteRuleRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionRuleResponse:
    dto = await svc.promote_rule(
        PromoteRule(
            tenant_id=tenant_id,
            rule_id=rule_id,
            target_state=body.target_state,
            actor=str(principal_id),
            reviewer_identity=body.reviewer_identity or str(principal_id),
        )
    )
    return DetectionRuleResponse.from_dto(dto)


@rules_router.post("/{rule_id}/demote", response_model=DetectionRuleResponse)
async def demote_rule(
    rule_id: UUID,
    body: DemoteRuleRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionRuleResponse:
    dto = await svc.demote_rule(
        DemoteRule(
            tenant_id=tenant_id,
            rule_id=rule_id,
            target_state=body.target_state,
            actor=str(principal_id),
            reason=body.reason,
        )
    )
    return DetectionRuleResponse.from_dto(dto)


@rules_router.post("/{rule_id}/validate", response_model=ValidateRuleResponse)
async def validate_rule(
    rule_id: UUID,
    tenant_id: TenantIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> ValidateRuleResponse:
    result = await svc.validate_rule(
        ValidateRule(tenant_id=tenant_id, rule_id=rule_id)
    )
    return ValidateRuleResponse(rule_id=UUID(result.rule_id), valid=result.valid)


@rules_router.post("/{rule_id}/test-suite", response_model=RuleTestSuiteResponse)
async def run_rule_test_suite(
    rule_id: UUID,
    tenant_id: TenantIdDep,
    svc: RuleServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> RuleTestSuiteResponse:
    result = await svc.run_rule_test_suite(
        RunRuleTestSuite(tenant_id=tenant_id, rule_id=rule_id)
    )
    return RuleTestSuiteResponse(
        rule_id=UUID(result.rule_id),
        results=list(result.results),
    )


@rules_router.post(
    "/{rule_id}/simulate",
    response_model=SimulationResultResponse,
)
async def simulate_rule(
    rule_id: UUID,
    body: SimulateRuleRequest,
    tenant_id: TenantIdDep,
    telemetry_svc: TelemetryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> SimulationResultResponse:
    from detection.application.commands.telemetry_commands import SimulateRule

    result = await telemetry_svc.simulate_rule(
        SimulateRule(
            tenant_id=tenant_id,
            rule_id=rule_id,
            source_id=UUID(body.source_id),
            window_start=body.window_start,
            window_end=body.window_end,
            version=body.version,
            limit=body.limit,
            synthetic_events=body.synthetic_events,
        )
    )
    return SimulationResultResponse(
        simulation_id=result.simulation_id,
        rule_id=result.rule_id,
        rule_version=result.rule_version,
        source_id=result.source_id,
        match_count=result.match_count,
        events_evaluated=result.events_evaluated,
        duration_ms=result.duration_ms,
        truncated=result.truncated,
        source_unavailable=result.source_unavailable,
        sample_matches=result.sample_matches,
        evidence=result.evidence,
        simulated_at=result.simulated_at,
        creates_findings=result.creates_findings,
        findings_created=result.findings_created,
    )


@rules_router.post(
    "/{rule_id}/validate-schema",
    response_model=SchemaValidationResponse,
)
async def validate_rule_against_schema(
    rule_id: UUID,
    body: ValidateRuleAgainstSchemaRequest,
    tenant_id: TenantIdDep,
    telemetry_svc: TelemetryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> SchemaValidationResponse:
    from detection.application.commands.telemetry_commands import (
        ValidateRuleAgainstSchema,
    )

    result = await telemetry_svc.validate_rule_against_schema(
        ValidateRuleAgainstSchema(
            tenant_id=tenant_id,
            rule_id=rule_id,
            source_id=UUID(body.source_id),
            version=body.version,
        )
    )
    return SchemaValidationResponse(
        is_valid=result.is_valid,
        missing_fields=result.missing_fields,
        unsupported_fields=result.unsupported_fields,
        issues=result.issues,
        schema_version=result.schema_version,
        compatible=result.compatible,
    )
