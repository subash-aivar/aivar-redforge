"""Versioned, server-controlled M9 correlation rule engine.

Rules are plain Python classes registered by (stable_rule_id,
rule_version) — never arbitrary expressions from the database, never
browser-authored code, never an LLM-generated predicate. Each rule
reads only canonical facts (via `facts.py` and the M8
`TenantSecurityConditionService`) and returns zero or more
`CorrelationRuleResult` instances; the evaluation service (`service.py`)
owns identity derivation, persistence, and resolution safety.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from redforge.application.security_correlation import facts
from redforge.core.exceptions import NotFoundError

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService


@dataclass(frozen=True, slots=True)
class CorrelationRuleResult:
    entity_ids: list[str]
    condition_ids: list[str]
    evidence_state: str
    title: str
    summary: str
    operator_action: str


class CorrelationRule(Protocol):
    stable_rule_id: str
    rule_version: int

    async def evaluate(self, organization_id: str) -> list[CorrelationRuleResult]: ...


class PublicSensitiveServiceContextRule:
    """RULE 1 — PUBLIC_SENSITIVE_SERVICE_CONTEXT.

    Fires when a canonical HOST is reachable from an OBSERVED public IP
    (`IP_ASSIGNED_TO_HOST`) AND that same HOST exposes a service already
    identified by M6's `SENSITIVE_SERVICE_OBSERVED` SecurityCondition
    (`HOST_EXPOSES_SERVICE`, decoded from the SERVICE asset's own
    `SERVICE_ENDPOINT` identity). Both source facts are OBSERVED, so the
    correlation's evidence_state is OBSERVED — this rule does not claim
    reachability was itself validated, only that the two OBSERVED facts
    co-occur on the same canonical host."""

    stable_rule_id = "PUBLIC_SENSITIVE_SERVICE_CONTEXT"
    rule_version = 1

    def __init__(
        self, asset_service: TenantAssetService, condition_service: TenantSecurityConditionService,
    ) -> None:
        self._asset_service = asset_service
        self._condition_service = condition_service

    async def evaluate(self, organization_id: str) -> list[CorrelationRuleResult]:
        sensitive_conditions = [
            c for c in await self._condition_service.list_for_org(
                organization_id, source_category="network_discovery", limit=500,
            )
            if c.stable_rule_id == "SENSITIVE_SERVICE_OBSERVED" and c.lifecycle == "active"
        ]
        if not sensitive_conditions:
            return []

        public_ips = await facts.public_ip_asset_ids(self._asset_service, organization_id)
        if not public_ips:
            return []
        public_hosts = await facts.public_host_asset_ids(
            self._asset_service, organization_id, public_ips
        )
        if not public_hosts:
            return []

        results: list[CorrelationRuleResult] = []
        for condition in sensitive_conditions:
            try:
                host_id = await facts.service_host_asset_id(
                    self._asset_service, organization_id, condition.affected_asset_id,
                )
            except NotFoundError:
                continue
            if host_id is None or host_id not in public_hosts:
                continue
            results.append(
                CorrelationRuleResult(
                    entity_ids=sorted({host_id, condition.affected_asset_id}),
                    condition_ids=[condition.id],
                    evidence_state="observed",
                    title="Sensitive service associated with public exposure context",
                    summary=(
                        f"{condition.title} on host {host_id} is associated with an "
                        "asset that has public-address exposure context."
                    ),
                    operator_action=(
                        "Verify external reachability and restrict the service to "
                        "approved administrative sources."
                    ),
                )
            )
        return results


class MultipleSecurityConditionsOnAssetRule:
    """RULE 3 — MULTIPLE_SECURITY_CONDITIONS_ON_ASSET.

    Fires when 2+ independent ACTIVE SecurityConditions (regardless of
    source category — two network-discovery findings still concentrate
    operator attention on one asset) affect the same canonical asset.
    Concentration context only — never exploitability, never a new
    SecurityCondition."""

    stable_rule_id = "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"
    rule_version = 1

    def __init__(self, condition_service: TenantSecurityConditionService) -> None:
        self._condition_service = condition_service

    async def evaluate(self, organization_id: str) -> list[CorrelationRuleResult]:
        asset_ids = await self._condition_service.list_asset_ids_with_multiple_active_conditions(
            organization_id, minimum_count=2,
        )
        results: list[CorrelationRuleResult] = []
        for asset_id in asset_ids:
            conditions = await self._condition_service.list_active_for_asset(
                organization_id, asset_id,
            )
            source_categories = sorted({c.source_category for c in conditions})
            results.append(
                CorrelationRuleResult(
                    entity_ids=[asset_id],
                    condition_ids=sorted(c.id for c in conditions),
                    evidence_state="observed",
                    title="Multiple active security conditions affect this asset",
                    summary=(
                        f"This asset has {len(conditions)} active security conditions "
                        f"across {len(source_categories)} source "
                        f"categor{'y' if len(source_categories) == 1 else 'ies'} "
                        f"({', '.join(source_categories)})."
                    ),
                    operator_action=(
                        "Review the active conditions together and prioritize "
                        "remediation based on severity and exposure context."
                    ),
                )
            )
        return results


class DuplicateRuleRegistrationError(ValueError):
    pass


class CorrelationRuleRegistry:
    """Rejects duplicate (stable_rule_id, rule_version) registration.
    Unknown rule IDs are simply absent — callers fail safely by getting
    an empty evaluation result, never a fabricated match."""

    def __init__(self) -> None:
        self._rules: dict[tuple[str, int], CorrelationRule] = {}

    def register(self, rule: CorrelationRule) -> None:
        key = (rule.stable_rule_id, rule.rule_version)
        if key in self._rules:
            raise DuplicateRuleRegistrationError(
                f"rule {rule.stable_rule_id} v{rule.rule_version} already registered"
            )
        self._rules[key] = rule

    def all_rules(self) -> list[CorrelationRule]:
        return list(self._rules.values())

    def get(self, stable_rule_id: str, rule_version: int) -> CorrelationRule | None:
        return self._rules.get((stable_rule_id, rule_version))
