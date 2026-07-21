"""Read-model store port + in-memory implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ai_posture.application.projections.read_models import (
    AIAgentDeviationReport,
    AIAssetInventoryDashboard,
    AICompliancePostureReport,
    AIRiskRegister,
    AISupplyChainIntegrityReport,
    EnvelopeHumanApprovalAudit,
    ShadowAIDiscoveryReport,
)


class IReadModelStore(ABC):
    @abstractmethod
    async def save_inventory(self, view: AIAssetInventoryDashboard) -> None: ...

    @abstractmethod
    async def load_inventory(self, tenant_id: str) -> AIAssetInventoryDashboard | None: ...

    @abstractmethod
    async def save_risk_register(self, view: AIRiskRegister) -> None: ...

    @abstractmethod
    async def load_risk_register(self, tenant_id: str) -> AIRiskRegister | None: ...

    @abstractmethod
    async def save_shadow_report(self, view: ShadowAIDiscoveryReport) -> None: ...

    @abstractmethod
    async def load_shadow_report(self, tenant_id: str) -> ShadowAIDiscoveryReport | None: ...

    @abstractmethod
    async def save_compliance_posture(self, view: AICompliancePostureReport) -> None: ...

    @abstractmethod
    async def load_compliance_posture(
        self, tenant_id: str, framework_id: str
    ) -> AICompliancePostureReport | None: ...

    @abstractmethod
    async def save_supply_chain(self, view: AISupplyChainIntegrityReport) -> None: ...

    @abstractmethod
    async def load_supply_chain(self, tenant_id: str) -> AISupplyChainIntegrityReport | None: ...

    @abstractmethod
    async def save_deviation_report(self, view: AIAgentDeviationReport) -> None: ...

    @abstractmethod
    async def load_deviation_report(self, tenant_id: str) -> AIAgentDeviationReport | None: ...

    @abstractmethod
    async def save_approval_audit(self, view: EnvelopeHumanApprovalAudit) -> None: ...

    @abstractmethod
    async def load_approval_audit(
        self, tenant_id: str, envelope_id: str
    ) -> EnvelopeHumanApprovalAudit | None: ...

    @abstractmethod
    async def clear_tenant(self, tenant_id: str) -> None: ...

    @abstractmethod
    def status(self) -> dict[str, Any]: ...


class InMemoryReadModelStore(IReadModelStore):
    def __init__(self) -> None:
        self.inventory: dict[str, AIAssetInventoryDashboard] = {}
        self.risk: dict[str, AIRiskRegister] = {}
        self.shadow: dict[str, ShadowAIDiscoveryReport] = {}
        self.compliance: dict[tuple[str, str], AICompliancePostureReport] = {}
        self.supply: dict[str, AISupplyChainIntegrityReport] = {}
        self.deviations: dict[str, AIAgentDeviationReport] = {}
        self.audits: dict[tuple[str, str], EnvelopeHumanApprovalAudit] = {}

    async def save_inventory(self, view: AIAssetInventoryDashboard) -> None:
        self.inventory[view.tenant_id] = view

    async def load_inventory(self, tenant_id: str) -> AIAssetInventoryDashboard | None:
        return self.inventory.get(tenant_id)

    async def save_risk_register(self, view: AIRiskRegister) -> None:
        self.risk[view.tenant_id] = view

    async def load_risk_register(self, tenant_id: str) -> AIRiskRegister | None:
        return self.risk.get(tenant_id)

    async def save_shadow_report(self, view: ShadowAIDiscoveryReport) -> None:
        self.shadow[view.tenant_id] = view

    async def load_shadow_report(self, tenant_id: str) -> ShadowAIDiscoveryReport | None:
        return self.shadow.get(tenant_id)

    async def save_compliance_posture(self, view: AICompliancePostureReport) -> None:
        self.compliance[(view.tenant_id, view.framework_id)] = view

    async def load_compliance_posture(
        self, tenant_id: str, framework_id: str
    ) -> AICompliancePostureReport | None:
        return self.compliance.get((tenant_id, framework_id))

    async def save_supply_chain(self, view: AISupplyChainIntegrityReport) -> None:
        self.supply[view.tenant_id] = view

    async def load_supply_chain(self, tenant_id: str) -> AISupplyChainIntegrityReport | None:
        return self.supply.get(tenant_id)

    async def save_deviation_report(self, view: AIAgentDeviationReport) -> None:
        self.deviations[view.tenant_id] = view

    async def load_deviation_report(self, tenant_id: str) -> AIAgentDeviationReport | None:
        return self.deviations.get(tenant_id)

    async def save_approval_audit(self, view: EnvelopeHumanApprovalAudit) -> None:
        self.audits[(view.tenant_id, view.envelope_id)] = view

    async def load_approval_audit(
        self, tenant_id: str, envelope_id: str
    ) -> EnvelopeHumanApprovalAudit | None:
        return self.audits.get((tenant_id, envelope_id))

    async def clear_tenant(self, tenant_id: str) -> None:
        self.inventory.pop(tenant_id, None)
        self.risk.pop(tenant_id, None)
        self.shadow.pop(tenant_id, None)
        self.supply.pop(tenant_id, None)
        self.deviations.pop(tenant_id, None)
        for key in list(self.compliance):
            if key[0] == tenant_id:
                del self.compliance[key]
        for key in list(self.audits):
            if key[0] == tenant_id:
                del self.audits[key]

    def status(self) -> dict[str, Any]:
        return {
            "inventory": len(self.inventory),
            "risk": len(self.risk),
            "shadow": len(self.shadow),
            "compliance": len(self.compliance),
            "supply": len(self.supply),
            "deviations": len(self.deviations),
            "audits": len(self.audits),
        }
