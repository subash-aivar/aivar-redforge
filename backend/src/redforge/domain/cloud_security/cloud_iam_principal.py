"""CloudIAMPrincipal aggregate root — cloud identity inventory (CIEM foundation)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.entities import (
    IAMRiskIndicator,
    PolicyAttachment,
    TrustRelationship,
)
from redforge.domain.cloud_security.events import (
    CloudSecurityDomainEvent,
    CrossAccountTrustDiscovered,
    IAMPrincipalDeleted,
    IAMPrincipalDisabled,
    IAMPrincipalDiscovered,
    IAMPrincipalUpdated,
)
from redforge.domain.cloud_security.exceptions import (
    CloudIAMPrincipalDeletedError,
    CloudIAMPrincipalDisabledError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudIAMPrincipalId,
    EffectivePermissions,
    IAMPrincipalType,
    OrganizationId,
    PrivilegeLevel,
)


@dataclass
class CloudIAMPrincipal:
    id: CloudIAMPrincipalId
    cloud_account_id: CloudAccountId
    organization_id: OrganizationId
    principal_type: IAMPrincipalType
    provider_id: str
    display_name: str
    attached_policies: list[PolicyAttachment]
    trust_relationships: list[TrustRelationship]
    privilege_level: PrivilegeLevel
    is_federated: bool
    is_human: bool
    last_activity_at: datetime | None
    risk_indicators: list[IAMRiskIndicator]
    is_disabled: bool
    is_deleted: bool
    deleted_at: datetime | None
    last_seen_at: datetime
    first_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int = 1
    # EffectivePermissions is never persisted (ADR-M26-003); kept in-memory only.
    _effective_permissions: EffectivePermissions = field(
        default_factory=EffectivePermissions.unknown, repr=False
    )
    _pending_events: list[CloudSecurityDomainEvent] = field(default_factory=list, repr=False)

    @property
    def effective_permissions(self) -> EffectivePermissions:
        return self._effective_permissions

    @classmethod
    def discover(
        cls,
        *,
        cloud_account_id: CloudAccountId,
        organization_id: OrganizationId,
        principal_type: IAMPrincipalType,
        provider_id: str,
        display_name: str,
        attached_policies: list[PolicyAttachment] | None = None,
        trust_relationships: list[TrustRelationship] | None = None,
        is_federated: bool = False,
        is_human: bool = False,
        last_activity_at: datetime | None = None,
        risk_indicators: list[IAMRiskIndicator] | None = None,
        privilege_level: PrivilegeLevel = PrivilegeLevel.NONE,
        now: datetime | None = None,
        principal_id: CloudIAMPrincipalId | None = None,
    ) -> CloudIAMPrincipal:
        pid = provider_id.strip() if provider_id else ""
        if not pid:
            raise InvalidCloudArgumentError("provider_id", "required")
        if len(pid) > 2048:
            raise InvalidCloudArgumentError("provider_id", "max 2048 chars")
        name = display_name.strip() if display_name else ""
        if not name:
            raise InvalidCloudArgumentError("display_name", "required")
        if len(name) > 512:
            raise InvalidCloudArgumentError("display_name", "max 512 chars")
        policies = list(attached_policies or [])
        trusts = list(trust_relationships or [])
        indicators = list(risk_indicators or [])
        if len(policies) > 500:
            raise InvalidCloudArgumentError("attached_policies", "max 500")
        if len(trusts) > 200:
            raise InvalidCloudArgumentError("trust_relationships", "max 200")
        if len(indicators) > 100:
            raise InvalidCloudArgumentError("risk_indicators", "max 100")
        ts = now or datetime.now(UTC)
        aggregate = cls(
            id=principal_id or CloudIAMPrincipalId.generate(),
            cloud_account_id=cloud_account_id,
            organization_id=organization_id,
            principal_type=principal_type,
            provider_id=pid,
            display_name=name,
            attached_policies=policies,
            trust_relationships=trusts,
            privilege_level=privilege_level,
            is_federated=is_federated,
            is_human=is_human,
            last_activity_at=last_activity_at,
            risk_indicators=indicators,
            is_disabled=False,
            is_deleted=False,
            deleted_at=None,
            last_seen_at=ts,
            first_seen_at=ts,
            created_at=ts,
            updated_at=ts,
            version=1,
        )
        aggregate._pending_events.append(
            IAMPrincipalDiscovered(
                principal_id=str(aggregate.id),
                cloud_account_id=str(cloud_account_id),
                organization_id=str(organization_id),
                principal_type=principal_type.value,
                provider_id=pid,
                occurred_at=ts,
            )
        )
        for trust in trusts:
            if trust.is_cross_account:
                aggregate._pending_events.append(
                    CrossAccountTrustDiscovered(
                        principal_id=str(aggregate.id),
                        organization_id=str(organization_id),
                        trusted_principal_provider_id=trust.trusted_principal_provider_id,
                        trust_type=trust.trust_type,
                        occurred_at=ts,
                    )
                )
        return aggregate

    def apply_discovery(
        self,
        *,
        display_name: str,
        attached_policies: list[PolicyAttachment],
        trust_relationships: list[TrustRelationship],
        is_federated: bool,
        is_human: bool,
        last_activity_at: datetime | None,
        now: datetime | None = None,
    ) -> None:
        if self.is_deleted:
            raise CloudIAMPrincipalDeletedError(str(self.id))
        if self.is_disabled:
            raise CloudIAMPrincipalDisabledError(str(self.id))
        name = display_name.strip() if display_name else ""
        if not name:
            raise InvalidCloudArgumentError("display_name", "required")
        if len(attached_policies) > 500 or len(trust_relationships) > 200:
            raise InvalidCloudArgumentError("relationships", "list size exceeded")
        ts = now or datetime.now(UTC)
        previous_trust_keys = {
            (t.trusted_principal_provider_id, t.trust_type) for t in self.trust_relationships
        }
        self.display_name = name
        self.attached_policies = list(attached_policies)
        self.trust_relationships = list(trust_relationships)
        self.is_federated = is_federated
        self.is_human = is_human
        self.last_activity_at = last_activity_at
        self.last_seen_at = ts
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            IAMPrincipalUpdated(
                principal_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                principal_type=self.principal_type.value,
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )
        for trust in trust_relationships:
            key = (trust.trusted_principal_provider_id, trust.trust_type)
            if trust.is_cross_account and key not in previous_trust_keys:
                self._pending_events.append(
                    CrossAccountTrustDiscovered(
                        principal_id=str(self.id),
                        organization_id=str(self.organization_id),
                        trusted_principal_provider_id=trust.trusted_principal_provider_id,
                        trust_type=trust.trust_type,
                        occurred_at=ts,
                    )
                )

    def update_relationships(
        self,
        *,
        attached_policies: list[PolicyAttachment] | None = None,
        trust_relationships: list[TrustRelationship] | None = None,
        now: datetime | None = None,
    ) -> None:
        if self.is_deleted:
            raise CloudIAMPrincipalDeletedError(str(self.id))
        if self.is_disabled:
            raise CloudIAMPrincipalDisabledError(str(self.id))
        ts = now or datetime.now(UTC)
        if attached_policies is not None:
            if len(attached_policies) > 500:
                raise InvalidCloudArgumentError("attached_policies", "max 500")
            self.attached_policies = list(attached_policies)
        if trust_relationships is not None:
            if len(trust_relationships) > 200:
                raise InvalidCloudArgumentError("trust_relationships", "max 200")
            self.trust_relationships = list(trust_relationships)
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            IAMPrincipalUpdated(
                principal_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                principal_type=self.principal_type.value,
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def disable(self, *, now: datetime | None = None) -> None:
        if self.is_deleted:
            raise CloudIAMPrincipalDeletedError(str(self.id))
        if self.is_disabled:
            return
        ts = now or datetime.now(UTC)
        self.is_disabled = True
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            IAMPrincipalDisabled(
                principal_id=str(self.id),
                organization_id=str(self.organization_id),
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def enable(self, *, now: datetime | None = None) -> None:
        if self.is_deleted:
            raise CloudIAMPrincipalDeletedError(str(self.id))
        if not self.is_disabled:
            return
        ts = now or datetime.now(UTC)
        self.is_disabled = False
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            IAMPrincipalUpdated(
                principal_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                principal_type=self.principal_type.value,
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def mark_deleted(self, *, now: datetime | None = None) -> None:
        if self.is_deleted:
            return
        ts = now or datetime.now(UTC)
        self.is_deleted = True
        self.deleted_at = ts
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            IAMPrincipalDeleted(
                principal_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def resurrect_from_discovery(
        self,
        *,
        display_name: str,
        attached_policies: list[PolicyAttachment],
        trust_relationships: list[TrustRelationship],
        is_federated: bool,
        is_human: bool,
        last_activity_at: datetime | None,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        self.is_deleted = False
        self.deleted_at = None
        self.is_disabled = False
        self.apply_discovery(
            display_name=display_name,
            attached_policies=attached_policies,
            trust_relationships=trust_relationships,
            is_federated=is_federated,
            is_human=is_human,
            last_activity_at=last_activity_at,
            now=ts,
        )
        self._pending_events.append(
            IAMPrincipalDiscovered(
                principal_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                principal_type=self.principal_type.value,
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def pop_events(self) -> list[CloudSecurityDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
