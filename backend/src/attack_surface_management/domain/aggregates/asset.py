"""Asset — the root aggregate of attack_surface_management (M49A): a
single external/internal/internet-facing network asset and everything
needed to assess its attack surface.

Aggregate boundary decision (recorded here per the milestone's request
to defend the choice): `OpenPort`, `Certificate`, and `DnsRecordEntry`
are modeled as **entities owned within this aggregate** — not as
separate aggregates referenced by id, and not as plain value objects.
Rationale:

- Transactional consistency: exposure classification (is this asset
  internet-facing and high-risk?) depends jointly on the asset's
  declared `AssetType` *and* its current set of open ports — these
  must be read and validated together, which is exactly the
  consistency boundary an aggregate exists to protect. Splitting ports
  into their own aggregate would make "add a port and recompute
  exposure" a multi-aggregate transaction, which this codebase avoids
  (see `cloud_security.CloudAsset`, which keeps its owned `CloudTag`s
  in the same aggregate for the same reason).
- Individual identity: unlike `risk_engine.RiskContribution` (a
  wholesale-replaced value collection with no per-item identity),
  ports/certificates/DNS records are independently discovered,
  updated, and retired over time (a port closes without the
  certificate changing; a certificate rotates without ports changing),
  so each needs its own stable id to be addressed/replaced
  individually — the entity, not value-object, shape.
- `CidrBlock`, by contrast, is deliberately **not** owned by `Asset`:
  a network range groups *many* assets, the inverse of the
  ownership cardinality above, so it is modeled as its own aggregate
  root (`NetworkRange`), referenced only indirectly (assets are never
  attached to a range by object reference; a range only tracks an
  aggregate asset count).

`Domain`/`Subdomain`/`IPAddress` are immutable value objects describing
*what* the asset is (its network identifier), not entities — they have
no independent lifecycle of their own once assigned."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.domain.events.asset_events import (
    AssetCertificateAdded,
    AssetCertificateRevoked,
    AssetCriticalityChanged,
    AssetDiscovered,
    AssetDnsRecordAdded,
    AssetDnsRecordRemoved,
    AssetExposureStateChanged,
    AssetLifecycleTransitioned,
    AssetOwnershipAssigned,
    AssetPortClosed,
    AssetPortDiscovered,
    AssetReclassified,
    AssetTechnologyFingerprintAdded,
)
from attack_surface_management.domain.exceptions.domain_exceptions import (
    CertificateNotFoundError,
    DuplicatePortError,
    EmptyAssetIdentifierError,
    InvalidAssetLifecycleTransition,
    PortNotFoundError,
    TenantMismatch,
)
from attack_surface_management.domain.policies.lifecycle_transition_policy import (
    AssetLifecycleTransitionPolicy,
)
from attack_surface_management.domain.value_objects.enums import (
    AssetClassification,
    AssetLifecycleState,
    AssetType,
    Criticality,
    DiscoverySource,
    ExposureState,
    PortState,
)

if TYPE_CHECKING:
    from datetime import datetime

    from attack_surface_management.domain.entities.certificate import Certificate
    from attack_surface_management.domain.entities.dns_record import DnsRecordEntry
    from attack_surface_management.domain.entities.open_port import OpenPort
    from attack_surface_management.domain.events.base import BaseDomainEvent
    from attack_surface_management.domain.value_objects.asset_ownership import AssetOwnership
    from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
    from attack_surface_management.domain.value_objects.identifiers import AssetId, TenantId
    from attack_surface_management.domain.value_objects.ip_address import IPAddress
    from attack_surface_management.domain.value_objects.technology_fingerprint import (
        TechnologyFingerprint,
    )


class Asset:
    __slots__ = (
        "_pending_events",
        "asset_id",
        "asset_type",
        "certificates",
        "classification",
        "created_at",
        "criticality",
        "discovery_source",
        "dns_records",
        "domain_name",
        "exposure_state",
        "fingerprints",
        "ip_address",
        "lifecycle_state",
        "ownership",
        "ports",
        "subdomain",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        asset_id: AssetId,
        tenant_id: TenantId,
        asset_type: AssetType,
        created_at: datetime,
        domain_name: DomainName | None = None,
        subdomain: Subdomain | None = None,
        ip_address: IPAddress | None = None,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL_ENTRY,
        classification: AssetClassification = AssetClassification.UNKNOWN,
        criticality: Criticality = Criticality.UNRATED,
        exposure_state: ExposureState = ExposureState.UNKNOWN,
        lifecycle_state: AssetLifecycleState = AssetLifecycleState.DISCOVERED,
        ownership: AssetOwnership | None = None,
        ports: tuple[OpenPort, ...] = (),
        certificates: tuple[Certificate, ...] = (),
        dns_records: tuple[DnsRecordEntry, ...] = (),
        fingerprints: tuple[TechnologyFingerprint, ...] = (),
        updated_at: datetime | None = None,
    ) -> None:
        if domain_name is None and subdomain is None and ip_address is None:
            raise EmptyAssetIdentifierError()
        self.asset_id = asset_id
        self.tenant_id = tenant_id
        self.asset_type = asset_type
        self.domain_name = domain_name
        self.subdomain = subdomain
        self.ip_address = ip_address
        self.discovery_source = discovery_source
        self.classification = classification
        self.criticality = criticality
        self.exposure_state = exposure_state
        self.lifecycle_state = lifecycle_state
        self.ownership = ownership
        self.ports = ports
        self.certificates = certificates
        self.dns_records = dns_records
        self.fingerprints = fingerprints
        self.created_at = created_at
        self.updated_at = updated_at or created_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @property
    def primary_identifier(self) -> str:
        if self.subdomain is not None:
            return str(self.subdomain)
        if self.domain_name is not None:
            return str(self.domain_name)
        assert self.ip_address is not None
        return str(self.ip_address)

    # -- construction ---------------------------------------------------

    @classmethod
    def _create(
        cls,
        asset_id: AssetId,
        tenant_id: TenantId,
        asset_type: AssetType,
        now: datetime,
        domain_name: DomainName | None,
        subdomain: Subdomain | None,
        ip_address: IPAddress | None,
        discovery_source: DiscoverySource,
    ) -> Asset:
        """Internal constructor used only by `AssetFactory`."""
        asset = cls(
            asset_id=asset_id,
            tenant_id=tenant_id,
            asset_type=asset_type,
            created_at=now,
            domain_name=domain_name,
            subdomain=subdomain,
            ip_address=ip_address,
            discovery_source=discovery_source,
        )
        asset._emit(
            AssetDiscovered(
                tenant_id=str(tenant_id),
                aggregate_id=str(asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                asset_type=asset_type.value,
                primary_identifier=asset.primary_identifier,
            )
        )
        return asset

    # -- ports ------------------------------------------------------------

    def add_port(self, tenant_id: TenantId, port: OpenPort, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        for existing in self.ports:
            if (
                existing.port_number == port.port_number
                and existing.protocol == port.protocol
                and existing.state == PortState.OPEN
            ):
                raise DuplicatePortError(port.port_number, port.protocol.value)
        self.ports = (*self.ports, port)
        self.updated_at = now
        self._emit(
            AssetPortDiscovered(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                port_number=port.port_number,
                protocol=port.protocol.value,
            )
        )

    def close_port(self, tenant_id: TenantId, port_id: object, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        for i, existing in enumerate(self.ports):
            if existing.port_id == port_id:
                closed = existing.close(now)
                self.ports = (*self.ports[:i], closed, *self.ports[i + 1 :])
                self.updated_at = now
                self._emit(
                    AssetPortClosed(
                        tenant_id=str(tenant_id),
                        aggregate_id=str(self.asset_id),
                        aggregate_type="Asset",
                        occurred_at=now,
                        port_number=existing.port_number,
                        protocol=existing.protocol.value,
                    )
                )
                return
        raise PortNotFoundError(port_id)

    # -- certificates -------------------------------------------------------

    def add_certificate(self, tenant_id: TenantId, certificate: Certificate, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.certificates = (*self.certificates, certificate)
        self.updated_at = now
        self._emit(
            AssetCertificateAdded(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                common_name=certificate.common_name,
                serial_number=certificate.serial_number,
            )
        )

    def revoke_certificate(
        self, tenant_id: TenantId, certificate_id: object, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        for i, existing in enumerate(self.certificates):
            if existing.certificate_id == certificate_id:
                revoked = existing.revoke()
                self.certificates = (*self.certificates[:i], revoked, *self.certificates[i + 1 :])
                self.updated_at = now
                self._emit(
                    AssetCertificateRevoked(
                        tenant_id=str(tenant_id),
                        aggregate_id=str(self.asset_id),
                        aggregate_type="Asset",
                        occurred_at=now,
                        serial_number=existing.serial_number,
                    )
                )
                return
        raise CertificateNotFoundError(certificate_id)

    # -- dns records ----------------------------------------------------

    def add_dns_record(self, tenant_id: TenantId, record: DnsRecordEntry, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.dns_records = (*self.dns_records, record)
        self.updated_at = now
        self._emit(
            AssetDnsRecordAdded(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                record_type=record.record_type.value,
                name=record.name,
            )
        )

    def remove_dns_record(self, tenant_id: TenantId, record_id: object, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        remaining = tuple(r for r in self.dns_records if r.record_id != record_id)
        if len(remaining) == len(self.dns_records):
            from attack_surface_management.domain.exceptions.domain_exceptions import (
                DnsRecordNotFoundError,
            )

            raise DnsRecordNotFoundError(record_id)
        removed = next(r for r in self.dns_records if r.record_id == record_id)
        self.dns_records = remaining
        self.updated_at = now
        self._emit(
            AssetDnsRecordRemoved(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                record_type=removed.record_type.value,
                name=removed.name,
            )
        )

    # -- fingerprints, classification, criticality, ownership ----------------

    def add_technology_fingerprint(
        self, tenant_id: TenantId, fingerprint: TechnologyFingerprint, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.fingerprints = (*self.fingerprints, fingerprint)
        self.updated_at = now
        self._emit(
            AssetTechnologyFingerprintAdded(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                technology_name=fingerprint.name,
            )
        )

    def update_exposure_state(
        self, tenant_id: TenantId, exposure_state: ExposureState, now: datetime
    ) -> None:
        """`exposure_state` is computed externally by
        `ExposureClassificationPolicy`/`ExposureEvaluationService` and
        passed in — the aggregate never derives it internally, mirroring
        `EnterpriseRiskProfile.recompute_score`'s separation of pure
        state-machine mutation from scoring computation."""
        self._assert_tenant(tenant_id)
        if exposure_state == self.exposure_state:
            return
        from_state = self.exposure_state
        self.exposure_state = exposure_state
        self.updated_at = now
        self._emit(
            AssetExposureStateChanged(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                from_state=from_state.value,
                to_state=exposure_state.value,
            )
        )

    def set_criticality(self, tenant_id: TenantId, criticality: Criticality, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if criticality == self.criticality:
            return
        from_criticality = self.criticality
        self.criticality = criticality
        self.updated_at = now
        self._emit(
            AssetCriticalityChanged(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                from_criticality=from_criticality.value,
                to_criticality=criticality.value,
            )
        )

    def reclassify(
        self, tenant_id: TenantId, classification: AssetClassification, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if classification == self.classification:
            return
        from_classification = self.classification
        self.classification = classification
        self.updated_at = now
        self._emit(
            AssetReclassified(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                from_classification=from_classification.value,
                to_classification=classification.value,
            )
        )

    def assign_ownership(
        self, tenant_id: TenantId, ownership: AssetOwnership, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.ownership = ownership
        self.updated_at = now
        self._emit(
            AssetOwnershipAssigned(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                owning_team=ownership.owning_team,
            )
        )

    # -- lifecycle -----------------------------------------------------

    def transition_lifecycle(
        self, tenant_id: TenantId, new_state: AssetLifecycleState, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if not AssetLifecycleTransitionPolicy.is_allowed(self.lifecycle_state, new_state):
            raise InvalidAssetLifecycleTransition(self.lifecycle_state.value, new_state.value)
        from_state = self.lifecycle_state
        self.lifecycle_state = new_state
        self.updated_at = now
        self._emit(
            AssetLifecycleTransitioned(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="Asset",
                occurred_at=now,
                from_state=from_state.value,
                to_state=new_state.value,
            )
        )

    def decommission(self, tenant_id: TenantId, now: datetime) -> None:
        self.transition_lifecycle(tenant_id, AssetLifecycleState.DECOMMISSIONED, now)
