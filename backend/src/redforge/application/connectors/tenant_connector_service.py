"""TenantConnectorService — M3.

Tenant-scoped connector lifecycle + discovery execution. Wraps the
existing `Connector` aggregate (Sprint 23) with real PostgreSQL
persistence; discovery execution here is the "RedForge Targets"
reference adapter (Capability 11): it discovers already-existing,
real AITarget rows for the organization and resolves/creates their
canonical assets — no simulated/stub provider data enters this path.

DISCOVERY vs ACTIVE VALIDATION boundary (Capability 14): this service
performs inventory resolution ONLY. It never executes an attack,
launches a campaign, or grants execution authorization — it has no
dependency on `RedTeamOrchestrator`/campaign execution at all. A
discovered asset is inventory identity, not authorized test scope;
authorization to run a campaign against a target remains entirely
owned by the existing campaign-launch path (api/v1/red_team.py), which
independently re-verifies tenant ownership.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.exceptions import (
    ConnectorDomainError,
    DiscoveryJobConflictError,
)
from redforge.domain.connectors.value_objects import (
    ConnectorCapability,
    ConnectorCapabilityType,
    ConnectorConfiguration,
    ConnectorCredentialReference,
    ConnectorType,
    ConnectorVersion,
    CredentialType,
)
from redforge.infrastructure.database.models.ai_target import AITargetModel
from redforge.infrastructure.database.repositories.connector_repository import (
    SqlAlchemyConnectorRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.directory_security.service import TenantDirectorySecurityService
    from redforge.application.inventory.tenant_asset_service import TenantAssetService

# The only connector type M3 ships as a real, working reference adapter —
# discovers real AITarget rows already owned by the caller's organization.
# Not a "stub"/simulated provider (application/connectors/stub_connectors.py
# exists for unrelated unit-test scaffolding and is never wired here).
REDFORGE_TARGETS_CONNECTOR_TYPE = ConnectorType.GENERIC

# The one real M5 identity/directory adapter — read-only LDAP discovery
# (see application/directory_security/ldap_adapter.py).
DIRECTORY_CONNECTOR_TYPE = ConnectorType.LDAP_DIRECTORY

# The one real M6 network adapter — bounded TCP-connect discovery
# (see application/network_discovery/scan_adapter.py).
NETWORK_CONNECTOR_TYPE = ConnectorType.NETWORK_SCAN

# The one real M7 cloud provider adapter — read-only AWS discovery
# (see application/cloud_security/aws_adapter.py). Azure/GCP are
# NOT implemented — see the M7 report's honest disposition.
CLOUD_AWS_CONNECTOR_TYPE = ConnectorType.CLOUD_AWS


@dataclass(frozen=True, slots=True)
class ConnectorDTO:
    id: str
    organization_id: str
    connector_type: str
    name: str
    status: str
    last_discovery_status: str | None
    last_discovery_completed_at: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, c: Connector) -> ConnectorDTO:
        last = c.last_discovery
        return cls(
            id=str(c.id),
            organization_id=str(c.organization_id),
            connector_type=c.connector_type.value,
            name=c.name,
            status=c.status.value,
            last_discovery_status=last.status.value if last else None,
            last_discovery_completed_at=(last.completed_at_iso or None) if last else None,
            created_at=c.timestamps.created_at.isoformat(),
            updated_at=c.timestamps.updated_at.isoformat(),
        )


@dataclass(frozen=True, slots=True)
class DiscoveryRunDTO:
    """A discovery run, read from `Connector.discovery_history` — see
    module docstring for why this is not a separate persisted entity.
    """

    job_id: str
    connector_id: str
    status: str
    started_at: str
    completed_at: str | None
    assets_discovered: int
    assets_normalized: int
    assets_failed: int
    error_message: str | None


class TenantConnectorService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        asset_service: TenantAssetService,
        directory_service: TenantDirectorySecurityService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._asset_service = asset_service
        self._directory_service = directory_service

    async def register_directory_connector(
        self,
        organization_id: str,
        name: str,
        server_uri: str,
        base_dn: str,
        bind_dn: str,
        credential_reference_id: str,
        use_start_tls: bool,
        allow_insecure_plaintext: bool,
        privileged_group_dns: tuple[str, ...] = (),
        description: str = "",
    ) -> ConnectorDTO:
        """Registers a real, read-only LDAP/Active-Directory-compatible
        directory connector. `credential_reference_id` is an
        environment-variable NAME (see
        `infrastructure/credential_resolver.py`'s documented dev-only
        resolution boundary) — never a raw bind password; the browser
        API never accepts or returns the password itself."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = Connector.register(
                organization_id=EntityId.from_string(organization_id),
                connector_type=DIRECTORY_CONNECTOR_TYPE,
                name=name,
                description=description,
                version=ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0"),
                capabilities=(
                    ConnectorCapability(capability_type=ConnectorCapabilityType.ASSET_DISCOVERY),
                ),
            )
            connector.configure(
                ConnectorConfiguration(
                    base_url=server_uri,
                    custom_config=(
                        ("base_dn", base_dn),
                        ("bind_dn", bind_dn),
                        ("use_start_tls", str(use_start_tls)),
                        ("allow_insecure_plaintext", str(allow_insecure_plaintext)),
                        ("privileged_group_dns", ",".join(privileged_group_dns)),
                    ),
                ),
                credential_ref=ConnectorCredentialReference(
                    reference_id=credential_reference_id,
                    credential_type=CredentialType.BASIC_AUTH,
                    description="LDAP bind password (env-var reference, never raw)",
                ),
            )
            connector.mark_validated()
            connector.enable()
            await repo.save(connector)
            await uow.commit()
        return ConnectorDTO.from_entity(connector)

    async def register_network_connector(
        self,
        organization_id: str,
        name: str,
        network_cidr: str,
        ports: tuple[int, ...],
        description: str = "",
    ) -> ConnectorDTO:
        """Registers a bounded, read-only TCP-connect network discovery
        connector. Scope validation (default-route rejection, address/
        port count limits) is enforced again at scan time by
        `BoundedNetworkScanAdapter` itself — this method does not skip
        that check merely because registration succeeded."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = Connector.register(
                organization_id=EntityId.from_string(organization_id),
                connector_type=NETWORK_CONNECTOR_TYPE,
                name=name,
                description=description,
                version=ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0"),
                capabilities=(
                    ConnectorCapability(capability_type=ConnectorCapabilityType.ASSET_DISCOVERY),
                ),
            )
            connector.configure(
                ConnectorConfiguration(
                    base_url="",
                    custom_config=(
                        ("network_cidr", network_cidr),
                        ("ports", ",".join(str(p) for p in ports)),
                    ),
                ),
            )
            connector.mark_validated()
            connector.enable()
            await repo.save(connector)
            await uow.commit()
        return ConnectorDTO.from_entity(connector)

    async def register_cloud_connector(
        self,
        organization_id: str,
        name: str,
        region: str,
        access_key_id: str,
        secret_access_key_credential_reference_id: str,
        session_token_credential_reference_id: str | None = None,
        description: str = "",
    ) -> ConnectorDTO:
        """Registers a real, read-only AWS discovery connector.
        `access_key_id` is an identifier (like a username), stored as
        connector configuration — never secret on its own. The secret
        access key (and optional session token) are environment-
        variable NAMES resolved server-side at discovery time (see
        `EnvironmentCredentialResolver`) — the raw secret value is
        never accepted by this API and never returned."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = Connector.register(
                organization_id=EntityId.from_string(organization_id),
                connector_type=CLOUD_AWS_CONNECTOR_TYPE,
                name=name,
                description=description,
                version=ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0"),
                capabilities=(
                    ConnectorCapability(capability_type=ConnectorCapabilityType.ASSET_DISCOVERY),
                ),
            )
            connector.configure(
                ConnectorConfiguration(
                    base_url="",
                    custom_config=(
                        ("region", region),
                        ("access_key_id", access_key_id),
                        ("session_token_ref", session_token_credential_reference_id or ""),
                    ),
                ),
                credential_ref=ConnectorCredentialReference(
                    reference_id=secret_access_key_credential_reference_id,
                    credential_type=CredentialType.API_KEY,
                    description="AWS secret access key (env-var reference, never raw)",
                ),
            )
            connector.mark_validated()
            connector.enable()
            await repo.save(connector)
            await uow.commit()
        return ConnectorDTO.from_entity(connector)

    async def register(
        self, organization_id: str, name: str, description: str = "",
    ) -> ConnectorDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = Connector.register(
                organization_id=EntityId.from_string(organization_id),
                connector_type=REDFORGE_TARGETS_CONNECTOR_TYPE,
                name=name,
                description=description,
                version=ConnectorVersion(
                    connector_type_version="1.0.0", schema_version="1.0",
                ),
                capabilities=(
                    ConnectorCapability(capability_type=ConnectorCapabilityType.ASSET_DISCOVERY),
                ),
            )
            connector.configure(
                ConnectorConfiguration(base_url=""),
            )
            connector.mark_validated()
            connector.enable()
            await repo.save(connector)
            await uow.commit()
        return ConnectorDTO.from_entity(connector)

    async def list_for_org(self, organization_id: str) -> list[ConnectorDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connectors = await repo.list_for_org(organization_id)
        return [ConnectorDTO.from_entity(c) for c in connectors]

    async def get_for_org(self, connector_id: str, organization_id: str) -> ConnectorDTO:
        connector = await self._load(connector_id, organization_id)
        return ConnectorDTO.from_entity(connector)

    async def disable(self, connector_id: str, organization_id: str) -> ConnectorDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = await repo.get_by_id_for_org(connector_id, organization_id)
            if connector is None:
                raise NotFoundError("Connector", connector_id)
            connector.disable()
            await repo.save(connector)
            await uow.commit()
        return ConnectorDTO.from_entity(connector)

    async def enable(self, connector_id: str, organization_id: str) -> ConnectorDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = await repo.get_by_id_for_org(connector_id, organization_id)
            if connector is None:
                raise NotFoundError("Connector", connector_id)
            connector.enable()
            await repo.save(connector)
            await uow.commit()
        return ConnectorDTO.from_entity(connector)

    async def list_discovery_runs(
        self, connector_id: str, organization_id: str
    ) -> list[DiscoveryRunDTO]:
        connector = await self._load(connector_id, organization_id)
        return [
            DiscoveryRunDTO(
                job_id=j.job_id,
                connector_id=connector_id,
                status=j.status.value,
                started_at=j.started_at_iso,
                completed_at=j.completed_at_iso or None,
                assets_discovered=j.assets_discovered,
                assets_normalized=j.assets_normalized,
                assets_failed=j.assets_failed,
                error_message=j.error_message or None,
            )
            for j in connector.discovery_history
        ]

    async def start_discovery(
        self, connector_id: str, organization_id: str
    ) -> DiscoveryRunDTO:
        """Runs the real RedForge-targets discovery adapter synchronously
        (M3 scope — no background job queue). Disabled connectors and
        connectors with an already-running discovery job are rejected by
        the domain aggregate itself (`_require_enabled`,
        `DiscoveryJobConflictError`), not re-implemented here.
        """
        job_id = str(uuid.uuid4())

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = await repo.get_by_id_for_org(connector_id, organization_id)
            if connector is None:
                raise NotFoundError("Connector", connector_id)

            try:
                connector.start_discovery_job(job_id)
            except DiscoveryJobConflictError as exc:
                raise ValidationError(
                    "A discovery job is already running for this connector."
                ) from exc
            except ConnectorDomainError as exc:
                raise ValidationError(str(exc)) from exc
            await repo.save(connector)
            await uow.commit()
            is_directory_connector = connector.connector_type == DIRECTORY_CONNECTOR_TYPE
            is_network_connector = connector.connector_type == NETWORK_CONNECTOR_TYPE
            is_cloud_connector = connector.connector_type == CLOUD_AWS_CONNECTOR_TYPE

        # Execute the real discovery: enumerate the org's actual AITarget
        # rows and resolve/create their canonical assets (RedForge Targets),
        # run the real LDAP directory discovery (LDAP_DIRECTORY), run the
        # real bounded TCP-connect network discovery (NETWORK_SCAN), or run
        # the real read-only AWS discovery (CLOUD_AWS). Real data only in
        # every path.
        discovered = 0
        normalized = 0
        failed = 0
        try:
            if is_directory_connector:
                discovered, normalized, failed = await self._run_directory_discovery(
                    connector_id, organization_id,
                )
            elif is_network_connector:
                discovered, normalized, failed = await self._run_network_discovery(
                    connector_id, organization_id,
                )
            elif is_cloud_connector:
                discovered, normalized, failed = await self._run_cloud_discovery(
                    connector_id, organization_id,
                )
            else:
                async with SessionUnitOfWork(self._session_factory) as uow:
                    from sqlalchemy import select

                    result = await uow.session.execute(
                        select(AITargetModel).where(
                            AITargetModel.organization_id == organization_id,
                        )
                    )
                    targets = result.scalars().all()

                discovered = len(targets)
                for t in targets:
                    try:
                        await self._asset_service.get_or_create_for_target(
                            organization_id=organization_id,
                            target_id=t.id,
                            target_name=t.name,
                            target_type=t.target_type,
                        )
                        normalized += 1
                    except Exception:
                        failed += 1

            async with SessionUnitOfWork(self._session_factory) as uow:
                repo = SqlAlchemyConnectorRepository(uow.session)
                connector = await repo.get_by_id_for_org(connector_id, organization_id)
                assert connector is not None
                connector.complete_discovery_job(
                    job_id,
                    assets_discovered=discovered,
                    assets_normalized=normalized,
                    assets_failed=failed,
                )
                await repo.save(connector)
                await uow.commit()
        except Exception as exc:
            async with SessionUnitOfWork(self._session_factory) as uow:
                repo = SqlAlchemyConnectorRepository(uow.session)
                connector = await repo.get_by_id_for_org(connector_id, organization_id)
                if connector is not None:
                    connector.fail_discovery_job(job_id, str(exc)[:500])
                    await repo.save(connector)
                    await uow.commit()
            raise

        completed = next(j for j in connector.discovery_history if j.job_id == job_id)
        return DiscoveryRunDTO(
            job_id=completed.job_id,
            connector_id=connector_id,
            status=completed.status.value,
            started_at=completed.started_at_iso,
            completed_at=completed.completed_at_iso or None,
            assets_discovered=completed.assets_discovered,
            assets_normalized=completed.assets_normalized,
            assets_failed=completed.assets_failed,
            error_message=completed.error_message or None,
        )

    async def _run_directory_discovery(
        self, connector_id: str, organization_id: str
    ) -> tuple[int, int, int]:
        """Runs the real read-only LDAP discovery adapter and resolves
        canonical identities/groups/memberships. Returns
        (discovered, normalized, failed) counts for the DiscoveryJobRecord —
        discovered/normalized here count identities+groups observed vs.
        successfully resolved; failed counts adapter-reported error
        entries (unresolved member references, unsupported source
        objects — never fabricated)."""
        if self._directory_service is None:
            raise ValidationError("Directory discovery service is not configured.")

        connector = await self._load(connector_id, organization_id)
        config = connector.config
        credential_ref = connector.credential_ref
        if config is None or credential_ref is None:
            raise ValidationError(
                "Directory connector is missing configuration or credential reference."
            )

        from redforge.application.directory_security.ldap_adapter import (
            LdapConnectionError,
            LdapDirectoryAdapter,
        )
        from redforge.domain.directory_security.value_objects import DirectoryIdentityScheme
        from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver

        base_dn = config.get_custom("base_dn") or ""
        bind_dn = config.get_custom("bind_dn") or ""
        use_start_tls = (config.get_custom("use_start_tls") or "False") == "True"
        allow_insecure_plaintext = (
            (config.get_custom("allow_insecure_plaintext") or "False") == "True"
        )
        privileged_group_dns = frozenset(
            g for g in (config.get_custom("privileged_group_dns") or "").split(",") if g
        )

        from redforge.core.exceptions import CredentialResolutionError

        try:
            bind_password = EnvironmentCredentialResolver().resolve(credential_ref.reference_id)
        except CredentialResolutionError as exc:
            raise ValidationError(f"Credential resolution failed: {exc.message}") from exc

        try:
            result = LdapDirectoryAdapter().discover(
                server_uri=config.base_url,
                base_dn=base_dn,
                bind_dn=bind_dn,
                bind_password=bind_password,
                use_start_tls=use_start_tls,
                allow_insecure_plaintext=allow_insecure_plaintext,
                page_size=config.page_size,
            )
        except LdapConnectionError as exc:
            raise ValidationError(str(exc)) from exc

        summary = await self._directory_service.run_directory_discovery(
            organization_id=organization_id,
            connector_id=connector_id,
            result=result,
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            privileged_group_external_ids_raw=privileged_group_dns,
        )
        observed = summary.identities_observed + summary.groups_observed
        return observed, observed - len(summary.errors), len(summary.errors)

    async def _run_network_discovery(
        self, connector_id: str, organization_id: str
    ) -> tuple[int, int, int]:
        """Runs the real bounded TCP-connect scan adapter and resolves
        canonical NETWORK/IP_ADDRESS/HOST/SERVICE assets. Scope policy
        (default-route rejection, address/port count limits) is
        enforced inside `BoundedNetworkScanAdapter.discover` itself —
        this method cannot bypass it even if connector configuration
        was somehow tampered with."""
        from redforge.application.network_discovery.scan_adapter import (
            BoundedNetworkScanAdapter,
            NetworkScanPolicyError,
        )
        from redforge.application.network_discovery.service import (
            TenantNetworkDiscoveryService,
        )

        connector = await self._load(connector_id, organization_id)
        config = connector.config
        if config is None:
            raise ValidationError("Network connector is missing configuration.")

        network_cidr = config.get_custom("network_cidr") or ""
        ports_raw = config.get_custom("ports") or ""
        try:
            ports = tuple(int(p) for p in ports_raw.split(",") if p)
        except ValueError as exc:
            raise ValidationError("Network connector has an invalid port list.") from exc

        try:
            result = await BoundedNetworkScanAdapter().discover(network_cidr, ports)
        except NetworkScanPolicyError as exc:
            raise ValidationError(str(exc)) from exc

        network_service = TenantNetworkDiscoveryService(self._asset_service)
        summary = await network_service.run_discovery(organization_id, connector_id, result)
        observed = summary.ips_observed + summary.hosts_observed + summary.services_observed
        return observed, observed - len(summary.errors), len(summary.errors)

    async def _run_cloud_discovery(
        self, connector_id: str, organization_id: str
    ) -> tuple[int, int, int]:
        """Runs the real read-only AWS discovery adapter and resolves
        canonical CLOUD_ACCOUNT/CLOUD_RESOURCE assets."""
        from redforge.application.cloud_security.aws_adapter import (
            AwsCloudAdapter,
            AwsCredential,
            AwsDiscoveryError,
        )
        from redforge.application.cloud_security.service import TenantCloudSecurityService
        from redforge.core.exceptions import CredentialResolutionError
        from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver

        connector = await self._load(connector_id, organization_id)
        config = connector.config
        credential_ref = connector.credential_ref
        if config is None or credential_ref is None:
            raise ValidationError(
                "Cloud connector is missing configuration or credential reference."
            )

        region = config.get_custom("region") or ""
        access_key_id = config.get_custom("access_key_id") or ""
        session_token_ref = config.get_custom("session_token_ref") or ""

        resolver = EnvironmentCredentialResolver()
        try:
            secret_access_key = resolver.resolve(credential_ref.reference_id)
            session_token = resolver.resolve(session_token_ref) if session_token_ref else None
        except CredentialResolutionError as exc:
            raise ValidationError(f"Credential resolution failed: {exc.message}") from exc

        credential = AwsCredential(
            access_key_id=access_key_id, secret_access_key=secret_access_key,
            session_token=session_token,
        )
        import asyncio

        try:
            result = await asyncio.to_thread(AwsCloudAdapter().discover, credential, region)
        except AwsDiscoveryError as exc:
            raise ValidationError(str(exc)) from exc

        cloud_service = TenantCloudSecurityService(self._asset_service)
        summary = await cloud_service.run_discovery(organization_id, connector_id, result)
        observed = 1 + summary.resources_observed
        return observed, observed - len(summary.errors), len(summary.errors)

    async def _load(self, connector_id: str, organization_id: str) -> Connector:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyConnectorRepository(uow.session)
            connector = await repo.get_by_id_for_org(connector_id, organization_id)
        if connector is None:
            raise NotFoundError("Connector", connector_id)
        return connector
