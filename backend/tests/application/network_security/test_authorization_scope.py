"""Adversarial tests for NetworkAuthorizationScopeChecker (M16) — real
Postgres, real M10 SecurityAuthorization aggregate, real AIAsset
resolution. Uses the shared `redforge_test` database (same DB the rest
of the backend test suite already runs integration-style tests
against)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.network_security.authorization_scope import (
    NetworkAuthorizationScopeChecker,
)
from redforge.domain.authorization.entity import SecurityAuthorization
from redforge.domain.authorization.value_objects import (
    ActionClass,
    AuthorizationScopeEntry,
    ScopeEntityType,
    ValidityWindow,
)
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.domain.network_security.value_objects import NetworkScopeReasonCode
from redforge.infrastructure.database.repositories.asset_repository import (
    SqlAlchemyAssetRepository,
)
from redforge.infrastructure.database.repositories.authorization.repository import (
    SqlAlchemySecurityAuthorizationRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

pytestmark = pytest.mark.asyncio

_DB_URL = "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test"


@pytest.fixture
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _create_ip_asset(session_factory, organization_id: str, ip: str) -> str:
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=organization_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id=ip, name=ip,
        description="test", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    return asset.id


async def _create_network_asset(session_factory, organization_id: str, cidr: str) -> str:
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=organization_id, asset_type=AssetType.NETWORK,
        scheme=IdentityScheme.NETWORK_CIDR, raw_external_id=cidr, name=cidr,
        description="test", discovery_source=AssetDiscoverySource.API_SCAN,
    )
    return asset.id


async def _authorize(
    session_factory, organization_id: str, requester_id: str, approver_id: str,
    scoped_asset_id: str, action_classes: set[ActionClass] | None = None,
) -> str:
    authorization = SecurityAuthorization.create(
        organization_id=EntityId.from_string(organization_id),
        requester_user_id=EntityId.from_string(requester_id),
        validity=ValidityWindow(
            valid_from=utc_now(), valid_until=utc_now().replace(year=utc_now().year + 1),
        ),
        action_classes=action_classes or {ActionClass.ACTIVE_VALIDATION},
        scope={
            AuthorizationScopeEntry(
                entity_type=ScopeEntityType.AI_ASSET, entity_id=scoped_asset_id,
            )
        },
    )
    authorization.submit_for_approval()
    authorization.approve(EntityId.from_string(approver_id))
    async with session_factory() as session:
        repo = SqlAlchemySecurityAuthorizationRepository(session)
        await repo.save(authorization)
        await session.commit()
    return str(authorization.id)


def _new_ids() -> tuple[str, str, str]:
    return (
        str(EntityId.generate()), str(EntityId.generate()), str(EntityId.generate()),
    )


class TestExactIpAuthorization:
    async def test_exact_ip_authorization_allows_same_ip(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.10")
        await _authorize(session_factory, org_id, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.10")
        assert decision.allowed is True
        assert decision.reason_code == NetworkScopeReasonCode.ALLOWED_BY_ACTIVE_AUTHORIZATION

    async def test_exact_ip_authorization_denies_adjacent_ip(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.10")
        await _authorize(session_factory, org_id, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.11")
        assert decision.allowed is False
        assert decision.reason_code == NetworkScopeReasonCode.NO_MATCHING_AUTHORIZATION


class TestCidrAuthorization:
    async def test_cidr_authorization_allows_member(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        network_asset_id = await _create_network_asset(session_factory, org_id, "203.0.113.0/24")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.50")
        assert decision.allowed is True

    async def test_cidr_authorization_denies_non_member(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        network_asset_id = await _create_network_asset(session_factory, org_id, "203.0.113.0/24")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.114.50")
        assert decision.allowed is False

    async def test_ipv6_cidr_member_allowed(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        network_asset_id = await _create_network_asset(session_factory, org_id, "2001:db8::/32")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "2001:db8::1")
        assert decision.allowed is True

    async def test_ipv6_non_member_denied(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        network_asset_id = await _create_network_asset(session_factory, org_id, "2001:db8::/32")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "2001:db9::1")
        assert decision.allowed is False


class TestLifecycleGates:
    async def test_time_expired_authorization_blocks_even_though_status_is_still_active(
        self, session_factory,
    ) -> None:
        """Scenario #17: an authorization whose validity window has
        elapsed must be denied even though its persisted `status`
        column is still ACTIVE (no background sweep has flipped it to
        EXPIRED yet) — the time-of-use check (`is_active_now()`) is
        never trusted to a stored status flag alone."""
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.25")

        authorization = SecurityAuthorization.create(
            organization_id=EntityId.from_string(org_id),
            requester_user_id=EntityId.from_string(requester_id),
            validity=ValidityWindow(
                valid_from=utc_now().replace(year=utc_now().year - 2),
                valid_until=utc_now().replace(year=utc_now().year - 1),
            ),
            action_classes={ActionClass.ACTIVE_VALIDATION},
            scope={
                AuthorizationScopeEntry(
                    entity_type=ScopeEntityType.AI_ASSET, entity_id=ip_asset_id,
                )
            },
        )
        authorization.submit_for_approval()
        authorization.approve(EntityId.from_string(approver_id))
        async with session_factory() as session:
            repo = SqlAlchemySecurityAuthorizationRepository(session)
            await repo.save(authorization)
            await session.commit()

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.25")
        assert decision.allowed is False
        assert decision.reason_code == NetworkScopeReasonCode.AUTHORIZATION_EXPIRED

    async def test_revoked_authorization_blocks(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.20")
        authorization_id = await _authorize(
            session_factory, org_id, requester_id, approver_id, ip_asset_id,
        )

        async with session_factory() as session:
            repo = SqlAlchemySecurityAuthorizationRepository(session)
            authorization = await repo.get_by_id_for_organization(
                EntityId.from_string(authorization_id), EntityId.from_string(org_id),
            )
            assert authorization is not None
            authorization.revoke(EntityId.from_string(org_id))
            await repo.save(authorization)
            await session.commit()

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.20")
        assert decision.allowed is False

    async def test_approval_required_blocks(self, session_factory) -> None:
        org_id, requester_id, _approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.30")
        authorization = SecurityAuthorization.create(
            organization_id=EntityId.from_string(org_id),
            requester_user_id=EntityId.from_string(requester_id),
            validity=ValidityWindow(
                valid_from=utc_now(), valid_until=utc_now().replace(year=utc_now().year + 1),
            ),
            action_classes={ActionClass.ACTIVE_VALIDATION},
            scope={
                AuthorizationScopeEntry(
                    entity_type=ScopeEntityType.AI_ASSET, entity_id=ip_asset_id,
                )
            },
        )
        authorization.submit_for_approval()  # PENDING_APPROVAL, never approved
        async with session_factory() as session:
            repo = SqlAlchemySecurityAuthorizationRepository(session)
            await repo.save(authorization)
            await session.commit()

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.30")
        assert decision.allowed is False

    async def test_action_class_mismatch_blocks(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.40")
        # Authorized for PASSIVE_DISCOVERY only, not ACTIVE_VALIDATION.
        await _authorize(
            session_factory, org_id, requester_id, approver_id, ip_asset_id,
            action_classes={ActionClass.PASSIVE_DISCOVERY},
        )

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "203.0.113.40")
        assert decision.allowed is False


class TestHardDeniedClasses:
    async def test_multicast_denied_even_with_authorization(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "224.0.0.1")
        await _authorize(session_factory, org_id, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "224.0.0.1")
        assert decision.allowed is False
        assert decision.reason_code == NetworkScopeReasonCode.ADDRESS_CLASS_HARD_DENIED

    async def test_metadata_address_denied_even_with_authorization(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "169.254.169.254")
        await _authorize(session_factory, org_id, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "169.254.169.254")
        assert decision.allowed is False
        assert decision.reason_code == NetworkScopeReasonCode.ADDRESS_CLASS_HARD_DENIED

    async def test_loopback_allowed_with_authorization(self, session_factory) -> None:
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "127.0.0.1")
        await _authorize(session_factory, org_id, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "127.0.0.1")
        assert decision.allowed is True


class TestTenantIsolation:
    async def test_cross_tenant_authorization_cannot_be_reused(self, session_factory) -> None:
        org_a, requester_id, approver_id = _new_ids()
        org_b = str(EntityId.generate())
        ip_asset_id = await _create_ip_asset(session_factory, org_a, "203.0.113.60")
        await _authorize(session_factory, org_a, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            # Same raw IP, but org_b has no authorization of its own —
            # org_a's authorization must never leak across tenants.
            decision = await checker.check_ip_authorized(org_b, "203.0.113.60")
        assert decision.allowed is False


class TestNestedAndBroadCidrAuthorization:
    async def test_broad_parent_authorization_covers_nested_narrow_address(
        self, session_factory,
    ) -> None:
        """A /16 authorization must cover an address inside a /24
        nested within it — containment is purely arithmetic, not tied
        to any particular prefix granularity."""
        org_id, requester_id, approver_id = _new_ids()
        network_asset_id = await _create_network_asset(session_factory, org_id, "10.20.0.0/16")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "10.20.30.40")
        assert decision.allowed is True

    async def test_sibling_subnet_outside_broad_authorization_denied(
        self, session_factory,
    ) -> None:
        """An address in a sibling /16 (same first octet, different
        second octet) must be denied — containment must not degrade to
        a prefix-string-startswith check."""
        org_id, requester_id, approver_id = _new_ids()
        network_asset_id = await _create_network_asset(session_factory, org_id, "10.20.0.0/16")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            decision = await checker.check_ip_authorized(org_id, "10.21.30.40")
        assert decision.allowed is False

    async def test_two_sibling_authorized_slash_24_networks_do_not_cross_authorize(
        self, session_factory,
    ) -> None:
        """Two DIFFERENT authorized /24 networks: an address in the
        first is allowed, the same host-suffix address in the second
        (unauthorized) sibling /24 is denied."""
        org_id, requester_id, approver_id = _new_ids()
        network_a = await _create_network_asset(session_factory, org_id, "192.0.2.0/24")
        await _authorize(session_factory, org_id, requester_id, approver_id, network_a)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            allowed = await checker.check_ip_authorized(org_id, "192.0.2.50")
            denied = await checker.check_ip_authorized(org_id, "192.0.3.50")
        assert allowed.allowed is True
        assert denied.allowed is False


class TestPerAddressRevalidation:
    async def test_authorization_revoked_after_initial_check_blocks_subsequent_check(
        self, session_factory,
    ) -> None:
        """Simulates 'authorization changed after run creation'/'during
        scheduling': an authorization that was valid for an earlier
        check must be independently re-evaluated (never cached) for a
        later check against the identical address."""
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.70")
        authorization_id = await _authorize(
            session_factory, org_id, requester_id, approver_id, ip_asset_id,
        )

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            first_check = await checker.check_ip_authorized(org_id, "203.0.113.70")
        assert first_check.allowed is True

        async with session_factory() as session:
            repo = SqlAlchemySecurityAuthorizationRepository(session)
            authorization = await repo.get_by_id_for_organization(
                EntityId.from_string(authorization_id), EntityId.from_string(org_id),
            )
            assert authorization is not None
            authorization.revoke(EntityId.from_string(org_id))
            await repo.save(authorization)
            await session.commit()

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            second_check = await checker.check_ip_authorized(org_id, "203.0.113.70")
        assert second_check.allowed is False

    async def test_each_address_in_a_multi_address_plan_is_independently_checked(
        self, session_factory,
    ) -> None:
        """Authorizing one specific IP inside a larger candidate set
        must not grant blanket coverage to the others — every address
        is checked on its own merits."""
        org_id, requester_id, approver_id = _new_ids()
        ip_asset_id = await _create_ip_asset(session_factory, org_id, "203.0.113.80")
        await _authorize(session_factory, org_id, requester_id, approver_id, ip_asset_id)

        async with session_factory() as session:
            checker = NetworkAuthorizationScopeChecker(
                SqlAlchemySecurityAuthorizationRepository(session),
                SqlAlchemyAssetRepository(session),
            )
            results = {
                addr: (await checker.check_ip_authorized(org_id, addr)).allowed
                for addr in ("203.0.113.79", "203.0.113.80", "203.0.113.81")
            }
        assert results == {
            "203.0.113.79": False, "203.0.113.80": True, "203.0.113.81": False,
        }
