"""SqlAlchemy repository for the immutable NetworkStateSnapshot (M16)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from redforge.domain.network_security.entity import (
    NetworkServiceSnapshotEntry,
    NetworkStateSnapshot,
)
from redforge.infrastructure.database.models.network_security import NetworkStateSnapshotModel
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _to_entity(model: NetworkStateSnapshotModel) -> NetworkStateSnapshot:
    services = tuple(
        NetworkServiceSnapshotEntry(
            port=s[0], validated_protocol=s[1], validator_id=s[2], tls_fingerprint_sha256=s[3],
        )
        for s in model.services
    )
    return NetworkStateSnapshot(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        policy_id=EntityId.from_string(model.policy_id),
        run_id=EntityId.from_string(model.run_id),
        schema_version=model.schema_version,
        resolved_ips=tuple(model.resolved_ips),
        reachable_ports=tuple(model.reachable_ports),
        services=services,
        active_condition_keys=tuple(model.active_condition_keys),
        active_correlation_keys=tuple(model.active_correlation_keys),
        content_fingerprint=model.content_fingerprint,
        captured_at=model.captured_at,
    )


def _to_model(snapshot: NetworkStateSnapshot) -> NetworkStateSnapshotModel:
    return NetworkStateSnapshotModel(
        id=str(snapshot.id),
        organization_id=str(snapshot.organization_id),
        policy_id=str(snapshot.policy_id),
        run_id=str(snapshot.run_id),
        schema_version=snapshot.schema_version,
        resolved_ips=list(snapshot.resolved_ips),
        reachable_ports=list(snapshot.reachable_ports),
        services=[list(s.as_tuple()) for s in snapshot.services],
        active_condition_keys=list(snapshot.active_condition_keys),
        active_correlation_keys=list(snapshot.active_correlation_keys),
        content_fingerprint=snapshot.content_fingerprint,
        captured_at=snapshot.captured_at,
    )


class SqlAlchemyNetworkStateSnapshotRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, snapshot: NetworkStateSnapshot) -> None:
        self._session.add(_to_model(snapshot))
        await self._session.flush()

    async def get_latest_for_policy(
        self, policy_id: EntityId, organization_id: EntityId,
    ) -> NetworkStateSnapshot | None:
        stmt = (
            select(NetworkStateSnapshotModel)
            .where(
                NetworkStateSnapshotModel.policy_id == str(policy_id),
                NetworkStateSnapshotModel.organization_id == str(organization_id),
            )
            .order_by(NetworkStateSnapshotModel.captured_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _to_entity(model) if model is not None else None
