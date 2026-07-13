"""Application service for the Security Authorization lifecycle (M10).

Orchestrates: canonical-entity verification -> SecurityAuthorization
creation -> submission -> approval/rejection -> revocation, each
producing an audit trail entry. Transaction boundaries are managed by
SessionUnitOfWork; repositories never commit — mirrors
application/invitations/service.py's pattern exactly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import ValidationError
from redforge.domain.authorization.entity import AuthorizationApproval, SecurityAuthorization
from redforge.domain.authorization.exceptions import SecurityAuthorizationNotFoundError
from redforge.domain.authorization.value_objects import (
    CATEGORICALLY_DENIED_ACTION_CLASSES,
    ActionClass,
    ApprovalDecision,
    AuthorizationScopeEntry,
    AuthorizationStatus,
    ScopeEntityType,
    ValidityWindow,
)
from redforge.domain.identity.value_objects import Permission
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from datetime import datetime
    from types import ModuleType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.authorization.contracts import EntityOwnershipPort
    from redforge.application.contracts import EventPublisherPort
    from redforge.infrastructure.audit.contracts import AuditEntry, AuditLog
    from redforge.infrastructure.database.repositories.authorization.repository import (
        SqlAlchemySecurityAuthorizationRepository,
    )


# ─── DTOs ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ScopeEntryDTO:
    entity_type: str
    entity_id: str


@dataclass(frozen=True, slots=True)
class AuthorizationDTO:
    id: str
    organization_id: str
    requester_user_id: str
    status: str
    action_classes: list[str]
    scope: list[ScopeEntryDTO]
    valid_from: str
    valid_until: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, authorization: SecurityAuthorization) -> AuthorizationDTO:
        return cls(
            id=str(authorization.id),
            organization_id=str(authorization.organization_id),
            requester_user_id=str(authorization.requester_user_id),
            status=str(authorization.status),
            action_classes=sorted(str(a) for a in authorization.action_classes),
            scope=[
                ScopeEntryDTO(entity_type=str(e.entity_type), entity_id=e.entity_id)
                for e in authorization.scope
            ],
            valid_from=authorization.validity.valid_from.isoformat(),
            valid_until=authorization.validity.valid_until.isoformat(),
            created_at=authorization.timestamps.created_at.isoformat(),
            updated_at=authorization.timestamps.updated_at.isoformat(),
        )


@dataclass(frozen=True, slots=True)
class ApprovalDTO:
    id: str
    authorization_id: str
    requester_user_id: str
    approver_user_id: str | None
    decision: str | None
    requested_at: str
    decided_at: str | None
    reason: str

    @classmethod
    def from_entity(cls, approval: AuthorizationApproval) -> ApprovalDTO:
        return cls(
            id=str(approval.id),
            authorization_id=str(approval.authorization_id),
            requester_user_id=str(approval.requester_user_id),
            approver_user_id=(
                str(approval.approver_user_id) if approval.approver_user_id else None
            ),
            decision=str(approval.decision) if approval.decision else None,
            requested_at=approval.requested_at.isoformat(),
            decided_at=approval.decided_at.isoformat() if approval.decided_at else None,
            reason=approval.reason,
        )


_STRONG_APPROVAL_CLASSES = (ActionClass.CREDENTIAL_VALIDATION,)


def _parse_action_classes(raw: list[str]) -> set[ActionClass]:
    from redforge.domain.authorization.exceptions import UnknownActionClassError

    parsed: set[ActionClass] = set()
    for value in raw:
        try:
            parsed.add(ActionClass(value))
        except ValueError as exc:
            raise UnknownActionClassError(value) from exc
    return parsed


def _repos() -> tuple[ModuleType, ModuleType]:
    """Lazy-loaded repository modules (avoids importing infrastructure at
    application-module import time). Returns (authorization_repo_module,
    approval_repo_module)."""
    from redforge.infrastructure.database.repositories.authorization import (
        approval_repository,
        repository,
    )

    return repository, approval_repository


# ─── Service ──────────────────────────────────────────────────────────────


class SecurityAuthorizationService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: EventPublisherPort,
        audit_log: AuditLog,
        ownership_checker: EntityOwnershipPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._event_publisher = event_publisher
        self._audit_log = audit_log
        self._ownership_checker = ownership_checker

    async def create(
        self,
        organization_id: str,
        requester_user_id: str,
        action_classes: list[str],
        scope: list[ScopeEntryDTO],
        valid_from: datetime,
        valid_until: datetime,
    ) -> AuthorizationDTO:
        """Create a new DRAFT SecurityAuthorization.

        Raises:
            ValidationError: If an action class string is not recognized,
                or is a categorically-denied class (EXPLOIT_EXECUTION,
                POST_EXPLOITATION, DESTRUCTIVE_ACTION) — M10 builds no
                execution capability for these, so the control plane
                never lets one be requested at all, let alone approved.
            NonCanonicalScopeEntityError: If a scope entity does not
                resolve to a real, same-tenant canonical entity.
        """
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, _approval_repository = _repos()

        parsed_classes = _parse_action_classes(action_classes)
        for ac in parsed_classes:
            if ac in CATEGORICALLY_DENIED_ACTION_CLASSES:
                raise ValidationError(
                    f"Action class '{ac.value}' cannot be requested — no execution "
                    "capability exists for it in this platform.",
                    details={"action_class": ac.value},
                )

        parsed_scope = await self._verify_and_parse_scope(scope, organization_id)

        authorization = SecurityAuthorization.create(
            organization_id=EntityId.from_string(organization_id),
            requester_user_id=EntityId.from_string(requester_user_id),
            validity=ValidityWindow(valid_from=valid_from, valid_until=valid_until),
            action_classes=parsed_classes,
            scope=parsed_scope,
        )

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            await repo.save(authorization)
            await uow.commit()

        await self._event_publisher.publish(authorization.collect_events())
        await self._audit_log.record(self._entry(
            action="authorization.created", actor_id=requester_user_id,
            resource_id=str(authorization.id), organization_id=organization_id,
            metadata={"action_classes": ",".join(sorted(a.value for a in parsed_classes))},
        ))
        return AuthorizationDTO.from_entity(authorization)

    async def submit_for_approval(
        self, organization_id: str, authorization_id: str, actor_user_id: str,
    ) -> AuthorizationDTO:
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, approval_repository = _repos()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            authorization = await self._load(repo, authorization_id, organization_id)
            authorization.submit_for_approval()
            await repo.save(authorization)

            approval = AuthorizationApproval.create(
                authorization_id=authorization.id,
                organization_id=authorization.organization_id,
                requester_user_id=authorization.requester_user_id,
            )
            approval_repo = approval_repository.SqlAlchemyAuthorizationApprovalRepository(
                uow.session,
            )
            await approval_repo.save(approval)
            await uow.commit()

        await self._event_publisher.publish(authorization.collect_events())
        await self._audit_log.record(self._entry(
            action="authorization.submitted", actor_id=actor_user_id,
            resource_id=str(authorization.id), organization_id=organization_id,
            metadata={},
        ))
        return AuthorizationDTO.from_entity(authorization)

    async def approve(
        self,
        organization_id: str,
        authorization_id: str,
        approver_user_id: str,
        approver_permissions: frozenset[Permission],
    ) -> AuthorizationDTO:
        """Approve a PENDING_APPROVAL authorization.

        Raises:
            SelfApprovalForbiddenError: If approver_user_id is the
                requester — unconditional, enforced by the aggregate
                itself (see SecurityAuthorization.approve()).
            ValidationError: If the authorization's scope includes
                CREDENTIAL_VALIDATION and the caller lacks
                Permission.AUTHORIZATIONS_APPROVE_CREDENTIAL — the
                stronger approval tier required for credential-based
                validation (see value_objects.STRONG_APPROVAL_ACTION_CLASSES).
        """
        return await self._decide(
            organization_id, authorization_id, approver_user_id,
            approver_permissions, decision=ApprovalDecision.APPROVED, reason="",
        )

    async def reject(
        self,
        organization_id: str,
        authorization_id: str,
        approver_user_id: str,
        approver_permissions: frozenset[Permission],
        reason: str = "",
    ) -> AuthorizationDTO:
        return await self._decide(
            organization_id, authorization_id, approver_user_id,
            approver_permissions, decision=ApprovalDecision.REJECTED, reason=reason,
        )

    async def revoke(
        self, organization_id: str, authorization_id: str, actor_user_id: str, reason: str = "",
    ) -> AuthorizationDTO:
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, _approval_repository = _repos()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            authorization = await self._load(repo, authorization_id, organization_id)
            authorization.revoke(EntityId.from_string(actor_user_id), reason)
            await repo.save(authorization)
            await uow.commit()

        await self._event_publisher.publish(authorization.collect_events())
        await self._audit_log.record(self._entry(
            action="authorization.revoked", actor_id=actor_user_id,
            resource_id=str(authorization.id), organization_id=organization_id,
            metadata={"reason": reason},
        ))
        return AuthorizationDTO.from_entity(authorization)

    async def summary(self, organization_id: str) -> dict[str, int]:
        """Backend-derived counts per lifecycle status. Every
        AuthorizationStatus member is always present in the returned
        dict (zero-filled), so the frontend never has to guess which
        keys might be missing."""
        from redforge.domain.authorization.value_objects import AuthorizationStatus
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, _approval_repository = _repos()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            raw_counts = await repo.count_by_status(EntityId.from_string(organization_id))
        return {status.value: raw_counts.get(status.value, 0) for status in AuthorizationStatus}

    async def get_by_id(self, organization_id: str, authorization_id: str) -> AuthorizationDTO:
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, _approval_repository = _repos()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            authorization = await self._load(repo, authorization_id, organization_id)
        return AuthorizationDTO.from_entity(authorization)

    async def list_by_organization(
        self, organization_id: str, status: str | None, limit: int, offset: int,
    ) -> list[AuthorizationDTO]:
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, _approval_repository = _repos()

        parsed_status = AuthorizationStatus(status) if status else None
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            authorizations = await repo.list_by_organization(
                EntityId.from_string(organization_id), parsed_status, limit, offset,
            )
        return [AuthorizationDTO.from_entity(a) for a in authorizations]

    async def get_approval(
        self, organization_id: str, authorization_id: str,
    ) -> ApprovalDTO | None:
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        _repository, approval_repository = _repos()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = approval_repository.SqlAlchemyAuthorizationApprovalRepository(uow.session)
            approval = await repo.get_by_authorization_id(
                EntityId.from_string(authorization_id), EntityId.from_string(organization_id),
            )
        return ApprovalDTO.from_entity(approval) if approval is not None else None

    # ─── Private ────────────────────────────────────────────────────────

    async def _decide(
        self,
        organization_id: str,
        authorization_id: str,
        approver_user_id: str,
        approver_permissions: frozenset[Permission],
        decision: ApprovalDecision,
        reason: str,
    ) -> AuthorizationDTO:
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        repository, approval_repository = _repos()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = repository.SqlAlchemySecurityAuthorizationRepository(uow.session)
            # Locked reads (SELECT ... FOR UPDATE against PostgreSQL) —
            # a concurrent second approve()/reject() call for the SAME
            # authorization blocks here until this transaction commits,
            # then observes the already-decided state and raises
            # ApprovalAlreadyDecidedError instead of silently
            # overwriting the winner's decision.
            authorization = await self._load_for_update(repo, authorization_id, organization_id)

            if (
                any(ac in authorization.action_classes for ac in _STRONG_APPROVAL_CLASSES)
                and Permission.AUTHORIZATIONS_APPROVE_CREDENTIAL not in approver_permissions
            ):
                raise ValidationError(
                    "Approving an authorization scoped to CREDENTIAL_VALIDATION requires "
                    "the stronger 'authorizations:approve_credential' permission.",
                    details={"authorization_id": authorization_id},
                )

            approval_repo = approval_repository.SqlAlchemyAuthorizationApprovalRepository(
                uow.session,
            )
            approval = await approval_repo.get_by_authorization_id_for_update(
                authorization.id, authorization.organization_id,
            )
            if approval is None:
                from redforge.core.exceptions import NotFoundError

                raise NotFoundError("AuthorizationApproval", authorization_id)

            approver_id = EntityId.from_string(approver_user_id)
            if decision == ApprovalDecision.APPROVED:
                authorization.approve(approver_id)
            else:
                authorization.reject(approver_id, reason)
            approval.decide(approver_id, decision, reason)

            await repo.save(authorization)
            await approval_repo.save(approval)
            await uow.commit()

        await self._event_publisher.publish(authorization.collect_events())
        action = (
            "authorization.approved"
            if decision == ApprovalDecision.APPROVED
            else "authorization.rejected"
        )
        await self._audit_log.record(self._entry(
            action=action, actor_id=approver_user_id,
            resource_id=str(authorization.id), organization_id=organization_id,
            metadata={"reason": reason},
        ))
        return AuthorizationDTO.from_entity(authorization)

    async def _verify_and_parse_scope(
        self, scope: list[ScopeEntryDTO], organization_id: str,
    ) -> set[AuthorizationScopeEntry]:
        from redforge.domain.authorization.exceptions import NonCanonicalScopeEntityError

        parsed: set[AuthorizationScopeEntry] = set()
        for entry in scope:
            try:
                entity_type = ScopeEntityType(entry.entity_type)
            except ValueError as exc:
                raise NonCanonicalScopeEntityError(entry.entity_type, entry.entity_id) from exc

            if self._ownership_checker is not None:
                owned = await self._ownership_checker.is_owned_by_organization(
                    entity_type.value, entry.entity_id, organization_id,
                )
                if not owned:
                    raise NonCanonicalScopeEntityError(entity_type.value, entry.entity_id)

            parsed.add(AuthorizationScopeEntry(entity_type=entity_type, entity_id=entry.entity_id))
        return parsed

    @staticmethod
    async def _load(
        repo: SqlAlchemySecurityAuthorizationRepository,
        authorization_id: str,
        organization_id: str,
    ) -> SecurityAuthorization:
        authorization = await repo.get_by_id_for_organization(
            EntityId.from_string(authorization_id), EntityId.from_string(organization_id),
        )
        if authorization is None:
            raise SecurityAuthorizationNotFoundError(authorization_id)
        return authorization

    @staticmethod
    async def _load_for_update(
        repo: SqlAlchemySecurityAuthorizationRepository,
        authorization_id: str,
        organization_id: str,
    ) -> SecurityAuthorization:
        authorization = await repo.get_by_id_for_organization_for_update(
            EntityId.from_string(authorization_id), EntityId.from_string(organization_id),
        )
        if authorization is None:
            raise SecurityAuthorizationNotFoundError(authorization_id)
        return authorization

    @staticmethod
    def _entry(
        *, action: str, actor_id: str, resource_id: str, organization_id: str,
        metadata: dict[str, str],
    ) -> AuditEntry:
        from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry

        return AuditEntry(
            action=AuditAction(action),
            actor_id=actor_id,
            resource_type="security_authorization",
            resource_id=resource_id,
            metadata={"organization_id": organization_id, **metadata},
        )
