"""Unit tests for the Invitation aggregate.

Covers creation, token security, acceptance (including idempotent
replay), rejection, revocation, resend, and expiry — the domain-level
guarantees the Enterprise Identity Platform's invitation system depends
on.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from redforge.domain.identity.entities import Invitation
from redforge.domain.identity.events import (
    InvitationAccepted,
    InvitationCreated,
    InvitationRejected,
    InvitationResent,
    InvitationRevoked,
)
from redforge.domain.identity.exceptions import (
    InvitationAlreadyProcessedError,
    InvitationEmailMismatchError,
    InvitationExpiredError,
    OwnerAssignmentNotAllowedError,
)
from redforge.domain.identity.value_objects import Email, InvitationStatus, MembershipRole
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now


def _create_invitation(
    email: str = "invitee@test.com",
    role: MembershipRole = MembershipRole.MEMBER,
    ttl: timedelta = timedelta(days=7),
) -> tuple[Invitation, str]:
    return Invitation.create(
        organization_id=EntityId.generate(),
        email=Email(email),
        role=role,
        invited_by_user_id=EntityId.generate(),
        ttl=ttl,
    )


class TestInvitationCreate:
    def test_create_sets_pending_status(self) -> None:
        invitation, _token = _create_invitation()
        assert invitation.status == InvitationStatus.PENDING
        assert invitation.is_pending is True

    def test_create_returns_plaintext_token_not_stored(self) -> None:
        invitation, token = _create_invitation()
        assert len(token) > 20  # secrets.token_urlsafe(32) — high entropy
        assert token != invitation.token_hash
        assert invitation.token_hash not in token  # hash is never a substring of the secret

    def test_create_emits_event(self) -> None:
        invitation, _token = _create_invitation("evt@test.com")
        events = invitation.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], InvitationCreated)
        assert events[0].email == "evt@test.com"

    def test_create_sets_expiry_from_ttl(self) -> None:
        before = utc_now()
        invitation, _token = _create_invitation(ttl=timedelta(hours=1))
        after = utc_now()
        upper = after + timedelta(hours=1, minutes=1)
        assert before + timedelta(minutes=59) < invitation.expires_at < upper

    def test_create_with_owner_role_raises(self) -> None:
        """Inviting someone directly as OWNER would create a Membership
        at OWNER on acceptance with no transfer_ownership() involved —
        the only valid path to OWNER. Blocked at the domain layer, the
        deepest and most robust enforcement point."""
        with pytest.raises(OwnerAssignmentNotAllowedError):
            _create_invitation("wouldbeowner@test.com", role=MembershipRole.OWNER)

    def test_two_invitations_get_different_tokens(self) -> None:
        _i1, t1 = _create_invitation()
        _i2, t2 = _create_invitation()
        assert t1 != t2


class TestInvitationExpiry:
    def test_not_expired_before_expiry(self) -> None:
        invitation, _token = _create_invitation(ttl=timedelta(days=1))
        assert invitation.is_expired(utc_now()) is False

    def test_expired_after_expiry(self) -> None:
        invitation, _token = _create_invitation(ttl=timedelta(days=1))
        future = utc_now() + timedelta(days=2)
        assert invitation.is_expired(future) is True

    def test_accept_after_expiry_raises(self) -> None:
        invitation, _token = _create_invitation(
            "expired@test.com", ttl=timedelta(seconds=-1),
        )
        with pytest.raises(InvitationExpiredError):
            invitation.accept(EntityId.generate(), Email("expired@test.com"))


class TestInvitationAccept:
    def test_accept_transitions_to_accepted(self) -> None:
        invitation, _token = _create_invitation("acc@test.com")
        invitation.collect_events()
        user_id = EntityId.generate()
        invitation.accept(user_id, Email("acc@test.com"))
        assert invitation.status == InvitationStatus.ACCEPTED
        assert invitation.accepted_by_user_id == user_id

    def test_accept_emits_event(self) -> None:
        invitation, _token = _create_invitation("acc2@test.com")
        invitation.collect_events()
        user_id = EntityId.generate()
        invitation.accept(user_id, Email("acc2@test.com"))
        events = invitation.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], InvitationAccepted)
        assert events[0].accepted_by_user_id == str(user_id)

    def test_accept_wrong_email_raises(self) -> None:
        invitation, _token = _create_invitation("real@test.com")
        with pytest.raises(InvitationEmailMismatchError):
            invitation.accept(EntityId.generate(), Email("attacker@test.com"))

    def test_accept_is_idempotent_for_same_user(self) -> None:
        """Replay protection: a network retry of the exact same
        successful acceptance must not raise or re-emit an event."""
        invitation, _token = _create_invitation("idem@test.com")
        invitation.collect_events()
        user_id = EntityId.generate()

        invitation.accept(user_id, Email("idem@test.com"))
        invitation.collect_events()

        # Second call: same user, same invitation — must be a silent no-op.
        invitation.accept(user_id, Email("idem@test.com"))
        assert invitation.status == InvitationStatus.ACCEPTED
        assert invitation.collect_events() == []

    def test_accept_by_different_user_after_acceptance_raises(self) -> None:
        """An already-accepted invitation cannot be re-accepted by a
        DIFFERENT user — this is not a replay, it's an attempted
        takeover of a consumed credential."""
        invitation, _token = _create_invitation("taken@test.com")
        invitation.accept(EntityId.generate(), Email("taken@test.com"))
        invitation.collect_events()

        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.accept(EntityId.generate(), Email("taken@test.com"))

    def test_accept_rejected_invitation_raises(self) -> None:
        invitation, _token = _create_invitation("rej@test.com")
        invitation.reject()
        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.accept(EntityId.generate(), Email("rej@test.com"))

    def test_accept_revoked_invitation_raises(self) -> None:
        invitation, _token = _create_invitation("rev@test.com")
        invitation.revoke(EntityId.generate())
        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.accept(EntityId.generate(), Email("rev@test.com"))


class TestInvitationReject:
    def test_reject_transitions_to_rejected(self) -> None:
        invitation, _token = _create_invitation()
        invitation.reject()
        assert invitation.status == InvitationStatus.REJECTED

    def test_reject_emits_event(self) -> None:
        invitation, _token = _create_invitation()
        invitation.collect_events()
        invitation.reject()
        events = invitation.collect_events()
        assert isinstance(events[0], InvitationRejected)

    def test_reject_already_accepted_raises(self) -> None:
        invitation, _token = _create_invitation("x@test.com")
        invitation.accept(EntityId.generate(), Email("x@test.com"))
        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.reject()

    def test_reject_twice_raises(self) -> None:
        invitation, _token = _create_invitation()
        invitation.reject()
        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.reject()


class TestInvitationRevoke:
    def test_revoke_transitions_to_revoked(self) -> None:
        invitation, _token = _create_invitation()
        invitation.revoke(EntityId.generate())
        assert invitation.status == InvitationStatus.REVOKED

    def test_revoke_emits_event(self) -> None:
        invitation, _token = _create_invitation()
        invitation.collect_events()
        revoker = EntityId.generate()
        invitation.revoke(revoker)
        events = invitation.collect_events()
        assert isinstance(events[0], InvitationRevoked)
        assert events[0].revoked_by_user_id == str(revoker)

    def test_revoke_already_accepted_raises(self) -> None:
        invitation, _token = _create_invitation("y@test.com")
        invitation.accept(EntityId.generate(), Email("y@test.com"))
        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.revoke(EntityId.generate())


class TestInvitationResend:
    def test_resend_generates_new_token(self) -> None:
        invitation, original_token = _create_invitation()
        new_token = invitation.resend()
        assert new_token != original_token

    def test_resend_invalidates_old_token(self) -> None:
        """The old token's hash must no longer match after resend —
        this is what makes a previously-sent (possibly intercepted)
        email link stop working."""
        invitation, _original_token = _create_invitation()
        original_hash = invitation.token_hash
        invitation.resend()
        assert invitation.token_hash != original_hash

    def test_resend_extends_expiry(self) -> None:
        invitation, _token = _create_invitation(ttl=timedelta(hours=1))
        old_expiry = invitation.expires_at
        invitation.resend(ttl=timedelta(days=7))
        assert invitation.expires_at > old_expiry

    def test_resend_emits_event(self) -> None:
        invitation, _token = _create_invitation()
        invitation.collect_events()
        invitation.resend()
        events = invitation.collect_events()
        assert isinstance(events[0], InvitationResent)

    def test_resend_after_acceptance_raises(self) -> None:
        invitation, _token = _create_invitation("z@test.com")
        invitation.accept(EntityId.generate(), Email("z@test.com"))
        with pytest.raises(InvitationAlreadyProcessedError):
            invitation.resend()

    def test_resend_still_pending_status(self) -> None:
        invitation, _token = _create_invitation()
        invitation.resend()
        assert invitation.status == InvitationStatus.PENDING


class TestInvitationEquality:
    def test_same_id_equal(self) -> None:
        invitation, _token = _create_invitation()
        other = Invitation(
            id=invitation.id,
            organization_id=EntityId.generate(),
            email=Email("different@test.com"),
            role=MembershipRole.VIEWER,
            invited_by_user_id=EntityId.generate(),
            token_hash="x" * 64,
            status=InvitationStatus.REJECTED,
            expires_at=utc_now(),
            timestamps=invitation.timestamps,
        )
        assert invitation == other

    def test_hashable(self) -> None:
        invitation, _token = _create_invitation()
        assert len({invitation, invitation}) == 1
