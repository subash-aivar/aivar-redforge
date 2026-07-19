"""Tests for AccessContext value object."""

from __future__ import annotations

from uuid import uuid4

import pytest

from credential_vault.domain.value_objects.access_context import AccessContext
from credential_vault.domain.value_objects.identifiers import PrincipalId


class TestAccessContext:
    def test_valid_context(self) -> None:
        ctx = AccessContext(
            principal_id=PrincipalId(uuid4()),
            purpose="deployment",
            client_ip="192.168.1.1",
            request_id="req-1",
        )
        assert ctx.purpose == "deployment"
        assert ctx.break_glass is False

    def test_empty_purpose_rejected(self) -> None:
        with pytest.raises(ValueError, match="purpose required"):
            AccessContext(
                principal_id=PrincipalId(uuid4()),
                purpose="",
                client_ip=None,
                request_id=None,
            )

    def test_break_glass_requires_justification(self) -> None:
        with pytest.raises(ValueError, match="justification required"):
            AccessContext(
                principal_id=PrincipalId(uuid4()),
                purpose="emergency",
                client_ip=None,
                request_id=None,
                break_glass=True,
            )

    def test_break_glass_with_justification(self) -> None:
        ctx = AccessContext(
            principal_id=PrincipalId(uuid4()),
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=True,
            justification="incident response",
        )
        assert ctx.break_glass is True

    def test_invalid_client_ip(self) -> None:
        with pytest.raises(ValueError, match="client_ip"):
            AccessContext(
                principal_id=PrincipalId(uuid4()),
                purpose="read",
                client_ip="not-an-ip",
                request_id=None,
            )
