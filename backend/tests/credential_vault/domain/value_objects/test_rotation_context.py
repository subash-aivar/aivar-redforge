"""Tests for RotationContext value object."""

from __future__ import annotations

from uuid import uuid4

import pytest

from credential_vault.domain.value_objects.audit_types import RotationTrigger
from credential_vault.domain.value_objects.identifiers import PrincipalId, VersionId
from credential_vault.domain.value_objects.rotation_context import RotationContext


class TestRotationContext:
    def test_valid_context(self) -> None:
        ctx = RotationContext(
            trigger=RotationTrigger.MANUAL,
            initiated_by=PrincipalId(uuid4()),
            previous_version_id=VersionId(uuid4()),
            policy_id=None,
            notes="manual rotation",
        )
        assert ctx.trigger == RotationTrigger.MANUAL

    def test_notes_too_long(self) -> None:
        with pytest.raises(ValueError, match="notes max"):
            RotationContext(
                trigger=RotationTrigger.SCHEDULED,
                initiated_by=PrincipalId(uuid4()),
                previous_version_id=VersionId(uuid4()),
                policy_id=None,
                notes="x" * 1025,
            )
