"""Tests for all Credential Vault domain exceptions."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from credential_vault.domain.exceptions import domain_exceptions as exc
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    TenantId,
    VaultBackendId,
    VersionId,
)

NOW = datetime.now(UTC)
CREDENTIAL_ID = CredentialId(uuid4())
TENANT_ID = TenantId(uuid4())
VERSION_ID = VersionId(uuid4())
PRINCIPAL_ID = PrincipalId(uuid4())
BACKEND_ID = VaultBackendId(uuid4())
NAME = CredentialName("test-credential")


EXCEPTION_CASES = [
    ("DomainException", lambda: exc.DomainException("base")),
    (
        "InvalidStateTransition",
        lambda: exc.InvalidStateTransition("ACTIVE", "enable", CREDENTIAL_ID),
    ),
    (
        "CredentialNotFound",
        lambda: exc.CredentialNotFound(CREDENTIAL_ID, TENANT_ID),
    ),
    (
        "CredentialAlreadyExists",
        lambda: exc.CredentialAlreadyExists(NAME, TENANT_ID),
    ),
    (
        "VersionNotFound",
        lambda: exc.VersionNotFound(VERSION_ID, CREDENTIAL_ID),
    ),
    (
        "ActiveVersionNotFound",
        lambda: exc.ActiveVersionNotFound(CREDENTIAL_ID),
    ),
    (
        "ConcurrentRotationConflict",
        lambda: exc.ConcurrentRotationConflict(CREDENTIAL_ID),
    ),
    ("PolicyNotFound", lambda: exc.PolicyNotFound("policy-1")),
    ("PolicyInUse", lambda: exc.PolicyInUse("policy-1", 3)),
    ("VaultBackendNotFound", lambda: exc.VaultBackendNotFound(BACKEND_ID)),
    ("VaultBackendInUse", lambda: exc.VaultBackendInUse(BACKEND_ID, 2)),
    (
        "AccessDenied",
        lambda: exc.AccessDenied(PRINCIPAL_ID, "READ", CREDENTIAL_ID),
    ),
    (
        "TenantMismatch",
        lambda: exc.TenantMismatch(TENANT_ID, TenantId(uuid4())),
    ),
    ("CredentialIsRevoked", lambda: exc.CredentialIsRevoked(CREDENTIAL_ID)),
    (
        "CredentialIsExpired",
        lambda: exc.CredentialIsExpired(CREDENTIAL_ID, NOW),
    ),
    ("CredentialIsDeleted", lambda: exc.CredentialIsDeleted(CREDENTIAL_ID)),
    (
        "BreakGlassJustificationRequired",
        lambda: exc.BreakGlassJustificationRequired(CREDENTIAL_ID),
    ),
    (
        "InsufficientApprovers",
        lambda: exc.InsufficientApprovers(2, 1, CREDENTIAL_ID),
    ),
    (
        "RecoveryVersionInvalid",
        lambda: exc.RecoveryVersionInvalid(VERSION_ID, "bad state"),
    ),
    (
        "OptimisticLockConflict",
        lambda: exc.OptimisticLockConflict("agg-1", 1, 2),
    ),
    ("InvalidArgument", lambda: exc.InvalidArgument("field", "reason")),
    (
        "NoPolicyAttached",
        lambda: exc.NoPolicyAttached(CREDENTIAL_ID, "rotation"),
    ),
    (
        "DuplicatePolicyName",
        lambda: exc.DuplicatePolicyName("monthly", TENANT_ID, "rotation"),
    ),
    ("ResolvedSecretZeroized", lambda: exc.ResolvedSecretZeroized()),
]


class TestDomainExceptions:
    @pytest.mark.parametrize("name, factory", EXCEPTION_CASES, ids=[c[0] for c in EXCEPTION_CASES])
    def test_instantiate_and_raise(self, name: str, factory) -> None:
        exception = factory()
        assert isinstance(exception, exc.DomainException)
        with pytest.raises(type(exception)):
            raise exception

    def test_exception_count(self) -> None:
        public_names = [
            n
            for n in dir(exc)
            if not n.startswith("_")
            and isinstance(getattr(exc, n), type)
            and issubclass(getattr(exc, n), exc.DomainException)
        ]
        assert len(public_names) == 26
