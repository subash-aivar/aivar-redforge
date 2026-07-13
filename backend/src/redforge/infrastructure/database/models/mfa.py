"""SQLAlchemy ORM models for MFA and privileged assurance — M2."""

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class MFAFactorModel(Base):
    """ORM representation of an MFAFactor.

    `secret_ciphertext` is the ONLY place the encrypted TOTP secret is
    stored — it is never assembled into a domain entity, DTO, or API
    response. Only `MFAService` reads this column, and only to decrypt
    for verification, never to return it.
    """

    __tablename__ = "mfa_factors"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    factor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    secret_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(26), nullable=True)


class PlatformPrivilegedAssuranceModel(Base):
    """A short-lived, server-side "did you just prove MFA" record.

    The opaque token handed to the client is this row's `id` — there is
    no cryptographic content in the token itself; validity is entirely
    a live database lookup (expires_at, revoked_at), matching the same
    "read live, never trust a long-lived claim" principle M1 applied to
    platform role resolution.
    """

    __tablename__ = "platform_privileged_assurances"

    id: Mapped[str] = mapped_column(String(43), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    established_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
