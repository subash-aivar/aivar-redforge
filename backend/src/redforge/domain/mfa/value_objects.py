from __future__ import annotations

from enum import StrEnum, unique


@unique
class FactorType(StrEnum):
    """Supported MFA factor types. TOTP only in M2 — WebAuthn/passkeys
    would be the stronger, phishing-resistant choice long-term, but
    require browser credential-management APIs and an RP-ID/attestation
    review that is its own dedicated milestone. TOTP (RFC 6238) is the
    standards-compliant, dependency-light choice available now.
    """

    TOTP = "totp"


@unique
class FactorStatus(StrEnum):
    """Lifecycle of an MFAFactor.

    - PENDING_ENROLLMENT: secret generated, not yet proven — cannot
      satisfy MFA or establish privileged assurance.
    - ACTIVE: proof of possession succeeded — can satisfy MFA.
    - REVOKED: terminal. Cannot satisfy MFA even if guessed/replayed.
    """

    PENDING_ENROLLMENT = "pending_enrollment"
    ACTIVE = "active"
    REVOKED = "revoked"
