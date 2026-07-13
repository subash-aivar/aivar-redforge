"""Authentication infrastructure contracts.

These abstractions allow swapping implementations without changing
business logic. Future: plug in Argon2, bcrypt, AWS KMS, HSM,
OAuth2, SAML, OIDC, Keycloak, Auth0, Azure AD, Okta.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class TokenPair:
    """JWT access + refresh token pair."""

    access_token: str
    refresh_token: str
    access_expires_in: int  # seconds
    refresh_expires_in: int  # seconds
    token_type: str = "Bearer"


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Decoded token claims."""

    sub: str  # user_id
    email: str
    organization_id: str | None = None
    role: str | None = None
    exp: int = 0  # expiration timestamp


@runtime_checkable
class PasswordHasher(Protocol):
    """Port for password hashing. Implementation: bcrypt, argon2, etc."""

    def hash(self, password: str) -> str:
        """Hash a plaintext password. Returns hash string."""
        ...

    def verify(self, password: str, hashed: str) -> bool:
        """Verify a plaintext password against a hash."""
        ...


@runtime_checkable
class TokenService(Protocol):
    """Port for JWT token generation and validation."""

    def create_tokens(self, payload: TokenPayload) -> TokenPair:
        """Generate access + refresh token pair from claims."""
        ...

    def decode_access_token(self, token: str) -> TokenPayload | None:
        """Decode and validate an access token. Returns None if invalid."""
        ...

    def decode_refresh_token(self, token: str) -> TokenPayload | None:
        """Decode and validate a refresh token. Returns None if invalid."""
        ...
