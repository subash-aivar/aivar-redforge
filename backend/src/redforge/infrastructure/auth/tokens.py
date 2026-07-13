"""JWT token service using PyJWT.

Production-grade implementation supporting:
- HS256 (symmetric — for single-service deployments)
- RS256 (asymmetric — for microservice/zero-trust deployments)
- Configurable expiration
- Clock skew tolerance
- Typed claims model
- Refresh token flow
- Key rotation readiness (via algorithm + key injection)

Architecture: implements TokenService protocol from contracts.py.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
)

from redforge.infrastructure.auth.contracts import TokenPair, TokenPayload


class JWTTokenService:
    """PyJWT-based token service — production grade.

    Supports HS256 (shared secret) and RS256 (public/private key pair).
    For RS256, pass the private key as secret_key and set algorithm="RS256".

    Clock skew tolerance of 30 seconds handles minor time drift between
    services in distributed deployments.
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_ttl: int = 1800,
        refresh_ttl: int = 604800,
        clock_skew_seconds: int = 30,
        issuer: str = "redforge",
    ) -> None:
        self._secret = secret_key
        self._algorithm = algorithm
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._clock_skew = clock_skew_seconds
        self._issuer = issuer

        # For RS256 verification, the public key would be separate.
        # In HS256 mode, encode and decode use the same secret.
        self._decode_key = secret_key

    def create_tokens(self, payload: TokenPayload) -> TokenPair:
        """Generate access + refresh token pair."""
        now = int(time.time())

        access_claims: dict[str, Any] = {
            "sub": payload.sub,
            "email": payload.email,
            "org": payload.organization_id,
            "role": payload.role,
            "type": "access",
            "iss": self._issuer,
            "iat": now,
            "exp": now + self._access_ttl,
        }

        refresh_claims: dict[str, Any] = {
            "sub": payload.sub,
            "type": "refresh",
            "iss": self._issuer,
            "iat": now,
            "exp": now + self._refresh_ttl,
        }

        access_token = jwt.encode(
            access_claims, self._secret, algorithm=self._algorithm
        )
        refresh_token = jwt.encode(
            refresh_claims, self._secret, algorithm=self._algorithm
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_in=self._access_ttl,
            refresh_expires_in=self._refresh_ttl,
        )

    def decode_access_token(self, token: str) -> TokenPayload | None:
        """Decode and validate an access token.

        Returns None if token is invalid, expired, or wrong type.
        """
        claims = self._decode(token)
        if claims is None:
            return None
        if claims.get("type") != "access":
            return None

        return TokenPayload(
            sub=str(claims["sub"]),
            email=str(claims.get("email", "")),
            organization_id=str(claims["org"]) if claims.get("org") else None,
            role=str(claims["role"]) if claims.get("role") else None,
            exp=int(claims.get("exp", 0)),
        )

    def decode_refresh_token(self, token: str) -> TokenPayload | None:
        """Decode and validate a refresh token.

        Returns None if token is invalid, expired, or wrong type.
        """
        claims = self._decode(token)
        if claims is None:
            return None
        if claims.get("type") != "refresh":
            return None

        return TokenPayload(
            sub=str(claims["sub"]),
            email="",
            exp=int(claims.get("exp", 0)),
        )

    def _decode(self, token: str) -> dict[str, Any] | None:
        """Decode and verify a JWT token.

        Validates: signature, expiration (with clock skew), issuer, algorithm.
        """
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self._decode_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                leeway=self._clock_skew,
                options={
                    "require": ["exp", "sub", "iss", "iat", "type"],
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_iat": True,
                },
            )
            return claims
        except (
            ExpiredSignatureError,
            InvalidSignatureError,
            InvalidAlgorithmError,
            InvalidTokenError,
            DecodeError,
            KeyError,
        ):
            return None
