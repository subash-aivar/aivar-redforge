"""Unit tests for enterprise authentication security.

Tests:
- Argon2id password hashing (hash, verify, legacy migration, rehash detection)
- PyJWT token service (create, decode, expiry, invalid sig, wrong alg, refresh flow)
"""

import time

import jwt

from redforge.infrastructure.auth.contracts import TokenPayload
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService

# ═══════════════════════════════════════════════════════════════════════════════
# PASSWORD HASHING — Argon2id
# ═══════════════════════════════════════════════════════════════════════════════


class TestArgon2PasswordHasher:
    """Tests for Argon2id password hashing."""

    def setup_method(self) -> None:
        self.hasher = Argon2PasswordHasher(
            time_cost=1, memory_cost=16384, parallelism=1  # Fast for tests
        )

    def test_hash_produces_argon2id_format(self) -> None:
        hashed = self.hasher.hash("correct-horse-battery-staple")
        assert hashed.startswith("$argon2id$")
        assert "$m=16384,t=1,p=1$" in hashed

    def test_hash_is_not_deterministic(self) -> None:
        h1 = self.hasher.hash("same-password")
        h2 = self.hasher.hash("same-password")
        assert h1 != h2  # Different salts

    def test_verify_correct_password(self) -> None:
        hashed = self.hasher.hash("my-secure-password")
        assert self.hasher.verify("my-secure-password", hashed) is True

    def test_verify_wrong_password(self) -> None:
        hashed = self.hasher.hash("my-secure-password")
        assert self.hasher.verify("wrong-password", hashed) is False

    def test_verify_empty_password(self) -> None:
        hashed = self.hasher.hash("real-password")
        assert self.hasher.verify("", hashed) is False

    def test_verify_corrupted_hash(self) -> None:
        assert self.hasher.verify("password", "corrupted-garbage") is False

    def test_verify_legacy_sha256_hash(self) -> None:
        """Backward compatibility: verify passwords hashed with old SHA-256."""
        import hashlib
        import secrets

        password = "legacy-password"
        salt = secrets.token_hex(16)
        legacy_hash = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        legacy_stored = f"sha256${salt}${legacy_hash}"

        assert self.hasher.verify(password, legacy_stored) is True
        assert self.hasher.verify("wrong", legacy_stored) is False

    def test_needs_rehash_for_legacy_hash(self) -> None:
        legacy = "sha256$abcdef1234567890$aabbccdd"
        assert self.hasher.needs_rehash(legacy) is True

    def test_needs_rehash_for_current_params(self) -> None:
        hashed = self.hasher.hash("password")
        assert self.hasher.needs_rehash(hashed) is False

    def test_needs_rehash_for_outdated_params(self) -> None:
        """A hash with weaker parameters should be rehashed."""
        weak_hasher = Argon2PasswordHasher(
            time_cost=1, memory_cost=8192, parallelism=1
        )
        hashed = weak_hasher.hash("password")
        # Our standard hasher (16384 memory) should flag the weak hash
        assert self.hasher.needs_rehash(hashed) is True


# ═══════════════════════════════════════════════════════════════════════════════
# JWT TOKEN SERVICE — PyJWT
# ═══════════════════════════════════════════════════════════════════════════════


class TestJWTTokenService:
    """Tests for PyJWT-based token service."""

    SECRET = "test-secret-key-32-chars-minimum!"
    ISSUER = "redforge"

    def setup_method(self) -> None:
        self.service = JWTTokenService(
            secret_key=self.SECRET,
            algorithm="HS256",
            access_ttl=3600,
            refresh_ttl=86400 * 7,
            clock_skew_seconds=30,
            issuer=self.ISSUER,
        )

    def test_create_tokens_returns_pair(self) -> None:
        payload = TokenPayload(sub="user-123", email="test@example.com")
        pair = self.service.create_tokens(payload)

        assert pair.access_token != ""
        assert pair.refresh_token != ""
        assert pair.access_token != pair.refresh_token
        assert pair.access_expires_in == 3600
        assert pair.refresh_expires_in == 86400 * 7
        assert pair.token_type == "Bearer"

    def test_decode_access_token_valid(self) -> None:
        payload = TokenPayload(
            sub="user-456",
            email="alice@example.com",
            organization_id="org-789",
            role="admin",
        )
        pair = self.service.create_tokens(payload)
        decoded = self.service.decode_access_token(pair.access_token)

        assert decoded is not None
        assert decoded.sub == "user-456"
        assert decoded.email == "alice@example.com"
        assert decoded.organization_id == "org-789"
        assert decoded.role == "admin"
        assert decoded.exp > 0

    def test_decode_refresh_token_valid(self) -> None:
        payload = TokenPayload(sub="user-456", email="alice@example.com")
        pair = self.service.create_tokens(payload)
        decoded = self.service.decode_refresh_token(pair.refresh_token)

        assert decoded is not None
        assert decoded.sub == "user-456"

    def test_access_token_cannot_be_used_as_refresh(self) -> None:
        payload = TokenPayload(sub="user-1", email="x@x.com")
        pair = self.service.create_tokens(payload)
        assert self.service.decode_refresh_token(pair.access_token) is None

    def test_refresh_token_cannot_be_used_as_access(self) -> None:
        payload = TokenPayload(sub="user-1", email="x@x.com")
        pair = self.service.create_tokens(payload)
        assert self.service.decode_access_token(pair.refresh_token) is None

    def test_expired_access_token_returns_none(self) -> None:
        """Token expired well beyond clock skew should fail."""
        claims = {
            "sub": "user-1",
            "email": "x@x.com",
            "type": "access",
            "org": None,
            "role": None,
            "iss": self.ISSUER,
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        }
        token = jwt.encode(claims, self.SECRET, algorithm="HS256")
        assert self.service.decode_access_token(token) is None

    def test_expired_refresh_token_returns_none(self) -> None:
        """Refresh token expired well beyond clock skew should fail."""
        claims = {
            "sub": "user-1",
            "type": "refresh",
            "iss": self.ISSUER,
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        }
        token = jwt.encode(claims, self.SECRET, algorithm="HS256")
        assert self.service.decode_refresh_token(token) is None

    def test_invalid_signature_returns_none(self) -> None:
        payload = TokenPayload(sub="user-1", email="x@x.com")
        pair = self.service.create_tokens(payload)

        # Tamper with the token
        tampered = pair.access_token[:-5] + "XXXXX"
        assert self.service.decode_access_token(tampered) is None

    def test_wrong_secret_returns_none(self) -> None:
        payload = TokenPayload(sub="user-1", email="x@x.com")
        pair = self.service.create_tokens(payload)

        other_service = JWTTokenService(
            secret_key="completely-different-secret-key!!!",
            issuer=self.ISSUER,
        )
        assert other_service.decode_access_token(pair.access_token) is None

    def test_wrong_algorithm_returns_none(self) -> None:
        """Token signed with HS256 cannot be decoded expecting HS384."""
        payload = TokenPayload(sub="user-1", email="x@x.com")
        pair = self.service.create_tokens(payload)

        hs384_service = JWTTokenService(
            secret_key=self.SECRET,
            algorithm="HS384",
            issuer=self.ISSUER,
        )
        assert hs384_service.decode_access_token(pair.access_token) is None

    def test_wrong_issuer_returns_none(self) -> None:
        payload = TokenPayload(sub="user-1", email="x@x.com")
        pair = self.service.create_tokens(payload)

        other_issuer = JWTTokenService(
            secret_key=self.SECRET,
            issuer="some-other-issuer",
        )
        assert other_issuer.decode_access_token(pair.access_token) is None

    def test_garbage_token_returns_none(self) -> None:
        assert self.service.decode_access_token("not.a.jwt") is None
        assert self.service.decode_access_token("") is None
        assert self.service.decode_access_token("abc123") is None

    def test_clock_skew_tolerance(self) -> None:
        """Token that expired 15 seconds ago should still be valid (30s skew)."""
        claims = {
            "sub": "user-1",
            "email": "x@x.com",
            "type": "access",
            "org": None,
            "role": None,
            "iss": self.ISSUER,
            "iat": int(time.time()) - 100,
            "exp": int(time.time()) - 15,  # Expired 15s ago, within 30s skew
        }
        token = jwt.encode(claims, self.SECRET, algorithm="HS256")
        decoded = self.service.decode_access_token(token)
        assert decoded is not None
        assert decoded.sub == "user-1"

    def test_clock_skew_exceeded_returns_none(self) -> None:
        """Token that expired 60 seconds ago should NOT be valid (30s skew)."""
        claims = {
            "sub": "user-1",
            "email": "x@x.com",
            "type": "access",
            "org": None,
            "role": None,
            "iss": self.ISSUER,
            "iat": int(time.time()) - 200,
            "exp": int(time.time()) - 60,  # Expired 60s ago, beyond 30s skew
        }
        token = jwt.encode(claims, self.SECRET, algorithm="HS256")
        assert self.service.decode_access_token(token) is None

    def test_none_algorithm_attack_rejected(self) -> None:
        """Prevent 'none' algorithm attack (CVE-2015-9235)."""
        import base64
        import json

        claims = {
            "sub": "admin",
            "email": "admin@x.com",
            "type": "access",
            "org": None,
            "role": "admin",
            "iss": self.ISSUER,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        # Manually craft a 'none' algorithm token (unsigned)
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(claims).encode()
        ).rstrip(b"=").decode()
        none_token = f"{header}.{payload_b64}."

        assert self.service.decode_access_token(none_token) is None

    def test_refresh_flow_end_to_end(self) -> None:
        """Full refresh flow: create → decode refresh → create new pair."""
        original = TokenPayload(sub="user-1", email="user@example.com")
        pair = self.service.create_tokens(original)

        # Simulate: access token expired, use refresh to get new tokens
        refresh_payload = self.service.decode_refresh_token(pair.refresh_token)
        assert refresh_payload is not None
        assert refresh_payload.sub == "user-1"

        # Create new tokens from refresh payload
        new_pair = self.service.create_tokens(
            TokenPayload(sub=refresh_payload.sub, email="user@example.com")
        )
        # New tokens should be valid
        new_decoded = self.service.decode_access_token(new_pair.access_token)
        assert new_decoded is not None
        assert new_decoded.sub == "user-1"
        assert new_decoded.email == "user@example.com"
