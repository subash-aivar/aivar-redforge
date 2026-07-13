"""Password hashing implementations.

Production implementation uses Argon2id — the winner of the Password
Hashing Competition, recommended by OWASP for password storage.

Architecture: implements the PasswordHasher protocol from contracts.py.
The application layer never knows which hashing algorithm is used.
"""

from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import Type as _Argon2Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Argon2PasswordHasher:
    """Argon2id password hasher — production grade.

    Uses argon2-cffi with OWASP-recommended parameters:
    - Type: Argon2id (hybrid of Argon2i + Argon2d)
    - Time cost: 3 iterations
    - Memory cost: 65536 KiB (64 MB)
    - Parallelism: 4 threads
    - Hash length: 32 bytes
    - Salt length: 16 bytes (auto-generated)

    Output format: standard PHC string format
    ($argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>)
    """

    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32,
        salt_len: int = 16,
    ) -> None:
        self._hasher = _Argon2Hasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=_Argon2Type.ID,
        )

    def hash(self, password: str) -> str:
        """Hash a password using Argon2id. Returns PHC-format string."""
        return self._hasher.hash(password)

    def verify(self, password: str, hashed: str) -> bool:
        """Verify a password against an Argon2id hash.

        Returns True if the password matches, False otherwise.
        Handles legacy SHA-256 hashes for migration compatibility.
        """
        # Support legacy SHA-256 hashes during migration period
        if hashed.startswith("sha256$"):
            return self._verify_legacy_sha256(password, hashed)

        try:
            return self._hasher.verify(hashed, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """Check if a hash needs to be re-hashed with current parameters.

        Returns True for legacy hashes or outdated Argon2 parameters.
        """
        if hashed.startswith("sha256$"):
            return True
        try:
            return self._hasher.check_needs_rehash(hashed)
        except Exception:
            return True

    @staticmethod
    def _verify_legacy_sha256(password: str, hashed: str) -> bool:
        """Verify against legacy SHA-256 format for backward compatibility."""
        import hashlib
        import secrets

        parts = hashed.split("$")
        if len(parts) != 3 or parts[0] != "sha256":
            return False
        salt = parts[1]
        expected = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return secrets.compare_digest(expected, parts[2])
