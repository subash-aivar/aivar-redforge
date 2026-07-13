"""Directory Security bounded context — M5.

Represents security-relevant PRINCIPALS OBSERVED in an external
directory/identity source (LDAP, Active Directory, Entra, etc.). This
is deliberately distinct from `domain/identity/` (RedForge's own
login-user/membership/RBAC bounded context) — a `DirectoryIdentity` is
never the same thing as a RedForge `User`, and the two are never
merged. See docs/M5_IDENTITY_DIRECTORY_SECURITY_VISIBILITY_REPORT.md
for the full architectural distinction.
"""
