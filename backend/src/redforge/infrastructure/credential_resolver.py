"""Development infrastructure: environment-backed credential resolver.

This is the DEVELOPMENT implementation of CredentialResolverPort.
It resolves provider credentials from environment variables.

IMPORTANT — what this is and is not:
  IS: a development-time server-side credential store backed by env vars.
      Credentials are never transmitted from the browser. The browser
      submits a provider_id (opaque UUID); the server resolves the
      corresponding env-var-backed secret at the infrastructure boundary.
  IS NOT: encrypted secret storage, vault, HSM, or production credential
      management. Production deployments must swap this adapter for an
      implementation backed by AWS Secrets Manager, Vault, or equivalent.

The auth_ref stored on a provider record is an environment variable NAME
(e.g. "OPENAI_API_KEY"), not the secret value itself. This name is safe
to store and display — it carries no secret material.
"""

from __future__ import annotations

import os

from redforge.core.exceptions import CredentialResolutionError


class EnvironmentCredentialResolver:
    """Resolves auth_ref strings to secret values from environment variables.

    auth_ref must be the name of an environment variable, e.g. "OPENAI_API_KEY".
    The resolved value is never logged, persisted, or serialized.
    """

    def resolve(self, auth_ref: str) -> str:
        """Look up auth_ref in the server environment.

        Raises CredentialResolutionError if the variable is unset or empty.
        The error message includes only the variable NAME, never the value.
        """
        if not auth_ref or not auth_ref.strip():
            raise CredentialResolutionError("(empty auth_ref)")
        value = os.environ.get(auth_ref.strip(), "")
        if not value:
            raise CredentialResolutionError(auth_ref.strip())
        return value
