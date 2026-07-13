"""Deterministic identity security analysis — M5.

Produces crisp, deterministic SECURITY OBSERVATIONS over canonical
directory identity/group/membership state — not fabricated
vulnerabilities, not AI-generated prose, not automatic Finding
creation (see Capability 15 / the M5 report's Finding-integration
decision: these are EXPOSURE CONTEXT, not validated security Findings —
weakening Finding semantics to inflate dashboard counts is explicitly
rejected). A disabled privileged identity is inventory worth reviewing,
never claimed "exploitable"; a privileged service identity is exposure
context, never automatically "compromised".

Rules implemented (each with a stable, deterministic ID):
  - DISABLED_PRIVILEGED_IDENTITY
  - PRIVILEGED_SERVICE_IDENTITY
  - HIGH_PRIVILEGE_GROUP_MEMBERSHIP (direct only — see the M5 report's
    honest deferral of nested/effective membership traversal)

NOT implemented in M5 (documented, not silently skipped):
  - STALE_PRIVILEGED_IDENTITY: would require a canonical, policy-driven
    staleness threshold; no such policy architecture exists yet — a
    hardcoded 30/60/90-day magic number is explicitly forbidden by the
    milestone, so this rule is deferred rather than faked.
  - ORPHANED_UNRESOLVED_MEMBERSHIP: would require the connector to
    guarantee a COMPLETE authoritative directory snapshot per run,
    which the current paged-but-not-completeness-verified LDAP adapter
    does not yet prove — calling a partial-discovery gap "orphaned"
    would be dishonest.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecurityObservation:
    rule_id: str
    title: str
    summary: str
    affected_identity_id: str
    affected_group_id: str | None


def analyze(
    identities: list[dict[str, object]],
    memberships: list[dict[str, str]],
    groups_by_id: dict[str, dict[str, object]],
) -> list[SecurityObservation]:
    """`identities`: list of dicts with id/display_name/principal_category/
    source_enabled/privilege_classification. `memberships`: list of
    dicts with identity_id/group_id. `groups_by_id`: group_id -> dict
    with display_name/is_recognized_privileged."""
    observations: list[SecurityObservation] = []

    direct_group_ids_by_identity: dict[str, list[str]] = {}
    for m in memberships:
        direct_group_ids_by_identity.setdefault(m["identity_id"], []).append(m["group_id"])

    for identity in identities:
        identity_id = str(identity["id"])
        display_name = str(identity["display_name"])
        privilege = str(identity["privilege_classification"])
        category = str(identity["principal_category"])
        enabled = bool(identity["source_enabled"])

        if privilege == "privileged" and not enabled:
            observations.append(
                SecurityObservation(
                    rule_id="DISABLED_PRIVILEGED_IDENTITY",
                    title="Disabled privileged identity",
                    summary=(
                        f"'{display_name}' is disabled at the source but retains privileged "
                        "classification — review before removal."
                    ),
                    affected_identity_id=identity_id,
                    affected_group_id=None,
                )
            )

        if privilege == "privileged" and category == "service":
            observations.append(
                SecurityObservation(
                    rule_id="PRIVILEGED_SERVICE_IDENTITY",
                    title="Privileged service identity",
                    summary=(
                        f"'{display_name}' is classified as a service identity and holds "
                        "privileged classification — exposure context, not a confirmed compromise."
                    ),
                    affected_identity_id=identity_id,
                    affected_group_id=None,
                )
            )

        for group_id in direct_group_ids_by_identity.get(identity_id, []):
            group = groups_by_id.get(group_id)
            if group is not None and group.get("is_recognized_privileged"):
                observations.append(
                    SecurityObservation(
                        rule_id="HIGH_PRIVILEGE_GROUP_MEMBERSHIP",
                        title="Direct high-privilege group membership",
                        summary=(
                            f"'{display_name}' is a DIRECT member of the recognized "
                            f"high-privilege group '{group['display_name']}'."
                        ),
                        affected_identity_id=identity_id,
                        affected_group_id=group_id,
                    )
                )

    return observations
