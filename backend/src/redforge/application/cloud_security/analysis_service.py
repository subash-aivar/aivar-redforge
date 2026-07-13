"""Deterministic cloud exposure analysis — M7.

Computed on read over canonical CLOUD_RESOURCE assets — never
persisted, never fabricated. `PUBLIC_STORAGE_CONFIGURATION` and
`PUBLIC_COMPUTE_ENDPOINT` are both derived strictly from the `public`
flag AWS itself returned (S3 bucket ACL grants to AllUsers; EC2
instance's own PublicIpAddress field) — never a name/region heuristic.
This is exposure context, never a claim of compromise or a CVE
assignment.

Cloud resource classification/region/public-flag facts are encoded in
each asset's `description` field as `key=value;...` pairs (see
`TenantCloudSecurityService._describe_resource`) — a deliberate
simplification given the current `AssetDTO` surface exposes
`description` but not a typed metadata dict; a future migration could
add typed columns if richer filtering is ever needed (documented as a
P1 in the M7 report).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CloudSecurityObservation:
    rule_id: str
    title: str
    summary: str
    affected_asset_id: str


def _parse_description(description: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for part in description.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            facts[key.strip()] = value.strip()
    return facts


def analyze(resources: list[dict[str, str]]) -> list[CloudSecurityObservation]:
    """`resources`: list of dicts with `id`, `name`, `description` for
    every CLOUD_RESOURCE asset in the organization."""
    observations: list[CloudSecurityObservation] = []

    for resource in resources:
        facts = _parse_description(resource["description"])
        if facts.get("public") != "true":
            continue

        resource_class = facts.get("class", "")
        if resource_class == "storage":
            observations.append(
                CloudSecurityObservation(
                    rule_id="PUBLIC_STORAGE_CONFIGURATION",
                    title="Public storage configuration",
                    summary=f"Storage resource {resource['name']} permits public access.",
                    affected_asset_id=resource["id"],
                )
            )
        elif resource_class == "compute":
            observations.append(
                CloudSecurityObservation(
                    rule_id="PUBLIC_COMPUTE_ENDPOINT",
                    title="Public compute endpoint",
                    summary=f"Compute resource {resource['name']} has a public IP address.",
                    affected_asset_id=resource["id"],
                )
            )

    return observations
