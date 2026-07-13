"""Read-only AWS discovery adapter — M7.

SAFETY BOUNDARY: this adapter performs read-only SDK calls only
(`get_caller_identity`, `describe_instances`, `list_buckets`,
`get_bucket_acl`). It exposes exactly one public method (`discover`) —
no `execute_aws_api(service, operation, params)` escape hatch, no
mutation/delete/policy-change capability of any kind. boto3 clients
are constructed and used entirely within `discover()`; they are never
retained on the instance or returned to a caller.

CREDENTIALS: this adapter never receives long-lived secrets directly —
the caller (`TenantCloudSecurityService`/`TenantConnectorService`)
resolves a credential reference via `EnvironmentCredentialResolver`
(the same dev-only, env-var-name-based boundary M2/M5/M6 already
established) and passes the resolved access key/secret/session token
in as a `AwsCredential` value object for the duration of one call —
never persisted, never logged, never included in an observation or
error message.

AUTHORITATIVE STATE ONLY: `public` on an S3 bucket is derived from the
bucket's own ACL grants (a grant to the AllUsers group URI) — never
from a bucket-name heuristic. `public` on an EC2 instance is the
instance's own `PublicIpAddress` field as returned by AWS — never
inferred from a security group rule alone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import boto3
import botocore.exceptions

from redforge.application.cloud_security.observations import (
    CloudAccountObservation,
    CloudDiscoveryResult,
    CloudProvider,
    CloudResourceClass,
    CloudResourceObservation,
)

logger = logging.getLogger(__name__)

_ALL_USERS_GRANTEE_URI = "http://acs.amazonaws.com/groups/global/AllUsers"


@dataclass(frozen=True, slots=True)
class AwsCredential:
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


class AwsDiscoveryError(RuntimeError):
    """Sanitized AWS SDK failure — never includes credential material."""


class AwsCloudAdapter:
    """Read-only AWS discovery. No write/mutate methods exist on this
    class by design (Capability boundary — see module docstring)."""

    def discover(self, credential: AwsCredential, region: str) -> CloudDiscoveryResult:
        session = boto3.Session(
            aws_access_key_id=credential.access_key_id,
            aws_secret_access_key=credential.secret_access_key,
            aws_session_token=credential.session_token,
            region_name=region,
        )

        try:
            account = self._discover_account(session)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"].get("Code", "Unknown")
            raise AwsDiscoveryError(f"STS call failed (sanitized): {code}") from exc
        except botocore.exceptions.BotoCoreError as exc:
            raise AwsDiscoveryError(
                f"AWS connection failed (sanitized): {type(exc).__name__}"
            ) from exc

        errors: list[str] = []
        resources: list[CloudResourceObservation] = []
        resources.extend(self._discover_ec2_instances(session, region, errors))
        resources.extend(self._discover_s3_buckets(session, region, errors))

        return CloudDiscoveryResult(
            account=account, resources=tuple(resources), errors=tuple(errors),
        )

    def _discover_account(self, session: object) -> CloudAccountObservation:
        sts = session.client("sts")  # type: ignore[attr-defined]
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        return CloudAccountObservation(
            provider=CloudProvider.AWS, account_identifier=account_id,
            display_name=f"AWS Account {account_id}",
        )

    def _discover_ec2_instances(
        self, session: object, region: str, errors: list[str]
    ) -> list[CloudResourceObservation]:
        resources: list[CloudResourceObservation] = []
        try:
            ec2 = session.client("ec2")  # type: ignore[attr-defined]
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    owner_id = reservation.get("OwnerId", "")
                    for instance in reservation.get("Instances", []):
                        instance_id = instance.get("InstanceId", "")
                        if not instance_id:
                            continue
                        public_ip = instance.get("PublicIpAddress")
                        name = instance_id
                        for tag in instance.get("Tags", []):
                            if tag.get("Key") == "Name":
                                name = tag.get("Value", instance_id)
                        arn = f"arn:aws:ec2:{region}:{owner_id}:instance/{instance_id}"
                        resources.append(
                            CloudResourceObservation(
                                provider=CloudProvider.AWS, native_resource_id=arn,
                                resource_class=CloudResourceClass.COMPUTE,
                                native_type="aws.ec2.instance", display_name=name,
                                region=region, public=public_ip is not None,
                                safe_attributes={"instance_type": instance.get("InstanceType", "")},
                            )
                        )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            errors.append(f"EC2 discovery failed (sanitized): {type(exc).__name__}")
        return resources

    def _discover_s3_buckets(
        self, session: object, region: str, errors: list[str]
    ) -> list[CloudResourceObservation]:
        resources: list[CloudResourceObservation] = []
        try:
            s3 = session.client("s3")  # type: ignore[attr-defined]
            listing = s3.list_buckets()
            for bucket in listing.get("Buckets", []):
                bucket_name = bucket.get("Name", "")
                if not bucket_name:
                    continue
                public = False
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") == _ALL_USERS_GRANTEE_URI:
                            public = True
                            break
                except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError):
                    errors.append(f"S3 ACL check failed for {bucket_name} (sanitized)")
                arn = f"arn:aws:s3:::{bucket_name}"
                resources.append(
                    CloudResourceObservation(
                        provider=CloudProvider.AWS, native_resource_id=arn,
                        resource_class=CloudResourceClass.STORAGE,
                        native_type="aws.s3.bucket", display_name=bucket_name,
                        region=region, public=public,
                    )
                )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            errors.append(f"S3 discovery failed (sanitized): {type(exc).__name__}")
        return resources
