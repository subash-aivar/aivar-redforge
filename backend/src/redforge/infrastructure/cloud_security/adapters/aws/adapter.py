"""AWS CloudProviderAdapter backed by an injectable AwsDiscoveryClient."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.ports import (
    CloudCredential,
    DiscoveredAccount,
    RawAIService,
    RawAsset,
    RawIAMPrincipal,
    RawK8sCluster,
    RawRuntimeEvent,
)
from redforge.domain.cloud_security.value_objects import CloudAccountType, CloudAssetType
from redforge.infrastructure.cloud_security.adapters.common import (
    CredentialMaterial,
    empty_async_iterator,
)


class AwsDiscoveryClient(Protocol):
    """Resource discovery surface — returns sanitized dict payloads only."""

    def caller_identity(self) -> dict[str, str]: ...

    def list_organization_accounts(self) -> list[dict[str, Any]]: ...

    def list_regions(self) -> list[str]: ...

    def list_ec2_instances(self, region: str) -> list[dict[str, Any]]: ...

    def list_s3_buckets(self, region: str) -> list[dict[str, Any]]: ...

    def list_rds_instances(self, region: str) -> list[dict[str, Any]]: ...

    def list_vpcs(self, region: str) -> list[dict[str, Any]]: ...

    def list_security_groups(self, region: str) -> list[dict[str, Any]]: ...

    def list_lambda_functions(self, region: str) -> list[dict[str, Any]]: ...

    def list_eks_clusters(self, region: str) -> list[dict[str, Any]]: ...

    def list_ecr_repositories(self, region: str) -> list[dict[str, Any]]: ...

    def list_route53_zones(self, region: str) -> list[dict[str, Any]]: ...

    def list_cloudfront_distributions(self, region: str) -> list[dict[str, Any]]: ...

    def list_kms_keys(self, region: str) -> list[dict[str, Any]]: ...

    def list_secrets_manager_secrets(self, region: str) -> list[dict[str, Any]]: ...

    def list_iam_users(self) -> list[dict[str, Any]]: ...

    def list_iam_roles(self) -> list[dict[str, Any]]: ...

    def list_iam_groups(self) -> list[dict[str, Any]]: ...

    def list_managed_policies(self) -> list[dict[str, Any]]: ...


@dataclass
class StaticAwsDiscoveryClient:
    """In-memory discovery client for tests and unit demos."""

    identity: dict[str, str] = field(
        default_factory=lambda: {"Account": "000000000000", "Arn": "", "UserId": ""}
    )
    organization_accounts: list[dict[str, Any]] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    ec2_instances: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    s3_buckets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    rds_instances: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    vpcs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    security_groups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    lambda_functions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    eks_clusters: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    ecr_repositories: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    route53_zones: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    cloudfront_distributions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    kms_keys: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    secrets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    iam_users: list[dict[str, Any]] = field(default_factory=list)
    iam_roles: list[dict[str, Any]] = field(default_factory=list)
    iam_groups: list[dict[str, Any]] = field(default_factory=list)
    managed_policies: list[dict[str, Any]] = field(default_factory=list)

    def caller_identity(self) -> dict[str, str]:
        return dict(self.identity)

    def list_organization_accounts(self) -> list[dict[str, Any]]:
        return list(self.organization_accounts)

    def list_regions(self) -> list[str]:
        return list(self.regions)

    def list_ec2_instances(self, region: str) -> list[dict[str, Any]]:
        return list(self.ec2_instances.get(region, []))

    def list_s3_buckets(self, region: str) -> list[dict[str, Any]]:
        return list(self.s3_buckets.get(region, []))

    def list_rds_instances(self, region: str) -> list[dict[str, Any]]:
        return list(self.rds_instances.get(region, []))

    def list_vpcs(self, region: str) -> list[dict[str, Any]]:
        return list(self.vpcs.get(region, []))

    def list_security_groups(self, region: str) -> list[dict[str, Any]]:
        return list(self.security_groups.get(region, []))

    def list_lambda_functions(self, region: str) -> list[dict[str, Any]]:
        return list(self.lambda_functions.get(region, []))

    def list_eks_clusters(self, region: str) -> list[dict[str, Any]]:
        return list(self.eks_clusters.get(region, []))

    def list_ecr_repositories(self, region: str) -> list[dict[str, Any]]:
        return list(self.ecr_repositories.get(region, []))

    def list_route53_zones(self, region: str) -> list[dict[str, Any]]:
        return list(self.route53_zones.get(region, []))

    def list_cloudfront_distributions(self, region: str) -> list[dict[str, Any]]:
        return list(self.cloudfront_distributions.get(region, []))

    def list_kms_keys(self, region: str) -> list[dict[str, Any]]:
        return list(self.kms_keys.get(region, []))

    def list_secrets_manager_secrets(self, region: str) -> list[dict[str, Any]]:
        return list(self.secrets.get(region, []))

    def list_iam_users(self) -> list[dict[str, Any]]:
        return list(self.iam_users)

    def list_iam_roles(self) -> list[dict[str, Any]]:
        return list(self.iam_roles)

    def list_iam_groups(self) -> list[dict[str, Any]]:
        return list(self.iam_groups)

    def list_managed_policies(self) -> list[dict[str, Any]]:
        return list(self.managed_policies)


def _sanitize_tags(tags: Any) -> list[dict[str, str]]:
    if not isinstance(tags, list):
        return []
    out: list[dict[str, str]] = []
    for item in tags:
        if isinstance(item, dict) and "Key" in item and "Value" in item:
            out.append({"Key": str(item["Key"]), "Value": str(item["Value"])})
    return out


class Boto3AwsDiscoveryClient:
    """AwsDiscoveryClient implemented with boto3 (already a project dependency)."""

    def __init__(
        self,
        material: CredentialMaterial,
        *,
        session_factory: Callable[[CredentialMaterial, str | None], Any] | None = None,
        default_region: str = "us-east-1",
    ) -> None:
        self._material = material
        self._default_region = default_region
        self._session_factory = session_factory or self._default_session

    @staticmethod
    def _default_session(material: CredentialMaterial, region: str | None) -> Any:
        import boto3

        return boto3.Session(
            aws_access_key_id=material.access_key_id,
            aws_secret_access_key=material.secret_access_key,
            aws_session_token=material.session_token,
            region_name=region,
        )

    def _client(self, service: str, region: str | None = None) -> Any:
        session = self._session_factory(self._material, region or self._default_region)
        return session.client(service)

    def caller_identity(self) -> dict[str, str]:
        identity = self._client("sts").get_caller_identity()
        return {
            "Account": str(identity.get("Account", "")),
            "Arn": str(identity.get("Arn", "")),
            "UserId": str(identity.get("UserId", "")),
        }

    def list_organization_accounts(self) -> list[dict[str, Any]]:
        try:
            org = self._client("organizations")
            paginator = org.get_paginator("list_accounts")
            accounts: list[dict[str, Any]] = []
            for page in paginator.paginate():
                for acct in page.get("Accounts", []):
                    accounts.append(
                        {
                            "id": str(acct.get("Id", "")),
                            "name": str(acct.get("Name", "")),
                            "status": str(acct.get("Status", "")),
                            "email": str(acct.get("Email", "")),
                        }
                    )
            return accounts
        except Exception:
            return []

    def list_regions(self) -> list[str]:
        if self._material.regions:
            return list(self._material.regions)
        try:
            ec2 = self._client("ec2", self._default_region)
            result = ec2.describe_regions(AllRegions=False)
            return [str(r["RegionName"]) for r in result.get("Regions", []) if r.get("RegionName")]
        except Exception:
            return [self._default_region]

    def list_ec2_instances(self, region: str) -> list[dict[str, Any]]:
        ec2 = self._client("ec2", region)
        out: list[dict[str, Any]] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    profile = inst.get("IamInstanceProfile") or {}
                    out.append(
                        {
                            "provider_id": str(inst.get("InstanceId", "")),
                            "display_name": str(
                                next(
                                    (
                                        t["Value"]
                                        for t in inst.get("Tags", [])
                                        if t.get("Key") == "Name"
                                    ),
                                    inst.get("InstanceId", ""),
                                )
                            ),
                            "vpc_id": inst.get("VpcId"),
                            "SubnetId": inst.get("SubnetId"),
                            "security_groups": [
                                {"GroupId": g.get("GroupId"), "GroupName": g.get("GroupName")}
                                for g in inst.get("SecurityGroups", [])
                            ],
                            "PublicIpAddress": inst.get("PublicIpAddress"),
                            "State": {"Name": (inst.get("State") or {}).get("Name")},
                            "InstanceType": inst.get("InstanceType"),
                            "AvailabilityZone": (inst.get("Placement") or {}).get(
                                "AvailabilityZone"
                            ),
                            "IamInstanceProfile": {"Arn": profile.get("Arn")} if profile else None,
                            "Tags": _sanitize_tags(inst.get("Tags")),
                        }
                    )
        return out

    def list_s3_buckets(self, region: str) -> list[dict[str, Any]]:
        s3 = self._client("s3", region)
        out: list[dict[str, Any]] = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = str(bucket.get("Name", ""))
            if not name:
                continue
            bucket_region = region
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                bucket_region = str(loc) if loc else "us-east-1"
            except Exception:
                bucket_region = region
            if bucket_region != region:
                continue
            kms_key_id = None
            sse_algorithm = None
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules") or []
                if rules:
                    default = rules[0].get("ApplyServerSideEncryptionByDefault") or {}
                    sse_algorithm = default.get("SSEAlgorithm")
                    kms_key_id = default.get("KMSMasterKeyID")
            except Exception:
                pass
            out.append(
                {
                    "provider_id": f"arn:aws:s3:::{name}",
                    "display_name": name,
                    "region": bucket_region,
                    "kms_key_id": kms_key_id,
                    "sse_algorithm": sse_algorithm,
                    "encryption_at_rest": bool(sse_algorithm),
                    "tags": [],
                }
            )
        return out

    def list_rds_instances(self, region: str) -> list[dict[str, Any]]:
        rds = self._client("rds", region)
        out: list[dict[str, Any]] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                subnet_group = db.get("DBSubnetGroup") or {}
                endpoint = db.get("Endpoint") or {}
                out.append(
                    {
                        "provider_id": str(
                            db.get("DBInstanceArn") or db.get("DBInstanceIdentifier", "")
                        ),
                        "display_name": str(db.get("DBInstanceIdentifier", "")),
                        "vpc_id": subnet_group.get("VpcId"),
                        "DBSubnetGroup": {"VpcId": subnet_group.get("VpcId")},
                        "security_groups": [
                            {"GroupId": g.get("VpcSecurityGroupId")}
                            for g in db.get("VpcSecurityGroups", [])
                        ],
                        "KmsKeyId": db.get("KmsKeyId"),
                        "StorageEncrypted": db.get("StorageEncrypted"),
                        "PubliclyAccessible": db.get("PubliclyAccessible"),
                        "Endpoint": {"Address": endpoint.get("Address")},
                        "DBInstanceStatus": db.get("DBInstanceStatus"),
                        "Engine": db.get("Engine"),
                        "EngineVersion": db.get("EngineVersion"),
                        "AvailabilityZone": db.get("AvailabilityZone"),
                        "tags": _sanitize_tags(db.get("TagList")),
                    }
                )
        return out

    def list_vpcs(self, region: str) -> list[dict[str, Any]]:
        ec2 = self._client("ec2", region)
        out: list[dict[str, Any]] = []
        for page in ec2.get_paginator("describe_vpcs").paginate():
            for vpc in page.get("Vpcs", []):
                out.append(
                    {
                        "provider_id": str(vpc.get("VpcId", "")),
                        "display_name": str(
                            next(
                                (t["Value"] for t in vpc.get("Tags", []) if t.get("Key") == "Name"),
                                vpc.get("VpcId", ""),
                            )
                        ),
                        "CidrBlock": vpc.get("CidrBlock"),
                        "IsDefault": vpc.get("IsDefault"),
                        "State": vpc.get("State"),
                        "Tags": _sanitize_tags(vpc.get("Tags")),
                    }
                )
        return out

    def list_security_groups(self, region: str) -> list[dict[str, Any]]:
        ec2 = self._client("ec2", region)
        out: list[dict[str, Any]] = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                out.append(
                    {
                        "provider_id": str(sg.get("GroupId", "")),
                        "display_name": str(sg.get("GroupName") or sg.get("GroupId", "")),
                        "VpcId": sg.get("VpcId"),
                        "GroupName": sg.get("GroupName"),
                        "Tags": _sanitize_tags(sg.get("Tags")),
                    }
                )
        return out

    def list_lambda_functions(self, region: str) -> list[dict[str, Any]]:
        client = self._client("lambda", region)
        out: list[dict[str, Any]] = []
        for page in client.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                vpc = fn.get("VpcConfig") or {}
                out.append(
                    {
                        "provider_id": str(fn.get("FunctionArn") or fn.get("FunctionName", "")),
                        "display_name": str(fn.get("FunctionName", "")),
                        "Role": fn.get("Role"),
                        "role_arn": fn.get("Role"),
                        "VpcConfig": {
                            "VpcId": vpc.get("VpcId"),
                            "SubnetIds": vpc.get("SubnetIds") or [],
                            "SecurityGroupIds": vpc.get("SecurityGroupIds") or [],
                        },
                        "Runtime": fn.get("Runtime"),
                        "PackageType": fn.get("PackageType"),
                        "KMSKeyArn": fn.get("KMSKeyArn"),
                        "State": fn.get("State"),
                        "tags": [],
                    }
                )
        return out

    def list_eks_clusters(self, region: str) -> list[dict[str, Any]]:
        eks = self._client("eks", region)
        names = eks.list_clusters().get("clusters") or []
        out: list[dict[str, Any]] = []
        for name in names:
            detail = eks.describe_cluster(name=name).get("cluster") or {}
            vpc_cfg = detail.get("resourcesVpcConfig") or {}
            out.append(
                {
                    "provider_id": str(detail.get("arn") or name),
                    "display_name": str(detail.get("name") or name),
                    "vpc_id": vpc_cfg.get("vpcId"),
                    "subnet_ids": vpc_cfg.get("subnetIds") or [],
                    "security_group_ids": vpc_cfg.get("securityGroupIds") or [],
                    "role_arn": detail.get("roleArn"),
                    "endpoint": detail.get("endpoint"),
                    "endpoint_public_access": vpc_cfg.get("endpointPublicAccess"),
                    "version": detail.get("version"),
                    "status": detail.get("status"),
                    "tags": detail.get("tags") or {},
                }
            )
        return out

    def list_ecr_repositories(self, region: str) -> list[dict[str, Any]]:
        ecr = self._client("ecr", region)
        out: list[dict[str, Any]] = []
        for page in ecr.get_paginator("describe_repositories").paginate():
            for repo in page.get("repositories", []):
                enc = repo.get("encryptionConfiguration") or {}
                out.append(
                    {
                        "provider_id": str(
                            repo.get("repositoryArn") or repo.get("repositoryName", "")
                        ),
                        "display_name": str(repo.get("repositoryName", "")),
                        "repository_uri": repo.get("repositoryUri"),
                        "kms_key_id": enc.get("kmsKey"),
                        "encryption_type": enc.get("encryptionType"),
                        "tags": [],
                    }
                )
        return out

    def list_route53_zones(self, region: str) -> list[dict[str, Any]]:
        del region  # Route53 is global
        r53 = self._client("route53", self._default_region)
        out: list[dict[str, Any]] = []
        for page in r53.get_paginator("list_hosted_zones").paginate():
            for zone in page.get("HostedZones", []):
                cfg = zone.get("Config") or {}
                out.append(
                    {
                        "provider_id": str(zone.get("Id", "")).removeprefix("/hostedzone/"),
                        "display_name": str(zone.get("Name", "")).rstrip("."),
                        "private_zone": cfg.get("PrivateZone"),
                        "resource_record_set_count": zone.get("ResourceRecordSetCount"),
                        "tags": [],
                    }
                )
        return out

    def list_cloudfront_distributions(self, region: str) -> list[dict[str, Any]]:
        del region
        cf = self._client("cloudfront", self._default_region)
        out: list[dict[str, Any]] = []
        for page in cf.get_paginator("list_distributions").paginate():
            items = (page.get("DistributionList") or {}).get("Items") or []
            for dist in items:
                out.append(
                    {
                        "provider_id": str(dist.get("ARN") or dist.get("Id", "")),
                        "display_name": str(dist.get("Id", "")),
                        "DomainName": dist.get("DomainName"),
                        "Status": dist.get("Status"),
                        "Enabled": dist.get("Enabled"),
                        "tags": [],
                    }
                )
        return out

    def list_kms_keys(self, region: str) -> list[dict[str, Any]]:
        kms = self._client("kms", region)
        out: list[dict[str, Any]] = []
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                key_id = str(key.get("KeyId", ""))
                if not key_id:
                    continue
                try:
                    meta = kms.describe_key(KeyId=key_id).get("KeyMetadata") or {}
                except Exception:
                    meta = {"KeyId": key_id}
                out.append(
                    {
                        "provider_id": str(meta.get("Arn") or key_id),
                        "display_name": str(meta.get("KeyId") or key_id),
                        "KeyState": meta.get("KeyState"),
                        "KeyUsage": meta.get("KeyUsage"),
                        "KeyManager": meta.get("KeyManager"),
                        "tags": [],
                    }
                )
        return out

    def list_secrets_manager_secrets(self, region: str) -> list[dict[str, Any]]:
        sm = self._client("secretsmanager", region)
        out: list[dict[str, Any]] = []
        for page in sm.get_paginator("list_secrets").paginate():
            for secret in page.get("SecretList", []):
                out.append(
                    {
                        "provider_id": str(secret.get("ARN") or secret.get("Name", "")),
                        "display_name": str(secret.get("Name", "")),
                        "KmsKeyId": secret.get("KmsKeyId"),
                        "RotationEnabled": secret.get("RotationEnabled"),
                        "tags": _sanitize_tags(secret.get("Tags")),
                    }
                )
        return out

    def list_iam_users(self) -> list[dict[str, Any]]:
        iam = self._client("iam")
        account_id = self.caller_identity().get("Account", "")
        out: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                name = str(user.get("UserName", ""))
                arn = str(user.get("Arn") or "")
                if not arn and name:
                    arn = f"arn:aws:iam::{account_id}:user/{name}"
                attached: list[dict[str, Any]] = []
                try:
                    for apage in iam.get_paginator("list_attached_user_policies").paginate(
                        UserName=name
                    ):
                        for pol in apage.get("AttachedPolicies", []):
                            attached.append(
                                {
                                    "policy_provider_id": str(pol.get("PolicyArn", "")),
                                    "policy_name": str(pol.get("PolicyName", "")),
                                    "attachment_type": "MANAGED",
                                    "is_inline": False,
                                }
                            )
                except Exception:
                    pass
                try:
                    for pname in iam.list_user_policies(UserName=name).get("PolicyNames", []):
                        attached.append(
                            {
                                "policy_provider_id": f"inline:user/{name}/{pname}",
                                "policy_name": str(pname),
                                "attachment_type": "INLINE",
                                "is_inline": True,
                            }
                        )
                except Exception:
                    pass
                last_used = user.get("PasswordLastUsed")
                out.append(
                    {
                        "provider_id": arn,
                        "display_name": name or arn,
                        "account_id": account_id,
                        "attached_policies": attached,
                        "is_human": True,
                        "is_federated": False,
                        "last_activity_at": last_used.isoformat()
                        if hasattr(last_used, "isoformat")
                        else last_used,
                    }
                )
        return out

    def list_iam_roles(self) -> list[dict[str, Any]]:
        iam = self._client("iam")
        account_id = self.caller_identity().get("Account", "")
        out: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                name = str(role.get("RoleName", ""))
                arn = str(role.get("Arn") or "")
                if not arn and name:
                    arn = f"arn:aws:iam::{account_id}:role/{name}"
                attached: list[dict[str, Any]] = []
                try:
                    for apage in iam.get_paginator("list_attached_role_policies").paginate(
                        RoleName=name
                    ):
                        for pol in apage.get("AttachedPolicies", []):
                            attached.append(
                                {
                                    "policy_provider_id": str(pol.get("PolicyArn", "")),
                                    "policy_name": str(pol.get("PolicyName", "")),
                                    "attachment_type": "MANAGED",
                                    "is_inline": False,
                                }
                            )
                except Exception:
                    pass
                try:
                    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                        attached.append(
                            {
                                "policy_provider_id": f"inline:role/{name}/{pname}",
                                "policy_name": str(pname),
                                "attachment_type": "INLINE",
                                "is_inline": True,
                            }
                        )
                except Exception:
                    pass
                trust_policy = role.get("AssumeRolePolicyDocument")
                out.append(
                    {
                        "provider_id": arn,
                        "display_name": name or arn,
                        "account_id": account_id,
                        "attached_policies": attached,
                        "trust_policy": trust_policy,
                        "is_human": False,
                        "is_federated": False,
                    }
                )
        return out

    def list_iam_groups(self) -> list[dict[str, Any]]:
        iam = self._client("iam")
        account_id = self.caller_identity().get("Account", "")
        out: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_groups").paginate():
            for group in page.get("Groups", []):
                name = str(group.get("GroupName", ""))
                arn = str(group.get("Arn") or "")
                if not arn and name:
                    arn = f"arn:aws:iam::{account_id}:group/{name}"
                attached: list[dict[str, Any]] = []
                try:
                    for apage in iam.get_paginator("list_attached_group_policies").paginate(
                        GroupName=name
                    ):
                        for pol in apage.get("AttachedPolicies", []):
                            attached.append(
                                {
                                    "policy_provider_id": str(pol.get("PolicyArn", "")),
                                    "policy_name": str(pol.get("PolicyName", "")),
                                    "attachment_type": "MANAGED",
                                    "is_inline": False,
                                }
                            )
                except Exception:
                    pass
                try:
                    for pname in iam.list_group_policies(GroupName=name).get("PolicyNames", []):
                        attached.append(
                            {
                                "policy_provider_id": f"inline:group/{name}/{pname}",
                                "policy_name": str(pname),
                                "attachment_type": "INLINE",
                                "is_inline": True,
                            }
                        )
                except Exception:
                    pass
                out.append(
                    {
                        "provider_id": arn,
                        "display_name": name or arn,
                        "account_id": account_id,
                        "attached_policies": attached,
                        "is_human": False,
                        "is_federated": False,
                    }
                )
        return out

    def list_managed_policies(self) -> list[dict[str, Any]]:
        iam = self._client("iam")
        account_id = self.caller_identity().get("Account", "")
        out: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for pol in page.get("Policies", []):
                arn = str(pol.get("Arn") or "")
                name = str(pol.get("PolicyName") or arn)
                if not arn:
                    continue
                out.append(
                    {
                        "provider_id": arn,
                        "display_name": name,
                        "account_id": account_id,
                        "attached_policies": [],
                        "is_human": False,
                        "is_federated": False,
                    }
                )
        return out


_LISTERS: dict[
    CloudAssetType,
    tuple[str, Callable[[AwsDiscoveryClient, str], list[dict[str, Any]]]],
] = {
    CloudAssetType.EC2_INSTANCE: ("list_ec2_instances", lambda c, r: c.list_ec2_instances(r)),
    CloudAssetType.S3_BUCKET: ("list_s3_buckets", lambda c, r: c.list_s3_buckets(r)),
    CloudAssetType.RDS_INSTANCE: ("list_rds_instances", lambda c, r: c.list_rds_instances(r)),
    CloudAssetType.VPC: ("list_vpcs", lambda c, r: c.list_vpcs(r)),
    CloudAssetType.SECURITY_GROUP: ("list_security_groups", lambda c, r: c.list_security_groups(r)),
    CloudAssetType.LAMBDA_FUNCTION: (
        "list_lambda_functions",
        lambda c, r: c.list_lambda_functions(r),
    ),
    CloudAssetType.EKS_CLUSTER: ("list_eks_clusters", lambda c, r: c.list_eks_clusters(r)),
    CloudAssetType.ECR_REPOSITORY: (
        "list_ecr_repositories",
        lambda c, r: c.list_ecr_repositories(r),
    ),
    CloudAssetType.ROUTE53_ZONE: ("list_route53_zones", lambda c, r: c.list_route53_zones(r)),
    CloudAssetType.CLOUDFRONT_DISTRIBUTION: (
        "list_cloudfront_distributions",
        lambda c, r: c.list_cloudfront_distributions(r),
    ),
    CloudAssetType.KMS_KEY: ("list_kms_keys", lambda c, r: c.list_kms_keys(r)),
    CloudAssetType.SECRETS_MANAGER_SECRET: (
        "list_secrets_manager_secrets",
        lambda c, r: c.list_secrets_manager_secrets(r),
    ),
}

_GLOBAL_TYPES = frozenset(
    {
        CloudAssetType.ROUTE53_ZONE,
        CloudAssetType.CLOUDFRONT_DISTRIBUTION,
        CloudAssetType.S3_BUCKET,
    }
)


class AWSCloudProviderAdapter:
    """CloudProviderAdapter for AWS using an injectable discovery client."""

    def __init__(self, client: AwsDiscoveryClient) -> None:
        self._client = client

    async def discover_accounts(self, credential: CloudCredential) -> list[DiscoveredAccount]:
        del credential
        org_accounts = self._client.list_organization_accounts()
        if org_accounts:
            return [
                DiscoveredAccount(
                    external_id=str(a.get("id", "")),
                    display_name=str(a.get("name") or a.get("id", "")),
                    account_type=(
                        CloudAccountType.ROOT
                        if a.get("id") == self._client.caller_identity().get("Account")
                        else CloudAccountType.MEMBER
                    ),
                    metadata={
                        k: str(v)
                        for k, v in a.items()
                        if k in {"status", "email"} and v is not None
                    },
                )
                for a in org_accounts
                if a.get("id")
            ]
        identity = self._client.caller_identity()
        account_id = identity.get("Account", "")
        return [
            DiscoveredAccount(
                external_id=account_id,
                display_name=f"AWS Account {account_id}",
                account_type=CloudAccountType.STANDALONE,
                metadata={"arn": identity.get("Arn", "")},
            )
        ]

    def list_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]:
        return self._iter_assets(account, asset_types)

    async def _iter_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]:
        regions = [r.region_code for r in account.regions] or self._client.list_regions()
        emitted_global: set[tuple[CloudAssetType, str]] = set()
        for asset_type in asset_types:
            if asset_type not in _LISTERS:
                continue
            _, lister = _LISTERS[asset_type]
            region_iter = ["global"] if asset_type in _GLOBAL_TYPES else regions
            for region in region_iter:
                lookup_region = regions[0] if region == "global" and regions else region
                for item in lister(self._client, lookup_region):
                    provider_id = str(item.get("provider_id") or "")
                    if not provider_id:
                        continue
                    if asset_type in _GLOBAL_TYPES:
                        key = (asset_type, provider_id)
                        if key in emitted_global:
                            continue
                        emitted_global.add(key)
                    display_name = str(item.get("display_name") or provider_id)
                    region_code = (
                        str(item.get("region"))
                        if item.get("region")
                        else (None if region == "global" else region)
                    )
                    yield RawAsset(
                        provider_id=provider_id,
                        asset_type=asset_type,
                        region_code=region_code,
                        display_name=display_name,
                        payload=dict(item),
                    )

    def list_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]:
        return self._iter_iam_principals(account)

    async def _iter_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]:
        account_id = account.external_id
        emitters: list[tuple[str, list[dict[str, Any]]]] = [
            ("USER", self._client.list_iam_users()),
            ("ROLE", self._client.list_iam_roles()),
            ("GROUP", self._client.list_iam_groups()),
            ("POLICY", self._client.list_managed_policies()),
        ]
        for principal_type, items in emitters:
            for item in items:
                provider_id = str(item.get("provider_id") or "")
                if not provider_id:
                    continue
                payload = dict(item)
                payload.setdefault("account_id", account_id)
                payload["provider_id"] = provider_id
                yield RawIAMPrincipal(
                    provider_id=provider_id,
                    principal_type=principal_type,
                    display_name=str(item.get("display_name") or provider_id),
                    payload=payload,
                )

    def ingest_runtime_events(
        self, account: CloudAccount, since: datetime
    ) -> AsyncIterator[RawRuntimeEvent]:
        del account, since
        return empty_async_iterator()

    def describe_k8s_clusters(self, account: CloudAccount) -> AsyncIterator[RawK8sCluster]:
        del account
        return empty_async_iterator()

    def list_ai_services(self, account: CloudAccount) -> AsyncIterator[RawAIService]:
        del account
        return empty_async_iterator()
