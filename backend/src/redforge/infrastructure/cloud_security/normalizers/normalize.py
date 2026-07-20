"""Table-driven RawAsset → NormalizedAssetDraft normalizers for Phase 2 types."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from redforge.domain.cloud_security.cloud_asset import relationship
from redforge.domain.cloud_security.entities import AssetRelationship
from redforge.domain.cloud_security.ports import RawAsset
from redforge.domain.cloud_security.value_objects import (
    CloudAssetRelationshipType,
    CloudAssetType,
    NetworkExposure,
    NormalizedConfig,
)
from redforge.infrastructure.cloud_security.normalizers.types import NormalizedAssetDraft

_SCHEMA_VERSION = "1"

NormalizerFn = Callable[[RawAsset], NormalizedAssetDraft]


def _str(value: object | None, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _optional_str(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bool(value: object | None) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return None


def _parse_tags(raw: object | None) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        tags: dict[str, str] = {}
        for item in raw:
            if not isinstance(item, dict):
                continue
            key = item.get("Key", item.get("key", item.get("name")))
            value = item.get("Value", item.get("value"))
            if key is not None and value is not None:
                tags[str(key)] = str(value)
        return tags
    return {}


def _string_list(raw: object | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(x) for x in raw if x is not None)
    return ()


def _sg_ids(payload: dict[str, Any]) -> tuple[str, ...]:
    if "security_group_ids" in payload:
        return _string_list(payload.get("security_group_ids"))
    groups = payload.get("security_groups") or payload.get("SecurityGroups") or []
    if not isinstance(groups, list):
        return ()
    ids: list[str] = []
    for item in groups:
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict):
            gid = item.get("GroupId") or item.get("group_id") or item.get("id")
            if gid is not None:
                ids.append(str(gid))
    return tuple(ids)


def _attrs(**kwargs: object) -> tuple[tuple[str, str], ...]:
    return tuple((k, str(v)) for k, v in kwargs.items() if v is not None)


def _rel(
    relationship_type: CloudAssetRelationshipType, target_provider_id: str | None
) -> AssetRelationship | None:
    if not target_provider_id:
        return None
    return relationship(
        relationship_type=relationship_type,
        target_provider_id=target_provider_id,
    )


def _exposure_from_public(is_public: bool | None) -> NetworkExposure:
    if is_public is True:
        return NetworkExposure.PUBLIC
    if is_public is False:
        return NetworkExposure.PRIVATE
    return NetworkExposure.UNKNOWN


def _draft(
    raw: RawAsset,
    *,
    resource_class: str,
    state: str | None = None,
    network_exposure: NetworkExposure = NetworkExposure.UNKNOWN,
    encryption_at_rest: bool | None = None,
    public_endpoints: tuple[str, ...] = (),
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    security_group_ids: tuple[str, ...] = (),
    kms_key_id: str | None = None,
    iam_role_arn: str | None = None,
    attributes: tuple[tuple[str, str], ...] = (),
    relationships: list[AssetRelationship] | None = None,
    az_name: str | None = None,
    region_code: str | None = None,
    tags: dict[str, str] | None = None,
    provider_metadata: dict[str, object] | None = None,
) -> NormalizedAssetDraft:
    payload = raw.payload
    return NormalizedAssetDraft(
        asset_type=raw.asset_type,
        provider_id=raw.provider_id,
        display_name=raw.display_name or raw.provider_id,
        region_code=region_code or raw.region_code or "global",
        az_name=az_name,
        tags=tags if tags is not None else _parse_tags(payload.get("tags") or payload.get("Tags")),
        provider_metadata=provider_metadata if provider_metadata is not None else dict(payload),
        normalized_config=NormalizedConfig(
            schema_version=_SCHEMA_VERSION,
            resource_class=resource_class,
            state=state,
            network_exposure=network_exposure,
            encryption_at_rest=encryption_at_rest,
            public_endpoints=public_endpoints,
            vpc_id=vpc_id,
            subnet_ids=subnet_ids,
            security_group_ids=security_group_ids,
            kms_key_id=kms_key_id,
            iam_role_arn=iam_role_arn,
            attributes=attributes,
        ),
        relationships=list(relationships or []),
    )


def _normalize_ec2(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vpc_id = _optional_str(p.get("vpc_id") or p.get("VpcId"))
    sg_ids = _sg_ids(p)
    public_ip = _optional_str(p.get("public_ip") or p.get("PublicIpAddress"))
    state_raw = p.get("state")
    if state_raw is None and isinstance(p.get("State"), dict):
        state_raw = p["State"].get("Name")
    profile = p.get("IamInstanceProfile")
    role_arn = p.get("iam_role_arn")
    if role_arn is None and isinstance(profile, dict):
        role_arn = profile.get("Arn")
    subnet = p.get("SubnetId") or p.get("subnet_id")
    subnet_ids = _string_list(p.get("subnet_ids") or ([subnet] if subnet else None))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, vpc_id),
            *[_rel(CloudAssetRelationshipType.ATTACHED_TO, sg) for sg in sg_ids],
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="compute",
        state=_optional_str(state_raw),
        network_exposure=_exposure_from_public(bool(public_ip) if public_ip else None),
        public_endpoints=(public_ip,) if public_ip else (),
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        security_group_ids=sg_ids,
        iam_role_arn=_optional_str(role_arn),
        attributes=_attrs(
            instance_type=p.get("instance_type") or p.get("InstanceType"),
            platform=p.get("platform") or p.get("Platform"),
        ),
        relationships=rels,
        az_name=_optional_str(
            p.get("az_name") or p.get("AvailabilityZone") or p.get("placement_az")
        ),
    )


def _normalize_s3(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(p.get("kms_key_id") or p.get("KmsKeyId"))
    is_public = _bool(p.get("public") if "public" in p else p.get("is_public"))
    encryption = _bool(p.get("encryption_at_rest"))
    if encryption is None:
        encryption = True if kms or p.get("sse_algorithm") else None
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="storage",
        network_exposure=_exposure_from_public(is_public),
        encryption_at_rest=encryption,
        kms_key_id=kms,
        public_endpoints=(_str(p.get("bucket_domain") or p.get("website_endpoint")),)
        if p.get("bucket_domain") or p.get("website_endpoint")
        else (),
        attributes=_attrs(versioning=p.get("versioning"), sse_algorithm=p.get("sse_algorithm")),
        relationships=rels,
        region_code=raw.region_code
        or _optional_str(p.get("region") or p.get("LocationConstraint"))
        or "global",
    )


def _normalize_rds(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vpc_id = _optional_str(
        p.get("vpc_id") or p.get("VpcId") or p.get("DBSubnetGroup", {}).get("VpcId")
        if isinstance(p.get("DBSubnetGroup"), dict)
        else p.get("vpc_id")
    )
    kms = _optional_str(p.get("kms_key_id") or p.get("KmsKeyId"))
    public = _bool(
        p.get("publicly_accessible") if "publicly_accessible" in p else p.get("PubliclyAccessible")
    )
    sg_ids = _sg_ids(p)
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, vpc_id),
            _rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),
            *[_rel(CloudAssetRelationshipType.ATTACHED_TO, sg) for sg in sg_ids],
        )
        if r is not None
    ]
    endpoint = _optional_str(
        p.get("endpoint")
        or (p.get("Endpoint", {}).get("Address") if isinstance(p.get("Endpoint"), dict) else None)
    )
    return _draft(
        raw,
        resource_class="database",
        state=_optional_str(p.get("state") or p.get("DBInstanceStatus")),
        network_exposure=_exposure_from_public(public),
        encryption_at_rest=_bool(
            p.get("storage_encrypted") if "storage_encrypted" in p else p.get("StorageEncrypted")
        ),
        public_endpoints=(endpoint,) if endpoint else (),
        vpc_id=vpc_id,
        subnet_ids=_string_list(p.get("subnet_ids")),
        security_group_ids=sg_ids,
        kms_key_id=kms,
        attributes=_attrs(
            engine=p.get("engine") or p.get("Engine"),
            engine_version=p.get("engine_version") or p.get("EngineVersion"),
        ),
        relationships=rels,
        az_name=_optional_str(p.get("az_name") or p.get("AvailabilityZone")),
    )


def _normalize_vpc(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    return _draft(
        raw,
        resource_class="network",
        state=_optional_str(p.get("state") or p.get("State")),
        vpc_id=raw.provider_id,
        attributes=_attrs(
            cidr=p.get("cidr") or p.get("CidrBlock"),
            is_default=p.get("is_default") or p.get("IsDefault"),
        ),
    )


def _normalize_sg(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vpc_id = _optional_str(p.get("vpc_id") or p.get("VpcId"))
    rels = [r for r in (_rel(CloudAssetRelationshipType.CONTAINED_IN, vpc_id),) if r is not None]
    return _draft(
        raw,
        resource_class="network",
        vpc_id=vpc_id,
        security_group_ids=(raw.provider_id,),
        attributes=_attrs(group_name=p.get("group_name") or p.get("GroupName")),
        relationships=rels,
    )


def _normalize_lambda(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    role = _optional_str(p.get("role_arn") or p.get("iam_role_arn") or p.get("Role"))
    vpc_id = _optional_str(
        p.get("vpc_id")
        or (p.get("VpcConfig", {}).get("VpcId") if isinstance(p.get("VpcConfig"), dict) else None)
    )
    sg_ids = _sg_ids(p) or _string_list(
        p.get("VpcConfig", {}).get("SecurityGroupIds")
        if isinstance(p.get("VpcConfig"), dict)
        else None
    )
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.USES_IDENTITY, role),
            _rel(CloudAssetRelationshipType.CONTAINED_IN, vpc_id),
            *[_rel(CloudAssetRelationshipType.ATTACHED_TO, sg) for sg in sg_ids],
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="serverless",
        state=_optional_str(p.get("state") or p.get("State")),
        vpc_id=vpc_id,
        subnet_ids=_string_list(
            p.get("subnet_ids")
            or (
                p.get("VpcConfig", {}).get("SubnetIds")
                if isinstance(p.get("VpcConfig"), dict)
                else None
            )
        ),
        security_group_ids=sg_ids,
        iam_role_arn=role,
        kms_key_id=_optional_str(p.get("kms_key_id") or p.get("KMSKeyArn")),
        attributes=_attrs(
            runtime=p.get("runtime") or p.get("Runtime"),
            package_type=p.get("package_type") or p.get("PackageType"),
        ),
        relationships=rels,
    )


def _normalize_eks(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vpc_id = _optional_str(
        p.get("vpc_id")
        or (
            p.get("resourcesVpcConfig", {}).get("vpcId")
            if isinstance(p.get("resourcesVpcConfig"), dict)
            else None
        )
        or (
            p.get("ResourcesVpcConfig", {}).get("VpcId")
            if isinstance(p.get("ResourcesVpcConfig"), dict)
            else None
        )
    )
    role = _optional_str(p.get("role_arn") or p.get("roleArn") or p.get("RoleArn"))
    endpoint = _optional_str(p.get("endpoint") or p.get("Endpoint"))
    public = _bool(p.get("endpoint_public_access") if "endpoint_public_access" in p else None)
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, vpc_id),
            _rel(CloudAssetRelationshipType.USES_IDENTITY, role),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="kubernetes",
        state=_optional_str(
            p.get("status") or p.get("status", {}).get("status")
            if isinstance(p.get("status"), dict)
            else p.get("status")
        ),
        network_exposure=_exposure_from_public(public),
        public_endpoints=(endpoint,) if endpoint else (),
        vpc_id=vpc_id,
        subnet_ids=_string_list(p.get("subnet_ids")),
        security_group_ids=_sg_ids(p),
        iam_role_arn=role,
        attributes=_attrs(version=p.get("version") or p.get("Version")),
        relationships=rels,
    )


def _normalize_ecr(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(
        p.get("kms_key_id") or p.get("encryptionConfiguration", {}).get("kmsKey")
        if isinstance(p.get("encryptionConfiguration"), dict)
        else p.get("kms_key_id")
    )
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="container_registry",
        encryption_at_rest=True if kms or p.get("encryption_type") else None,
        kms_key_id=kms,
        attributes=_attrs(uri=p.get("repository_uri") or p.get("repositoryUri")),
        relationships=rels,
    )


def _normalize_route53(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    return _draft(
        raw,
        resource_class="dns",
        attributes=_attrs(
            private_zone=p.get("private_zone") or p.get("Config", {}).get("PrivateZone")
            if isinstance(p.get("Config"), dict)
            else p.get("private_zone"),
            record_count=p.get("resource_record_set_count") or p.get("ResourceRecordSetCount"),
        ),
        region_code=raw.region_code or "global",
    )


def _normalize_cloudfront(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    domain = _optional_str(p.get("domain_name") or p.get("DomainName"))
    return _draft(
        raw,
        resource_class="cdn",
        state=_optional_str(p.get("status") or p.get("Status")),
        network_exposure=NetworkExposure.PUBLIC,
        public_endpoints=(domain,) if domain else (),
        attributes=_attrs(enabled=p.get("enabled") or p.get("Enabled")),
        region_code=raw.region_code or "global",
    )


def _normalize_kms(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    return _draft(
        raw,
        resource_class="key_management",
        state=_optional_str(p.get("key_state") or p.get("KeyState")),
        encryption_at_rest=True,
        kms_key_id=raw.provider_id,
        attributes=_attrs(
            key_usage=p.get("key_usage") or p.get("KeyUsage"),
            key_manager=p.get("key_manager") or p.get("KeyManager"),
        ),
    )


def _normalize_secrets_manager(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(p.get("kms_key_id") or p.get("KmsKeyId"))
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="secret",
        encryption_at_rest=True,
        kms_key_id=kms,
        attributes=_attrs(rotation_enabled=p.get("rotation_enabled") or p.get("RotationEnabled")),
        relationships=rels,
    )


def _normalize_azure_vm(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vnet = _optional_str(p.get("vnet_id") or p.get("vpc_id"))
    nsg = _optional_str(p.get("nsg_id") or p.get("network_security_group_id"))
    identity = _optional_str(p.get("identity_principal_id") or p.get("managed_identity_id"))
    public_ip = _optional_str(p.get("public_ip"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, vnet),
            _rel(CloudAssetRelationshipType.ATTACHED_TO, nsg),
            _rel(CloudAssetRelationshipType.USES_IDENTITY, identity),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="compute",
        state=_optional_str(p.get("power_state") or p.get("state")),
        network_exposure=_exposure_from_public(
            bool(public_ip) if public_ip else _bool(p.get("public"))
        ),
        public_endpoints=(public_ip,) if public_ip else (),
        vpc_id=vnet,
        subnet_ids=_string_list(
            p.get("subnet_ids") or ([p["subnet_id"]] if p.get("subnet_id") else None)
        ),
        security_group_ids=(nsg,) if nsg else (),
        attributes=_attrs(
            vm_size=p.get("vm_size") or p.get("hardware_profile_vm_size"), os_type=p.get("os_type")
        ),
        relationships=rels,
        az_name=_optional_str(
            p.get("az_name")
            or (p["zones"][0] if isinstance(p.get("zones"), list) and p.get("zones") else None)
        ),
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_vnet(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    return _draft(
        raw,
        resource_class="network",
        vpc_id=raw.provider_id,
        attributes=_attrs(
            address_space=",".join(
                _string_list(p.get("address_prefixes") or p.get("address_space"))
            )
        ),
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_nsg(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vnet = _optional_str(p.get("vnet_id"))
    rels = [r for r in (_rel(CloudAssetRelationshipType.ASSOCIATED_WITH, vnet),) if r is not None]
    return _draft(
        raw,
        resource_class="network",
        vpc_id=vnet,
        security_group_ids=(raw.provider_id,),
        relationships=rels,
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_storage(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(p.get("kms_key_id") or p.get("encryption_key_vault_uri"))
    public = _bool(
        p.get("allow_blob_public_access") if "allow_blob_public_access" in p else p.get("public")
    )
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="storage",
        network_exposure=_exposure_from_public(public),
        encryption_at_rest=_bool(p.get("encryption_at_rest"))
        if "encryption_at_rest" in p
        else True,
        kms_key_id=kms,
        public_endpoints=(_str(p.get("primary_endpoint")),) if p.get("primary_endpoint") else (),
        attributes=_attrs(sku=p.get("sku") or p.get("sku_name"), kind=p.get("kind")),
        relationships=rels,
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_sql(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(p.get("kms_key_id"))
    public = _bool(
        p.get("public_network_access") if "public_network_access" in p else p.get("public")
    )
    if isinstance(p.get("public_network_access"), str):
        public = str(p["public_network_access"]).lower() in {"enabled", "true"}
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="database",
        state=_optional_str(p.get("status") or p.get("state")),
        network_exposure=_exposure_from_public(public),
        encryption_at_rest=True,
        kms_key_id=kms,
        attributes=_attrs(server_name=p.get("server_name"), edition=p.get("edition")),
        relationships=rels,
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_aks(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    vnet = _optional_str(p.get("vnet_id") or p.get("vpc_id"))
    identity = _optional_str(p.get("identity_principal_id") or p.get("cluster_identity"))
    endpoint = _optional_str(p.get("fqdn") or p.get("endpoint"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, vnet),
            _rel(CloudAssetRelationshipType.USES_IDENTITY, identity),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="kubernetes",
        state=_optional_str(p.get("power_state") or p.get("state")),
        network_exposure=_exposure_from_public(_bool(p.get("api_server_public"))),
        public_endpoints=(endpoint,) if endpoint else (),
        vpc_id=vnet,
        subnet_ids=_string_list(p.get("subnet_ids")),
        iam_role_arn=identity,
        attributes=_attrs(kubernetes_version=p.get("kubernetes_version")),
        relationships=rels,
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_keyvault(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    return _draft(
        raw,
        resource_class="key_management",
        network_exposure=_exposure_from_public(_bool(p.get("public_network_access"))),
        encryption_at_rest=True,
        kms_key_id=raw.provider_id,
        public_endpoints=(_str(p.get("vault_uri")),) if p.get("vault_uri") else (),
        attributes=_attrs(sku=p.get("sku")),
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_azure_function(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    identity = _optional_str(p.get("identity_principal_id") or p.get("managed_identity_id"))
    kms = _optional_str(p.get("kms_key_id"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.USES_IDENTITY, identity),
            _rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="serverless",
        state=_optional_str(p.get("state")),
        network_exposure=_exposure_from_public(_bool(p.get("public"))),
        public_endpoints=(_str(p.get("default_hostname")),) if p.get("default_hostname") else (),
        iam_role_arn=identity,
        kms_key_id=kms,
        attributes=_attrs(kind=p.get("kind"), runtime=p.get("runtime")),
        relationships=rels,
        tags=_parse_tags(p.get("tags")),
    )


def _normalize_gcp_compute(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    network = _optional_str(p.get("network") or p.get("vpc_id") or p.get("network_self_link"))
    public_ip = _optional_str(p.get("public_ip") or p.get("nat_ip"))
    sa = _optional_str(p.get("service_account") or p.get("service_account_email"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, network),
            _rel(CloudAssetRelationshipType.USES_IDENTITY, sa),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="compute",
        state=_optional_str(p.get("status") or p.get("state")),
        network_exposure=_exposure_from_public(
            bool(public_ip) if public_ip else _bool(p.get("public"))
        ),
        public_endpoints=(public_ip,) if public_ip else (),
        vpc_id=network,
        subnet_ids=_string_list(
            p.get("subnet_ids") or ([p["subnetwork"]] if p.get("subnetwork") else None)
        ),
        iam_role_arn=sa,
        attributes=_attrs(machine_type=p.get("machine_type"), zone=p.get("zone")),
        relationships=rels,
        az_name=_optional_str(p.get("zone") or p.get("az_name")),
        tags=_parse_tags(p.get("tags") or p.get("labels")),
    )


def _normalize_gcp_vpc(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    return _draft(
        raw,
        resource_class="network",
        vpc_id=raw.provider_id,
        attributes=_attrs(auto_create_subnetworks=p.get("auto_create_subnetworks")),
        tags=_parse_tags(p.get("tags") or p.get("labels")),
        region_code=raw.region_code or "global",
    )


def _normalize_gcp_storage(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(p.get("kms_key_id") or p.get("kms_key_name"))
    public = _bool(p.get("public") if "public" in p else p.get("public_access"))
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="storage",
        network_exposure=_exposure_from_public(public),
        encryption_at_rest=True,
        kms_key_id=kms,
        attributes=_attrs(
            location=p.get("location") or p.get("location_type"),
            storage_class=p.get("storage_class"),
        ),
        relationships=rels,
        tags=_parse_tags(p.get("tags") or p.get("labels")),
        region_code=raw.region_code or _optional_str(p.get("location")) or "global",
    )


def _normalize_gcp_sql(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    network = _optional_str(p.get("network") or p.get("vpc_id") or p.get("private_network"))
    kms = _optional_str(p.get("kms_key_id") or p.get("disk_encryption_key"))
    public = _bool(p.get("public_ip_enabled") if "public_ip_enabled" in p else p.get("public"))
    ip = _optional_str(p.get("public_ip") or p.get("ip_address"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, network),
            _rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="database",
        state=_optional_str(p.get("state") or p.get("status")),
        network_exposure=_exposure_from_public(public),
        encryption_at_rest=True,
        public_endpoints=(ip,) if ip else (),
        vpc_id=network,
        kms_key_id=kms,
        attributes=_attrs(database_version=p.get("database_version"), tier=p.get("tier")),
        relationships=rels,
        tags=_parse_tags(p.get("tags") or p.get("labels")),
    )


def _normalize_gcp_gke(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    network = _optional_str(p.get("network") or p.get("vpc_id"))
    sa = _optional_str(p.get("service_account") or p.get("node_service_account"))
    endpoint = _optional_str(p.get("endpoint"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.CONTAINED_IN, network),
            _rel(CloudAssetRelationshipType.USES_IDENTITY, sa),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="kubernetes",
        state=_optional_str(p.get("status") or p.get("state")),
        network_exposure=_exposure_from_public(_bool(p.get("endpoint_public"))),
        public_endpoints=(endpoint,) if endpoint else (),
        vpc_id=network,
        subnet_ids=_string_list(
            p.get("subnet_ids") or ([p["subnetwork"]] if p.get("subnetwork") else None)
        ),
        iam_role_arn=sa,
        attributes=_attrs(
            current_master_version=p.get("current_master_version") or p.get("version")
        ),
        relationships=rels,
        tags=_parse_tags(p.get("tags") or p.get("labels")),
    )


def _normalize_gcp_secret(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    kms = _optional_str(p.get("kms_key_id") or p.get("kms_key_name"))
    rels = [r for r in (_rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),) if r is not None]
    return _draft(
        raw,
        resource_class="secret",
        encryption_at_rest=True,
        kms_key_id=kms,
        attributes=_attrs(replication=p.get("replication")),
        relationships=rels,
        tags=_parse_tags(p.get("tags") or p.get("labels")),
        region_code=raw.region_code or "global",
    )


def _normalize_gcp_function(raw: RawAsset) -> NormalizedAssetDraft:
    p = raw.payload
    network = _optional_str(p.get("network") or p.get("vpc_id") or p.get("vpc_connector"))
    sa = _optional_str(p.get("service_account") or p.get("service_account_email"))
    kms = _optional_str(p.get("kms_key_id") or p.get("kms_key_name"))
    url = _optional_str(p.get("https_trigger_url") or p.get("url"))
    rels = [
        r
        for r in (
            _rel(CloudAssetRelationshipType.USES_IDENTITY, sa),
            _rel(CloudAssetRelationshipType.CONTAINED_IN, network),
            _rel(CloudAssetRelationshipType.ENCRYPTED_BY, kms),
        )
        if r is not None
    ]
    return _draft(
        raw,
        resource_class="serverless",
        state=_optional_str(p.get("state") or p.get("status")),
        network_exposure=_exposure_from_public(bool(url) if url else _bool(p.get("public"))),
        public_endpoints=(url,) if url else (),
        vpc_id=network,
        iam_role_arn=sa,
        kms_key_id=kms,
        attributes=_attrs(runtime=p.get("runtime"), entry_point=p.get("entry_point")),
        relationships=rels,
        tags=_parse_tags(p.get("tags") or p.get("labels")),
    )


def _normalize_unknown(raw: RawAsset) -> NormalizedAssetDraft:
    return _draft(
        raw,
        resource_class="unknown",
        attributes=_attrs(raw_asset_type=raw.asset_type.value),
    )


_HANDLERS: dict[CloudAssetType, NormalizerFn] = {
    CloudAssetType.EC2_INSTANCE: _normalize_ec2,
    CloudAssetType.S3_BUCKET: _normalize_s3,
    CloudAssetType.RDS_INSTANCE: _normalize_rds,
    CloudAssetType.VPC: _normalize_vpc,
    CloudAssetType.SECURITY_GROUP: _normalize_sg,
    CloudAssetType.LAMBDA_FUNCTION: _normalize_lambda,
    CloudAssetType.EKS_CLUSTER: _normalize_eks,
    CloudAssetType.ECR_REPOSITORY: _normalize_ecr,
    CloudAssetType.ROUTE53_ZONE: _normalize_route53,
    CloudAssetType.CLOUDFRONT_DISTRIBUTION: _normalize_cloudfront,
    CloudAssetType.KMS_KEY: _normalize_kms,
    CloudAssetType.SECRETS_MANAGER_SECRET: _normalize_secrets_manager,
    CloudAssetType.AZURE_VM: _normalize_azure_vm,
    CloudAssetType.AZURE_VNET: _normalize_azure_vnet,
    CloudAssetType.AZURE_NSG: _normalize_azure_nsg,
    CloudAssetType.AZURE_STORAGE_ACCOUNT: _normalize_azure_storage,
    CloudAssetType.AZURE_SQL_DATABASE: _normalize_azure_sql,
    CloudAssetType.AZURE_AKS_CLUSTER: _normalize_azure_aks,
    CloudAssetType.AZURE_KEYVAULT: _normalize_azure_keyvault,
    CloudAssetType.AZURE_FUNCTION_APP: _normalize_azure_function,
    CloudAssetType.GCP_COMPUTE_INSTANCE: _normalize_gcp_compute,
    CloudAssetType.GCP_VPC_NETWORK: _normalize_gcp_vpc,
    CloudAssetType.GCP_STORAGE_BUCKET: _normalize_gcp_storage,
    CloudAssetType.GCP_CLOUD_SQL: _normalize_gcp_sql,
    CloudAssetType.GCP_GKE_CLUSTER: _normalize_gcp_gke,
    CloudAssetType.GCP_SECRET_MANAGER: _normalize_gcp_secret,
    CloudAssetType.GCP_CLOUD_FUNCTION: _normalize_gcp_function,
}


def normalize_raw_asset(raw: RawAsset) -> NormalizedAssetDraft:
    """Dispatch RawAsset to the Phase 2 normalizer for its asset_type."""
    handler = _HANDLERS.get(raw.asset_type, _normalize_unknown)
    return handler(raw)
