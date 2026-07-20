"""Normalize raw Kubernetes inventory dicts into domain aggregates."""

from __future__ import annotations

from typing import Any, cast

from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.entities import (
    NetworkRule,
    PodContainer,
    RBACBinding,
    ServiceAccountReference,
    VolumeMount,
)
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode
from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
from redforge.domain.cloud_security.kubernetes.service import KubernetesService
from redforge.domain.cloud_security.kubernetes.value_objects import (
    ClusterId,
    ContainerImage,
    K8sClusterType,
    ResourceLimits,
    ResourceRequests,
    WorkloadExposure,
    WorkloadKind,
)
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    OrganizationId,
)

_WORKLOAD_KINDS = {
    "deployment": WorkloadKind.DEPLOYMENT,
    "statefulset": WorkloadKind.STATEFULSET,
    "daemonset": WorkloadKind.DAEMONSET,
    "replicaset": WorkloadKind.REPLICASET,
    "job": WorkloadKind.JOB,
    "cronjob": WorkloadKind.CRONJOB,
    "pod": WorkloadKind.POD,
}


def _as_dict(value: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []



class NormalizedInventory:
    """Container for normalized domain objects from a single inventory sync."""

    def __init__(self) -> None:
        self.cluster: KubernetesCluster | None = None
        self.namespaces: list[KubernetesNamespace] = []
        self.workloads: list[KubernetesWorkload] = []
        self.nodes: list[KubernetesNode] = []
        self.services: list[KubernetesService] = []
        self.rbac_principals: list[KubernetesRBACPrincipal] = []
        self.network_policies: list[KubernetesNetworkPolicy] = []
        self.admission_policies: list[KubernetesAdmissionPolicy] = []
        self.metadata_only: list[dict[str, Any]] = []
        self.ingress_exposure: dict[str, str] = {}


class KubernetesNormalizationService:
    """Converts raw inventory dicts → domain aggregates (no k8s SDK types)."""

    def normalize_cluster(
        self,
        info: dict[str, Any],
        *,
        organization_id: OrganizationId,
        cloud_account_id: CloudAccountId,
        cloud_asset_id: CloudAssetId | None = None,
        credential_ref_id: str = "",
        cluster_id: ClusterId | None = None,
    ) -> KubernetesCluster:
        ctype_raw = str(info.get("cluster_type") or info.get("type") or "SELF_MANAGED")
        try:
            ctype = K8sClusterType(ctype_raw.upper())
        except ValueError:
            ctype = K8sClusterType.SELF_MANAGED
        labels = _as_dict(info.get("labels"))
        pss = _as_dict(info.get("pod_security_standards"))
        return KubernetesCluster.discover(
            organization_id=organization_id,
            cloud_account_id=cloud_account_id,
            cluster_type=ctype,
            name=str(info.get("name") or "unnamed-cluster"),
            version=str(info.get("version") or info.get("kubernetes_version") or ""),
            api_server_endpoint=str(info.get("api_server_endpoint") or info.get("endpoint") or ""),
            region=str(info.get("region") or ""),
            credential_ref_id=credential_ref_id or str(info.get("credential_ref_id") or ""),
            cloud_asset_id=cloud_asset_id,
            labels={str(k): str(v) for k, v in labels.items()},
            pod_security_standards={str(k): str(v) for k, v in pss.items()},
            cluster_id=cluster_id,
        )

    def normalize_resources(
        self,
        resources: list[dict[str, Any]],
        *,
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> NormalizedInventory:
        result = NormalizedInventory()
        role_map: dict[str, dict[str, Any]] = {}
        binding_resources: list[dict[str, Any]] = []
        service_accounts: list[dict[str, Any]] = []
        public_services: set[tuple[str, str]] = set()

        for resource in resources:
            kind = str(resource.get("kind") or "").strip()
            kind_l = kind.lower()
            if kind_l == "namespace":
                ns = self._normalize_namespace(resource, cluster_id, organization_id)
                if ns is not None:
                    result.namespaces.append(ns)
            elif kind_l in _WORKLOAD_KINDS:
                wl = self._normalize_workload(resource, cluster_id, organization_id)
                if wl is not None:
                    result.workloads.append(wl)
            elif kind_l == "node":
                node = self._normalize_node(resource, cluster_id, organization_id)
                if node is not None:
                    result.nodes.append(node)
            elif kind_l == "service":
                svc = self._normalize_service(resource, cluster_id, organization_id)
                if svc is not None:
                    result.services.append(svc)
                    if svc.is_public:
                        public_services.add((svc.namespace, svc.name))
            elif kind_l == "ingress":
                self._record_ingress(resource, result)
            elif kind_l == "networkpolicy":
                np = self._normalize_network_policy(resource, cluster_id, organization_id)
                if np is not None:
                    result.network_policies.append(np)
            elif kind_l in {"role", "clusterrole"}:
                key = f"{kind_l}:{resource.get('metadata', {}).get('name', '')}"
                role_map[key] = resource
            elif kind_l in {"rolebinding", "clusterrolebinding"}:
                binding_resources.append(resource)
            elif kind_l == "serviceaccount":
                service_accounts.append(resource)
            elif kind_l in {
                "configmap",
                "secret",
                "persistentvolume",
                "persistentvolumeclaim",
                "poddisruptionbudget",
                "horizontalpodautoscaler",
            }:
                result.metadata_only.append(self._metadata_only(resource))
            elif kind_l in {"validatingwebhookconfiguration", "mutatingwebhookconfiguration"}:
                adm = self._normalize_admission(resource, cluster_id, organization_id)
                if adm is not None:
                    result.admission_policies.append(adm)

        result.rbac_principals = self._normalize_rbac(
            bindings=binding_resources,
            roles=role_map,
            service_accounts=service_accounts,
            cluster_id=cluster_id,
            organization_id=organization_id,
        )

        # Mark workload exposure from public services / ingress.
        for wl in result.workloads:
            if (wl.namespace, wl.name) in public_services or result.ingress_exposure.get(
                f"{wl.namespace}/{wl.name}"
            ):
                wl.exposure = WorkloadExposure.PUBLIC

        np_namespaces = {p.namespace for p in result.network_policies}
        for ns in result.namespaces:
            if ns.name in np_namespaces:
                ns.mark_network_policy(True)

        return result

    def _meta(self, resource: dict[str, Any]) -> dict[str, Any]:
        return _as_dict(resource.get("metadata"))

    def _labels(self, meta: dict[str, Any]) -> dict[str, str]:
        labels = _as_dict(meta.get("labels"))
        return {str(k): str(v) for k, v in labels.items()}

    def _annotations(self, meta: dict[str, Any]) -> dict[str, str]:
        annotations = _as_dict(meta.get("annotations"))
        return {str(k): str(v) for k, v in annotations.items()}

    def _metadata_only(self, resource: dict[str, Any]) -> dict[str, Any]:
        meta = self._meta(resource)
        return {
            "kind": str(resource.get("kind") or ""),
            "name": str(meta.get("name") or ""),
            "namespace": str(meta.get("namespace") or ""),
            "uid": str(meta.get("uid") or ""),
            "labels": self._labels(meta),
        }

    def _normalize_namespace(
        self,
        resource: dict[str, Any],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> KubernetesNamespace | None:
        meta = self._meta(resource)
        name = str(meta.get("name") or "").strip()
        if not name:
            return None
        labels = self._labels(meta)
        annotations = self._annotations(meta)
        pss = annotations.get("pod-security.kubernetes.io/enforce", "UNKNOWN")
        return KubernetesNamespace.discover(
            cluster_id=cluster_id,
            organization_id=organization_id,
            name=name,
            labels=labels,
            annotations=annotations,
            pod_security_level=pss,
        )

    def _pod_spec(self, resource: dict[str, Any]) -> dict[str, Any]:
        kind = str(resource.get("kind") or "").lower()
        spec = _as_dict(resource.get("spec"))
        if kind == "pod":
            return spec
        if kind == "cronjob":
            job_template = _as_dict(spec.get("jobTemplate"))
            job_spec = _as_dict(job_template.get("spec"))
            template = _as_dict(job_spec.get("template"))
            return _as_dict(template.get("spec"))
        template = _as_dict(spec.get("template"))
        return _as_dict(template.get("spec"))

    def _parse_container(self, raw: dict[str, Any]) -> PodContainer:
        security = (
            _as_dict(raw.get("securityContext"))
        )
        caps = (
            _as_dict(security.get("capabilities"))
        )
        resources = _as_dict(raw.get("resources"))
        requests = _as_dict(resources.get("requests"))
        limits = _as_dict(resources.get("limits"))
        mounts_raw = _as_list(raw.get("volumeMounts"))
        mounts: list[VolumeMount] = []
        for m in mounts_raw:
            if isinstance(m, dict):
                mounts.append(
                    VolumeMount(
                        name=str(m.get("name") or ""),
                        mount_path=str(m.get("mountPath") or ""),
                        read_only=bool(m.get("readOnly", False)),
                        host_path="",
                    )
                )
        env_from = _as_list(raw.get("envFrom"))
        env_from_secret = any(isinstance(e, dict) and "secretRef" in e for e in env_from)
        image_raw = str(raw.get("image") or "unknown:latest")
        try:
            image = ContainerImage.parse(image_raw)
        except ValueError:
            image = ContainerImage(repository="unknown", tag="latest")
        return PodContainer(
            name=str(raw.get("name") or "container"),
            image=image,
            privileged=bool(security.get("privileged", False)),
            allow_privilege_escalation=bool(security.get("allowPrivilegeEscalation", True)),
            read_only_root_filesystem=bool(security.get("readOnlyRootFilesystem", False)),
            run_as_non_root=bool(security.get("runAsNonRoot", False)),
            run_as_user=int(security["runAsUser"])
            if security.get("runAsUser") is not None
            else None,
            capabilities_add=tuple(str(x) for x in (caps.get("add") or [])),
            capabilities_drop=tuple(str(x) for x in (caps.get("drop") or [])),
            image_pull_policy=str(raw.get("imagePullPolicy") or "IfNotPresent"),
            requests=ResourceRequests.from_dict(
                {str(k): str(v) for k, v in requests.items()} if requests else None
            ),
            limits=ResourceLimits.from_dict(
                {str(k): str(v) for k, v in limits.items()} if limits else None
            ),
            volume_mounts=tuple(mounts),
            env_from_secret=env_from_secret,
        )

    def _normalize_workload(
        self,
        resource: dict[str, Any],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> KubernetesWorkload | None:
        meta = self._meta(resource)
        name = str(meta.get("name") or "").strip()
        namespace = str(meta.get("namespace") or "default").strip()
        kind_l = str(resource.get("kind") or "").lower()
        if not name or kind_l not in _WORKLOAD_KINDS:
            return None
        pod_spec = self._pod_spec(resource)
        containers_raw = (
            _as_list(pod_spec.get("containers"))
        )
        containers = [self._parse_container(c) for c in containers_raw if isinstance(c, dict)]
        sa_name = str(
            pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount") or "default"
        )
        spec = _as_dict(resource.get("spec"))
        replicas = int(spec.get("replicas") or 1)
        return KubernetesWorkload.discover(
            cluster_id=cluster_id,
            organization_id=organization_id,
            namespace=namespace,
            name=name,
            kind=_WORKLOAD_KINDS[kind_l],
            uid=str(meta.get("uid") or ""),
            service_account=ServiceAccountReference(name=sa_name, namespace=namespace),
            containers=containers,
            host_network=bool(pod_spec.get("hostNetwork", False)),
            host_pid=bool(pod_spec.get("hostPID", False)),
            host_ipc=bool(pod_spec.get("hostIPC", False)),
            labels=self._labels(meta),
            annotations=self._annotations(meta),
            replicas=replicas,
            exposure=WorkloadExposure.CLUSTER_LOCAL,
        )

    def _normalize_node(
        self,
        resource: dict[str, Any],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> KubernetesNode | None:
        meta = self._meta(resource)
        name = str(meta.get("name") or "").strip()
        if not name:
            return None
        status = _as_dict(resource.get("status"))
        node_info = _as_dict(status.get("nodeInfo"))
        labels = self._labels(meta)
        roles = [
            key.removeprefix("node-role.kubernetes.io/")
            for key in labels
            if key.startswith("node-role.kubernetes.io/")
        ]
        spec = _as_dict(resource.get("spec"))
        taints_raw = _as_list(spec.get("taints"))
        taints = [
            f"{t.get('key', '')}={t.get('value', '')}:{t.get('effect', '')}"
            for t in taints_raw
            if isinstance(t, dict)
        ]
        return KubernetesNode.discover(
            cluster_id=cluster_id,
            organization_id=organization_id,
            name=name,
            uid=str(meta.get("uid") or ""),
            kubelet_version=str(node_info.get("kubeletVersion") or ""),
            os_image=str(node_info.get("osImage") or ""),
            container_runtime=str(node_info.get("containerRuntimeVersion") or ""),
            roles=roles,
            labels=labels,
            taints=taints,
            unschedulable=bool(spec.get("unschedulable", False)),
        )

    def _normalize_service(
        self,
        resource: dict[str, Any],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> KubernetesService | None:
        meta = self._meta(resource)
        name = str(meta.get("name") or "").strip()
        namespace = str(meta.get("namespace") or "default").strip()
        if not name:
            return None
        spec = _as_dict(resource.get("spec"))
        status = _as_dict(resource.get("status"))
        lb = _as_dict(status.get("loadBalancer"))
        ingress = _as_list(lb.get("ingress"))
        lb_hosts: list[str] = []
        for item in ingress:
            if isinstance(item, dict):
                host = str(item.get("hostname") or item.get("ip") or "")
                if host:
                    lb_hosts.append(host)
        ports_raw = _as_list(spec.get("ports"))
        ports = [
            {
                "name": str(p.get("name") or ""),
                "port": p.get("port"),
                "protocol": str(p.get("protocol") or "TCP"),
                "targetPort": p.get("targetPort"),
            }
            for p in ports_raw
            if isinstance(p, dict)
        ]
        selector = _as_dict(spec.get("selector"))
        return KubernetesService.discover(
            cluster_id=cluster_id,
            organization_id=organization_id,
            namespace=namespace,
            name=name,
            service_type=str(spec.get("type") or "ClusterIP"),
            cluster_ip=str(spec.get("clusterIP") or ""),
            external_ips=[str(x) for x in (spec.get("externalIPs") or [])],
            load_balancer_ingress=lb_hosts,
            ports=ports,
            selector={str(k): str(v) for k, v in selector.items()},
        )

    def _record_ingress(self, resource: dict[str, Any], result: NormalizedInventory) -> None:
        meta = self._meta(resource)
        namespace = str(meta.get("namespace") or "default")
        spec = _as_dict(resource.get("spec"))
        rules = _as_list(spec.get("rules"))
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            http = _as_dict(rule.get("http"))
            paths = _as_list(http.get("paths"))
            for path in paths:
                if not isinstance(path, dict):
                    continue
                backend = _as_dict(path.get("backend"))
                svc = _as_dict(backend.get("service"))
                svc_name = str(svc.get("name") or "")
                if svc_name:
                    result.ingress_exposure[f"{namespace}/{svc_name}"] = "PUBLIC"
        result.metadata_only.append(self._metadata_only(resource))

    def _normalize_network_policy(
        self,
        resource: dict[str, Any],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> KubernetesNetworkPolicy | None:
        meta = self._meta(resource)
        name = str(meta.get("name") or "").strip()
        namespace = str(meta.get("namespace") or "default").strip()
        if not name:
            return None
        spec = _as_dict(resource.get("spec"))
        pod_sel = _as_dict(spec.get("podSelector"))
        pod_selector = _as_dict(pod_sel.get("matchLabels"))
        policy_types = [str(x) for x in (spec.get("policyTypes") or ["Ingress"])]
        ingress_rules = self._parse_net_rules(spec.get("ingress"), "ingress")
        egress_rules = self._parse_net_rules(spec.get("egress"), "egress")
        allows_cross = any(
            "namespace" in p.lower() for r in ingress_rules + egress_rules for p in r.peers
        )
        return KubernetesNetworkPolicy.discover(
            cluster_id=cluster_id,
            organization_id=organization_id,
            namespace=namespace,
            name=name,
            pod_selector={str(k): str(v) for k, v in pod_selector.items()},
            policy_types=policy_types,
            ingress_rules=ingress_rules,
            egress_rules=egress_rules,
            allows_cross_namespace=allows_cross,
        )

    def _parse_net_rules(self, raw: Any, direction: str) -> list[NetworkRule]:
        if not isinstance(raw, list):
            return []
        rules: list[NetworkRule] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            peers: list[str] = []
            from_or_to = _as_list(item.get("from") or item.get("to"))
            for peer in from_or_to:
                if isinstance(peer, dict):
                    if "namespaceSelector" in peer:
                        peers.append("namespaceSelector")
                    if "podSelector" in peer:
                        peers.append("podSelector")
                    if "ipBlock" in peer:
                        cidr = str(_as_dict(peer.get("ipBlock")).get("cidr", ""))
                        peers.append(f"ipBlock:{cidr}")
            ports_raw = _as_list(item.get("ports"))
            ports = [
                f"{p.get('protocol', 'TCP')}/{p.get('port', '*')}"
                for p in ports_raw
                if isinstance(p, dict)
            ]
            rules.append(NetworkRule(direction=direction, peers=tuple(peers), ports=tuple(ports)))
        return rules

    def _normalize_admission(
        self,
        resource: dict[str, Any],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> KubernetesAdmissionPolicy | None:
        meta = self._meta(resource)
        name = str(meta.get("name") or "").strip()
        if not name:
            return None
        kind = str(resource.get("kind") or "")
        webhooks = _as_list(resource.get("webhooks"))
        rules: list[dict[str, object]] = []
        for wh in webhooks:
            if isinstance(wh, dict):
                rules.append(
                    {
                        "name": str(wh.get("name") or ""),
                        "failurePolicy": str(wh.get("failurePolicy") or ""),
                        "sideEffects": str(wh.get("sideEffects") or ""),
                    }
                )
        return KubernetesAdmissionPolicy.register(
            cluster_id=cluster_id,
            organization_id=organization_id,
            name=name,
            mode="ENFORCE",
            controller=kind,
            rules=rules,
        )

    def _normalize_rbac(
        self,
        *,
        bindings: list[dict[str, Any]],
        roles: dict[str, dict[str, Any]],
        service_accounts: list[dict[str, Any]],
        cluster_id: ClusterId,
        organization_id: OrganizationId,
    ) -> list[KubernetesRBACPrincipal]:
        principals: dict[str, KubernetesRBACPrincipal] = {}

        def _ensure(kind: str, name: str, namespace: str) -> KubernetesRBACPrincipal:
            key = f"{kind}:{namespace}:{name}"
            if key not in principals:
                principals[key] = KubernetesRBACPrincipal.discover(
                    cluster_id=cluster_id,
                    organization_id=organization_id,
                    kind=kind,
                    name=name,
                    namespace=namespace,
                )
            return principals[key]

        for sa in service_accounts:
            meta = self._meta(sa)
            name = str(meta.get("name") or "").strip()
            namespace = str(meta.get("namespace") or "default")
            if name:
                _ensure("SERVICE_ACCOUNT", name, namespace)

        for binding in bindings:
            meta = self._meta(binding)
            binding_name = str(meta.get("name") or "")
            binding_ns = str(meta.get("namespace") or "")
            binding_kind = str(binding.get("kind") or "")
            spec = binding  # RoleBinding uses top-level roleRef/subjects
            role_ref = _as_dict(spec.get("roleRef"))
            role_ref_kind = str(role_ref.get("kind") or "")
            role_ref_name = str(role_ref.get("name") or "")
            subjects = _as_list(spec.get("subjects"))
            verbs: list[str] = []
            resources_list: list[str] = []
            api_groups: list[str] = []
            role_key = f"{role_ref_kind.lower()}:{role_ref_name}"
            role_res = roles.get(role_key)
            if role_res is not None:
                role_spec = _as_list(role_res.get("rules"))
                for rule in role_spec:
                    if isinstance(rule, dict):
                        verbs.extend(str(v) for v in (rule.get("verbs") or []))
                        resources_list.extend(str(r) for r in (rule.get("resources") or []))
                        api_groups.extend(str(g) for g in (rule.get("apiGroups") or []))

            subject_dicts: list[dict[str, str]] = []
            for subj in subjects:
                if not isinstance(subj, dict):
                    continue
                skind = (
                    str(subj.get("kind") or "").upper().replace("SERVICEACCOUNT", "SERVICE_ACCOUNT")
                )
                sname = str(subj.get("name") or "")
                sns = str(subj.get("namespace") or binding_ns)
                if not sname:
                    continue
                if skind not in {"USER", "GROUP", "SERVICE_ACCOUNT"}:
                    skind = "USER"
                subject_dicts.append({"kind": skind, "name": sname, "namespace": sns})
                principal = _ensure(skind, sname, sns)
                rb = RBACBinding(
                    binding_name=binding_name,
                    binding_kind=binding_kind,
                    role_ref_kind=role_ref_kind,
                    role_ref_name=role_ref_name,
                    subjects=tuple(subject_dicts),
                    namespace=binding_ns,
                    verbs=tuple(verbs),
                    resources=tuple(resources_list),
                    api_groups=tuple(api_groups),
                )
                # Rebuild principal with accumulated bindings/roles (immutable-ish update)
                roles_list = list(principal.roles)
                cluster_roles_list = list(principal.cluster_roles)
                if role_ref_kind.lower() == "clusterrole":
                    if role_ref_name not in cluster_roles_list:
                        cluster_roles_list.append(role_ref_name)
                elif role_ref_name and role_ref_name not in roles_list:
                    roles_list.append(role_ref_name)
                bindings_list = [*list(principal.bindings), rb]
                principals[f"{skind}:{sns}:{sname}"] = KubernetesRBACPrincipal(
                    id=principal.id,
                    cluster_id=principal.cluster_id,
                    organization_id=principal.organization_id,
                    kind=principal.kind,
                    name=principal.name,
                    namespace=principal.namespace,
                    bindings=tuple(bindings_list),
                    roles=tuple(roles_list),
                    cluster_roles=tuple(cluster_roles_list),
                    trust_references=principal.trust_references,
                    created_at=principal.created_at,
                    updated_at=principal.updated_at,
                    row_version=principal.row_version,
                    _pending_events=list(principal._pending_events),
                )

        return list(principals.values())
