"""GCP API clients and helper functions."""

from google.cloud import compute_v1, container_v1
from google.cloud.resourcemanager_v3 import FoldersClient, ProjectsClient
from google.api_core.exceptions import PermissionDenied, NotFound, Forbidden

from .auth import get_credentials
from .models import FirewallRule


class GCPClients:
    """Singleton holder for GCP API clients. Created once to avoid
    repeated gRPC channel setup (~2-4s per client instantiation)."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        creds = get_credentials()
        self.firewalls = compute_v1.FirewallsClient(credentials=creds)
        self.forwarding_rules = compute_v1.ForwardingRulesClient(credentials=creds)
        self.projects = compute_v1.ProjectsClient(credentials=creds)
        self.gke = container_v1.ClusterManagerClient(credentials=creds)
        self.rm_projects = ProjectsClient(credentials=creds)
        self.rm_folders = FoldersClient(credentials=creds)
        self._credentials = creds
        self._initialized = True


def get_clients() -> GCPClients:
    return GCPClients()


def list_firewall_rules(project: str) -> list[FirewallRule]:
    try:
        rules = []
        for r in get_clients().firewalls.list(project=project):
            allowed = []
            for a in r.allowed:
                proto = a.I_p_protocol
                if a.ports:
                    allowed.extend(f"{proto}:{p}" for p in a.ports)
                else:
                    allowed.append(proto)
            denied = []
            for d in r.denied:
                proto = d.I_p_protocol
                if d.ports:
                    denied.extend(f"{proto}:{p}" for p in d.ports)
                else:
                    denied.append(proto)
            rules.append(FirewallRule(
                name=r.name, project=project,
                direction=r.direction, priority=r.priority,
                source_ranges=list(r.source_ranges),
                allowed=allowed, denied=denied,
                target_tags=list(r.target_tags),
                description=r.description or "",
            ))
        return rules
    except (PermissionDenied, NotFound, Forbidden):
        return []


def list_forwarding_rules(project: str) -> list[dict]:
    try:
        results = []
        for region_name, rules in get_clients().forwarding_rules.aggregated_list(project=project):
            if rules.forwarding_rules:
                for r in rules.forwarding_rules:
                    if r.load_balancing_scheme == "EXTERNAL":
                        region = r.region.split("/")[-1] if r.region else ""
                        results.append({
                            "name": r.name, "ip": r.I_p_address,
                            "ports": r.port_range or "", "region": region,
                        })
        return results
    except (PermissionDenied, NotFound, Forbidden):
        return []


def list_gke_clusters(project: str) -> list[dict]:
    try:
        response = get_clients().gke.list_clusters(parent=f"projects/{project}/locations/-")
        clusters = []
        for c in response.clusters:
            # Collect all unique network tags across node pools
            node_tags = set()
            for np in c.node_pools:
                if np.config and np.config.tags:
                    node_tags.update(np.config.tags)
            clusters.append({
                "name": c.name,
                "location": c.location,
                "version": c.current_master_version,
                "node_tags": list(node_tags),
            })
        return clusters
    except (PermissionDenied, NotFound, Forbidden, Exception):
        return []


def get_project_quota(project: str) -> tuple[int, int]:
    try:
        proj = get_clients().projects.get(project=project)
        for q in proj.quotas:
            if q.metric == "FIREWALLS":
                return int(q.usage), int(q.limit)
    except (PermissionDenied, NotFound, Forbidden):
        pass
    return 0, 0


def classify_project_api(project_id: str) -> tuple[str, str]:
    """Classify project as HOST, SERVICE, or STANDALONE."""
    try:
        proj = get_clients().projects.get(project=project_id)
        if proj.xpn_project_status == "HOST":
            return ("HOST", "")
    except (PermissionDenied, NotFound, Forbidden):
        return ("ERROR", "")

    try:
        xpn_host = get_clients().projects.get_xpn_host(project=project_id)
        if xpn_host and xpn_host.name:
            return ("SERVICE", xpn_host.name)
    except (PermissionDenied, NotFound, Forbidden, Exception):
        pass

    return ("STANDALONE", "")


def get_service_projects_api(host_project: str) -> list[str]:
    try:
        resources = get_clients().projects.get_xpn_resources(project=host_project)
        return [r.id for r in resources if r.type_ == "PROJECT"]
    except (PermissionDenied, NotFound, Forbidden, Exception):
        return []


def list_projects_in_folder_api(folder_id: str, limit: int) -> list[str]:
    try:
        projects = []
        for p in get_clients().rm_projects.list_projects(parent=f"folders/{folder_id}"):
            projects.append(p.project_id)
            if len(projects) >= limit:
                break
        return projects
    except (PermissionDenied, NotFound, Forbidden):
        return []


def list_folders_in_org_api(org_id: str) -> list[str]:
    try:
        return [f.name.split("/")[-1]
                for f in get_clients().rm_folders.list_folders(parent=f"organizations/{org_id}")]
    except (PermissionDenied, NotFound, Forbidden):
        return []


def list_projects_in_org_api(org_id: str, limit: int) -> list[str]:
    from .output import status
    projects = []
    try:
        for p in get_clients().rm_projects.list_projects(parent=f"organizations/{org_id}"):
            projects.append(p.project_id)
            if len(projects) >= limit:
                return projects
    except (PermissionDenied, NotFound, Forbidden):
        pass

    folders = list_folders_in_org_api(org_id)
    if folders:
        status(f"Found {len(folders)} folder(s) in org. Listing projects...")
    for fid in folders:
        if len(projects) >= limit:
            break
        projects.extend(list_projects_in_folder_api(fid, limit - len(projects)))

    return projects[:limit]


def classify_and_check_gke(project_id: str) -> tuple[str, str, bool]:
    """Classify project AND check for GKE clusters in one pass."""
    cls, host = classify_project_api(project_id)
    has_gke = False
    if cls == "STANDALONE":
        has_gke = bool(list_gke_clusters(project_id))
    return cls, host, has_gke
