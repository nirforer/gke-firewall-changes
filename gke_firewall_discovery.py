#!/usr/bin/env python3
"""
GKE Firewall Change Discovery Script (GCP API version)

Uses Google Cloud Python SDKs instead of gcloud CLI subprocess calls.
Faster and more reliable for large-scale scans.

Setup:
  pip install -r requirements.txt

Usage:
  python gke_firewall_discovery.py --host-project=PROJECT
  python gke_firewall_discovery.py --project=PROJECT
  python gke_firewall_discovery.py --folder=FOLDER_ID
  python gke_firewall_discovery.py --org=ORG_ID --limit=100
  python gke_firewall_discovery.py --output=report.md

Prerequisites:
  - Application Default Credentials: gcloud auth application-default login
  - Or a service account with roles/compute.viewer + roles/container.viewer
"""

import argparse
import datetime
import os
import re
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress noisy warnings from google-auth and gRPC
warnings.filterwarnings("ignore", message="Your application has authenticated using end user credentials")
os.environ["GRPC_VERBOSITY"] = "ERROR"
os.environ["GLOG_minloglevel"] = "2"
from dataclasses import dataclass, field
from typing import Optional

import google.auth
import google.auth.transport.requests
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import compute_v1
from google.cloud import container_v1
from google.cloud.resourcemanager_v3 import (
    FoldersClient,
    ProjectsClient,
)
from google.api_core.exceptions import PermissionDenied, NotFound, Forbidden


# ============================================================
# Output helpers
# ============================================================

class Colors:
    def __init__(self, enabled: bool):
        if enabled:
            self.RED = "\033[0;31m"
            self.YELLOW = "\033[1;33m"
            self.GREEN = "\033[0;32m"
            self.CYAN = "\033[0;36m"
            self.BOLD = "\033[1m"
            self.NC = "\033[0m"
        else:
            self.RED = self.YELLOW = self.GREEN = self.CYAN = self.BOLD = self.NC = ""


C: Colors
VERBOSE = False


def status(msg: str):
    print(f"  {msg}", file=sys.stderr)


def detail(msg: str):
    if VERBOSE:
        print(f"  {msg}", file=sys.stderr)


def progress_error(msg: str):
    print(f"  {C.YELLOW}! {msg}{C.NC}", file=sys.stderr)


# ============================================================
# Data structures (shared with subprocess version)
# ============================================================

@dataclass
class ScanTarget:
    host_project: str
    service_projects: list[str]
    is_shared_vpc: bool


@dataclass
class FirewallRule:
    name: str
    project: str
    direction: str
    priority: int
    source_ranges: list[str]
    allowed: list[str]
    denied: list[str]
    target_tags: list[str]
    description: str = ""

    @property
    def is_allow(self) -> bool:
        return len(self.allowed) > 0

    @property
    def is_deny(self) -> bool:
        return len(self.denied) > 0

    @property
    def has_gke_tags(self) -> bool:
        return any("gke-" in t for t in self.target_tags)

    @property
    def has_no_tags(self) -> bool:
        return len(self.target_tags) == 0

    @property
    def action_str(self) -> str:
        return ",".join(self.denied) if self.denied else ",".join(self.allowed)

    @property
    def rule_type(self) -> str:
        return "DENY" if self.is_deny else "ALLOW"


@dataclass
class ExternalLB:
    project: str
    name: str
    ip: str
    ports: str
    region: str
    cluster: str = ""
    cluster_version: str = ""


@dataclass
class Finding:
    project: str
    vpc_type: str
    severity: str
    category: str
    rule_name: str
    detail: str
    action: str


@dataclass
class ProjectResult:
    host_project: str
    is_shared_vpc: bool
    service_projects: list[str]
    external_lbs: list[ExternalLB]
    conflicting_rules: list[Finding]
    custom_p1000_count: int = 0
    quota_usage: int = 0
    quota_limit: int = 0
    errors: list[str] = field(default_factory=list)


def is_internal_ip(ip: str) -> bool:
    return bool(re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", ip))


# ============================================================
# GCP API clients — created once, reused across all calls
# ============================================================

class GCPClients:
    """Singleton-ish holder for GCP API clients. Created once to avoid
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
        self.firewalls = compute_v1.FirewallsClient()
        self.forwarding_rules = compute_v1.ForwardingRulesClient()
        self.projects = compute_v1.ProjectsClient()
        self.gke = container_v1.ClusterManagerClient()
        self.rm_projects = ProjectsClient()
        self.rm_folders = FoldersClient()
        self._initialized = True


def get_clients() -> GCPClients:
    return GCPClients()


# ============================================================
# GCP API helpers
# ============================================================

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
        return [{"name": c.name, "location": c.location, "version": c.current_master_version}
                for c in response.clusters]
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
    """Classify project as HOST, SERVICE, or STANDALONE.
    Uses a single API call when possible."""
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
    """Classify project AND check for GKE clusters in one pass.
    Returns (classification, host_project, has_gke)."""
    cls, host = classify_project_api(project_id)
    # Only check GKE for standalone (HOST/SERVICE don't need it)
    has_gke = False
    if cls == "STANDALONE":
        has_gke = bool(list_gke_clusters(project_id))
    return cls, host, has_gke


# ============================================================
# Discovery
# ============================================================

def discover_targets(args, workers: int) -> list[ScanTarget]:
    targets = []
    seen_hosts = set()

    for hp in args.host_project:
        if hp in seen_hosts:
            continue
        svcs = get_service_projects_api(hp)
        if svcs:
            status(f"  Shared VPC: {hp} → {','.join(svcs)}")
            targets.append(ScanTarget(host_project=hp, service_projects=svcs, is_shared_vpc=True))
        else:
            status(f"  Standalone: {hp}")
            targets.append(ScanTarget(host_project=hp, service_projects=[hp], is_shared_vpc=False))
        seen_hosts.add(hp)

    for sp in args.project:
        cls, host = classify_project_api(sp)
        if cls == "SERVICE" and host and host not in seen_hosts:
            svcs = get_service_projects_api(host)
            status(f"  Shared VPC: {host} → {','.join(svcs) or sp} (via {sp})")
            targets.append(ScanTarget(host_project=host, service_projects=svcs or [sp], is_shared_vpc=True))
            seen_hosts.add(host)
        elif cls == "HOST" and sp not in seen_hosts:
            svcs = get_service_projects_api(sp)
            status(f"  Shared VPC: {sp} → {','.join(svcs)}")
            targets.append(ScanTarget(host_project=sp, service_projects=svcs or [sp], is_shared_vpc=True))
            seen_hosts.add(sp)
        elif cls not in ("SERVICE", "HOST"):
            status(f"  Standalone: {sp}")
            targets.append(ScanTarget(host_project=sp, service_projects=[sp], is_shared_vpc=False))

    if targets:
        return targets

    # Auto-discovery
    if args.org:
        all_projs = list_projects_in_org_api(args.org, args.limit)
    elif args.folder:
        all_projs = list_projects_in_folder_api(args.folder, args.limit)
    else:
        status("Listing accessible projects...")
        try:
            all_projs = []
            for p in get_clients().rm_projects.search_projects():
                all_projs.append(p.project_id)
                if len(all_projs) >= args.limit:
                    break
        except Exception:
            all_projs = []

    status(f"Found {len(all_projs)} project(s). Classifying + checking GKE in parallel...")

    # Single parallel pass: classify AND check GKE for standalones simultaneously
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results_map = {}
        for proj, result in zip(all_projs, executor.map(classify_and_check_gke, all_projs)):
            results_map[proj] = result  # (cls, host, has_gke)

    # Collect unique hosts needing service project resolution
    hosts_to_resolve = set()
    for proj, (cls, host, _) in results_map.items():
        if cls == "HOST":
            hosts_to_resolve.add(proj)
        elif cls == "SERVICE" and host:
            hosts_to_resolve.add(host)

    # Resolve all host → service project mappings in parallel
    host_svc_map = {}
    if hosts_to_resolve:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_host = {executor.submit(get_service_projects_api, hp): hp for hp in hosts_to_resolve}
            for future in as_completed(future_to_host):
                hp = future_to_host[future]
                host_svc_map[hp] = future.result()

    # Build targets
    seen_service = set()

    for proj, (cls, _, _) in results_map.items():
        if cls == "HOST" and proj not in seen_hosts:
            svcs = host_svc_map.get(proj, [])
            status(f"  Shared VPC: {proj} → {','.join(svcs) or '(no service projects)'}")
            targets.append(ScanTarget(host_project=proj, service_projects=svcs or [proj], is_shared_vpc=bool(svcs)))
            seen_hosts.add(proj)
            seen_service.update(svcs)

    for proj, (cls, host, _) in results_map.items():
        if cls == "SERVICE" and host and host not in seen_hosts:
            svcs = host_svc_map.get(host, [])
            status(f"  Shared VPC: {host} → {','.join(svcs) or proj} (via {proj})")
            targets.append(ScanTarget(host_project=host, service_projects=svcs or [proj], is_shared_vpc=True))
            seen_hosts.add(host)
            seen_service.update(svcs or [proj])

    for proj, (cls, _, has_gke) in results_map.items():
        if cls == "STANDALONE" and has_gke and proj not in seen_hosts and proj not in seen_service:
            status(f"  Standalone: {proj}")
            targets.append(ScanTarget(host_project=proj, service_projects=[proj], is_shared_vpc=False))

    if len(all_projs) >= args.limit:
        progress_error(f"Reached limit ({args.limit}). Increase with --limit=N.")

    return targets


# ============================================================
# Scanning
# ============================================================

def scan_target(target: ScanTarget, workers: int) -> ProjectResult:
    hp = target.host_project
    result = ProjectResult(
        host_project=hp, is_shared_vpc=target.is_shared_vpc,
        service_projects=target.service_projects,
        external_lbs=[], conflicting_rules=[],
    )
    vpc_type = "Shared VPC" if target.is_shared_vpc else "Standalone"

    # Firewall analysis
    all_rules = list_firewall_rules(hp)
    if not all_rules:
        result.errors.append(f"Cannot list firewall rules in {hp}")
        return result

    import json
    for r in all_rules:
        if r.priority == 1000 and r.name.startswith("k8s-fw-") and not r.name.startswith("k8s-fw-l7"):
            try:
                desc = json.loads(r.description)
                svc_ip = desc.get("kubernetes.io/service-ip", "")
                if svc_ip and not is_internal_ip(svc_ip):
                    result.conflicting_rules.append(Finding(
                        project=hp, vpc_type=vpc_type, severity="INFO",
                        category="External LB FW Rule", rule_name=r.name,
                        detail=f"GKE-managed rule for External LB IP {svc_ip}",
                        action="Will be automatically updated by GKE 1.35.1",
                    ))
            except (json.JSONDecodeError, TypeError):
                pass

    for r in all_rules:
        if r.priority == 999 and not r.name.startswith("gke-"):
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="MEDIUM",
                category="Custom P999", rule_name=r.name,
                detail=f"{r.rule_type} {r.action_str} (src: {','.join(r.source_ranges)[:40]})",
                action="Review — new GKE ALLOW also at P999.",
            ))

    custom_p1000 = [r for r in all_rules
                    if r.priority == 1000 and r.direction == "INGRESS"
                    and not r.name.startswith("gke-") and not r.name.startswith("k8s-")]
    result.custom_p1000_count = len(custom_p1000)

    for r in custom_p1000:
        if r.is_allow and r.has_no_tags:
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="HIGH",
                category="Scenario A", rule_name=r.name,
                detail=f"ALLOW {r.action_str} from {','.join(r.source_ranges)[:40]} — NO target tags",
                action="Move to P998.",
            ))
        elif r.is_allow and r.has_gke_tags:
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="MEDIUM",
                category="Scenario A", rule_name=r.name,
                detail=f"ALLOW {r.action_str} tags: {','.join(r.target_tags)[:40]}",
                action="Move to P998.",
            ))
        elif r.is_deny:
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="HIGH",
                category="Scenario B", rule_name=r.name,
                detail=f"DENY {r.action_str} from {','.join(r.source_ranges)[:40]}",
                action="Move to P998.",
            ))

    result.quota_usage, result.quota_limit = get_project_quota(hp)

    # Service project scanning
    def scan_svc(project_id: str) -> list[ExternalLB]:
        lbs = []
        for fr in list_forwarding_rules(project_id):
            lbs.append(ExternalLB(
                project=project_id, name=fr["name"], ip=fr["ip"],
                ports=fr["ports"], region=fr["region"],
            ))
        clusters = list_gke_clusters(project_id)
        for cl in clusters:
            for lb in lbs:
                if not lb.cluster:
                    lb.cluster = cl["name"]
                    lb.cluster_version = cl["version"]
        return lbs

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_proj = {executor.submit(scan_svc, sp): sp for sp in target.service_projects}
        for future in as_completed(future_to_proj):
            proj = future_to_proj[future]
            try:
                result.external_lbs.extend(future.result())
            except Exception as e:
                result.errors.append(f"Error scanning {proj}: {e}")

    return result


# ============================================================
# Report (identical to subprocess version)
# ============================================================

def print_report(results: list[ProjectResult], out=None, colors: Colors = None):
    if out is None:
        out = sys.stdout
    if colors is None:
        colors = C

    def p(msg=""):
        print(msg, file=out)

    all_findings = []
    all_lbs = []
    total_projects = len(results)
    shared_vpc_count = sum(1 for r in results if r.is_shared_vpc)
    standalone_count = total_projects - shared_vpc_count
    projects_with_issues = 0

    for r in results:
        all_findings.extend(r.conflicting_rules)
        all_lbs.extend(r.external_lbs)
        if r.external_lbs or any(f.severity in ("HIGH", "MEDIUM") for f in r.conflicting_rules):
            projects_with_issues += 1

    actionable = [f for f in all_findings if f.severity in ("HIGH", "MEDIUM") and f.category.startswith("Scenario")]

    p()
    p(f"{'=' * 70}")
    p(f"  GKE 1.35.1 FIREWALL CHANGE — IMPACT REPORT")
    p(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p(f"{'=' * 70}")
    p()
    p(f"## Overview\n")
    p(f"| Metric | Count |")
    p(f"|--------|-------|")
    p(f"| Projects scanned | {total_projects} ({shared_vpc_count} shared VPC, {standalone_count} standalone) |")
    p(f"| External LoadBalancers found | {len(all_lbs)} |")
    p(f"| Firewall rules requiring action | {len(actionable)} |")
    p(f"| Projects with issues | {projects_with_issues} |")
    p()

    if not all_lbs and not actionable:
        p(f"RESULT: No impact detected. No action required.")
        p()
        p("No External LoadBalancer Services were found, and no conflicting firewall")
        p("rules exist at priority 999 or 1000. The GKE 1.35.1 change will have no effect.")
        return

    if all_lbs:
        p(f"## External LoadBalancers\n")
        p(f"| Project | LB IP | Ports | Region | Cluster | Version |")
        p(f"|---------|-------|-------|--------|---------|---------|")
        for lb in all_lbs:
            p(f"| {lb.project} | {lb.ip} | {lb.ports} | {lb.region} | {lb.cluster or '-'} | {lb.cluster_version or '-'} |")
        p()

    if actionable:
        p(f"## Action Required — Firewall Rules to Move to Priority 998\n")
        p(f"GCP does not allow in-place priority changes. For each rule: create a copy at P998, verify, then delete the original.\n")

        scenario_a = [f for f in actionable if f.category == "Scenario A"]
        if scenario_a:
            p(f"### Scenario A — Custom ALLOW rules at P1000 (will be overridden by new GKE DENY)\n")
            p(f"| Priority | Project | Rule | Detail | Tags |")
            p(f"|----------|---------|------|--------|------|")
            for f in sorted(scenario_a, key=lambda x: x.severity):
                p(f"| {f.severity} | {f.project} | `{f.rule_name}` | {f.detail} | {'no tags' if 'NO target' in f.detail else 'GKE tags'} |")
            p()

        scenario_b = [f for f in actionable if f.category == "Scenario B"]
        if scenario_b:
            p(f"### Scenario B — Custom DENY rules at P1000 (will be bypassed by new GKE ALLOW at P999)\n")
            p(f"| Priority | Project | Rule | Detail |")
            p(f"|----------|---------|------|--------|")
            for f in sorted(scenario_b, key=lambda x: x.severity):
                p(f"| {f.severity} | {f.project} | `{f.rule_name}` | {f.detail} |")
            p()

    p999_findings = [f for f in all_findings if f.category == "Custom P999"]
    if p999_findings:
        p(f"### Custom Rules at Priority 999 (review recommended)\n")
        p(f"| Project | Rule | Detail |")
        p(f"|---------|------|--------|")
        for f in p999_findings:
            p(f"| {f.project} | `{f.rule_name}` | {f.detail} |")
        p()

    p(f"## Per-Project Summary\n")
    p(f"| Project | Type | Ext LBs | Rules to Fix | Quota |")
    p(f"|---------|------|---------|-------------|-------|")
    for r in results:
        vpc_type = "Shared VPC" if r.is_shared_vpc else "Standalone"
        n_lbs = len(r.external_lbs)
        n_fix = len([f for f in r.conflicting_rules if f.severity in ("HIGH", "MEDIUM") and f.category.startswith("Scenario")])
        quota = f"{r.quota_usage}/{r.quota_limit}" if r.quota_limit else "-"
        marker = " **" if n_lbs > 0 or n_fix > 0 else ""
        p(f"| {r.host_project}{marker} | {vpc_type} | {n_lbs} | {n_fix} | {quota} |")
    p()

    if actionable:
        p(f"## Remediation\n")
        p("```bash")
        p('RULE="<rule-name>"')
        p('PROJECT="<project>"')
        p("gcloud compute firewall-rules describe $RULE --project=$PROJECT --format=json > /tmp/${RULE}.json")
        p("gcloud compute firewall-rules create ${RULE}-p998 --project=$PROJECT --priority=998 \\")
        p("  ... # copy parameters from exported JSON")
        p("gcloud compute firewall-rules delete $RULE --project=$PROJECT")
        p("```")
        p()
        p("**Notes:**")
        p("- Test in staging before modifying production rules")
        p("- Rules with internal-only source ranges (10.x, 172.x, 192.168.x) are lower risk")
        p("- The new GKE DENY only targets External LB IPs — other traffic is unaffected")

    all_errors = [e for r in results for e in r.errors]
    if all_errors:
        p(f"\n## Errors\n")
        for e in all_errors:
            p(f"- {e}")


# ============================================================
# HTML report
# ============================================================

def _html_template(timestamp, total_projects, shared_vpc_count, standalone_count,
                   total_lbs, total_actionable, projects_with_issues,
                   lb_card_class, rules_card_class, issues_card_class,
                   result_banner, external_lbs_section, scenario_a_section,
                   scenario_b_section, p999_section, project_summary_section,
                   remediation_section, errors_section):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GKE 1.35.1 Firewall Change — Impact Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: #0d1117; color: #e6edf3; padding: 2rem; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #30363d; }}
  h3 {{ font-size: 1.1rem; margin: 1.5rem 0 0.5rem; color: #8b949e; }}
  .subtitle {{ color: #8b949e; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; }}
  .card .value {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ color: #8b949e; font-size: 0.85rem; }}
  .card.red .value {{ color: #f85149; }}
  .card.green .value {{ color: #3fb950; }}
  .card.yellow .value {{ color: #d29922; }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; font-size: 0.9rem; }}
  th {{ background: #161b22; text-align: left; padding: 0.6rem 0.8rem; border: 1px solid #30363d;
       color: #8b949e; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em;
       cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ color: #e6edf3; }}
  th .sort-arrow {{ margin-left: 4px; opacity: 0.4; }}
  th.sorted .sort-arrow {{ opacity: 1; }}
  td {{ padding: 0.6rem 0.8rem; border: 1px solid #30363d; }}
  tr:hover td {{ background: rgba(56, 139, 253, 0.05); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge-high {{ background: rgba(248,81,73,0.15); color: #f85149; }}
  .badge-medium {{ background: rgba(210,153,34,0.15); color: #d29922; }}
  .badge-info {{ background: rgba(56,139,253,0.15); color: #58a6ff; }}
  .badge-clean {{ background: rgba(63,185,80,0.15); color: #3fb950; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  pre {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem;
        overflow-x: auto; font-size: 0.85rem; margin: 1rem 0; }}
  .result-banner {{ padding: 1rem 1.5rem; border-radius: 8px; margin: 1.5rem 0; font-weight: 600; font-size: 1.1rem; }}
  .result-clean {{ background: rgba(63,185,80,0.1); border: 1px solid #3fb950; color: #3fb950; }}
  .result-action {{ background: rgba(248,81,73,0.1); border: 1px solid #f85149; color: #f85149; }}
  .note {{ background: #161b22; border-left: 3px solid #d29922; padding: 0.8rem 1rem; margin: 1rem 0;
          border-radius: 0 4px 4px 0; font-size: 0.9rem; }}
  details {{ margin: 0.5rem 0; }}
  summary {{ cursor: pointer; font-weight: 600; padding: 0.5rem 0; color: #58a6ff; }}
  summary:hover {{ text-decoration: underline; }}
  .filter-bar {{ margin: 0.5rem 0; }}
  .filter-bar input {{ background: #161b22; border: 1px solid #30363d; color: #e6edf3;
                       padding: 6px 12px; border-radius: 4px; width: 300px; font-size: 0.85rem; }}
  .filter-bar input::placeholder {{ color: #8b949e; }}
</style>
</head>
<body>
<div class="container">
  <h1>GKE 1.35.1 Firewall Change — Impact Report</h1>
  <p class="subtitle">Generated: {timestamp}</p>

  <div class="cards">
    <div class="card"><div class="value">{total_projects}</div><div class="label">Projects Scanned<br><small>{shared_vpc_count} shared VPC, {standalone_count} standalone</small></div></div>
    <div class="card {lb_card_class}"><div class="value">{total_lbs}</div><div class="label">External LoadBalancers</div></div>
    <div class="card {rules_card_class}"><div class="value">{total_actionable}</div><div class="label">Rules Requiring Action</div></div>
    <div class="card {issues_card_class}"><div class="value">{projects_with_issues}</div><div class="label">Projects with Issues</div></div>
  </div>

  {result_banner}

  {external_lbs_section}

  {scenario_a_section}

  {scenario_b_section}

  {p999_section}

  {project_summary_section}

  {remediation_section}

  {errors_section}

</div>
<script>
document.querySelectorAll('th[data-sort]').forEach(function(th) {{
  th.addEventListener('click', function() {{
    var table = th.closest('table');
    var tbody = table.querySelector('tbody');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    var idx = Array.from(th.parentNode.children).indexOf(th);
    var dir = th.classList.contains('sorted-asc') ? -1 : 1;
    table.querySelectorAll('th').forEach(function(h) {{ h.classList.remove('sorted-asc','sorted-desc','sorted'); }});
    th.classList.add('sorted', dir === 1 ? 'sorted-asc' : 'sorted-desc');
    rows.sort(function(a,b) {{
      var av = (a.children[idx] || {{}}).textContent ? a.children[idx].textContent.trim() : '';
      var bv = (b.children[idx] || {{}}).textContent ? b.children[idx].textContent.trim() : '';
      var an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return (an - bn) * dir;
      return av.localeCompare(bv) * dir;
    }});
    rows.forEach(function(r) {{ tbody.appendChild(r); }});
  }});
}});
document.querySelectorAll('.filter-bar input').forEach(function(input) {{
  input.addEventListener('input', function() {{
    var val = input.value.toLowerCase();
    var table = input.closest('div').querySelector('table');
    table.querySelectorAll('tbody tr').forEach(function(row) {{
      row.style.display = row.textContent.toLowerCase().includes(val) ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>"""


def generate_html_report(results: list[ProjectResult]) -> str:
    """Generate a self-contained HTML report."""
    all_findings = []
    all_lbs = []
    total_projects = len(results)
    shared_vpc_count = sum(1 for r in results if r.is_shared_vpc)
    standalone_count = total_projects - shared_vpc_count
    projects_with_issues = 0

    for r in results:
        all_findings.extend(r.conflicting_rules)
        all_lbs.extend(r.external_lbs)
        if r.external_lbs or any(f.severity in ("HIGH", "MEDIUM") for f in r.conflicting_rules):
            projects_with_issues += 1

    actionable = [f for f in all_findings if f.severity in ("HIGH", "MEDIUM") and f.category.startswith("Scenario")]

    def badge(severity):
        cls = {"HIGH": "badge-high", "MEDIUM": "badge-medium", "INFO": "badge-info"}.get(severity, "badge-info")
        return f'<span class="badge {cls}">{severity}</span>'

    # Result banner
    if not all_lbs and not actionable:
        result_banner = '<div class="result-banner result-clean">No impact detected. No action required.</div>'
    else:
        result_banner = f'<div class="result-banner result-action">{len(actionable)} firewall rule(s) require action across {projects_with_issues} project(s)</div>'

    # External LBs table
    if all_lbs:
        rows = ""
        for lb in all_lbs:
            rows += f"<tr><td>{lb.project}</td><td><code>{lb.ip}</code></td><td>{lb.ports}</td><td>{lb.region}</td><td>{lb.cluster or '-'}</td><td>{lb.cluster_version or '-'}</td></tr>\n"
        external_lbs_section = f"""
        <h2>External LoadBalancers</h2>
        <div class="filter-bar"><input type="text" placeholder="Filter..."></div>
        <table>
          <thead><tr><th data-sort>Project <span class="sort-arrow">↕</span></th><th data-sort>LB IP</th><th data-sort>Ports</th><th data-sort>Region</th><th data-sort>Cluster</th><th data-sort>Version</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        external_lbs_section = ""

    # Scenario A
    scenario_a = [f for f in actionable if f.category == "Scenario A"]
    if scenario_a:
        rows = ""
        for f in sorted(scenario_a, key=lambda x: x.severity):
            tags = "no tags" if "NO target" in f.detail else "GKE tags"
            rows += f"<tr><td>{badge(f.severity)}</td><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.detail}</td><td>{tags}</td></tr>\n"
        scenario_a_section = f"""
        <h2>Scenario A — Custom ALLOW Rules at P1000</h2>
        <p>These will be <strong>overridden</strong> by the new GKE DENY rule at P1000. Move to P998.</p>
        <table>
          <thead><tr><th data-sort>Priority</th><th data-sort>Project</th><th data-sort>Rule</th><th>Detail</th><th data-sort>Tags</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        scenario_a_section = ""

    # Scenario B
    scenario_b = [f for f in actionable if f.category == "Scenario B"]
    if scenario_b:
        rows = ""
        for f in sorted(scenario_b, key=lambda x: x.severity):
            rows += f"<tr><td>{badge(f.severity)}</td><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.detail}</td></tr>\n"
        scenario_b_section = f"""
        <h2>Scenario B — Custom DENY Rules at P1000</h2>
        <p>These will be <strong>bypassed</strong> by the new GKE ALLOW rule at P999. Move to P998.</p>
        <table>
          <thead><tr><th data-sort>Priority</th><th data-sort>Project</th><th data-sort>Rule</th><th>Detail</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        scenario_b_section = ""

    # P999
    p999 = [f for f in all_findings if f.category == "Custom P999"]
    if p999:
        rows = ""
        for f in p999:
            rows += f"<tr><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.detail}</td></tr>\n"
        p999_section = f"""
        <details><summary>Custom Rules at Priority 999 ({len(p999)} rule(s) — review recommended)</summary>
        <table>
          <thead><tr><th data-sort>Project</th><th data-sort>Rule</th><th>Detail</th></tr></thead>
          <tbody>{rows}</tbody>
        </table></details>"""
    else:
        p999_section = ""

    # Project summary
    rows = ""
    for r in results:
        vpc_type = "Shared VPC" if r.is_shared_vpc else "Standalone"
        n_lbs = len(r.external_lbs)
        n_fix = len([f for f in r.conflicting_rules if f.severity in ("HIGH", "MEDIUM") and f.category.startswith("Scenario")])
        quota = f"{r.quota_usage}/{r.quota_limit}" if r.quota_limit else "-"
        status_badge = badge("HIGH") if n_fix > 0 else '<span class="badge badge-clean">clean</span>'
        rows += f"<tr><td>{r.host_project}</td><td>{vpc_type}</td><td>{n_lbs}</td><td>{n_fix}</td><td>{quota}</td><td>{status_badge}</td></tr>\n"
    project_summary_section = f"""
    <h2>Per-Project Summary</h2>
    <div class="filter-bar"><input type="text" placeholder="Filter projects..."></div>
    <table>
      <thead><tr><th data-sort>Project <span class="sort-arrow">↕</span></th><th data-sort>Type</th><th data-sort>Ext LBs</th><th data-sort>Rules to Fix</th><th data-sort>Quota</th><th data-sort>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""

    # Remediation
    if actionable:
        remediation_section = """
        <h2>Remediation</h2>
        <div class="note">GCP does not allow in-place priority changes. For each rule: create a copy at P998, verify, then delete the original.</div>
        <pre><code>RULE="&lt;rule-name&gt;"
PROJECT="&lt;project&gt;"

# 1. Export current rule
gcloud compute firewall-rules describe $RULE --project=$PROJECT --format=json &gt; /tmp/$RULE.json

# 2. Create replacement at priority 998
gcloud compute firewall-rules create $RULE-p998 \\
  --project=$PROJECT --priority=998 \\
  ... # copy parameters from exported JSON

# 3. Verify new rule, then delete old one
gcloud compute firewall-rules delete $RULE --project=$PROJECT</code></pre>
        <div class="note">
          <strong>Notes:</strong><br>
          • Test in staging before modifying production rules<br>
          • Rules with internal-only source ranges (10.x, 172.x, 192.168.x) are lower risk<br>
          • The new GKE DENY only targets External LB IPs — other traffic is unaffected
        </div>"""
    else:
        remediation_section = ""

    # Errors
    all_errors = [e for r in results for e in r.errors]
    if all_errors:
        items = "".join(f"<li>{e}</li>" for e in all_errors)
        errors_section = f'<details><summary>Errors ({len(all_errors)})</summary><ul>{items}</ul></details>'
    else:
        errors_section = ""

    return _html_template(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_projects=total_projects,
        shared_vpc_count=shared_vpc_count,
        standalone_count=standalone_count,
        total_lbs=len(all_lbs),
        total_actionable=len(actionable),
        projects_with_issues=projects_with_issues,
        lb_card_class="red" if all_lbs else "green",
        rules_card_class="red" if actionable else "green",
        issues_card_class="red" if projects_with_issues else "green",
        result_banner=result_banner,
        external_lbs_section=external_lbs_section,
        scenario_a_section=scenario_a_section,
        scenario_b_section=scenario_b_section,
        p999_section=p999_section,
        project_summary_section=project_summary_section,
        remediation_section=remediation_section,
        errors_section=errors_section,
    )


# ============================================================
# Main
# ============================================================

def main():
    global C, VERBOSE

    parser = argparse.ArgumentParser(
        description="GKE Firewall Change Discovery (GCP API version)",
    )
    parser.add_argument("--org", default="", help="Scan projects in this organization")
    parser.add_argument("--folder", default="", help="Scan projects in this folder")
    parser.add_argument("--host-project", action="append", default=[], help="Shared VPC host (repeatable)")
    parser.add_argument("--project", action="append", default=[], help="Standalone project (repeatable)")
    parser.add_argument("--all-projects", action="store_true", help="Scan accessible projects up to --limit")
    parser.add_argument("--limit", type=int, default=50, help="Max projects in discovery mode (default: 50)")
    parser.add_argument("--workers", type=int, default=15, help="Parallel workers (default: 15)")
    parser.add_argument("--output", default="", help="Write report to file (.md or .html)")
    parser.add_argument("--serve", action="store_true", help="Serve HTML report on port 8080 (for Cloud Shell Web Preview)")
    parser.add_argument("--port", type=int, default=8080, help="Port for --serve (default: 8080)")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()
    use_color = not args.no_color and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    C = Colors(use_color)
    VERBOSE = args.verbose

    # Auth check
    try:
        credentials, project = google.auth.default()
        # Verify credentials actually work (Cloud Shell metadata creds can fail with SDK)
        credentials.refresh(google.auth.transport.requests.Request())
        status(f"Authenticated (default project: {project or 'none'})")
    except DefaultCredentialsError:
        print("ERROR: No credentials found. Run: gcloud auth application-default login", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if "email" in str(e) or "metadata" in str(e):
            print("ERROR: Cloud Shell default credentials don't work with Python SDKs.", file=sys.stderr)
            print("Run: gcloud auth application-default login --no-launch-browser", file=sys.stderr)
        else:
            print(f"ERROR: Auth failed: {e}", file=sys.stderr)
            print("Run: gcloud auth application-default login", file=sys.stderr)
        sys.exit(1)

    # Discovery
    status("Discovering projects...")
    targets = discover_targets(args, args.workers)

    if not targets:
        status("No projects with GKE clusters found.")
        status("Try: --host-project=PROJECT, --project=PROJECT, --folder=FOLDER_ID, or --org=ORG_ID")
        sys.exit(0)

    print(file=sys.stderr)
    n_shared = sum(1 for t in targets if t.is_shared_vpc)
    n_standalone = len(targets) - n_shared
    status(f"Scan plan: {len(targets)} target(s) — {n_shared} shared VPC, {n_standalone} standalone")
    print(file=sys.stderr)

    # Scan
    status(f"Scanning with {args.workers} workers...")
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_target = {executor.submit(scan_target, t, args.workers): t for t in targets}
        for future in as_completed(future_to_target):
            t = future_to_target[future]
            try:
                r = future.result()
                results.append(r)
                n_issues = len(r.external_lbs) + len([f for f in r.conflicting_rules if f.severity == "HIGH"])
                if n_issues:
                    status(f"  {C.RED}!{C.NC} {t.host_project} — {len(r.external_lbs)} ext LB(s), {n_issues} issue(s)")
                else:
                    status(f"  {C.GREEN}.{C.NC} {t.host_project} — clean")
            except Exception as e:
                progress_error(f"Failed: {t.host_project}: {e}")

    print(file=sys.stderr)

    # Determine output format
    output_file = args.output
    if args.serve and not output_file:
        output_file = "report.html"

    is_html = output_file.endswith(".html") if output_file else False

    # Terminal report (always markdown)
    print_report(results, out=sys.stdout, colors=C)

    # File report
    if output_file:
        if is_html:
            html = generate_html_report(results)
            with open(output_file, "w") as f:
                f.write(html)
        else:
            no_color = Colors(enabled=False)
            with open(output_file, "w") as f:
                print_report(results, out=f, colors=no_color)
        status(f"Report written to {output_file}")

    # Serve
    if args.serve:
        import http.server
        import socketserver
        import threading

        if not is_html:
            # Generate HTML if user didn't specify .html
            html = generate_html_report(results)
            output_file = "report.html"
            with open(output_file, "w") as f:
                f.write(html)

        report_dir = os.path.dirname(os.path.abspath(output_file)) or "."
        report_name = os.path.basename(output_file)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=report_dir, **kw)
            def do_GET(self):
                if self.path == "/":
                    self.path = f"/{report_name}"
                return super().do_GET()
            def log_message(self, fmt, *a):
                pass  # silence request logs

        port = args.port
        status(f"\n  Serving report at http://localhost:{port}")
        status(f"  In Cloud Shell: click 'Web Preview' → 'Preview on port {port}'")
        status(f"  Press Ctrl+C to stop.\n")

        with socketserver.TCPServer(("", port), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                status("Server stopped.")


if __name__ == "__main__":
    main()
