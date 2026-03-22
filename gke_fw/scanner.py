"""Firewall rule analysis — scan targets for conflicts with GKE 1.35.1 changes.

Scenario mapping to the GCP email (ref 493570689):

  Scenario A: Custom ALLOW rules at P1000
    The new GKE DENY at P1000 may override these custom ALLOW rules,
    blocking traffic they previously permitted to LB IPs.

  Scenario B: Custom DENY rules at P1000
    The new GKE ALLOW at P999 has higher precedence, bypassing these
    custom DENY rules. Fix: move to P999 (DENY wins over ALLOW at
    same priority) or lower.

  Custom P999: Custom ALLOW rules already at P999
    May conflict with the new GKE ALLOW also at P999. DENY rules at
    P999 are NOT flagged — they naturally win over ALLOW at the same
    priority per GCP firewall semantics.

Note: Only INGRESS rules are checked. The GKE 1.35.1 change only
affects INGRESS rules for External LoadBalancer Services — EGRESS
rules are not impacted.
"""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import (
    ScanTarget, ProjectResult, ExternalLB, Finding, is_internal_ip,
)
from .clients import (
    list_firewall_rules, list_forwarding_rules,
    list_gke_clusters, get_project_quota,
)


def _scan_service_project(project_id: str) -> tuple[list[ExternalLB], set[str]]:
    """Scan a service project for External LBs and GKE node tags."""
    lbs = []
    node_tags = set()
    for fr in list_forwarding_rules(project_id):
        lbs.append(ExternalLB(
            project=project_id, name=fr["name"], ip=fr["ip"],
            ports=fr["ports"], region=fr["region"],
        ))
    clusters = list_gke_clusters(project_id)
    for cl in clusters:
        node_tags.update(cl.get("node_tags", []))
        for lb in lbs:
            if not lb.cluster:
                lb.cluster = cl["name"]
                lb.cluster_version = cl["version"]
    return lbs, node_tags


def _has_gke_node_tag(rule_tags: list[str], known_node_tags: set[str]) -> bool:
    """Check if a firewall rule targets GKE nodes by matching its target
    tags against known node pool tags. Falls back to the 'gke-' prefix
    heuristic if no node tags were discovered (e.g. permission denied)."""
    if known_node_tags:
        return bool(set(rule_tags) & known_node_tags)
    return any("gke-" in t for t in rule_tags)


def scan_target(target: ScanTarget, workers: int) -> ProjectResult:
    hp = target.host_project
    result = ProjectResult(
        host_project=hp, is_shared_vpc=target.is_shared_vpc,
        service_projects=target.service_projects,
        external_lbs=[], conflicting_rules=[],
    )
    vpc_type = "Shared VPC" if target.is_shared_vpc else "Standalone"

    # --- Phase 1: Scan service projects for LBs and GKE node tags ---
    # We need node tags before analyzing firewall rules so we can do
    # exact tag matching instead of the "gke-" prefix heuristic.
    all_node_tags: set[str] = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_proj = {
            executor.submit(_scan_service_project, sp): sp
            for sp in target.service_projects
        }
        for future in as_completed(future_to_proj):
            proj = future_to_proj[future]
            try:
                lbs, tags = future.result()
                result.external_lbs.extend(lbs)
                all_node_tags.update(tags)
            except Exception as e:
                result.errors.append(f"Error scanning {proj}: {e}")

    # --- Phase 2: Analyze firewall rules using discovered node tags ---
    all_rules = list_firewall_rules(hp)
    if not all_rules:
        result.errors.append(f"Cannot list firewall rules in {hp}")
        return result

    # Identify existing GKE-managed External LB firewall rules (INFO)
    for r in all_rules:
        if r.priority == 1000 and r.name.startswith("k8s-fw-") and not r.name.startswith("k8s-fw-l7"):
            try:
                desc = json.loads(r.description)
                svc_ip = desc.get("kubernetes.io/service-ip", "")
                if svc_ip and not is_internal_ip(svc_ip):
                    result.conflicting_rules.append(Finding(
                        project=hp, vpc_type=vpc_type, severity="INFO",
                        category="External LB FW Rule", rule_name=r.name,
                        priority=r.priority, direction=r.direction,
                        rule_action="ALLOW", protocols=r.action_str,
                        source_ranges=",".join(r.source_ranges),
                        detail=f"GKE-managed rule for External LB IP {svc_ip}",
                        action="Will be automatically updated by GKE 1.35.1",
                    ))
            except (json.JSONDecodeError, TypeError):
                pass

    # Custom rules at P999 — not affected by the change. ALLOW rules
    # at P999 still work (both ALLOW, no conflict with new GKE ALLOW).
    # DENY rules at P999 also fine (DENY wins over ALLOW at same priority).
    # Listed as INFO for awareness since they share priority with new GKE rules.
    for r in all_rules:
        if r.priority == 999 and not r.name.startswith("gke-"):
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="INFO",
                category="Custom P999", rule_name=r.name,
                priority=r.priority, direction=r.direction,
                rule_action=r.rule_type, protocols=r.action_str,
                source_ranges=",".join(r.source_ranges),
                target_tags=",".join(r.target_tags) or "All instances",
                detail="not affected by this change",
                action="No action needed.",
            ))

    # Custom rules at P1000 (INGRESS only) — EGRESS is not affected.
    custom_p1000 = [r for r in all_rules
                    if r.priority == 1000 and r.direction == "INGRESS"
                    and not r.name.startswith("gke-") and not r.name.startswith("k8s-")]
    result.custom_p1000_count = len(custom_p1000)

    for r in custom_p1000:
        if r.is_allow and r.has_no_tags:
            # Scenario A — HIGH: applies to ALL instances including GKE nodes
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="HIGH",
                category="Scenario A", rule_name=r.name,
                priority=r.priority, direction=r.direction,
                rule_action="ALLOW", protocols=r.action_str,
                source_ranges=",".join(r.source_ranges),
                target_tags="All instances",
                action="Move to P998.",
            ))
        elif r.is_allow and _has_gke_node_tag(r.target_tags, all_node_tags):
            # Scenario A — HIGH: targets GKE nodes (exact tag match
            # against discovered node pool tags, or "gke-" heuristic)
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="HIGH",
                category="Scenario A", rule_name=r.name,
                priority=r.priority, direction=r.direction,
                rule_action="ALLOW", protocols=r.action_str,
                source_ranges=",".join(r.source_ranges),
                target_tags=",".join(r.target_tags),
                action="Move to P998.",
            ))
        elif r.is_allow:
            if all_node_tags:
                # We have real node tags — this rule doesn't target GKE nodes
                detail = "does not target GKE nodes"
                action = "No action needed."
            else:
                # No node tags discovered (GKE API permission denied?) —
                # can't confirm whether these tags match GKE nodes or not
                detail = "could not verify against GKE node tags"
                action = "Verify manually — GKE node tags could not be read."
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="INFO",
                category="Scenario A", rule_name=r.name,
                priority=r.priority, direction=r.direction,
                rule_action="ALLOW", protocols=r.action_str,
                source_ranges=",".join(r.source_ranges),
                target_tags=",".join(r.target_tags),
                detail=detail,
                action=action,
            ))
        elif r.is_deny:
            # Scenario B — HIGH: new GKE ALLOW at P999 will bypass this DENY
            result.conflicting_rules.append(Finding(
                project=hp, vpc_type=vpc_type, severity="HIGH",
                category="Scenario B", rule_name=r.name,
                priority=r.priority, direction=r.direction,
                rule_action="DENY", protocols=r.action_str,
                source_ranges=",".join(r.source_ranges),
                target_tags=",".join(r.target_tags) or "All instances",
                action="Move to P999 or lower.",
            ))

    result.quota_usage, result.quota_limit = get_project_quota(hp)

    return result
