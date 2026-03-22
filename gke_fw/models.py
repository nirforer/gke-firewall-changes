"""Data structures shared across all modules."""

import re
from dataclasses import dataclass, field


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
    action: str
    priority: int = 0
    direction: str = ""
    rule_action: str = ""  # ALLOW or DENY
    protocols: str = ""
    source_ranges: str = ""
    target_tags: str = ""
    detail: str = ""  # free-form note (used for INFO findings)


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
