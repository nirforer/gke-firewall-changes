"""Report generation — text (Markdown) and HTML."""

import datetime
import sys

from .models import ProjectResult
from .output import Colors


# ============================================================
# Text report
# ============================================================

def print_report(results: list[ProjectResult], out=None, colors: Colors = None):
    if out is None:
        out = sys.stdout
    if colors is None:
        from .output import C
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
    p(f"## What is changing (GCP Ref: 493570689)\n")
    p(f"In GKE 1.35.1-gke.1473000, GKE-managed ALLOW rules for External LB Services")
    p(f"move from P1000 to P999, and a new DENY rule is added at P1000 blocking all")
    p(f"other traffic to the LB IP(s).")
    p()
    p(f"- **Scenario A**: Custom ALLOW at P1000 may be overridden by the new GKE DENY at P1000.")
    p(f"- **Scenario B**: Custom DENY at P1000 will be bypassed by the new GKE ALLOW at P999.")
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
        p(f"| Project | LB IP | Ports | Cluster | Version |")
        p(f"|---------|-------|-------|---------|---------|")
        for lb in all_lbs:
            p(f"| {lb.project} | {lb.ip} | {lb.ports} | {lb.cluster or '-'} | {lb.cluster_version or '-'} |")
        p()

    if actionable:
        p(f"## Action Required\n")
        p(f"GCP does not allow in-place priority changes. For each rule: create a copy at the target priority, verify, then delete the original.\n")

        scenario_a = [f for f in actionable if f.category == "Scenario A"]
        if scenario_a:
            p(f"### Scenario A — Custom ALLOW rules at P1000 (will be overridden by new GKE DENY)\n")
            p(f"| Severity | Project | Rule | Priority | Action | Protocols | Source Ranges | Target Tags |")
            p(f"|----------|---------|------|----------|--------|-----------|---------------|-------------|")
            for f in sorted(scenario_a, key=lambda x: x.severity):
                p(f"| {f.severity} | {f.project} | `{f.rule_name}` | {f.priority} | {f.rule_action} | {f.protocols} | {f.source_ranges} | {f.target_tags} |")
            p()

        scenario_b = [f for f in actionable if f.category == "Scenario B"]
        if scenario_b:
            p(f"### Scenario B — Custom DENY rules at P1000 (will be bypassed by new GKE ALLOW at P999)\n")
            p(f"Move to P999 (DENY wins over ALLOW at same priority) or lower.\n")
            p(f"| Severity | Project | Rule | Priority | Action | Protocols | Source Ranges | Target Tags |")
            p(f"|----------|---------|------|----------|--------|-----------|---------------|-------------|")
            for f in sorted(scenario_b, key=lambda x: x.severity):
                p(f"| {f.severity} | {f.project} | `{f.rule_name}` | {f.priority} | {f.rule_action} | {f.protocols} | {f.source_ranges} | {f.target_tags} |")
            p()

    p999_findings = [f for f in all_findings if f.category == "Custom P999"]
    if p999_findings:
        p(f"### Custom Rules at Priority 999 (review recommended)\n")
        p(f"| Project | Rule | Priority | Action | Protocols | Source Ranges | Target Tags |")
        p(f"|---------|------|----------|--------|-----------|---------------|-------------|")
        for f in p999_findings:
            p(f"| {f.project} | `{f.rule_name}` | {f.priority} | {f.rule_action} | {f.protocols} | {f.source_ranges} | {f.target_tags} |")
        p()

    # INFO findings for awareness
    info_findings = [f for f in all_findings if f.severity == "INFO" and f.category == "Scenario A"]
    if info_findings:
        p(f"### Other Custom ALLOW rules at P1000\n")
        p(f"These rules are not affected by the GKE 1.35.1 change because they don't target GKE node tags.\n")
        p(f"| Project | Rule | Priority | Protocols | Source Ranges | Target Tags | Status |")
        p(f"|---------|------|----------|-----------|---------------|-------------|--------|")
        for f in info_findings:
            p(f"| {f.project} | `{f.rule_name}` | {f.priority} | {f.protocols} | {f.source_ranges} | {f.target_tags} | {f.detail} |")
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
        p("")
        p("# For Scenario A (ALLOW rules): move to P998")
        p("gcloud compute firewall-rules create ${RULE}-p998 --project=$PROJECT --priority=998 \\")
        p("  ... # copy parameters from exported JSON")
        p("")
        p("# For Scenario B (DENY rules): move to P999 or lower")
        p("gcloud compute firewall-rules create ${RULE}-p999 --project=$PROJECT --priority=999 \\")
        p("  ... # copy parameters from exported JSON")
        p("")
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

    # External LBs table — no Region column
    if all_lbs:
        rows = ""
        for lb in all_lbs:
            rows += f"<tr><td>{lb.project}</td><td><code>{lb.ip}</code></td><td>{lb.ports}</td><td>{lb.cluster or '-'}</td><td>{lb.cluster_version or '-'}</td></tr>\n"
        external_lbs_section = f"""
        <h2>External LoadBalancers</h2>
        <div class="filter-bar"><input type="text" placeholder="Filter..."></div>
        <table>
          <thead><tr><th data-sort>Project <span class="sort-arrow">↕</span></th><th data-sort>LB IP</th><th data-sort>Ports</th><th data-sort>Cluster</th><th data-sort>Version</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        external_lbs_section = ""

    # Scenario A
    scenario_a = [f for f in actionable if f.category == "Scenario A"]
    if scenario_a:
        rows = ""
        for f in sorted(scenario_a, key=lambda x: x.severity):
            rows += f"<tr><td>{badge(f.severity)}</td><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.priority}</td><td>{f.rule_action}</td><td>{f.protocols}</td><td>{f.source_ranges}</td><td>{f.target_tags}</td></tr>\n"
        scenario_a_section = f"""
        <h2>Scenario A — Custom ALLOW Rules at P1000</h2>
        <p>These will be <strong>overridden</strong> by the new GKE DENY rule at P1000. Move to P998.</p>
        <table>
          <thead><tr><th data-sort>Severity</th><th data-sort>Project</th><th data-sort>Rule</th><th data-sort>Priority</th><th data-sort>Action</th><th data-sort>Protocols</th><th data-sort>Source Ranges</th><th data-sort>Target Tags</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        scenario_a_section = ""

    # Scenario A — INFO (non-GKE tags or unverified)
    info_a = [f for f in all_findings if f.severity == "INFO" and f.category == "Scenario A"]
    if info_a:
        rows = ""
        for f in info_a:
            rows += f"<tr><td>{badge(f.severity)}</td><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.priority}</td><td>{f.protocols}</td><td>{f.source_ranges}</td><td>{f.target_tags}</td><td>{f.detail}</td></tr>\n"
        scenario_a_section += f"""
        <details><summary>Other ALLOW at P1000 ({len(info_a)} rule(s)) — not affected, don't target GKE node tags</summary>
        <table>
          <thead><tr><th>Severity</th><th data-sort>Project</th><th data-sort>Rule</th><th data-sort>Priority</th><th data-sort>Protocols</th><th data-sort>Source Ranges</th><th data-sort>Target Tags</th><th>Status</th></tr></thead>
          <tbody>{rows}</tbody>
        </table></details>"""

    # Scenario B
    scenario_b = [f for f in actionable if f.category == "Scenario B"]
    if scenario_b:
        rows = ""
        for f in sorted(scenario_b, key=lambda x: x.severity):
            rows += f"<tr><td>{badge(f.severity)}</td><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.priority}</td><td>{f.rule_action}</td><td>{f.protocols}</td><td>{f.source_ranges}</td><td>{f.target_tags}</td></tr>\n"
        scenario_b_section = f"""
        <h2>Scenario B — Custom DENY Rules at P1000</h2>
        <p>These will be <strong>bypassed</strong> by the new GKE ALLOW rule at P999. Move to P999 (DENY wins over ALLOW at same priority) or lower.</p>
        <table>
          <thead><tr><th data-sort>Severity</th><th data-sort>Project</th><th data-sort>Rule</th><th data-sort>Priority</th><th data-sort>Action</th><th data-sort>Protocols</th><th data-sort>Source Ranges</th><th data-sort>Target Tags</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        scenario_b_section = ""

    # P999
    p999 = [f for f in all_findings if f.category == "Custom P999"]
    if p999:
        rows = ""
        for f in p999:
            rows += f"<tr><td>{f.project}</td><td><code>{f.rule_name}</code></td><td>{f.priority}</td><td>{f.rule_action}</td><td>{f.protocols}</td><td>{f.source_ranges}</td><td>{f.target_tags}</td></tr>\n"
        p999_section = f"""
        <details><summary>Custom Rules at Priority 999 ({len(p999)} rule(s) — review recommended)</summary>
        <table>
          <thead><tr><th data-sort>Project</th><th data-sort>Rule</th><th data-sort>Priority</th><th data-sort>Action</th><th data-sort>Protocols</th><th data-sort>Source Ranges</th><th data-sort>Target Tags</th></tr></thead>
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
        <div class="note">GCP does not allow in-place priority changes. For each rule: create a copy at the target priority, verify, then delete the original.</div>
        <pre><code>RULE="&lt;rule-name&gt;"
PROJECT="&lt;project&gt;"

# 1. Export current rule
gcloud compute firewall-rules describe $RULE --project=$PROJECT --format=json &gt; /tmp/$RULE.json

# 2a. For Scenario A (ALLOW rules): move to P998
gcloud compute firewall-rules create $RULE-p998 \\
  --project=$PROJECT --priority=998 \\
  ... # copy parameters from exported JSON

# 2b. For Scenario B (DENY rules): move to P999 or lower
gcloud compute firewall-rules create $RULE-p999 \\
  --project=$PROJECT --priority=999 \\
  ... # copy parameters from exported JSON

# 3. Verify new rule, then delete old one
gcloud compute firewall-rules delete $RULE --project=$PROJECT</code></pre>
        <div class="note">
          <strong>Notes:</strong><br>
          &bull; Test in staging before modifying production rules<br>
          &bull; Rules with internal-only source ranges (10.x, 172.x, 192.168.x) are lower risk<br>
          &bull; The new GKE DENY only targets External LB IPs &mdash; other traffic is unaffected<br>
          &bull; For Scenario B, DENY at P999 works because DENY wins over ALLOW at the same priority
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

  <details open>
    <summary>What is changing (GCP Reference: 493570689)</summary>
    <div class="note" style="margin-top: 0.5rem;">
      <p>In <strong>GKE 1.35.1-gke.1473000</strong>, Google is changing how firewall rules are managed for External LoadBalancer Services:</p>
      <ul style="margin: 0.8rem 0 0.8rem 1.5rem;">
        <li>The existing GKE-managed <strong>ALLOW</strong> rule for LoadBalancer Service ports will be changed from <strong>priority 1000 to priority 999</strong>.</li>
        <li>A new GKE-managed <strong>DENY</strong> rule will be introduced at <strong>priority 1000</strong>, blocking all other traffic to the LoadBalancer IP(s).</li>
      </ul>
      <p><strong>Scenario A</strong> &mdash; Custom ALLOW rules at P1000 may be overridden by the new GKE DENY at P1000, blocking traffic they previously permitted.</p>
      <p><strong>Scenario B</strong> &mdash; Custom DENY rules at P1000 (e.g. geo-blocking) will be bypassed by the new GKE ALLOW at P999.</p>
      <p style="margin-top: 0.5rem; color: #8b949e; font-size: 0.85rem;">Source: Google Cloud Support notification, reference issue 493570689.</p>
    </div>
  </details>

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
