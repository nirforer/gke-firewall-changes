# GKE 1.35.1 Firewall Change Discovery

Scans your GCP projects to assess the impact of the GKE 1.35.1 firewall rule change (GCP ref: 493570689) for External LoadBalancer Services.

**What's changing:** In GKE 1.35.1-gke.1473000, the GKE-managed ALLOW rule for External LB Service ports moves from priority 1000 to 999, and a new DENY rule is added at priority 1000 blocking all other traffic to the LB IP(s).

**What it checks:**
- External LoadBalancer Services across all GKE clusters
- Custom firewall rules at priority 999 and 1000 that may conflict
- Exact GKE node pool tag matching (with fallback heuristic)
- Shared VPC and standalone project configurations
- Firewall quota headroom

**Output:** An interactive HTML report with sortable tables, severity badges, and remediation steps.

## Quick Start (Cloud Shell)

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/open?cloudshell_git_repo=https://github.com/nirforer/gke-firewall-changes.git&shellonly=true)

Or manually in Cloud Shell:

```bash
git clone https://github.com/nirforer/gke-firewall-changes.git
cd gke-firewall-changes
bash run.sh
```

The interactive wizard will prompt you for the scan scope, generate an HTML report, and serve it via Web Preview.

## Manual Usage

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
gcloud auth application-default login
```

### Run

```bash
# Scan a specific project
python3 gke_firewall_discovery.py --project=my-project --output=report.html

# Scan a shared VPC host (auto-discovers service projects)
python3 gke_firewall_discovery.py --host-project=my-network-project --output=report.html

# Scan all projects in a folder
python3 gke_firewall_discovery.py --folder=123456789 --output=report.html

# Scan all projects in an org
python3 gke_firewall_discovery.py --org=987654321 --output=report.html

# Generate and serve HTML report (for Cloud Shell Web Preview)
python3 gke_firewall_discovery.py --host-project=my-project --serve

# Markdown output
python3 gke_firewall_discovery.py --host-project=my-project --output=report.md
```

### All Flags

| Flag | Description |
|------|-------------|
| `--project=ID` | Scan a specific project (repeatable) |
| `--host-project=ID` | Scan a shared VPC host project (repeatable) |
| `--folder=ID` | Scan all projects in a GCP folder |
| `--org=ID` | Scan all projects in a GCP organization |
| `--all-projects` | Auto-discover all accessible projects |
| `--workers=N` | Parallel API workers (default: 15) |
| `--output=FILE` | Write report to file (.html or .md) |
| `--serve` | Serve HTML report on port 8080 for Web Preview |
| `--port=N` | Port for --serve (default: 8080) |
| `--no-color` | Disable terminal colors |
| `--verbose` | Show detailed scan progress |

## Required Permissions

| Scope | Role | Purpose |
|-------|------|---------|
| Host/Network project | `roles/compute.viewer` | List firewall rules, quota |
| Service/GKE projects | `roles/compute.viewer` | List forwarding rules |
| Service/GKE projects | `roles/container.viewer` | List GKE clusters and node pool tags |
| Org/Folder (optional) | `roles/resourcemanager.folderViewer` | Auto-discover projects |

## What the Script Detects

### Scenario A — Custom ALLOW rules at priority 1000

The new GKE-managed DENY rule at priority 1000 will block traffic to External LB IPs on non-service ports. Custom ALLOW rules at the same priority may be overridden, blocking traffic they previously permitted.

**Fix:** Move affected ALLOW rules to priority 998.

### Scenario B — Custom DENY rules at priority 1000

The GKE-managed ALLOW rule moves from priority 1000 to 999. Custom DENY rules at priority 1000 (e.g. geo-blocking) will be bypassed since 999 takes precedence over 1000.

**Fix:** Move affected DENY rules to priority 999 (DENY wins over ALLOW at the same priority) or lower.

## Architecture

```
Scan Phase (parallel per service project)
├── External LB detection (forwarding rules API)
├── GKE cluster inventory + node pool tag extraction
└── Results collected before firewall analysis

Analysis Phase (per host/network project)
├── Firewall rules analysis (priority 999, 1000)
├── Exact node tag matching against discovered GKE node pools
│   └── Fallback to "gke-" prefix heuristic if tags unavailable
└── Quota check

Report Phase
└── Consolidated HTML/MD report with all findings
```
