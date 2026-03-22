# GKE 1.35.1 Firewall Change Discovery

Scans your GCP projects to assess the impact of the [GKE 1.35.1 firewall rule change](https://cloud.google.com/kubernetes-engine/docs/concepts/firewall-rules) for External LoadBalancer Services.

**What it checks:**
- External LoadBalancer Services across all GKE clusters
- Custom firewall rules at priority 999 and 1000 that may conflict
- Shared VPC and standalone project configurations
- Firewall quota headroom

**Output:** An interactive HTML report with sortable tables, severity badges, and remediation steps.

## Quick Start (Cloud Shell)

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/open?git_repo=https://github.com/nirforer/gke-firewall-changes.git&page=shell&tutorial=tutorial.md)

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
python3 gke_firewall_discovery.py --folder=123456789 --limit=100 --output=report.html

# Scan all projects in an org
python3 gke_firewall_discovery.py --org=987654321 --limit=200 --output=report.html

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
| `--all-projects` | Auto-discover projects (up to --limit) |
| `--limit=N` | Max projects to scan in discovery mode (default: 50) |
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
| Service/GKE projects | `roles/container.viewer` | List GKE clusters |
| Org/Folder (optional) | `roles/resourcemanager.folderViewer` | Auto-discover projects |

## What the Script Detects

### Scenario A — Custom ALLOW rules at priority 1000

After GKE 1.35.1, a new GKE-managed DENY rule at priority 1000 will block traffic to External LB IPs on non-service ports. Custom ALLOW rules at the same priority will be overridden (DENY wins at equal priority).

**Fix:** Move affected ALLOW rules to priority 998.

### Scenario B — Custom DENY rules at priority 1000

The existing GKE-managed ALLOW rule moves from priority 1000 to 999. Custom DENY rules at priority 1000 that previously blocked this traffic will now be bypassed (999 takes precedence over 1000).

**Fix:** Move affected DENY rules to priority 998.

## Architecture

```
Discovery Phase (parallel)
├── List projects in org/folder
├── Classify each: HOST / SERVICE / STANDALONE
├── Resolve shared VPC host → service project mappings
└── Check standalone projects for GKE clusters

Scan Phase (parallel per target)
├── Firewall rules analysis (priority 999, 1000)
├── External LB detection (forwarding rules API)
├── GKE cluster inventory
└── Quota check

Report Phase
└── Consolidated HTML/MD report with all findings
```
