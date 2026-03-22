# GKE 1.35.1 Firewall Change Discovery

Google sent an email (ref: 493570689) notifying customers about an upcoming change to how GKE manages firewall rules for External LoadBalancer Services. This tool helps you figure out if that change affects you.

![Report Demo](https://github.com/nirforer/gke-firewall-changes/raw/main/docs/demo.png)

## What does this tool do?

1. **Finds your External LoadBalancers** — scans your GKE clusters for Services of type LoadBalancer with external IPs. These are the services that the GKE change applies to.

2. **Checks your custom firewall rules** — looks at your VPC firewall rules at priority 999 and 1000 to see if any of them will break or be bypassed after the change.

3. **Matches rules to GKE nodes** — reads the actual network tags from your GKE node pools and checks if your custom firewall rules target those nodes. If a rule doesn't target GKE nodes, it won't be affected.

4. **Generates a report** — produces an HTML report showing exactly which rules need action, which are fine, and what to do about it.

## How does it know if you're affected?

The GKE change moves a firewall rule from priority 1000 to 999 and adds a new DENY rule at 1000. This tool checks two things:

- **Do you have custom ALLOW rules at priority 1000 that target GKE nodes?** If yes, the new DENY rule at the same priority could block traffic you need. You'd need to move those rules to a higher priority (lower number).

- **Do you have custom DENY rules at priority 1000?** If yes, the new GKE ALLOW at priority 999 will take precedence over your DENY, potentially allowing traffic you intended to block. You'd need to move those DENY rules to priority 999 or lower.

If you don't have any custom firewall rules at those priorities, or your rules don't target GKE nodes, you're not affected.

## Quick Start (Cloud Shell)

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/open?cloudshell_git_repo=https://github.com/nirforer/gke-firewall-changes.git&shellonly=true)

Or manually in Cloud Shell:

```bash
git clone https://github.com/nirforer/gke-firewall-changes.git
cd gke-firewall-changes
bash run.sh
```

The interactive wizard will prompt you for the scan scope, generate an HTML report, and serve it via Web Preview.

**To view the report:** once the scan finishes, click **Web Preview** (the icon to the right of the blue terminal button in the top-right corner of Cloud Shell) and select **Preview on port 8080**.

![Web Preview button location](https://github.com/nirforer/gke-firewall-changes/raw/main/docs/web-preview.png)

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
