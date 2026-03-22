#!/usr/bin/env bash
#
# GKE Firewall Change Discovery — Cloud Shell Quick Start
#
# This script installs dependencies, prompts for scan scope,
# runs the discovery, generates an HTML report, and serves it
# via Cloud Shell Web Preview.
#

set -o pipefail

echo ""
echo "============================================"
echo "  GKE 1.35.1 Firewall Change Discovery"
echo "============================================"
echo ""

# Install dependencies
if [ ! -d ".venv" ]; then
  echo "Setting up Python environment..."
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -q -r requirements.txt
else
  source .venv/bin/activate
fi

# Check auth
if ! gcloud auth application-default print-access-token &>/dev/null; then
  echo ""
  echo "You need to authenticate first:"
  echo ""
  gcloud auth application-default login
  echo ""
fi

# Prompt for scan scope
echo ""
echo "How would you like to scan?"
echo ""
echo "  1) Specific project (fastest)"
echo "  2) Shared VPC host project (auto-discovers service projects)"
echo "  3) Folder (scans all projects in a folder)"
echo "  4) Organization (scans all projects in an org)"
echo "  5) Custom (enter your own flags)"
echo ""
read -p "Choice [1-5]: " CHOICE

EXTRA_FLAGS=""

case "$CHOICE" in
  1)
    read -p "Project ID: " PROJECT_ID
    EXTRA_FLAGS="--project=${PROJECT_ID}"
    ;;
  2)
    read -p "Host project ID: " HOST_PROJECT
    EXTRA_FLAGS="--host-project=${HOST_PROJECT}"
    ;;
  3)
    read -p "Folder ID: " FOLDER_ID
    read -p "Max projects to scan [50]: " LIMIT
    LIMIT=${LIMIT:-50}
    EXTRA_FLAGS="--folder=${FOLDER_ID} --limit=${LIMIT}"
    ;;
  4)
    # List orgs for convenience
    echo ""
    echo "Your accessible organizations:"
    gcloud organizations list --format="table(ID,displayName)" 2>/dev/null
    echo ""
    read -p "Organization ID: " ORG_ID
    read -p "Max projects to scan [50]: " LIMIT
    LIMIT=${LIMIT:-50}
    EXTRA_FLAGS="--org=${ORG_ID} --limit=${LIMIT}"
    ;;
  5)
    echo ""
    echo "Available flags:"
    echo "  --project=PROJECT         Scan a specific project"
    echo "  --host-project=PROJECT    Scan a shared VPC host project"
    echo "  --folder=FOLDER_ID        Scan all projects in a folder"
    echo "  --org=ORG_ID              Scan all projects in an org"
    echo "  --limit=N                 Max projects to scan (default: 50)"
    echo "  --workers=N               Parallel workers (default: 15)"
    echo ""
    read -p "Enter flags: " EXTRA_FLAGS
    ;;
  *)
    echo "Invalid choice. Exiting."
    exit 1
    ;;
esac

echo ""
echo "Running discovery..."
echo ""

# Run the scan with HTML output and serve
python3 gke_firewall_discovery.py ${EXTRA_FLAGS} --output=report.html --serve
