#!/usr/bin/env bash
#
# GKE Firewall Change Discovery — Cloud Shell Quick Start
#
# This script installs dependencies, prompts for scan scope,
# runs the discovery, generates an HTML report, and serves it
# via Cloud Shell Web Preview.
#

set -o pipefail

# ============================================================
# Interactive picker — arrow keys + enter
# ============================================================
pick_one() {
  # Usage: pick_one "prompt" "option1" "option2" ...
  # Returns the selected option text to stdout
  local prompt="$1"
  shift
  local options=("$@")
  local selected=0
  local count=${#options[@]}

  # Hide cursor
  tput civis >/dev/tty 2>/dev/null

  # Print prompt
  echo "$prompt" >/dev/tty
  echo "" >/dev/tty

  # Draw options
  _draw_menu() {
    for i in "${!options[@]}"; do
      tput el >/dev/tty 2>/dev/null  # clear line
      if [ $i -eq $selected ]; then
        echo -e "  \033[1;36m❯ ${options[$i]}\033[0m" >/dev/tty
      else
        echo -e "    ${options[$i]}" >/dev/tty
      fi
    done
  }

  _draw_menu

  # Read keys
  while true; do
    read -rsn1 key </dev/tty
    case "$key" in
      $'\x1b')  # escape sequence
        read -rsn2 rest </dev/tty
        case "$rest" in
          '[A') # up
            ((selected > 0)) && ((selected--))
            ;;
          '[B') # down
            ((selected < count - 1)) && ((selected++))
            ;;
        esac
        ;;
      '')  # enter
        break
        ;;
    esac
    # Move cursor up to redraw
    tput cuu $count >/dev/tty 2>/dev/null
    _draw_menu
  done

  # Show cursor
  tput cnorm >/dev/tty 2>/dev/null
  echo "" >/dev/tty

  # Return selected option (this goes to stdout for capture)
  echo "${options[$selected]}"
}

pick_from_list() {
  # Usage: pick_from_list "prompt" < <(command that outputs lines)
  # Reads lines from stdin into an array, shows interactive picker
  # Uses fzf for type-to-filter when available, falls back to arrow-key picker
  local prompt="$1"
  local items=()
  while IFS= read -r line; do
    [ -n "$line" ] && items+=("$line")
  done

  if [ ${#items[@]} -eq 0 ]; then
    echo ""
    return
  fi

  if [ ${#items[@]} -eq 1 ]; then
    echo "  Auto-selected: ${items[0]}"  >&2
    echo "${items[0]}"
    return
  fi

  if command -v fzf &>/dev/null; then
    printf '%s\n' "${items[@]}" | fzf --height=20 --prompt="$prompt " --reverse
  else
    pick_one "$prompt" "${items[@]}"
  fi
}

# ============================================================
# Main
# ============================================================

echo ""
echo "============================================"
echo "  GKE 1.35.1 Firewall Change Discovery"
echo "============================================"
echo ""

# Install fzf if not available (needed for interactive selection)
if ! command -v fzf &>/dev/null; then
  echo "Installing fzf..."
  sudo apt-get install -y -qq fzf 2>/dev/null || true
fi

# Install dependencies
if [ ! -d ".venv" ]; then
  echo "Setting up Python environment..."
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -q -r requirements.txt
else
  source .venv/bin/activate
fi

# Check gcloud auth
if ! gcloud auth print-access-token &>/dev/null; then
  echo ""
  echo "You need to authenticate first:"
  gcloud auth login --no-launch-browser
  echo ""
fi

# Step 1: Pick scan scope
echo ""
SCOPE=$(pick_one "How would you like to scan?" \
  "Organization (scan all projects in an org)" \
  "Folder (scan all projects in a folder)" \
  "Project (scan a single project)" \
  "Host project (shared VPC — auto-discovers service projects)" \
  "Custom flags")

EXTRA_FLAGS=""

case "$SCOPE" in
  Project*)
    echo "Loading your projects..."
    PROJECTS=$(gcloud projects list --format="value(projectId)" --sort-by=projectId 2>/dev/null)
    SELECTED=$(pick_from_list "Select a project:" <<< "$PROJECTS")
    if [ -z "$SELECTED" ]; then
      echo "No projects found."
      exit 1
    fi
    EXTRA_FLAGS="--project=${SELECTED}"
    ;;

  Host*)
    echo "Loading your projects..."
    PROJECTS=$(gcloud projects list --format="value(projectId)" --sort-by=projectId 2>/dev/null)
    SELECTED=$(pick_from_list "Select the shared VPC host project:" <<< "$PROJECTS")
    if [ -z "$SELECTED" ]; then
      echo "No projects found."
      exit 1
    fi
    EXTRA_FLAGS="--host-project=${SELECTED}"
    ;;

  Folder*)
    echo "Loading your organizations..."
    ORGS=$(gcloud organizations list --format="value(ID,displayName)" 2>/dev/null | while IFS=$'\t' read -r id name; do
      echo "${id}  ${name}"
    done)
    ORG_LINE=$(pick_from_list "Select an organization:" <<< "$ORGS")
    ORG_ID=$(echo "$ORG_LINE" | awk '{print $1}')

    if [ -n "$ORG_ID" ]; then
      echo "Loading folders in org ${ORG_ID}..."
      FOLDERS=$(gcloud resource-manager folders list --organization="$ORG_ID" --format="value(ID,displayName)" 2>/dev/null | while IFS=$'\t' read -r id name; do
        echo "${id}  ${name}"
      done)
      FOLDER_LINE=$(pick_from_list "Select a folder:" <<< "$FOLDERS")
      FOLDER_ID=$(echo "$FOLDER_LINE" | awk '{print $1}')
    fi

    if [ -z "$FOLDER_ID" ]; then
      read -p "Folder ID: " FOLDER_ID
    fi

    EXTRA_FLAGS="--folder=${FOLDER_ID}"
    ;;

  Organization*)
    echo "Loading your organizations..."
    ORGS=$(gcloud organizations list --format="value(ID,displayName)" 2>/dev/null | while IFS=$'\t' read -r id name; do
      echo "${id}  ${name}"
    done)
    ORG_LINE=$(pick_from_list "Select an organization:" <<< "$ORGS")
    ORG_ID=$(echo "$ORG_LINE" | awk '{print $1}')

    if [ -z "$ORG_ID" ]; then
      read -p "Organization ID: " ORG_ID
    fi

    EXTRA_FLAGS="--org=${ORG_ID}"
    ;;

  Custom*)
    echo ""
    echo "Available flags:"
    echo "  --project=PROJECT         Scan a specific project"
    echo "  --host-project=PROJECT    Scan a shared VPC host project"
    echo "  --folder=FOLDER_ID        Scan all projects in a folder"
    echo "  --org=ORG_ID              Scan all projects in an org"
    echo "  --workers=N               Parallel workers (default: 15)"
    echo ""
    read -p "Enter flags: " EXTRA_FLAGS
    ;;
esac

echo ""
echo "Running discovery..."
echo ""

# Run the scan with HTML output and serve
python3 gke_firewall_discovery.py ${EXTRA_FLAGS} --output=report.html --serve
