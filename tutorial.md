# GKE 1.35.1 Firewall Change Discovery

## Overview

This tool scans your GCP projects to assess the impact of the upcoming GKE 1.35.1 firewall rule change for External LoadBalancer Services.

**Time to complete**: 5-10 minutes

Click **Start** to begin.

## Setup

Install the Python dependencies:

```bash
bash run.sh
```

The script will:
1. Create a Python virtual environment
2. Install required packages
3. Prompt you for the scan scope
4. Generate an interactive HTML report
5. Serve it via Cloud Shell Web Preview

## View the Report

After the scan completes, click the **Web Preview** button in the Cloud Shell toolbar and select **Preview on port 8080**.

The report shows:
- All External LoadBalancers across your projects
- Firewall rules that need to be moved to priority 998
- Per-project summary with severity indicators

## Congratulations

You've completed the GKE firewall change impact assessment!

If the report shows issues, follow the remediation steps in the report to move affected firewall rules to priority 998 before GKE 1.35.1 rolls out.
