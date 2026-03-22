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
  python gke_firewall_discovery.py --org=ORG_ID
  python gke_firewall_discovery.py --output=report.html

Prerequisites:
  - Application Default Credentials: gcloud auth application-default login
  - Or a service account with roles/compute.viewer + roles/container.viewer
"""

import argparse
import os
import subprocess
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress noisy warnings from google-auth and gRPC
warnings.filterwarnings("ignore", message="Your application has authenticated using end user credentials")
os.environ["GRPC_VERBOSITY"] = "ERROR"
os.environ["GLOG_minloglevel"] = "2"

from gke_fw.output import Colors, status, progress_error
from gke_fw.output import C as _default_colors
import gke_fw.output as output_mod
from gke_fw.clients import get_clients
from gke_fw.targets import discover_targets
from gke_fw.scanner import scan_target
from gke_fw.report import print_report, generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="GKE Firewall Change Discovery (GCP API version)",
    )
    parser.add_argument("--org", default="", help="Scan projects in this organization")
    parser.add_argument("--folder", default="", help="Scan projects in this folder")
    parser.add_argument("--host-project", action="append", default=[], help="Shared VPC host (repeatable)")
    parser.add_argument("--project", action="append", default=[], help="Standalone project (repeatable)")
    parser.add_argument("--all-projects", action="store_true", help="Scan all accessible projects")
    parser.add_argument("--workers", type=int, default=15, help="Parallel workers (default: 15)")
    parser.add_argument("--output", default="", help="Write report to file (.md or .html)")
    parser.add_argument("--serve", action="store_true", help="Serve HTML report on port 8080 (for Cloud Shell Web Preview)")
    parser.add_argument("--port", type=int, default=8080, help="Port for --serve (default: 8080)")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()
    use_color = not args.no_color and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    output_mod.C = Colors(use_color)
    output_mod.VERBOSE = args.verbose

    # Auth check
    try:
        get_clients()
        account = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        status(f"Authenticated as {account or 'unknown'}")
    except Exception as e:
        print(f"ERROR: Authentication failed: {e}", file=sys.stderr)
        print("Run: gcloud auth login", file=sys.stderr)
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
    C = output_mod.C
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

    # Terminal report
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

        if not is_html:
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
                if self.path == "/" or self.path.startswith("/?"):
                    self.path = f"/{report_name}"
                return super().do_GET()
            def log_message(self, fmt, *a):
                pass

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
