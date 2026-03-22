"""Project discovery — find scan targets."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import ScanTarget
from .output import status, progress_error
from .clients import (
    classify_project_api, get_service_projects_api,
    classify_and_check_gke, list_projects_in_org_api,
    list_projects_in_folder_api, get_clients,
)


def discover_targets(args, workers: int) -> list[ScanTarget]:
    targets = []
    seen_hosts = set()

    for hp in args.host_project:
        if hp in seen_hosts:
            continue
        svcs = get_service_projects_api(hp)
        if svcs:
            status(f"  Shared VPC: {hp} → {','.join(svcs)}")
            targets.append(ScanTarget(host_project=hp, service_projects=svcs, is_shared_vpc=True))
        else:
            status(f"  Standalone: {hp}")
            targets.append(ScanTarget(host_project=hp, service_projects=[hp], is_shared_vpc=False))
        seen_hosts.add(hp)

    for sp in args.project:
        cls, host = classify_project_api(sp)
        if cls == "SERVICE" and host and host not in seen_hosts:
            svcs = get_service_projects_api(host)
            status(f"  Shared VPC: {host} → {','.join(svcs) or sp} (via {sp})")
            targets.append(ScanTarget(host_project=host, service_projects=svcs or [sp], is_shared_vpc=True))
            seen_hosts.add(host)
        elif cls == "HOST" and sp not in seen_hosts:
            svcs = get_service_projects_api(sp)
            status(f"  Shared VPC: {sp} → {','.join(svcs)}")
            targets.append(ScanTarget(host_project=sp, service_projects=svcs or [sp], is_shared_vpc=True))
            seen_hosts.add(sp)
        elif cls not in ("SERVICE", "HOST"):
            status(f"  Standalone: {sp}")
            targets.append(ScanTarget(host_project=sp, service_projects=[sp], is_shared_vpc=False))

    if targets:
        return targets

    # Auto-discovery
    if args.org:
        all_projs = list_projects_in_org_api(args.org)
    elif args.folder:
        all_projs = list_projects_in_folder_api(args.folder)
    else:
        status("Listing accessible projects...")
        try:
            all_projs = [p.project_id for p in get_clients().rm_projects.search_projects()]
        except Exception:
            all_projs = []

    status(f"Found {len(all_projs)} project(s). Classifying + checking GKE in parallel...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results_map = {}
        for proj, result in zip(all_projs, executor.map(classify_and_check_gke, all_projs)):
            results_map[proj] = result

    hosts_to_resolve = set()
    for proj, (cls, host, _) in results_map.items():
        if cls == "HOST":
            hosts_to_resolve.add(proj)
        elif cls == "SERVICE" and host:
            hosts_to_resolve.add(host)

    host_svc_map = {}
    if hosts_to_resolve:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_host = {executor.submit(get_service_projects_api, hp): hp for hp in hosts_to_resolve}
            for future in as_completed(future_to_host):
                hp = future_to_host[future]
                host_svc_map[hp] = future.result()

    seen_service = set()

    for proj, (cls, _, _) in results_map.items():
        if cls == "HOST" and proj not in seen_hosts:
            svcs = host_svc_map.get(proj, [])
            status(f"  Shared VPC: {proj} → {','.join(svcs) or '(no service projects)'}")
            targets.append(ScanTarget(host_project=proj, service_projects=svcs or [proj], is_shared_vpc=bool(svcs)))
            seen_hosts.add(proj)
            seen_service.update(svcs)

    for proj, (cls, host, _) in results_map.items():
        if cls == "SERVICE" and host and host not in seen_hosts:
            svcs = host_svc_map.get(host, [])
            status(f"  Shared VPC: {host} → {','.join(svcs) or proj} (via {proj})")
            targets.append(ScanTarget(host_project=host, service_projects=svcs or [proj], is_shared_vpc=True))
            seen_hosts.add(host)
            seen_service.update(svcs or [proj])

    for proj, (cls, _, has_gke) in results_map.items():
        if cls == "STANDALONE" and has_gke and proj not in seen_hosts and proj not in seen_service:
            status(f"  Standalone: {proj}")
            targets.append(ScanTarget(host_project=proj, service_projects=[proj], is_shared_vpc=False))

    return targets
