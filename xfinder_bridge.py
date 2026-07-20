from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, DefaultDict, Iterable
from urllib.parse import urlparse


TEAM1_FILES = {
    "subdomains": "subdomains.json",
    "dns": "dns.json",
    "http": "http.json",
    "cloud": "cloud.json",
    "ports": "ports.json",
    "services": "services.json",
    "technologies": "technologies.json",
    "api": "api.json",
    "vulnerabilities": "vulnerabilities.json",
    "changes": "changes.json",
    "full_scan": "full_scan.json",
}


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    bundle_path = Path(bundle_dir)
    bundle: dict[str, Any] = {}
    for key, filename in TEAM1_FILES.items():
        bundle[key] = load_json(bundle_path / filename)

    meta_source = next((bundle[name] for name in ("full_scan", "subdomains", "dns", "http") if bundle.get(name)), None)
    if meta_source is None:
        raise ValueError(f"No XFinder JSON files found in {bundle_path}")

    bundle["scan_id"] = meta_source.get("scan_id")
    bundle["target"] = meta_source.get("target")
    bundle["exported_at"] = meta_source.get("exported_at")
    return bundle


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def root_domain(host: str | None) -> str | None:
    if not host:
        return None
    parts = host.split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def subdomain_label(host: str | None, domain: str | None) -> str | None:
    if not host:
        return None
    if not domain:
        return host
    if host == domain:
        return None
    suffix = f".{domain}"
    if host.endswith(suffix):
        return host[: -len(suffix)]
    return host


def normalize_protocol(protocol: str | None) -> str:
    return (protocol or "tcp").upper()


def normalize_provider(provider: str | None) -> str | None:
    if not provider:
        return None
    return provider.strip().lower()


def parse_ip(value: str | None) -> ipaddress._BaseAddress | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def pick_primary_ip(addresses: Iterable[str]) -> str | None:
    ip_values = [addr for addr in addresses if addr]
    if not ip_values:
        return None
    ipv4 = next((addr for addr in ip_values if (parsed := parse_ip(addr)) and parsed.version == 4), None)
    return ipv4 or ip_values[0]


def split_references(value: str | None) -> list[dict[str, str]]:
    if not value:
        return []
    references: list[dict[str, str]] = []
    for index, chunk in enumerate(
        part.strip() for part in value.replace("\n", ",").split(",") if part.strip()
    ):
        references.append({"url": chunk, "label": f"Reference {index + 1}"})
    return references


def find_host_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    return parsed.hostname


def infer_cloud_profile(http_entries: list[dict[str, Any]], cloud_entry: dict[str, Any] | None) -> dict[str, Any]:
    if cloud_entry:
        return {
            "provider": normalize_provider(cloud_entry.get("provider")),
            "cdn": cloud_entry.get("cdn"),
            "waf": cloud_entry.get("waf"),
            "is_cloud_hosted": bool(cloud_entry.get("is_cloud_hosted")),
            "evidence": cloud_entry.get("evidence"),
        }

    combined_text = " ".join(
        filter(
            None,
            [
                *(str(entry.get("server_header") or "") for entry in http_entries),
                *(str(entry.get("webserver") or "") for entry in http_entries),
                " ".join(
                    tech for entry in http_entries for tech in (entry.get("technologies") or [])
                ),
            ],
        )
    ).lower()

    if "cloudflare" in combined_text:
        return {
            "provider": "cloudflare",
            "cdn": "Cloudflare",
            "waf": "Cloudflare",
            "is_cloud_hosted": True,
            "evidence": "Inferred from Cloudflare headers or technologies",
        }
    if any(token in combined_text for token in ("amazon", "aws", "cloudfront")):
        return {
            "provider": "aws",
            "cdn": None,
            "waf": None,
            "is_cloud_hosted": True,
            "evidence": "Inferred from AWS/CloudFront headers or technologies",
        }
    if any(token in combined_text for token in ("azure", "microsoft")):
        return {
            "provider": "azure",
            "cdn": None,
            "waf": None,
            "is_cloud_hosted": True,
            "evidence": "Inferred from Azure/Microsoft headers or technologies",
        }
    if "gcp" in combined_text or "google cloud" in combined_text:
        return {
            "provider": "gcp",
            "cdn": None,
            "waf": None,
            "is_cloud_hosted": True,
            "evidence": "Inferred from GCP headers or technologies",
        }
    return {
        "provider": None,
        "cdn": None,
        "waf": None,
        "is_cloud_hosted": False,
        "evidence": None,
    }


def build_ctem_rows(bundle: dict[str, Any]) -> dict[str, Any]:
    target = bundle.get("target")
    scan_id = bundle.get("scan_id")
    exported_at = bundle.get("exported_at")
    full_scan = bundle.get("full_scan") or {}
    subdomains = (bundle.get("subdomains") or {}).get("data", [])
    dns_rows = (bundle.get("dns") or {}).get("data", [])
    http_rows = (bundle.get("http") or {}).get("data", [])
    cloud_rows = (bundle.get("cloud") or {}).get("data", [])
    ports_rows = (bundle.get("ports") or {}).get("data", [])
    services_rows = (bundle.get("services") or {}).get("data", [])
    vulns_rows = (bundle.get("vulnerabilities") or {}).get("data", [])
    api_rows = (bundle.get("api") or {}).get("data", [])

    cloud_by_subdomain_id = {row.get("subdomain_id"): row for row in cloud_rows if row.get("subdomain_id") is not None}
    http_by_host = {row.get("host"): row for row in http_rows if row.get("host")}
    services_by_key = {
        (row.get("ip"), row.get("port"), normalize_protocol(row.get("protocol"))): row
        for row in services_rows
    }
    dns_by_host: DefaultDict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in dns_rows:
        if row.get("host"):
            dns_by_host[row["host"]].append(row)

    hosts = set(subdomains)
    hosts.update(row.get("host") for row in http_rows if row.get("host"))
    hosts.update(row.get("host") for row in ports_rows if row.get("host"))
    hosts.update(row.get("host") for row in dns_rows if row.get("host"))
    hosts.update(find_host_from_url(row.get("matched_url")) for row in vulns_rows if row.get("matched_url"))
    hosts.discard(None)

    asset_rows: list[dict[str, Any]] = []
    asset_lookup: dict[str, dict[str, Any]] = {}
    scan_timestamp = parse_timestamp(full_scan.get("timestamp") or exported_at)
    cloud_profile = infer_cloud_profile(http_rows, cloud_rows[0] if cloud_rows else None)

    for host in sorted(hosts):
        http_entry = http_by_host.get(host)
        host_ips = []
        host_technologies: list[str] = []
        if http_entry:
            host_ips.extend(http_entry.get("ips") or [])
            host_technologies.extend(http_entry.get("technologies") or [])
        for dns_entry in dns_by_host.get(host, []):
            if dns_entry.get("type") in {"A", "AAAA"} and dns_entry.get("value"):
                host_ips.append(dns_entry["value"])
        for port_entry in ports_rows:
            if port_entry.get("host") == host and port_entry.get("ip"):
                host_ips.append(port_entry["ip"])

        primary_ip = pick_primary_ip(host_ips)
        secondary_ips = [ip for ip in dict.fromkeys(host_ips) if ip != primary_ip]

        asset_row = {
            "asset_name": host,
            "asset_type": "server",
            "hostname": host,
            "fqdn": host,
            "ip_address": primary_ip,
            "secondary_ips": secondary_ips,
            "network_zone": "cloud_vpc" if cloud_profile.get("is_cloud_hosted") else "external",
            "operating_system": None,
            "installed_software": [{"name": name, "version": None} for name in dict.fromkeys(host_technologies)],
            "cloud_provider": cloud_profile.get("provider"),
            "cloud_region": None,
            "cloud_instance_id": None,
            "physical_location": None,
            "owner": None,
            "department": None,
            "business_unit": None,
            "contact_email": None,
            "environment": "production",
            "criticality": "medium",
            "data_classification": "internal",
            "status": "active",
            "tags": {
                "source": "xfinder",
                "scan_id": scan_id,
                "target": target,
                "technologies": host_technologies,
            },
            "first_seen": scan_timestamp.isoformat() if scan_timestamp else None,
            "last_seen": scan_timestamp.isoformat() if scan_timestamp else None,
        }
        if http_entry:
            asset_row["status"] = "active" if http_entry.get("status_code") is not None else "inactive"
            asset_row["tags"]["http_status_code"] = http_entry.get("status_code")
            asset_row["tags"]["server_header"] = http_entry.get("server_header")
            asset_row["tags"]["scheme"] = http_entry.get("scheme")
            asset_row["tags"]["title"] = http_entry.get("title")
        if http_entry and http_entry.get("webserver"):
            asset_row["operating_system"] = http_entry.get("webserver")
        if cloud_profile.get("provider"):
            asset_row["cloud_provider"] = cloud_profile.get("provider")
        asset_rows.append(asset_row)
        asset_lookup[host] = asset_row

    scan_started_at = scan_timestamp - timedelta(seconds=float(full_scan.get("duration_seconds") or 0)) if scan_timestamp else None
    scan_row = {
        "scan_name": f"{target} - {full_scan.get('scan_type') or 'full'} - {full_scan.get('timestamp') or exported_at}",
        "scan_type": full_scan.get("scan_type") or "full",
        "scanner_tool": "XFinder",
        "initiated_by": "scheduler",
        "target_range": target,
        "assets_scanned": len(subdomains),
        "total_findings": int((full_scan.get("scanners") or {}).get("nuclei", {}).get("summary", {}).get("count") or 0),
        "critical_findings": int((full_scan.get("scanners") or {}).get("nuclei", {}).get("summary", {}).get("by_severity", {}).get("critical") or 0),
        "high_findings": int((full_scan.get("scanners") or {}).get("nuclei", {}).get("summary", {}).get("by_severity", {}).get("high") or 0),
        "medium_findings": int((full_scan.get("scanners") or {}).get("nuclei", {}).get("summary", {}).get("by_severity", {}).get("medium") or 0),
        "low_findings": int((full_scan.get("scanners") or {}).get("nuclei", {}).get("summary", {}).get("by_severity", {}).get("low") or 0),
        "new_assets_found": 0,
        "scan_started_at": scan_started_at.isoformat() if scan_started_at else None,
        "scan_finished_at": scan_timestamp.isoformat() if scan_timestamp else None,
        "duration_seconds": int(round(float(full_scan.get("duration_seconds") or 0))),
        "status": "completed"
        if all((scanner.get("success", True) for scanner in (full_scan.get("scanners") or {}).values()))
        else "failed",
        "notes": "Imported from XFinder bundle",
    }

    open_ports_rows: list[dict[str, Any]] = []
    for row in ports_rows:
        host = row.get("host")
        asset = asset_lookup.get(host or "")
        service_key = (row.get("ip"), row.get("port"), normalize_protocol(row.get("protocol")))
        service = services_by_key.get(service_key, {})
        open_ports_rows.append(
            {
                "asset_key": host,
                "asset_name": host,
                "port_number": row.get("port"),
                "protocol": normalize_protocol(row.get("protocol")),
                "state": service.get("state") or "open",
                "service_name": service.get("name"),
                "service_version": service.get("version"),
                "service_product": service.get("product"),
                "banner": service.get("extra"),
                "is_expected": row.get("port") in {80, 443, 53, 25, 110, 143, 587},
                "risk_level": (
                    "critical"
                    if row.get("port") in {22, 3389, 445, 8443}
                    else "high"
                    if row.get("port") in {8080, 8081, 8000}
                    else "medium"
                    if row.get("port") in {21, 23, 3306, 5432, 9200}
                    else "low"
                ),
                "notes": None,
                "ip_address": row.get("ip"),
                "asset_exists": bool(asset),
            }
        )

    vuln_rows: list[dict[str, Any]] = []
    asset_vuln_rows: list[dict[str, Any]] = []
    for row in vulns_rows:
        matched_host = find_host_from_url(row.get("matched_url"))
        vuln_rows.append(
            {
                "cve_id": row.get("template_id"),
                "title": row.get("name") or row.get("template_id"),
                "description": row.get("description"),
                "cvss_score": row.get("cvss_score"),
                "severity": row.get("severity"),
                "fix_available": False,
                "exploit_available": bool(row.get("evidence")),
                "exploit_maturity": "poc" if row.get("evidence") else "unproven",
                "vuln_references": split_references(row.get("reference_urls")),
                "cwe_ids": row.get("tags"),
                "published_date": None,
                "last_modified_date": None,
                "matched_url": row.get("matched_url"),
                "matched_at": row.get("matched_at"),
                "evidence": row.get("evidence"),
                "tags": row.get("tags"),
            }
        )
        if matched_host and matched_host in asset_lookup:
            priority = "urgent" if row.get("severity") in {"high", "critical"} else "high" if row.get("severity") == "medium" else "medium"
            asset_vuln_rows.append(
                {
                    "asset_key": matched_host,
                    "cve_id": row.get("template_id"),
                    "status": "open",
                    "priority": priority,
                    "assigned_to": None,
                    "detected_on": scan_started_at.date().isoformat() if scan_started_at else None,
                    "remediated_on": None,
                    "due_date": None,
                    "last_seen": scan_started_at.date().isoformat() if scan_started_at else None,
                    "affected_component": matched_host,
                    "proof_of_concept": row.get("evidence"),
                    "notes": row.get("description"),
                }
            )

    dns_rows_ctem: list[dict[str, Any]] = []
    for row in dns_rows:
        host = row.get("host")
        dns_rows_ctem.append(
            {
                "asset_key": host,
                "domain": root_domain(host),
                "subdomain": subdomain_label(host, root_domain(host)),
                "fqdn": host,
                "record_type": row.get("type"),
                "record_value": row.get("value"),
                "ttl": row.get("ttl"),
                "is_internal": False,
                "is_wildcard": bool(host and host.startswith("*.")),
                "status": "active",
                "risk_notes": None,
                "registrar": None,
                "dns_provider": None,
                "expires_at": None,
            }
        )

    changes = bundle.get("changes") or {}
    raw_change_report = {
        "scan_id": scan_id,
        "previous_scan_id": changes.get("previous_scan_id"),
        "generated_at": changes.get("generated_at"),
        "new_subdomains": changes.get("new_subdomains") or [],
        "removed_subdomains": changes.get("removed_subdomains") or [],
        "new_ports": changes.get("new_ports") or [],
        "closed_ports": changes.get("closed_ports") or [],
        "new_technologies": changes.get("new_technologies") or [],
        "removed_technologies": changes.get("removed_technologies") or [],
        "dns_changes": changes.get("dns_changes") or [],
        "cloud_changes": changes.get("cloud_changes") or [],
        "new_vulnerabilities": changes.get("new_vulnerabilities") or [],
        "resolved_vulnerabilities": changes.get("resolved_vulnerabilities") or [],
        "new_api_endpoints": changes.get("new_api_endpoints") or [],
        "removed_api_endpoints": changes.get("removed_api_endpoints") or [],
        "summary": changes.get("summary") or {},
    }

    raw_scan_report = {
        "scan_id": scan_id,
        "target": target,
        "scan_type": full_scan.get("scan_type") or "full",
        "timestamp": full_scan.get("timestamp") or exported_at,
        "duration_seconds": full_scan.get("duration_seconds"),
        "scanners": full_scan.get("scanners") or {},
    }

    return {
        "assets": asset_rows,
        "asset_lookup": asset_lookup,
        "scans": [scan_row],
        "open_ports": open_ports_rows,
        "dns_records": dns_rows_ctem,
        "vulnerabilities": vuln_rows,
        "asset_vulnerabilities": asset_vuln_rows,
        "raw_scan_report": raw_scan_report,
        "raw_change_report": raw_change_report,
        "api_endpoints": api_rows,
    }


def build_xfinder_rows(bundle: dict[str, Any]) -> dict[str, Any]:
    target = bundle.get("target")
    scan_id = bundle.get("scan_id")
    exported_at = bundle.get("exported_at")
    full_scan = bundle.get("full_scan") or {}
    subdomains = (bundle.get("subdomains") or {}).get("data", [])
    dns_rows = (bundle.get("dns") or {}).get("data", [])
    http_rows = (bundle.get("http") or {}).get("data", [])
    cloud_rows = (bundle.get("cloud") or {}).get("data", [])
    ports_rows = (bundle.get("ports") or {}).get("data", [])
    services_rows = (bundle.get("services") or {}).get("data", [])
    technologies_rows = (bundle.get("technologies") or {}).get("data", [])
    api_rows = (bundle.get("api") or {}).get("data", [])
    vulns_rows = (bundle.get("vulnerabilities") or {}).get("data", [])
    changes = bundle.get("changes") or {}

    return {
        "targets": [{"domain": target, "created_at": exported_at, "is_active": True}],
        "scans": [
            {
                "source_scan_id": scan_id,
                "scan_type": full_scan.get("scan_type") or "full",
                "status": "completed"
                if all((scanner.get("success", True) for scanner in (full_scan.get("scanners") or {}).values()))
                else "failed",
                "started_at": (
                    parse_timestamp(full_scan.get("timestamp") or exported_at)
                    - timedelta(seconds=float(full_scan.get("duration_seconds") or 0))
                ).isoformat() if (full_scan.get("timestamp") or exported_at) else None,
                "finished_at": parse_timestamp(full_scan.get("timestamp") or exported_at).isoformat() if (full_scan.get("timestamp") or exported_at) else None,
                "duration_seconds": full_scan.get("duration_seconds"),
                "error": None,
                "output_dir": None,
            }
        ],
        "subdomains": [{"name": value, "is_resolved": False, "is_live_http": False, "source": "subfinder"} for value in subdomains],
        "dns_records": [{"host": row.get("host"), "record_type": row.get("type"), "value": row.get("value"), "ttl": row.get("ttl")} for row in dns_rows],
        "http_information": http_rows,
        "cloud_assets": cloud_rows,
        "ip_addresses": [],
        "ports": ports_rows,
        "services": services_rows,
        "technologies": technologies_rows,
        "api_endpoints": api_rows,
        "vulnerabilities": vulns_rows,
        "scan_report": {
            "scan_id": scan_id,
            "target": target,
            "scan_type": full_scan.get("scan_type") or "full",
            "timestamp": full_scan.get("timestamp") or exported_at,
            "duration_seconds": full_scan.get("duration_seconds"),
            "scanners": full_scan.get("scanners") or {},
        },
        "change_report": {
            "scan_id": scan_id,
            "previous_scan_id": changes.get("previous_scan_id"),
            "generated_at": changes.get("generated_at"),
            "new_subdomains": changes.get("new_subdomains") or [],
            "removed_subdomains": changes.get("removed_subdomains") or [],
            "new_ports": changes.get("new_ports") or [],
            "closed_ports": changes.get("closed_ports") or [],
            "new_technologies": changes.get("new_technologies") or [],
            "removed_technologies": changes.get("removed_technologies") or [],
            "dns_changes": changes.get("dns_changes") or [],
            "cloud_changes": changes.get("cloud_changes") or [],
            "new_vulnerabilities": changes.get("new_vulnerabilities") or [],
            "resolved_vulnerabilities": changes.get("resolved_vulnerabilities") or [],
            "new_api_endpoints": changes.get("new_api_endpoints") or [],
            "removed_api_endpoints": changes.get("removed_api_endpoints") or [],
            "summary": changes.get("summary") or {},
        },
    }


def build_raw_xfinder_report_rows(bundle: dict[str, Any]) -> dict[str, Any]:
    rows = build_xfinder_rows(bundle)
    return {
        "scan_report": rows["scan_report"],
        "change_report": rows["change_report"],
    }
