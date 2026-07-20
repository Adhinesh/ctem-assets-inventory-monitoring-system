#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from xfinder_bridge import build_ctem_rows, find_host_from_url, load_bundle


def upsert_raw_report(supabase, table: str, payload: dict[str, Any]) -> None:
    supabase.table(table).upsert(payload, on_conflict="scan_id").execute()


def upsert_rows(supabase, table: str, rows: list[dict[str, Any]], conflict: str | None = None) -> None:
    if not rows:
        return
    query = supabase.table(table)
    if conflict:
        query = query.upsert(rows, on_conflict=conflict)
    else:
        query = query.insert(rows)
    query.execute()


def upsert_single_row(supabase, table: str, payload: dict[str, Any], conflict: str | None = None) -> dict[str, Any]:
    query = supabase.table(table)
    if conflict:
        query = query.upsert(payload, on_conflict=conflict)
    else:
        query = query.insert(payload)
    result = query.execute()
    if not result.data:
        raise RuntimeError(f"Failed to write row to {table}")
    return result.data[0]


def sanitize_vulnerability_row(row: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "cve_id",
        "title",
        "description",
        "cvss_score",
        "cvss_vector",
        "severity",
        "epss_score",
        "affected_software",
        "affected_versions",
        "affected_platforms",
        "fix_available",
        "patch_details",
        "workaround",
        "exploit_available",
        "exploit_maturity",
        "exploit_url",
        "vuln_references",
        "cwe_ids",
        "published_date",
        "last_modified_date",
    }
    return {key: value for key, value in row.items() if key in allowed_keys}


def derive_asset_changes(bundle: dict[str, Any], asset_map: dict[str, int], scan_finished_at: str | None) -> list[dict[str, Any]]:
    changes = bundle.get("changes") or {}
    resolved: list[dict[str, Any]] = []

    for host in changes.get("new_subdomains") or []:
        asset_id = asset_map.get(host)
        if asset_id:
            resolved.append(
                {
                    "asset_id": asset_id,
                    "change_type": "asset_discovered",
                    "field_changed": "asset_name",
                    "old_value": None,
                    "new_value": host,
                    "changed_by": "scanner_auto",
                    "source": "scanner",
                    "changed_at": scan_finished_at,
                }
            )

    for host in changes.get("removed_subdomains") or []:
        asset_id = asset_map.get(host)
        if asset_id:
            resolved.append(
                {
                    "asset_id": asset_id,
                    "change_type": "asset_decommissioned",
                    "field_changed": "asset_name",
                    "old_value": host,
                    "new_value": None,
                    "changed_by": "scanner_auto",
                    "source": "scanner",
                    "changed_at": scan_finished_at,
                }
            )

    for endpoint in changes.get("new_api_endpoints") or []:
        asset_id = asset_map.get(find_host_from_url(endpoint) or "")
        if asset_id:
            resolved.append(
                {
                    "asset_id": asset_id,
                    "change_type": "config_change",
                    "field_changed": "api_endpoints",
                    "old_value": None,
                    "new_value": endpoint,
                    "changed_by": "scanner_auto",
                    "source": "scanner",
                    "changed_at": scan_finished_at,
                }
            )

    for endpoint in changes.get("removed_api_endpoints") or []:
        asset_id = asset_map.get(find_host_from_url(endpoint) or "")
        if asset_id:
            resolved.append(
                {
                    "asset_id": asset_id,
                    "change_type": "config_change",
                    "field_changed": "api_endpoints",
                    "old_value": endpoint,
                    "new_value": None,
                    "changed_by": "scanner_auto",
                    "source": "scanner",
                    "changed_at": scan_finished_at,
                }
            )

    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description="Import an XFinder bundle into Supabase.")
    parser.add_argument("--bundle-dir", required=True, help="Directory containing XFinder JSON exports")
    parser.add_argument("--dry-run", action="store_true", help="Print the derived CTEM payloads without writing to Supabase")
    args = parser.parse_args()

    bundle = load_bundle(Path(args.bundle_dir))
    ctem = build_ctem_rows(bundle)

    if args.dry_run:
        print(json.dumps(ctem, indent=2, default=str))
        return 0

    from insert_tool import SupabaseInserter

    inserter = SupabaseInserter()
    supabase = inserter.supabase

    scan_row = ctem["scans"][0]
    xfinder_target = upsert_single_row(
        supabase,
        "xfinder_targets",
        {"domain": bundle.get("target"), "is_active": True},
        conflict="domain",
    )
    xfinder_scan = upsert_single_row(
        supabase,
        "xfinder_scans",
        {
            "source_scan_id": bundle.get("scan_id"),
            "target_id": xfinder_target["id"],
            "scan_type": scan_row.get("scan_type") or "full",
            "status": scan_row.get("status") or "completed",
            "started_at": scan_row.get("scan_started_at"),
            "finished_at": scan_row.get("scan_finished_at"),
            "duration_seconds": scan_row.get("duration_seconds"),
            "error": None,
            "output_dir": None,
        },
        conflict="source_scan_id",
    )
    xfinder_scan_id = xfinder_scan["id"]

    supabase.table("xfinder_scan_reports").upsert(
        {
            **ctem["raw_scan_report"],
            "scan_id": xfinder_scan_id,
            "source_scan_id": bundle.get("scan_id"),
        },
        on_conflict="scan_id",
    ).execute()
    supabase.table("xfinder_change_reports").upsert(
        {
            **ctem["raw_change_report"],
            "scan_id": xfinder_scan_id,
            "source_scan_id": bundle.get("scan_id"),
        },
        on_conflict="scan_id",
    ).execute()

    scan = inserter.upsert_scan(scan_row)
    scan_id = scan["scan_id"]
    scan_finished_at = scan_row.get("scan_finished_at")

    asset_map: dict[str, int] = {}
    for asset_row in ctem["assets"]:
        created = inserter.upsert_asset(asset_row)
        asset_map[asset_row["asset_name"]] = created["asset_id"]

    vuln_map: dict[str, int] = {}
    for vuln_row in ctem["vulnerabilities"]:
        sanitized_vuln_row = sanitize_vulnerability_row(vuln_row)
        created = inserter.upsert_vuln(sanitized_vuln_row)
        vuln_map[sanitized_vuln_row["cve_id"]] = created["vuln_id"]

    for dns_row in ctem["dns_records"]:
        row = dict(dns_row)
        row["asset_id"] = asset_map.get(row.pop("asset_key"), None)
        inserter.upsert_dns_record(row)

    for port_row in ctem["open_ports"]:
        row = dict(port_row)
        row["asset_id"] = asset_map.get(row.pop("asset_key"), None)
        row.pop("asset_name", None)
        row.pop("asset_exists", None)
        row.pop("ip_address", None)
        inserter.upsert_open_port(row)

    for av_row in ctem["asset_vulnerabilities"]:
        row = dict(av_row)
        row["asset_id"] = asset_map.get(row.pop("asset_key"), None)
        row["vuln_id"] = vuln_map.get(row["cve_id"])
        row["scan_id"] = scan_id
        row.pop("cve_id", None)
        if row["asset_id"] is not None and row["vuln_id"] is not None:
            inserter.upsert_asset_vuln(row)

    change_rows = derive_asset_changes(bundle, asset_map, scan_finished_at)
    if change_rows:
        upsert_rows(supabase, "asset_changes", change_rows)

    print(
        json.dumps(
            {
                "scan_id": scan_id,
                "assets": len(ctem["assets"]),
                "vulnerabilities": len(ctem["vulnerabilities"]),
                "open_ports": len(ctem["open_ports"]),
                "dns_records": len(ctem["dns_records"]),
                "asset_changes": len(change_rows),
                "raw_reports": 2,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
