"""
routers/dashboard.py — Summary statistics for dashboards.
"""
from __future__ import annotations
from datetime import date
from fastapi import APIRouter, Depends
from supabase import Client

from api.db import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", summary="Get overall CTEM dashboard summary")
def dashboard_summary(db: Client = Depends(get_db)):
    """
    Returns a high-level summary of the entire CTEM posture:
    - Asset counts by criticality and status
    - Vulnerability counts by severity
    - Open exposure counts
    - Alert counts
    - Recent activity
    """
    today = date.today().isoformat()

    # ── Assets ────────────────────────────────────────────────────────────────
    all_assets = db.table("assets").select("asset_id, criticality, status, environment").execute().data
    total_assets = len(all_assets)
    assets_by_criticality = {}
    assets_by_status = {}
    for a in all_assets:
        c = a.get("criticality", "unknown")
        s = a.get("status", "unknown")
        assets_by_criticality[c] = assets_by_criticality.get(c, 0) + 1
        assets_by_status[s] = assets_by_status.get(s, 0) + 1

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    all_vulns = db.table("vulnerabilities").select("vuln_id, severity, exploit_available, fix_available").execute().data
    total_vulns = len(all_vulns)
    vulns_by_severity = {}
    exploitable = 0
    unpatched = 0
    for v in all_vulns:
        sev = v.get("severity", "unknown")
        vulns_by_severity[sev] = vulns_by_severity.get(sev, 0) + 1
        if v.get("exploit_available"):
            exploitable += 1
        if not v.get("fix_available"):
            unpatched += 1

    # ── Asset-Vulnerability Links ─────────────────────────────────────────────
    open_av = (
        db.table("asset_vulnerabilities")
        .select("id", count="exact")
        .eq("status", "open")
        .execute()
    )

    # ── Exposures ─────────────────────────────────────────────────────────────
    active_exp = (
        db.table("exposures")
        .select("exposure_id, risk_score", count="exact")
        .eq("status", "active")
        .execute()
    )
    avg_risk = 0
    if active_exp.data:
        scores = [e["risk_score"] for e in active_exp.data if e.get("risk_score")]
        avg_risk = round(sum(scores) / len(scores), 1) if scores else 0

    # ── Recent Changes (today) ────────────────────────────────────────────────
    recent_changes = (
        db.table("asset_changes")
        .select("change_id", count="exact")
        .gte("changed_at", today)
        .execute()
    )

    # ── Recent Scans ──────────────────────────────────────────────────────────
    latest_scan = (
        db.table("scans")
        .select("scan_id, scan_name, status, scan_started_at, total_findings")
        .order("scan_started_at", desc=True)
        .limit(1)
        .execute()
        .data
    )

    return {
        "generated_at": date.today().isoformat(),
        "assets": {
            "total": total_assets,
            "by_criticality": assets_by_criticality,
            "by_status": assets_by_status,
        },
        "vulnerabilities": {
            "total": total_vulns,
            "by_severity": vulns_by_severity,
            "exploitable": exploitable,
            "unpatched": unpatched,
            "open_asset_links": open_av.count or 0,
        },
        "exposures": {
            "active": active_exp.count or 0,
            "average_risk_score": avg_risk,
        },
        "alerts": {
            "changes_today": recent_changes.count or 0,
        },
        "latest_scan": latest_scan[0] if latest_scan else None,
    }


@router.get("/risk-overview", summary="Per-asset risk overview")
def risk_overview(
    limit: int = 20,
    db: Client = Depends(get_db),
):
    """Return top N assets sorted by number of open critical/high vulnerabilities."""
    # Get asset-vuln links joined with vuln severity
    res = (
        db.table("asset_vulnerabilities")
        .select("asset_id, assets(asset_name, ip_address, criticality), vulnerabilities(severity, cvss_score)")
        .eq("status", "open")
        .execute()
    )

    # Aggregate per asset
    asset_map: dict = {}
    for row in res.data:
        aid = row["asset_id"]
        if aid not in asset_map:
            a = row.get("assets") or {}
            asset_map[aid] = {
                "asset_id": aid,
                "asset_name": a.get("asset_name"),
                "ip_address": a.get("ip_address"),
                "criticality": a.get("criticality"),
                "open_vulns": 0,
                "critical_vulns": 0,
                "high_vulns": 0,
                "max_cvss": 0.0,
            }
        v = row.get("vulnerabilities") or {}
        sev = v.get("severity", "")
        cvss = v.get("cvss_score") or 0
        asset_map[aid]["open_vulns"] += 1
        if sev == "critical":
            asset_map[aid]["critical_vulns"] += 1
        elif sev == "high":
            asset_map[aid]["high_vulns"] += 1
        if cvss > asset_map[aid]["max_cvss"]:
            asset_map[aid]["max_cvss"] = cvss

    ranked = sorted(asset_map.values(), key=lambda x: (x["critical_vulns"], x["high_vulns"], x["max_cvss"]), reverse=True)
    return {"total": len(ranked), "data": ranked[:limit]}
