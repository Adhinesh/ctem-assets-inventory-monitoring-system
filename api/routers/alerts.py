"""
routers/alerts.py — Alerts stored from the monitoring pipeline.

Alerts are persisted to the `monitoring_logs` directory as JSON by the existing
monitor.py. This router reads from Supabase's exposures table and asset_changes
for structured alert data, and also provides a direct way to acknowledge them.

For real-time alert generation, POST /monitor/run.
"""
from __future__ import annotations
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from supabase import Client

from api.db import get_db

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/changes", summary="Recent asset field changes (alerts)")
def list_change_alerts(
    change_type: Optional[str] = Query(None, description="ip_change | os_update | status_change | owner_change | criticality_change | ..."),
    asset_id:    Optional[int] = Query(None),
    since:       Optional[str] = Query(None, description="ISO datetime — show changes after this time, e.g. 2024-06-01T00:00:00"),
    limit:       int           = Query(100, ge=1, le=500),
    db: Client = Depends(get_db),
):
    """
    Return asset change events from the audit trail. Each change record is effectively
    an alert — it tells you something changed on an asset.
    """
    q = db.table("asset_changes").select(
        "change_id, change_type, field_changed, old_value, new_value, "
        "changed_by, source, change_reason, changed_at, notes, "
        "assets(asset_id, asset_name, ip_address, criticality)"
    )
    if change_type:
        q = q.eq("change_type", change_type)
    if asset_id:
        q = q.eq("asset_id", asset_id)
    if since:
        q = q.gte("changed_at", since)
    res = q.order("changed_at", desc=True).limit(limit).execute()
    latest_changed_at = res.data[0]["changed_at"] if res.data else since
    return {
        "total": len(res.data),
        "since": since,
        "latest_changed_at": latest_changed_at,
        "server_time": datetime.utcnow().isoformat(),
        "data": res.data,
    }


@router.get("/exposures", summary="Active high-risk exposures as alerts")
def list_exposure_alerts(
    min_risk_score: int = Query(70, ge=1, le=100, description="Only return exposures above this risk score"),
    db: Client = Depends(get_db),
):
    """
    Return active exposures sorted by risk score — these are the highest-priority
    alerts in the system. Defaults to risk_score >= 70.
    """
    res = (
        db.table("exposures")
        .select("*, assets(asset_name, ip_address, criticality), vulnerabilities(cve_id, title, cvss_score)")
        .eq("status", "active")
        .gte("risk_score", min_risk_score)
        .order("risk_score", desc=True)
        .execute()
    )
    return {"total": len(res.data), "data": res.data}


@router.get("/logs", summary="Asset event log alerts (warning/critical level)")
def list_log_alerts(
    log_level: str = Query("warning", description="warning | error | critical"),
    asset_id:  Optional[int] = Query(None),
    limit:     int           = Query(100, ge=1, le=500),
    db: Client = Depends(get_db),
):
    """
    Return asset event log entries filtered to a minimum log level.
    Use this for SIEM-style alert feeds.
    """
    level_map = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}
    min_level = level_map.get(log_level, 2)
    valid_levels = [lvl for lvl, rank in level_map.items() if rank >= min_level]

    q = (
        db.table("asset_logs")
        .select("*, assets(asset_name, ip_address, criticality)")
        .in_("log_level", valid_levels)
        .order("logged_at", desc=True)
        .limit(limit)
    )
    if asset_id:
        q = q.eq("asset_id", asset_id)
    res = q.execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/summary", summary="Alert summary counts")
def alert_summary(db: Client = Depends(get_db)):
    """
    Return headline numbers: how many of each kind of alert exist today.
    Useful for dashboard widgets.
    """
    from datetime import date
    today = date.today().isoformat()

    # Count today's changes
    changes = (
        db.table("asset_changes")
        .select("change_id", count="exact")
        .gte("changed_at", today)
        .execute()
    )
    # Count active exposures
    active_exp = (
        db.table("exposures")
        .select("exposure_id", count="exact")
        .eq("status", "active")
        .execute()
    )
    # Count critical active exposures
    critical_exp = (
        db.table("exposures")
        .select("exposure_id", count="exact")
        .eq("status", "active")
        .gte("risk_score", 80)
        .execute()
    )
    # Count warning/error/critical logs today
    log_alerts = (
        db.table("asset_logs")
        .select("log_id", count="exact")
        .in_("log_level", ["warning", "error", "critical"])
        .gte("logged_at", today)
        .execute()
    )

    return {
        "changes_today": changes.count or 0,
        "active_exposures": active_exp.count or 0,
        "critical_exposures": critical_exp.count or 0,
        "log_alerts_today": log_alerts.count or 0,
    }
