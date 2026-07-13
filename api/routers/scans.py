"""
routers/scans.py — All /scans endpoints.
"""
from __future__ import annotations
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from supabase import Client

from api.db import get_db

router = APIRouter(prefix="/scans", tags=["Scans"])


class ScanCreate(BaseModel):
    scan_name: Optional[str] = None
    scan_type: Optional[str] = None          # vulnerability | port | dns | compliance | pentest | full
    scanner_tool: Optional[str] = None
    scanner_version: Optional[str] = None
    initiated_by: Optional[str] = None
    target_range: Optional[str] = None
    assets_scanned: Optional[int] = 0
    total_findings: Optional[int] = 0
    critical_findings: Optional[int] = 0
    high_findings: Optional[int] = 0
    medium_findings: Optional[int] = 0
    low_findings: Optional[int] = 0
    new_assets_found: Optional[int] = 0
    scan_started_at: Optional[datetime] = None
    scan_finished_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    status: Optional[str] = "running"        # running | completed | failed | cancelled
    error_message: Optional[str] = None
    notes: Optional[str] = None


@router.get("/", summary="List all scan runs")
def list_scans(
    status: Optional[str] = Query(None, description="running | completed | failed | cancelled"),
    limit:  int           = Query(50, ge=1, le=200),
    offset: int           = Query(0, ge=0),
    db: Client = Depends(get_db),
):
    q = db.table("scans").select("*")
    if status:
        q = q.eq("status", status)
    res = q.order("scan_started_at", desc=True).range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/{scan_id}", summary="Get a scan with its snapshots")
def get_scan(scan_id: int, db: Client = Depends(get_db)):
    """Return a scan record plus all per-asset snapshots captured in that run."""
    res = db.table("scans").select("*").eq("scan_id", scan_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    scan = res.data[0]

    snap_res = (
        db.table("scan_snapshots")
        .select("*, assets(asset_name, ip_address, criticality)")
        .eq("scan_id", scan_id)
        .execute()
    )
    scan["snapshots"] = snap_res.data
    return scan


@router.post("/", summary="Create a new scan record", status_code=201)
def create_scan(payload: ScanCreate, db: Client = Depends(get_db)):
    data = payload.model_dump(exclude_none=True)
    for field in ("scan_started_at", "scan_finished_at"):
        if field in data and data[field] is not None:
            data[field] = data[field].isoformat()
    res = db.table("scans").insert(data).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create scan")
    return res.data[0]


@router.patch("/{scan_id}/complete", summary="Mark a scan as completed")
def complete_scan(scan_id: int, db: Client = Depends(get_db)):
    """Update a running scan to completed status."""
    res = db.table("scans").select("scan_id").eq("scan_id", scan_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    update = {
        "status": "completed",
        "scan_finished_at": datetime.utcnow().isoformat(),
    }
    res = db.table("scans").update(update).eq("scan_id", scan_id).execute()
    return res.data[0]
