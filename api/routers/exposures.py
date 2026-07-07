"""
routers/exposures.py — All /exposures endpoints.
"""
from __future__ import annotations
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from supabase import Client

from api.db import get_db

router = APIRouter(prefix="/exposures", tags=["Exposures"])


class ExposureCreate(BaseModel):
    asset_id: Optional[int] = None
    vuln_id: Optional[int] = None
    exposure_type: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    risk_score: Optional[int] = None
    business_impact: Optional[str] = None
    status: Optional[str] = "active"
    assigned_to: Optional[str] = None
    escalated: Optional[bool] = False
    sla_deadline: Optional[datetime] = None
    description: Optional[str] = None


def _exposure_or_404(db: Client, exposure_id: int) -> dict:
    res = db.table("exposures").select("*").eq("exposure_id", exposure_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Exposure {exposure_id} not found")
    return res.data[0]


@router.get("/", summary="List all exposures")
def list_exposures(
    status:     Optional[str] = Query(None, description="active | mitigated | accepted | closed"),
    risk_score_min: Optional[int] = Query(None, ge=1, le=100, description="Min risk score"),
    asset_id:   Optional[int] = Query(None),
    escalated:  Optional[bool] = Query(None),
    limit:      int           = Query(100, ge=1, le=500),
    offset:     int           = Query(0, ge=0),
    db: Client = Depends(get_db),
):
    """List active threat exposures. Filter by status, risk score, or escalation flag."""
    q = db.table("exposures").select(
        "exposure_id, exposure_type, attack_vector, risk_score, business_impact, "
        "status, assigned_to, escalated, identified_on, closed_on, sla_deadline, description, "
        "assets(asset_name, ip_address, criticality), "
        "vulnerabilities(cve_id, title, cvss_score)"
    )
    if status:
        q = q.eq("status", status)
    if asset_id:
        q = q.eq("asset_id", asset_id)
    if escalated is not None:
        q = q.eq("escalated", escalated)
    if risk_score_min is not None:
        q = q.gte("risk_score", risk_score_min)
    res = q.order("risk_score", desc=True).range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/{exposure_id}", summary="Get a single exposure")
def get_exposure(exposure_id: int, db: Client = Depends(get_db)):
    res = (
        db.table("exposures")
        .select("*, assets(asset_name, ip_address, criticality), vulnerabilities(cve_id, title, cvss_score, severity)")
        .eq("exposure_id", exposure_id)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Exposure {exposure_id} not found")
    return res.data[0]


@router.post("/", summary="Create a new exposure", status_code=201)
def create_exposure(payload: ExposureCreate, db: Client = Depends(get_db)):
    data = payload.model_dump(exclude_none=True)
    if "sla_deadline" in data and data["sla_deadline"]:
        data["sla_deadline"] = data["sla_deadline"].isoformat()
    res = db.table("exposures").insert(data).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create exposure")
    return res.data[0]


@router.patch("/{exposure_id}/close", summary="Close/mitigate an exposure")
def close_exposure(exposure_id: int, db: Client = Depends(get_db)):
    """Mark an exposure as closed and record the closed_on timestamp."""
    _exposure_or_404(db, exposure_id)
    res = (
        db.table("exposures")
        .update({"status": "closed", "closed_on": datetime.utcnow().isoformat()})
        .eq("exposure_id", exposure_id)
        .execute()
    )
    return res.data[0]


@router.patch("/{exposure_id}/escalate", summary="Escalate an exposure")
def escalate_exposure(exposure_id: int, db: Client = Depends(get_db)):
    """Set escalated=true on an exposure."""
    _exposure_or_404(db, exposure_id)
    res = (
        db.table("exposures")
        .update({"escalated": True})
        .eq("exposure_id", exposure_id)
        .execute()
    )
    return res.data[0]
