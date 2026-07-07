"""
routers/vulnerabilities.py — All /vulnerabilities endpoints.
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from supabase import Client

from api.db import get_db
from api.models.vulnerability import VulnerabilityCreate, VulnerabilityUpdate

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


def _vuln_or_404(db: Client, vuln_id: int) -> dict:
    res = db.table("vulnerabilities").select("*").eq("vuln_id", vuln_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")
    return res.data[0]


@router.get("/", summary="List all vulnerabilities")
def list_vulnerabilities(
    severity:          Optional[str]  = Query(None, description="none | low | medium | high | critical"),
    exploit_available: Optional[bool] = Query(None, description="Filter to exploitable CVEs only"),
    fix_available:     Optional[bool] = Query(None, description="Filter to CVEs with a fix"),
    search:            Optional[str]  = Query(None, description="Search CVE ID or title"),
    limit:             int            = Query(100, ge=1, le=500),
    offset:            int            = Query(0, ge=0),
    db: Client = Depends(get_db),
):
    """List CVEs sorted by CVSS score descending."""
    q = db.table("vulnerabilities").select(
        "vuln_id, cve_id, title, cvss_score, severity, epss_score, "
        "exploit_available, exploit_maturity, fix_available, "
        "affected_software, published_date, created_at"
    )
    if severity:
        q = q.eq("severity", severity)
    if exploit_available is not None:
        q = q.eq("exploit_available", exploit_available)
    if fix_available is not None:
        q = q.eq("fix_available", fix_available)
    if search:
        q = q.or_(f"cve_id.ilike.%{search}%,title.ilike.%{search}%")

    res = q.order("cvss_score", desc=True).range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/cve/{cve_id}", summary="Get a vulnerability by CVE ID string")
def get_vulnerability_by_cve(cve_id: str, db: Client = Depends(get_db)):
    """Look up a vulnerability using its CVE ID (e.g. CVE-2024-1234)."""
    res = db.table("vulnerabilities").select("*").eq("cve_id", cve_id.upper()).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")
    return res.data[0]


@router.get("/{vuln_id}", summary="Get a vulnerability by numeric ID")
def get_vulnerability(vuln_id: int, db: Client = Depends(get_db)):
    return _vuln_or_404(db, vuln_id)


@router.post("/", summary="Create or update a vulnerability", status_code=201)
def create_vulnerability(payload: VulnerabilityCreate, db: Client = Depends(get_db)):
    """
    Create a new vulnerability. If the CVE ID already exists, updates it (upsert).
    """
    data = payload.model_dump(exclude_none=True)
    # Convert date objects to strings for JSON serialisation
    for field in ("published_date", "last_modified_date"):
        if field in data and data[field] is not None:
            data[field] = str(data[field])
    res = db.table("vulnerabilities").upsert(data, on_conflict="cve_id").execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create vulnerability")
    return res.data[0]


@router.put("/{vuln_id}", summary="Update a vulnerability")
def update_vulnerability(vuln_id: int, payload: VulnerabilityUpdate, db: Client = Depends(get_db)):
    """Update specific fields of an existing vulnerability."""
    _vuln_or_404(db, vuln_id)
    data = payload.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(status_code=400, detail="No fields provided to update")
    res = db.table("vulnerabilities").update(data).eq("vuln_id", vuln_id).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Update failed")
    return res.data[0]


@router.get("/{vuln_id}/assets", summary="Get assets affected by a vulnerability")
def get_vuln_assets(vuln_id: int, db: Client = Depends(get_db)):
    """Return all assets that have this vulnerability linked, with remediation status."""
    _vuln_or_404(db, vuln_id)
    res = (
        db.table("asset_vulnerabilities")
        .select("*, assets(asset_id, asset_name, ip_address, criticality, environment)")
        .eq("vuln_id", vuln_id)
        .execute()
    )
    return {"vuln_id": vuln_id, "total": len(res.data), "data": res.data}
