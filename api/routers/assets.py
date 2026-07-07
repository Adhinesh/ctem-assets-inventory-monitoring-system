"""
routers/assets.py — All /assets endpoints.
"""
from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from supabase import Client

from api.db import get_db
from api.models.asset import AssetCreate, AssetUpdate, AssetResponse

router = APIRouter(prefix="/assets", tags=["Assets"])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _asset_or_404(db: Client, asset_id: int) -> dict:
    res = db.table("assets").select("*").eq("asset_id", asset_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return res.data[0]


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/", summary="List all assets")
def list_assets(
    criticality: Optional[str] = Query(None, description="Filter by criticality: low | medium | high | critical"),
    status:      Optional[str] = Query(None, description="Filter by status: active | inactive | decommissioned | under_maintenance"),
    environment: Optional[str] = Query(None, description="Filter by environment: production | staging | development | testing"),
    asset_type:  Optional[str] = Query(None, description="Filter by type: server | workstation | network_device | cloud_instance"),
    search:      Optional[str] = Query(None, description="Search by asset_name or ip_address (partial match)"),
    limit:       int            = Query(100, ge=1, le=500),
    offset:      int            = Query(0, ge=0),
    db: Client = Depends(get_db),
):
    """
    List assets with optional filters. Supports filtering by criticality,
    status, environment, type, and a keyword search on name/IP.
    """
    q = db.table("assets").select(
        "asset_id, asset_name, asset_type, ip_address, fqdn, operating_system, "
        "owner, department, environment, criticality, status, network_zone, "
        "cloud_provider, tags, created_at, updated_at"
    )
    if criticality:
        q = q.eq("criticality", criticality)
    if status:
        q = q.eq("status", status)
    if environment:
        q = q.eq("environment", environment)
    if asset_type:
        q = q.eq("asset_type", asset_type)
    if search:
        q = q.or_(f"asset_name.ilike.%{search}%,ip_address.eq.{search}")

    res = q.order("criticality").range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/{asset_id}", summary="Get a single asset by ID")
def get_asset(asset_id: int, db: Client = Depends(get_db)):
    """Return full detail for one asset."""
    return _asset_or_404(db, asset_id)


@router.post("/", summary="Create a new asset", status_code=201)
def create_asset(payload: AssetCreate, db: Client = Depends(get_db)):
    """
    Create a new asset. If an asset with the same `asset_name` already exists,
    it will be updated (upsert behaviour) to prevent duplicates.
    """
    data = payload.model_dump(exclude_none=True)
    # Check-then-insert/update pattern (no unique constraint on asset_name in DB)
    existing = (
        db.table("assets")
        .select("asset_id")
        .eq("asset_name", data["asset_name"])
        .execute()
        .data
    )
    if existing:
        asset_id = existing[0]["asset_id"]
        res = db.table("assets").update(data).eq("asset_id", asset_id).execute()
    else:
        res = db.table("assets").insert(data).execute()

    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create asset")
    return res.data[0]


@router.put("/{asset_id}", summary="Update an asset")
def update_asset(asset_id: int, payload: AssetUpdate, db: Client = Depends(get_db)):
    """Update one or more fields on an existing asset."""
    _asset_or_404(db, asset_id)
    data = payload.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(status_code=400, detail="No fields provided to update")
    res = db.table("assets").update(data).eq("asset_id", asset_id).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Update failed")
    return res.data[0]


@router.delete("/{asset_id}", summary="Delete an asset")
def delete_asset(asset_id: int, db: Client = Depends(get_db)):
    """Permanently delete an asset and all its related records (cascade)."""
    _asset_or_404(db, asset_id)
    db.table("assets").delete().eq("asset_id", asset_id).execute()
    return {"message": f"Asset {asset_id} deleted successfully"}


# ── Sub-resources ─────────────────────────────────────────────────────────────

@router.get("/{asset_id}/vulnerabilities", summary="Get vulnerabilities linked to an asset")
def get_asset_vulnerabilities(asset_id: int, status: Optional[str] = None, db: Client = Depends(get_db)):
    """Return all CVEs linked to this asset, optionally filtered by remediation status."""
    _asset_or_404(db, asset_id)
    q = (
        db.table("asset_vulnerabilities")
        .select("*, vulnerabilities(cve_id, title, cvss_score, severity, exploit_available, fix_available)")
        .eq("asset_id", asset_id)
    )
    if status:
        q = q.eq("status", status)
    res = q.execute()
    return {"asset_id": asset_id, "total": len(res.data), "data": res.data}


@router.get("/{asset_id}/ports", summary="Get open ports for an asset")
def get_asset_ports(asset_id: int, db: Client = Depends(get_db)):
    """Return all open ports discovered on this asset."""
    _asset_or_404(db, asset_id)
    res = (
        db.table("open_ports")
        .select("port_id, port_number, protocol, state, service_name, service_version, is_expected, risk_level, notes, first_detected, last_seen")
        .eq("asset_id", asset_id)
        .order("port_number")
        .execute()
    )
    return {"asset_id": asset_id, "total": len(res.data), "data": res.data}


@router.get("/{asset_id}/changes", summary="Get audit trail for an asset")
def get_asset_changes(
    asset_id: int,
    limit: int = Query(50, ge=1, le=200),
    db: Client = Depends(get_db),
):
    """Return the full audit trail of field-level changes for this asset."""
    _asset_or_404(db, asset_id)
    res = (
        db.table("asset_changes")
        .select("*")
        .eq("asset_id", asset_id)
        .order("changed_at", desc=True)
        .limit(limit)
        .execute()
    )
    return {"asset_id": asset_id, "total": len(res.data), "data": res.data}


@router.get("/{asset_id}/logs", summary="Get event logs for an asset")
def get_asset_logs(
    asset_id: int,
    log_level: Optional[str] = Query(None, description="debug | info | warning | error | critical"),
    limit:     int           = Query(100, ge=1, le=500),
    db: Client = Depends(get_db),
):
    """Return streaming event logs for this asset (newest first)."""
    _asset_or_404(db, asset_id)
    q = (
        db.table("asset_logs")
        .select("*")
        .eq("asset_id", asset_id)
        .order("logged_at", desc=True)
        .limit(limit)
    )
    if log_level:
        q = q.eq("log_level", log_level)
    res = q.execute()
    return {"asset_id": asset_id, "total": len(res.data), "data": res.data}
