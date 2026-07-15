"""
routers/assets.py — All /assets endpoints.
"""
from __future__ import annotations
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from supabase import Client

from api.db import get_db
from api.models.asset import AssetCreate, AssetUpdate, AssetResponse
from logging_utils import get_logger

router = APIRouter(prefix="/assets", tags=["Assets"])
logger = get_logger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _asset_or_404(db: Client, asset_id: int) -> dict:
    res = db.table("assets").select("*").eq("asset_id", asset_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return res.data[0]


def _record_asset_change(
    db: Client,
    *,
    asset_id: int,
    change_type: str,
    field_changed: Optional[str] = None,
    old_value: Optional[object] = None,
    new_value: Optional[object] = None,
    change_reason: Optional[str] = None,
) -> None:
    db.table("asset_changes").insert({
        "asset_id": asset_id,
        "change_type": change_type,
        "field_changed": field_changed,
        "old_value": None if old_value is None else str(old_value),
        "new_value": None if new_value is None else str(new_value),
        "changed_at": datetime.now(timezone.utc).isoformat(),
        "changed_by": "api",
        "source": "manual",
        "change_reason": change_reason,
    }).execute()


def _clean_asset_payload(data: dict) -> dict:
    """Drop Swagger placeholder values that can break Supabase writes."""
    cleaned = {}
    for field, value in data.items():
        if value is None:
            continue
        if value == "string":
            continue
        if isinstance(value, list) and value and all(item == "string" for item in value):
            continue
        if field == "tags" and isinstance(value, dict):
            if set(value.keys()) == {"additionalProp1"} and value.get("additionalProp1") == {}:
                continue
        cleaned[field] = value
    return cleaned


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
    select_fields = (
        "asset_id, asset_name, asset_type, ip_address, fqdn, operating_system, "
        "owner, department, environment, criticality, status, network_zone, "
        "cloud_provider, tags, created_at, updated_at"
    )
    q = db.table("assets").select(select_fields)
    if criticality:
        q = q.eq("criticality", criticality)
    if status:
        q = q.eq("status", status)
    if environment:
        q = q.eq("environment", environment)
    if asset_type:
        q = q.eq("asset_type", asset_type)
    if search:
        name_matches = q.ilike("asset_name", f"%{search}%").execute().data
        ip_matches = q.eq("ip_address", search).execute().data
        combined = []
        seen_ids = set()
        for row in name_matches + ip_matches:
            asset_id = row.get("asset_id")
            if asset_id in seen_ids:
                continue
            seen_ids.add(asset_id)
            combined.append(row)
        combined.sort(key=lambda row: (row.get("criticality") or "", row.get("asset_name") or ""))
        return {"total": len(combined), "data": combined[offset:offset + limit]}

    res = q.order("criticality").range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/{asset_id}", summary="Get a single asset by ID")
def get_asset(asset_id: int, db: Client = Depends(get_db)):
    """Return full detail for one asset."""
    return _asset_or_404(db, asset_id)


@router.post("/", summary="Create a new asset", status_code=201)
def create_asset(payload: AssetCreate, db: Client = Depends(get_db)):
    """
    Create a new asset. The caller must provide `asset_id`.
    If that `asset_id` already exists, the record is updated.
    """
    try:
        data = _clean_asset_payload(payload.model_dump(exclude_none=True))
        asset_id = data["asset_id"]
        existing = (
            db.table("assets")
            .select("asset_id")
            .eq("asset_id", asset_id)
            .execute()
            .data
        )
        if existing:
            before = _asset_or_404(db, asset_id)
            res = db.table("assets").update(data).eq("asset_id", asset_id).execute()
            if res.data:
                for field, new_value in data.items():
                    old_value = before.get(field)
                    if old_value != new_value:
                        _record_asset_change(
                            db,
                            asset_id=asset_id,
                            change_type="asset_modified",
                            field_changed=field,
                            old_value=old_value,
                            new_value=new_value,
                            change_reason="Asset updated through create/upsert endpoint",
                        )
        else:
            res = db.table("assets").insert(data).execute()
            if res.data:
                created = res.data[0]
                _record_asset_change(
                    db,
                    asset_id=created["asset_id"],
                    change_type="asset_added",
                    new_value=created.get("asset_name"),
                    change_reason="Asset created through API",
                )

        if not res.data:
            raise HTTPException(status_code=500, detail="Failed to create asset")
        return res.data[0]
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to create asset")
        raise HTTPException(status_code=500, detail="Failed to create asset") from exc


@router.put("/{asset_id}", summary="Update an asset")
def update_asset(asset_id: int, payload: AssetUpdate, db: Client = Depends(get_db)):
    """Update one or more fields on an existing asset."""
    try:
        before = _asset_or_404(db, asset_id)
        data = _clean_asset_payload(payload.model_dump(exclude_none=True))
        if not data:
            raise HTTPException(status_code=400, detail="No fields provided to update")
        res = db.table("assets").update(data).eq("asset_id", asset_id).execute()
        if not res.data:
            raise HTTPException(status_code=500, detail="Update failed")
        for field, new_value in data.items():
            old_value = before.get(field)
            if old_value != new_value:
                _record_asset_change(
                    db,
                    asset_id=asset_id,
                    change_type="asset_modified",
                    field_changed=field,
                    old_value=old_value,
                    new_value=new_value,
                    change_reason="Asset updated through API",
                )
        return res.data[0]
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to update asset %s", asset_id)
        raise HTTPException(status_code=500, detail="Failed to update asset") from exc


@router.delete("/{asset_id}", summary="Delete an asset")
def delete_asset(asset_id: int, db: Client = Depends(get_db)):
    """Permanently delete an asset and all its related records (cascade)."""
    try:
        asset = _asset_or_404(db, asset_id)
        _record_asset_change(
            db,
            asset_id=asset_id,
            change_type="asset_removed",
            old_value=asset.get("asset_name"),
            change_reason="Asset deleted through API",
        )
        db.table("assets").delete().eq("asset_id", asset_id).execute()
        return {"message": f"Asset {asset_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to delete asset %s", asset_id)
        raise HTTPException(status_code=500, detail="Failed to delete asset") from exc


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
