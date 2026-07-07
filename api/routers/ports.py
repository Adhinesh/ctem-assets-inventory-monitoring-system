"""
routers/ports.py — All /ports endpoints.
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from supabase import Client

from api.db import get_db

router = APIRouter(prefix="/ports", tags=["Open Ports"])


class PortCreate(BaseModel):
    asset_id: int
    port_number: int
    protocol: str = "TCP"
    state: str = "open"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_product: Optional[str] = None
    banner: Optional[str] = None
    is_expected: Optional[bool] = True
    risk_level: Optional[str] = "low"
    notes: Optional[str] = None


@router.get("/", summary="List all open ports")
def list_ports(
    is_expected: Optional[bool] = Query(None, description="True = known port, False = rogue/unexpected"),
    risk_level:  Optional[str]  = Query(None, description="low | medium | high | critical"),
    asset_id:    Optional[int]  = Query(None, description="Filter by asset"),
    limit:       int            = Query(100, ge=1, le=500),
    offset:      int            = Query(0, ge=0),
    db: Client = Depends(get_db),
):
    """List open ports. Use `is_expected=false` to find rogue/unexpected ports."""
    q = db.table("open_ports").select(
        "port_id, port_number, protocol, state, service_name, service_version, "
        "is_expected, risk_level, notes, first_detected, last_seen, "
        "assets(asset_id, asset_name, ip_address)"
    )
    if is_expected is not None:
        q = q.eq("is_expected", is_expected)
    if risk_level:
        q = q.eq("risk_level", risk_level)
    if asset_id:
        q = q.eq("asset_id", asset_id)
    res = q.order("port_number").range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/unexpected", summary="List all unexpected/rogue ports")
def list_unexpected_ports(db: Client = Depends(get_db)):
    """Shortcut: return all ports where is_expected = false (potential rogue services)."""
    res = (
        db.table("open_ports")
        .select("*, assets(asset_name, ip_address)")
        .eq("is_expected", False)
        .order("risk_level")
        .execute()
    )
    return {"total": len(res.data), "data": res.data}


@router.get("/{port_id}", summary="Get a single port record")
def get_port(port_id: int, db: Client = Depends(get_db)):
    res = db.table("open_ports").select("*, assets(asset_name, ip_address)").eq("port_id", port_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Port record {port_id} not found")
    return res.data[0]


@router.post("/", summary="Add an open port record", status_code=201)
def create_port(payload: PortCreate, db: Client = Depends(get_db)):
    """
    Add a port record. Upserts on (asset_id, port_number, protocol) constraint.
    """
    data = payload.model_dump(exclude_none=True)
    res = db.table("open_ports").upsert(data, on_conflict="asset_id,port_number,protocol").execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to add port")
    return res.data[0]


@router.delete("/{port_id}", summary="Delete a port record")
def delete_port(port_id: int, db: Client = Depends(get_db)):
    res = db.table("open_ports").select("port_id").eq("port_id", port_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"Port record {port_id} not found")
    db.table("open_ports").delete().eq("port_id", port_id).execute()
    return {"message": f"Port record {port_id} deleted"}
