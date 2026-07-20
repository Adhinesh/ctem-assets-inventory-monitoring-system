"""
routers/dns.py — All /dns endpoints.
"""
from __future__ import annotations
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from supabase import Client

from api.db import get_db

router = APIRouter(prefix="/dns", tags=["DNS Records"])


class DNSRecordCreate(BaseModel):
    asset_id: Optional[int] = None
    domain: str
    subdomain: Optional[str] = None
    fqdn: Optional[str] = None
    record_type: str                 # A | AAAA | CNAME | MX | TXT | NS | PTR | SRV | CAA
    record_value: str
    ttl: Optional[int] = None
    is_internal: Optional[bool] = False
    is_wildcard: Optional[bool] = False
    status: Optional[str] = "active"
    risk_notes: Optional[str] = None
    registrar: Optional[str] = None
    dns_provider: Optional[str] = None
    expires_at: Optional[datetime] = None


def _asset_exists(db: Client, asset_id: int) -> bool:
    res = db.table("assets").select("asset_id").eq("asset_id", asset_id).limit(1).execute()
    return bool(res.data)


@router.get("/", summary="List all DNS records")
def list_dns(
    status:    Optional[str] = Query(None, description="active | stale | dangling | expired"),
    domain:    Optional[str] = Query(None, description="Filter by domain"),
    asset_id:  Optional[int] = Query(None),
    limit:     int           = Query(100, ge=1, le=500),
    offset:    int           = Query(0, ge=0),
    db: Client = Depends(get_db),
):
    """List DNS records. Use `status=dangling` to find subdomain takeover risks."""
    q = db.table("dns_records").select(
        "record_id, domain, subdomain, fqdn, record_type, record_value, "
        "ttl, is_internal, status, risk_notes, registrar, dns_provider, "
        "first_seen, last_seen, expires_at, assets(asset_name, ip_address)"
    )
    if status:
        q = q.eq("status", status)
    if domain:
        q = q.ilike("domain", f"%{domain}%")
    if asset_id:
        q = q.eq("asset_id", asset_id)
    res = q.order("domain").range(offset, offset + limit - 1).execute()
    return {"total": len(res.data), "data": res.data}


@router.get("/dangling", summary="List dangling DNS records (subdomain takeover risk)")
def list_dangling_dns(db: Client = Depends(get_db)):
    """Shortcut: return all DNS records with status=dangling."""
    res = (
        db.table("dns_records")
        .select("*, assets(asset_name, ip_address)")
        .eq("status", "dangling")
        .execute()
    )
    return {"total": len(res.data), "data": res.data}


@router.get("/{record_id}", summary="Get a single DNS record")
def get_dns(record_id: int, db: Client = Depends(get_db)):
    res = db.table("dns_records").select("*").eq("record_id", record_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"DNS record {record_id} not found")
    return res.data[0]


@router.post("/", summary="Add a DNS record", status_code=201)
def create_dns(payload: DNSRecordCreate, db: Client = Depends(get_db)):
    """Add a new DNS record. Upserts on (domain, subdomain, record_type, record_value)."""
    data = payload.model_dump(exclude_none=True)
    if "expires_at" in data and data["expires_at"]:
        data["expires_at"] = data["expires_at"].isoformat()
    if data.get("asset_id") is not None and not _asset_exists(db, data["asset_id"]):
        raise HTTPException(status_code=404, detail=f"Asset {data['asset_id']} not found")
    res = (
        db.table("dns_records")
        .upsert(data, on_conflict="domain,subdomain,record_type,record_value")
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to add DNS record")
    return res.data[0]


@router.delete("/{record_id}", summary="Delete a DNS record")
def delete_dns(record_id: int, db: Client = Depends(get_db)):
    res = db.table("dns_records").select("record_id").eq("record_id", record_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail=f"DNS record {record_id} not found")
    db.table("dns_records").delete().eq("record_id", record_id).execute()
    return {"message": f"DNS record {record_id} deleted"}
