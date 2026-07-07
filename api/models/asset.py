"""
models/asset.py — Pydantic models for the assets table.
"""
from __future__ import annotations
from typing import Any, List, Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str = Field(..., description="server | workstation | network_device | cloud_instance | container | iot_device | mobile")
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    mac_address: Optional[str] = None

    ip_address: Optional[str] = None
    secondary_ips: Optional[List[str]] = None
    network_zone: Optional[str] = None

    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    os_architecture: Optional[str] = None
    installed_software: Optional[List[Any]] = []

    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    physical_location: Optional[str] = None

    owner: Optional[str] = None
    department: Optional[str] = None
    business_unit: Optional[str] = None
    contact_email: Optional[str] = None

    environment: Optional[str] = "production"
    criticality: Optional[str] = "medium"
    data_classification: Optional[str] = "internal"
    tags: Optional[dict] = {}

    status: Optional[str] = "active"
    notes: Optional[str] = None


class AssetUpdate(BaseModel):
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    ip_address: Optional[str] = None
    network_zone: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[dict] = None


class AssetResponse(BaseModel):
    asset_id: int
    asset_name: str
    asset_type: str
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    operating_system: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    network_zone: Optional[str] = None
    cloud_provider: Optional[str] = None
    tags: Optional[dict] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
