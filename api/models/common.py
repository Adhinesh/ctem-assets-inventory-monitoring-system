"""
models/common.py — Shared response envelope models.
"""
from __future__ import annotations
from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel

T = TypeVar("T")


class PagedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""
    total: int
    page: int
    page_size: int
    data: List[Any]


class MessageResponse(BaseModel):
    """Simple message / confirmation response."""
    message: str
    detail: Optional[Any] = None
