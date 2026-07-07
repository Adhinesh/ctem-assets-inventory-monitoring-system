from __future__ import annotations
"""
db.py — Supabase client singleton for the CTEM FastAPI.
"""
import sys
import os

# Add parent directory to path so config.py is found
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supabase import create_client, Client
from config import SUPABASE_URL, SUPABASE_KEY

_client: Client | None = None


def get_db() -> Client:
    """Return the Supabase client, creating it once on first call."""
    global _client
    if _client is None:
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client
