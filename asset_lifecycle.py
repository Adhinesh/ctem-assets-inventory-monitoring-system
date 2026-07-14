# ================================================================
# asset_lifecycle.py 
# ================================================================
"""
========================================================
asset_lifecycle.py
========================================================

PURPOSE:
    Manages asset lifecycle tracking in CTEM system.

    It ensures:
    - first_seen is set when an asset is discovered for the first time
    - last_seen is updated every time the asset is observed in a scan
    - new assets are  into Supabase 
"""
from datetime import datetime
from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY
from logging_utils import get_logger

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
logger = get_logger(__name__)


class AssetLifecycleManager:

    def update_first_last_seen(self, scanned_assets):
        """
        Updates:
        - first_seen (only for new assets)
        - last_seen (only for observed assets in current scan)
        """

        now = datetime.utcnow().isoformat()

        # ------------------------------------------------
        # Load existing assets from DB
        # ------------------------------------------------
        db_assets = supabase.table("assets").select("*").execute().data

        db_map = {
            asset["asset_id"]: asset
            for asset in db_assets
            if asset.get("asset_id")
        }

        # ------------------------------------------------
        # Process scanned assets
        # ------------------------------------------------
        for asset in scanned_assets:

            asset_id = asset.get("asset_id")

            if not asset_id:
                logger.warning("Skipping asset without asset_id")
                continue

            # =================================================
            # CASE 1: Existing asset → update last_seen only
            # =================================================
            if asset_id in db_map:

                supabase.table("assets").update({
                    "last_seen": now
                }).eq("asset_id", asset_id).execute()

                logger.info("Updated %s last_seen", asset_id)

            # =================================================
            # CASE 2: New asset → insert with first_seen + last_seen
            # =================================================
            else:

                required_fields = ["asset_name", "asset_type"]

                missing = [f for f in required_fields if f not in asset]

                if missing:
                    logger.warning("Skipping %s missing fields: %s", asset_id, missing)
                    continue

                asset["first_seen"] = now
                asset["last_seen"] = now

                # ✅ SAFE INSERT (prevents duplicates if rerun)
                supabase.table("assets").upsert(
                    asset,
                    on_conflict="asset_id"
                ).execute()

                logger.info("Inserted new asset %s", asset_id)
