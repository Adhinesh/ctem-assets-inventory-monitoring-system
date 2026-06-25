# ================================================================
# scan_asset_change.py 
# ================================================================
"""
========================================================
scan_asset_change.py
========================================================

PURPOSE:
    Detects and records changes between previous and current asset scans
    as part of CTEM (Continuous Threat Exposure Management) pipeline.

    It stores:
    - Newly added assets
    - Removed assets
    - Field-level modifications in assets

WORKING:
    1. Fetches previous asset state from Supabase "assets" table
    2. Receives current scan data as input
    3. Uses AssetChangeDetector to compare both datasets
    4. Generates a change report containing:
        - added assets
        - removed assets
        - modified assets (field-level differences)

    5. Stores results into "asset_changes" table:
        - asset_added → for new assets
        - asset_removed → for missing assets
        - asset_modified → for changed fields

    6. Adds scan_id and timestamp to avoid duplicate tracking issues

OUTPUT:
    - Persistent audit trail of all asset changes in Supabase
    - Historical tracking of asset evolution across scans
"""
from datetime import datetime
from supabase import create_client
from change_detector import AssetChangeDetector
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


class ScanAssetChangeTracker:

    def detect_and_store_changes(self, current_scan):

        now = datetime.utcnow().isoformat()

        # Load previous state
        db_assets = supabase.table("assets").select("*").execute().data

        # Run detector
        detector = AssetChangeDetector(
            previous=db_assets,
            current=current_scan,
            id_field="asset_id"
        )

        report = detector.detect()

        # -------------------------
        # ADDED
        # -------------------------
        for asset in report.added:
            supabase.table("asset_changes").insert({
                "asset_id": asset.get("asset_id"),
                "change_type": "asset_added",
                "field_changed": None,
                "old_value": None,
                "new_value": "New Asset Discovered",
                "changed_at": now,
                "changed_by": "scanner",
                "source": "automated_scan"
            }).execute()

        # -------------------------
        # REMOVED
        # -------------------------
        for asset in report.removed:
            supabase.table("asset_changes").insert({
                "asset_id": asset.get("asset_id"),
                "change_type": "asset_removed",
                "field_changed": None,
                "old_value": "Previously Existing Asset",
                "new_value": None,
                "changed_at": now,
                "changed_by": "scanner",
                "source": "automated_scan"
            }).execute()

        # -------------------------
        # MODIFIED
        # -------------------------
        for asset_id, changes in report.modified.items():
            for change in changes:
                supabase.table("asset_changes").insert({
                    "asset_id": asset_id,
                    "change_type": "asset_modified",
                    "field_changed": change.field,
                    "old_value": str(change.old_value),
                    "new_value": str(change.new_value),
                    "changed_at": now,
                    "changed_by": "scanner",
                    "source": "automated_scan"
                }).execute()

        return report