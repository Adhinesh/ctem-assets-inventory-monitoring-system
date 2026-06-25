# ================================================================
# test_run.py 
# ================================================================

from asset_lifecycle import AssetLifecycleManager
from scan_asset_change import ScanAssetChangeTracker
from datetime import datetime

# ✔ FIX: Supabase client added for direct DB read
from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


print("\n================================================")
print(" CTEM PIPELINE TEST RUN ")
print("================================================\n")


# ------------------------------------------------
# STEP 1: SIMULATED NEW SCAN INPUT
# ------------------------------------------------
current_scan = [
    {
        "asset_id": "1",
        "asset_name": "Web Server 01",
        "asset_type": "server",
        "ip_address": "192.168.1.10",
    },
    {
        "asset_id": "2",
        "asset_name": "Test App Server",
        "asset_type": "server",
        "ip_address": "10.10.10.10",
    },
]


# ------------------------------------------------
# STEP 2: UPDATE FIRST/LAST SEEN
# ------------------------------------------------
print("STEP 1 : Updating first_seen / last_seen...\n")

lifecycle = AssetLifecycleManager()
lifecycle.update_first_last_seen(current_scan)


# ================================================================
# 🔥 ONLY ADDED SECTION (PRINT FIRST SEEN / LAST SEEN)
# ================================================================
print("\n FIRST SEEN / LAST SEEN VALUES\n")

for a in current_scan:
    print(f"Asset: {a['asset_id']} | {a['asset_name']}")

    # ✔ FIXED: use direct supabase client (NOT lifecycle.supabase)
    db_asset = supabase.table("assets") \
        .select("first_seen, last_seen") \
        .eq("asset_id", a["asset_id"]) \
        .single() \
        .execute().data

    print(f"   First Seen : {db_asset.get('first_seen')}")
    print(f"   Last Seen  : {db_asset.get('last_seen')}\n")


# ------------------------------------------------
# STEP 3: DETECT CHANGES
# ------------------------------------------------
print("\nSTEP 2 : Detecting asset changes...\n")

tracker = ScanAssetChangeTracker()
report = tracker.detect_and_store_changes(current_scan)


# ------------------------------------------------
# STEP 4: PRINT STRUCTURED RESULT
# ------------------------------------------------

print("\n================================================")
print(" FINAL  TEST REPORT")
print("================================================\n")


# -------- ADDED ----------
print(" - ADDED ASSETS")
if report.added:
    for a in report.added:
        print(f" - {a['asset_id']} | {a.get('asset_name')}")
else:
    print(" - None")


# -------- REMOVED ----------
print("\n - REMOVED ASSETS")
if report.removed:
    for a in report.removed:
        print(f" - {a['asset_id']} | {a.get('asset_name')}")
else:
    print(" - None")


# -------- MODIFIED ----------
print("\n - MODIFIED ASSETS")
if report.modified:
    for asset_id, changes in report.modified.items():
        print(f"\n Asset: {asset_id}")
        for c in changes:
            print(f"   • {c.field}: {c.old_value} → {c.new_value}")
else:
    print(" - None")


# -------- SUMMARY ----------
print("\n================================================")
print(" SUMMARY")
print("================================================")

print(f"Added     : {report.total_added}")
print(f"Removed   : {report.total_removed}")
print(f"Modified  : {report.total_modified}")
print(f"Unchanged : {report.total_unchanged}")

print("\n - TEST COMPLETED\n")