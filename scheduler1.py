"""
scheduler.py
--------------------------------------------------
CTEM Scheduled Asset Monitoring

Runs the complete monitoring pipeline automatically.

Run:
    python scheduler.py
"""

from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler

# Existing project imports
from asset_lifecycle import AssetLifecycleManager
from scan_asset_change import ScanAssetChangeTracker
from monitor import AssetMonitor

# Supabase
from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# ==========================================================
# Monitoring Job
# ==========================================================

def run_monitoring():

    print("\n" + "=" * 60)
    print("CTEM Scheduled Monitoring")
    print("Started :", datetime.now())
    print("=" * 60)

    try:

        # ----------------------------------------------------
        # STEP 1
        # Load previous inventory from database
        # ----------------------------------------------------

        previous_inventory = (
            supabase
            .table("assets")
            .select("*")
            .execute()
            .data
        )

        # ----------------------------------------------------
        # STEP 2
        # Get current scan
        #
        # Currently:
        # using database as scan source.
        #
        # Later replace ONLY this section with 
        # Nmap / scanner output.
        # ----------------------------------------------------

        current_scan = (
            supabase
            .table("assets")
            .select("*")
            .execute()
            .data
        )

        # ----------------------------------------------------
        # STEP 3
        # Update First Seen / Last Seen
        # ----------------------------------------------------

        lifecycle = AssetLifecycleManager()
        lifecycle.update_first_last_seen(current_scan)

        # ----------------------------------------------------
        # STEP 4
        # Detect & Store Changes
        # ----------------------------------------------------

        tracker = ScanAssetChangeTracker()
        report = tracker.detect_and_store_changes(current_scan)

        # ----------------------------------------------------
        # STEP 5
        # Generate Monitoring Report
        # ----------------------------------------------------

        monitor = AssetMonitor(
            previous=previous_inventory,
            current=current_scan,
            run_label="Scheduled Monitoring Run",
            save_locally=True,
            push_to_supabase=True
        )

        final_report = monitor.run()

        print(final_report)

        print("\nMonitoring completed successfully.")

        print("\nSummary")
        print("---------------------------")
        print("Added     :", report.total_added)
        print("Removed   :", report.total_removed)
        print("Modified  :", report.total_modified)
        print("Unchanged :", report.total_unchanged)

    except Exception as e:

        print("\nMonitoring Failed")
        print(e)


# ==========================================================
# APScheduler
# ==========================================================

scheduler = BlockingScheduler()

scheduler.add_job(
    run_monitoring,
    trigger="interval",
    minutes=1,
    id="ctem_monitor",
    replace_existing=True,
)

print("\nScheduler Started")
print("Monitoring runs every 1 minute.")
print("Press CTRL + C to stop.\n")

# Run immediately once
run_monitoring()

# Continue running automatically
try:
    scheduler.start()
except (KeyboardInterrupt, SystemExit):
    print("\nScheduler stopped by user (CTRL + C).")
    scheduler.shutdown()