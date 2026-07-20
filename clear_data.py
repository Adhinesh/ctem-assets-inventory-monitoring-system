# ================================================================
# clear_data.py — Delete all data from Supabase tables
# ================================================================
# Run: python clear_data.py
# ================================================================

from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Connected to Supabase\n")

print("🗑️  Clearing all data from tables...")

# Due to foreign key cascades (ON DELETE CASCADE), deleting assets 
# and vulnerabilities will also clear most of the dependent tables.
# But we'll delete from all root tables just to be safe.

tables_to_clear = [
    "xfinder_change_reports",
    "xfinder_scan_reports",
    "xfinder_api_endpoints",
    "xfinder_vulnerabilities",
    "xfinder_technologies",
    "xfinder_services",
    "xfinder_ports",
    "xfinder_ip_addresses",
    "xfinder_cloud_assets",
    "xfinder_http_information",
    "xfinder_dns_records",
    "xfinder_subdomains",
    "xfinder_scans",
    "xfinder_targets",
    "exposures",
    "asset_vulnerabilities",
    "scan_snapshots",
    "scans",
    "asset_logs",
    "asset_changes",
    "dns_records",
    "open_ports",
    "vulnerabilities",
    "assets"
]

for table in tables_to_clear:
    # Supabase requires a filter to delete. 'neq' on id = 0 deletes everything
    try:
        if table == "asset_logs":
            res = supabase.table(table).delete().neq("log_id", 0).execute()
        elif table == "dns_records":
            res = supabase.table(table).delete().neq("record_id", 0).execute()
        elif table == "vulnerabilities":
            res = supabase.table(table).delete().neq("vuln_id", 0).execute()
        elif table == "assets":
            res = supabase.table(table).delete().neq("asset_id", 0).execute()
        elif table == "exposures":
            res = supabase.table(table).delete().neq("exposure_id", 0).execute()
        elif table == "scans":
            res = supabase.table(table).delete().neq("scan_id", 0).execute()
        elif table == "asset_vulnerabilities":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "open_ports":
            res = supabase.table(table).delete().neq("port_id", 0).execute()
        elif table == "asset_changes":
            res = supabase.table(table).delete().neq("change_id", 0).execute()
        elif table == "scan_snapshots":
            res = supabase.table(table).delete().neq("snapshot_id", 0).execute()
        elif table == "xfinder_targets":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_scans":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_subdomains":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_dns_records":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_http_information":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_cloud_assets":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_ip_addresses":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_ports":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_services":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_technologies":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_api_endpoints":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_vulnerabilities":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_scan_reports":
            res = supabase.table(table).delete().neq("id", 0).execute()
        elif table == "xfinder_change_reports":
            res = supabase.table(table).delete().neq("id", 0).execute()
            
        print(f"  ✔ Cleared table: {table}")
    except Exception as e:
        print(f"  ⚠ Failed to clear {table}: {e}")

print("\n🎉 Database is now empty and ready for fresh insertion!")
