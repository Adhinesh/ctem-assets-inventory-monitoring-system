# ================================================================
# queries.py — Retrieve CTEM data from Supabase (all tables)
# ================================================================
# Run: python queries.py
# Requires: pip install supabase
# ================================================================

from supabase import create_client
from collections import Counter
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# ── Pretty printer ───────────────────────────────────────────────
def section(title):
    print(f"\n{'━'*64}")
    print(f"  {title}")
    print(f"{'━'*64}")

def show(rows, fields=None):
    if not rows:
        print("  (no results)\n")
        return
    for i, row in enumerate(rows, 1):
        items = {k: v for k, v in row.items() if fields is None or k in fields}
        print(f"\n  [{i}]")
        for k, v in items.items():
            # Truncate long values for readability
            val = str(v)[:90] + "…" if v and len(str(v)) > 90 else v
            print(f"      {k:<28} {val}")


# ================================================================
# 1. ASSET INVENTORY
# ================================================================
section("ALL ASSETS — Full Inventory")
rows = (
    supabase.table("assets")
    .select("asset_name, asset_type, ip_address, fqdn, operating_system, owner, environment, criticality, status, network_zone, cloud_provider")
    .order("criticality")
    .execute().data
)
show(rows)


section("CRITICAL & HIGH ASSETS ONLY")
rows = (
    supabase.table("assets")
    .select("asset_name, ip_address, fqdn, owner, criticality, data_classification, environment")
    .in_("criticality", ["critical", "high"])
    .execute().data
)
show(rows)


section("ASSETS BY ENVIRONMENT")
all_assets = supabase.table("assets").select("environment").execute().data
counts = Counter(a["environment"] for a in all_assets)
for env, count in sorted(counts.items()):
    print(f"      {env:<20} {count} asset(s)")


# ================================================================
# 2. VULNERABILITIES
# ================================================================
section("VULNERABILITY CATALOG — Sorted by CVSS Score")
rows = (
    supabase.table("vulnerabilities")
    .select("cve_id, title, cvss_score, severity, epss_score, exploit_available, exploit_maturity, fix_available, published_date")
    .order("cvss_score", desc=True)
    .execute().data
)
show(rows)


section("EXPLOITABLE VULNERABILITIES (exploit_available = true)")
rows = (
    supabase.table("vulnerabilities")
    .select("cve_id, title, cvss_score, severity, exploit_maturity, affected_software")
    .eq("exploit_available", True)
    .order("cvss_score", desc=True)
    .execute().data
)
show(rows)


# ================================================================
# 3. OPEN PORTS
# ================================================================
section("ALL OPEN PORTS — By Asset")
rows = (
    supabase.table("open_ports")
    .select("port_number, protocol, state, service_name, service_version, is_expected, risk_level, notes, assets(asset_name, ip_address)")
    .order("port_number")
    .execute().data
)
# Flatten
flat = [{
    "asset":           r["assets"]["asset_name"],
    "ip":              r["assets"]["ip_address"],
    "port":            r["port_number"],
    "protocol":        r["protocol"],
    "service":         r["service_name"],
    "version":         r["service_version"],
    "expected":        r["is_expected"],
    "risk":            r["risk_level"],
    "notes":           r.get("notes"),
} for r in rows]
show(flat)


section("⚠️  UNEXPECTED / ROGUE PORTS (is_expected = false)")
rows = (
    supabase.table("open_ports")
    .select("port_number, protocol, service_name, risk_level, notes, assets(asset_name, ip_address, environment)")
    .eq("is_expected", False)
    .execute().data
)
flat = [{
    "asset":       r["assets"]["asset_name"],
    "environment": r["assets"]["environment"],
    "port":        r["port_number"],
    "protocol":    r["protocol"],
    "service":     r["service_name"],
    "risk":        r["risk_level"],
    "notes":       r.get("notes"),
} for r in rows]
show(flat)


# ================================================================
# 4. DNS RECORDS
# ================================================================
section("ALL DNS RECORDS")
rows = (
    supabase.table("dns_records")
    .select("fqdn, record_type, record_value, ttl, is_internal, status, risk_notes, assets(asset_name)")
    .order("domain")
    .execute().data
)
flat = [{
    "fqdn":        r["fqdn"],
    "type":        r["record_type"],
    "value":       r["record_value"],
    "ttl":         r["ttl"],
    "internal":    r["is_internal"],
    "status":      r["status"],
    "linked_asset":r["assets"]["asset_name"] if r["assets"] else "N/A",
    "risk_notes":  r.get("risk_notes"),
} for r in rows]
show(flat)


section("⚠️  DANGLING DNS RECORDS (Subdomain Takeover Risk)")
rows = (
    supabase.table("dns_records")
    .select("fqdn, record_type, record_value, risk_notes, status")
    .eq("status", "dangling")
    .execute().data
)
show(rows)


# ================================================================
# 5. ASSET CHANGES (Audit Trail)
# ================================================================
section("ASSET CHANGE AUDIT TRAIL — Most Recent First")
rows = (
    supabase.table("asset_changes")
    .select("change_type, field_changed, old_value, new_value, changed_by, source, changed_at, notes, assets(asset_name)")
    .order("changed_at", desc=True)
    .execute().data
)
flat = [{
    "asset":        r["assets"]["asset_name"],
    "change_type":  r["change_type"],
    "field":        r["field_changed"],
    "old":          r["old_value"],
    "new":          r["new_value"],
    "changed_by":   r["changed_by"],
    "source":       r["source"],
    "at":           r["changed_at"],
} for r in rows]
show(flat)


section("CHANGES FOR A SPECIFIC ASSET — Web Server 01")
# First get asset_id
asset = (
    supabase.table("assets")
    .select("asset_id")
    .eq("asset_name", "Web Server 01")
    .execute()
    .data
)
rows = (
    supabase.table("asset_changes")
    .select("change_type, field_changed, old_value, new_value, changed_by, changed_at")
    .eq("asset_id", asset[0]["asset_id"])
    .order("changed_at", desc=True)
    .execute().data
)
show(rows)
# ================================================================
# 6. ASSET LOGS (Event Stream)
# ================================================================
section("RECENT ASSET LOGS — Most Recent First")
rows = (
    supabase.table("asset_logs")
    .select("log_level, event_type, event_source, message, logged_at, assets(asset_name)")
    .order("logged_at", desc=True)
    .limit(15)
    .execute().data
)
flat = [{
    "asset":    r["assets"]["asset_name"],
    "level":    r["log_level"],
    "event":    r["event_type"],
    "source":   r["event_source"],
    "message":  r["message"],
    "at":       r["logged_at"],
} for r in rows]
show(flat)


section("CRITICAL & ERROR LOGS ONLY")
rows = (
    supabase.table("asset_logs")
    .select("log_level, event_type, message, logged_at, assets(asset_name)")
    .in_("log_level", ["critical", "error"])
    .order("logged_at", desc=True)
    .execute().data
)
flat = [{
    "asset":   r["assets"]["asset_name"],
    "level":   r["log_level"],
    "event":   r["event_type"],
    "message": r["message"],
    "at":      r["logged_at"],
} for r in rows]
show(flat)


# ================================================================
# 7. SCAN SNAPSHOTS
# ================================================================
section("SCAN SNAPSHOTS — Point-in-Time Security State")
rows = (
    supabase.table("scan_snapshots")
    .select("snapshot_taken_at, total_vulns, critical_vulns, high_vulns, total_open_ports, unexpected_ports, risk_score, compliance_score, os_detected, assets(asset_name), scans(scan_name)")
    .order("snapshot_taken_at", desc=True)
    .execute().data
)
flat = [{
    "asset":            r["assets"]["asset_name"],
    "scan":             r["scans"]["scan_name"],
    "taken_at":         r["snapshot_taken_at"],
    "risk_score":       r["risk_score"],
    "compliance":       r["compliance_score"],
    "total_vulns":      r["total_vulns"],
    "critical_vulns":   r["critical_vulns"],
    "open_ports":       r["total_open_ports"],
    "unexpected_ports": r["unexpected_ports"],
    "os":               r["os_detected"],
} for r in rows]
show(flat)


# ================================================================
# 8. ASSET VULNERABILITIES — Remediation Status
# ================================================================
section("OPEN VULNERABILITIES — Remediation Backlog")
rows = (
    supabase.table("asset_vulnerabilities")
    .select("status, priority, detected_on, due_date, assigned_to, notes, affected_component, assets(asset_name, criticality), vulnerabilities(cve_id, title, cvss_score, severity)")
    .eq("status", "open")
    .order("priority")
    .execute().data
)
flat = [{
    "asset":        r["assets"]["asset_name"],
    "criticality":  r["assets"]["criticality"],
    "cve":          r["vulnerabilities"]["cve_id"],
    "cvss":         r["vulnerabilities"]["cvss_score"],
    "severity":     r["vulnerabilities"]["severity"],
    "priority":     r["priority"],
    "assigned_to":  r["assigned_to"],
    "due_date":     r["due_date"],
    "component":    r["affected_component"],
} for r in rows]
show(flat)


section("REMEDIATION SUMMARY — All Statuses")
all_avs = supabase.table("asset_vulnerabilities").select("status, priority").execute().data
status_count = Counter(r["status"] for r in all_avs)
priority_count = Counter(r["priority"] for r in all_avs if r["status"] == "open")
print("\n  By Status:")
for s, c in sorted(status_count.items()):
    print(f"      {s:<20} {c} finding(s)")
print("\n  Open Findings by Priority:")
for p, c in sorted(priority_count.items()):
    print(f"      {p:<20} {c} finding(s)")


# ================================================================
# 9. CTEM EXPOSURES
# ================================================================
section("ACTIVE CTEM EXPOSURES — Highest Risk First")
rows = (
    supabase.table("exposures")
    .select("risk_score, exposure_type, attack_vector, status, escalated, assigned_to, sla_deadline, business_impact, assets(asset_name, ip_address), vulnerabilities(cve_id, severity)")
    .eq("status", "active")
    .order("risk_score", desc=True)
    .execute().data
)
flat = [{
    "asset":         r["assets"]["asset_name"] if r["assets"] else "N/A",
    "cve":           r["vulnerabilities"]["cve_id"] if r["vulnerabilities"] else "N/A",
    "risk_score":    r["risk_score"],
    "exposure_type": r["exposure_type"],
    "attack_vector": r["attack_vector"],
    "escalated":     r["escalated"],
    "assigned_to":   r["assigned_to"],
    "sla_deadline":  r["sla_deadline"],
    "impact":        str(r.get("business_impact", ""))[:80] + "…" if r.get("business_impact") and len(r.get("business_impact","")) > 80 else r.get("business_impact"),
} for r in rows]
show(flat)


# ================================================================
# 10. SCAN HISTORY
# ================================================================
section("SCAN HISTORY")
rows = (
    supabase.table("scans")
    .select("scan_name, scan_type, scanner_tool, status, assets_scanned, total_findings, critical_findings, high_findings, scan_started_at, duration_seconds")
    .order("scan_started_at", desc=True)
    .execute().data
)
show(rows)
# ================================================================
# 11.To view asset statuses from the database
# ================================================================
#To view asset statuses from the database
result = (
    supabase.table("assets")
    .select("asset_id, asset_name, status")
    .execute()
)

print("\nAsset Status Report")
print("-" * 50)

for asset in result.data:
    print(
        f"{asset['asset_id']} | "
        f"{asset['asset_name']} | "
        f"{asset['status']}"
        )
#To show only inactive assets
result = (
    supabase.table("assets")
    .select("asset_id, asset_name, status")
    .eq("status", "inactive")
    .execute()
)

print("\nInactive Assets")
print("-" * 50)

if result.data:
    for asset in result.data:
        print(
            f"{asset['asset_id']} | "
            f"{asset['asset_name']} | "
            f"{asset['status']}"
        )
else:
    print("No inactive assets found.")
# ================================================================
# USEFUL UPDATE EXAMPLES (uncomment to use)
# ================================================================

# ── Mark a vulnerability as remediated ───────────────────────────
# asset = supabase.table("assets").select("asset_id").eq("asset_name", "Web Server 01").single().execute().data
# vuln  = supabase.table("vulnerabilities").select("vuln_id").eq("cve_id", "CVE-2024-1234").single().execute().data
#
# supabase.table("asset_vulnerabilities").update({
#     "status":        "remediated",
#     "remediated_on": "2024-06-12",
#     "notes":         "Upgraded Log4j to 2.17.1. Verified by rescan."
# }).eq("asset_id", asset["asset_id"]).eq("vuln_id", vuln["vuln_id"]).execute()
# print("✔ Vulnerability marked as remediated")


# ── Log a new event on an asset ───────────────────────────────────
# asset = supabase.table("assets").select("asset_id").eq("asset_name", "Web Server 01").single().execute().data
#
# supabase.table("asset_logs").insert({
#     "asset_id":     asset["asset_id"],
#     "log_level":    "info",
#     "event_type":   "patch_applied",
#     "event_source": "manual",
#     "message":      "Log4j upgraded to 2.17.1. No longer vulnerable.",
#     "details":      {"cve": "CVE-2024-1234", "action": "upgrade", "new_version": "2.17.1"}
# }).execute()
# print("✔ Log entry added")


# ── Close an exposure after it's fixed ───────────────────────────
# supabase.table("exposures").update({
#     "status":   "closed",
#     "closed_on": "2024-06-12T15:00:00"
# }).eq("exposure_id", 1).execute()
# print("✔ Exposure closed")


print(f"\n{'━'*64}")
print("  ✅ All queries done.")
print(f"{'━'*64}\n")
