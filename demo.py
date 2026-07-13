"""
demo.py
=======
Demonstration script for the Asset Change Detection System.

Runs a realistic scenario simulating a week's worth of changes to a
CTEM asset inventory, then prints the formatted summary report.

Run:
    python3 demo.py

Take a screenshot of this output for your assignment submission!
"""

from change_detector import AssetChangeDetector

print("\n  Running Asset Change Detection Demo...")
print("  (Simulating changes between Monday and Friday inventories)\n")


# ─────────────────────────────────────────────────────────────────────────────
# Monday's Snapshot  (previous inventory)
# ─────────────────────────────────────────────────────────────────────────────
monday_inventory = [
    {
        "asset_id":    "SRV-001",
        "asset_name":  "Web Server 01",
        "asset_type":  "server",
        "ip_address":  "192.168.1.10",
        "os":          "Ubuntu 20.04 LTS",
        "owner":       "Infrastructure Team",
        "environment": "production",
        "criticality": "critical",
        "status":      "active",
    },
    {
        "asset_id":    "SRV-002",
        "asset_name":  "Database Server",
        "asset_type":  "server",
        "ip_address":  "192.168.1.20",
        "os":          "Windows Server 2019",
        "owner":       "Database Team",
        "environment": "production",
        "criticality": "critical",
        "status":      "active",
    },
    {
        "asset_id":    "WRK-001",
        "asset_name":  "HR Workstation",
        "asset_type":  "workstation",
        "ip_address":  "192.168.2.15",
        "os":          "Windows 11",
        "owner":       "HR Department",
        "environment": "production",
        "criticality": "medium",
        "status":      "active",
    },
    {
        "asset_id":    "WRK-002",
        "asset_name":  "Dev Laptop - Alice",
        "asset_type":  "workstation",
        "ip_address":  "192.168.3.5",
        "os":          "macOS Ventura",
        "owner":       "Engineering Team",
        "environment": "development",
        "criticality": "low",
        "status":      "active",
    },
    {
        "asset_id":    "NET-001",
        "asset_name":  "Core Switch",
        "asset_type":  "network_device",
        "ip_address":  "192.168.1.1",
        "os":          "Cisco IOS 15.2",
        "owner":       "Network Team",
        "environment": "production",
        "criticality": "critical",
        "status":      "active",
    },
    {
        "asset_id":    "CLO-001",
        "asset_name":  "Cloud API Gateway",
        "asset_type":  "cloud_instance",
        "ip_address":  "10.0.1.4",
        "os":          "Amazon Linux 2",
        "owner":       "DevOps Team",
        "environment": "production",
        "criticality": "high",
        "status":      "active",
    },
    # This asset will be DECOMMISSIONED by Friday
    {
        "asset_id":    "SRV-003",
        "asset_name":  "Old Backup Server",
        "asset_type":  "server",
        "ip_address":  "192.168.1.99",
        "os":          "CentOS 7",
        "owner":       "Infrastructure Team",
        "environment": "production",
        "criticality": "medium",
        "status":      "active",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Friday's Snapshot  (current inventory)
# ─────────────────────────────────────────────────────────────────────────────
friday_inventory = [
    {
        "asset_id":    "SRV-001",
        "asset_name":  "Web Server 01",
        "asset_type":  "server",
        "ip_address":  "192.168.1.10",
        "os":          "Ubuntu 22.04 LTS",       # ← OS UPGRADED
        "owner":       "Infrastructure Team",
        "environment": "production",
        "criticality": "critical",
        "status":      "active",
    },
    {
        "asset_id":    "SRV-002",
        "asset_name":  "Database Server",
        "asset_type":  "server",
        "ip_address":  "192.168.1.20",
        "os":          "Windows Server 2022",    # ← OS UPGRADED
        "owner":       "Database Team",
        "environment": "production",
        "criticality": "critical",
        "status":      "active",
    },
    {
        "asset_id":    "WRK-001",
        "asset_name":  "HR Workstation",
        "asset_type":  "workstation",
        "ip_address":  "192.168.2.15",
        "os":          "Windows 11",
        "owner":       "HR Department",
        "environment": "production",
        "criticality": "medium",
        "status":      "active",
        # no changes — should appear as UNCHANGED
    },
    {
        "asset_id":    "WRK-002",
        "asset_name":  "Dev Laptop - Alice",
        "asset_type":  "workstation",
        "ip_address":  "192.168.3.5",
        "os":          "macOS Ventura",
        "owner":       "Engineering Team",
        "environment": "development",
        "criticality": "high",                   # ← CRITICALITY RAISED
        "status":      "active",
    },
    {
        "asset_id":    "NET-001",
        "asset_name":  "Core Switch",
        "asset_type":  "network_device",
        "ip_address":  "192.168.1.1",
        "os":          "Cisco IOS 15.2",
        "owner":       "Network Team",
        "environment": "production",
        "criticality": "critical",
        "status":      "active",
        # no changes — should appear as UNCHANGED
    },
    {
        "asset_id":    "CLO-001",
        "asset_name":  "Cloud API Gateway",
        "asset_type":  "cloud_instance",
        "ip_address":  "10.0.1.5",               # ← IP CHANGED (redeployment)
        "os":          "Amazon Linux 2",
        "owner":       "DevOps Team",
        "environment": "production",
        "criticality": "high",
        "status":      "active",
    },
    # SRV-003 (Old Backup Server) is GONE — decommissioned

    # NEW assets provisioned this week
    {
        "asset_id":    "CLO-002",
        "asset_name":  "Cloud Storage Bucket",
        "asset_type":  "cloud_instance",
        "ip_address":  "10.0.2.1",
        "os":          "N/A",
        "owner":       "DevOps Team",
        "environment": "production",
        "criticality": "high",
        "status":      "active",
    },
    {
        "asset_id":    "SRV-004",
        "asset_name":  "New CI/CD Build Server",
        "asset_type":  "server",
        "ip_address":  "192.168.1.55",
        "os":          "Ubuntu 22.04 LTS",
        "owner":       "Engineering Team",
        "environment": "staging",
        "criticality": "medium",
        "status":      "active",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Run the detector and print the report
# ─────────────────────────────────────────────────────────────────────────────
detector = AssetChangeDetector(
    previous=monday_inventory,
    current=friday_inventory,
    id_field="asset_id"
)

report_text = detector.generate_report()
print(report_text)
