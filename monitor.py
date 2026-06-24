"""
monitor.py
==========
CTEM Asset Monitoring System — main orchestrator.

Full pipeline:
  1. Load previous inventory  (from Supabase or supplied list)
  2. Load current  inventory  (from Supabase or supplied list)
  3. Detect changes           (via AssetChangeDetector)
  4. Generate alerts          (via AlertEngine)
  5. Store alerts + run log   (to Supabase AND local JSON file)
  6. Print monitoring report  (formatted summary)

Run (Supabase mode — uses your live database):
    python3 monitor.py

Run (demo mode — uses built-in sample data, no Supabase needed):
    python3 monitor.py --demo
"""

import argparse
import json
import os
import uuid
from datetime import datetime

from change_detector import AssetChangeDetector
from alert_engine import AlertEngine

# ── Supabase import (optional — only needed when not in demo mode) ────────────
try:
    from supabase import create_client
    from config import SUPABASE_URL, SUPABASE_KEY
    _SUPABASE_AVAILABLE = True
except ImportError:
    _SUPABASE_AVAILABLE = False

LOGS_DIR = os.path.join(os.path.dirname(__file__), "monitoring_logs")


# ─────────────────────────────────────────────────────────────────────────────
# Asset Monitor
# ─────────────────────────────────────────────────────────────────────────────

class AssetMonitor:
    """
    Orchestrates the full asset monitoring pipeline.

    Parameters
    ----------
    previous : list[dict]
        The older inventory snapshot.
    current : list[dict]
        The latest inventory snapshot.
    run_label : str, optional
        A human-readable label for this monitoring run (shown in logs).
    save_locally : bool
        If True, saves a JSON log file to the monitoring_logs/ directory.
    push_to_supabase : bool
        If True, stores alerts and the run record in Supabase.
    """

    def __init__(
        self,
        previous: list,
        current: list,
        run_label: str = "Asset Monitor Run",
        save_locally: bool = True,
        push_to_supabase: bool = True,
    ):
        self.previous         = previous
        self.current          = current
        self.run_label        = run_label
        self.save_locally     = save_locally
        self.push_to_supabase = push_to_supabase and _SUPABASE_AVAILABLE

        self.run_id       = str(uuid.uuid4())
        self.started_at   = datetime.now()
        self._supabase    = None

        if self.push_to_supabase:
            self._supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self) -> str:
        """
        Execute the full monitoring pipeline.
        Returns the formatted monitoring report as a string.
        """
        print(f"\n{'━'*60}")
        print(f"  🛡️  CTEM Asset Monitor — {self.run_label}")
        print(f"  Run ID : {self.run_id}")
        print(f"  Started: {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'━'*60}\n")

        # Step 1 — Detect changes
        print("  🔍  Step 1 — Detecting changes...")
        detector     = AssetChangeDetector(self.previous, self.current)
        report       = detector.detect()
        print(f"       Added: {report.total_added}  |  Removed: {report.total_removed}  |  Modified: {report.total_modified}  |  Unchanged: {report.total_unchanged}")

        # Step 2 — Generate alerts
        print("\n  🚨  Step 2 — Generating alerts...")
        engine = AlertEngine(report)
        alerts = engine.generate_alerts()
        summ   = engine.summary()
        print(f"       Total: {summ['total']}  |  🔴 Critical: {summ['critical']}  |  🟡 Warning: {summ['warning']}  |  🔵 Info: {summ['info']}")

        finished_at = datetime.now()
        duration    = (finished_at - self.started_at).total_seconds()

        # Step 3 — Store locally
        log_path = None
        if self.save_locally:
            print("\n  💾  Step 3 — Saving local log...")
            log_path = self._save_local_log(report, alerts, summ, finished_at, duration)
            print(f"       Saved → {log_path}")

        # Step 4 — Push to Supabase
        if self.push_to_supabase:
            print("\n  ☁️   Step 4 — Storing in Supabase...")
            self._push_to_supabase(report, alerts, summ, finished_at, duration)
        else:
            print("\n  ☁️   Step 4 — Skipping Supabase (demo mode or unavailable).")

        # Step 5 — Generate report
        print("\n  📊  Step 5 — Generating monitoring report...\n")
        final_report = _format_monitoring_report(
            run_id      = self.run_id,
            run_label   = self.run_label,
            started_at  = self.started_at,
            finished_at = finished_at,
            duration    = duration,
            previous    = self.previous,
            current     = self.current,
            report      = report,
            alerts      = alerts,
            log_path    = log_path,
        )
        return final_report

    # ── Local JSON log ────────────────────────────────────────────────────────

    def _save_local_log(self, report, alerts, summ, finished_at, duration) -> str:
        """Save a complete JSON log of this monitoring run to disk."""
        os.makedirs(LOGS_DIR, exist_ok=True)

        filename  = f"monitor_{self.started_at.strftime('%Y%m%d_%H%M%S')}.json"
        file_path = os.path.join(LOGS_DIR, filename)

        log_data = {
            "run_id":           self.run_id,
            "run_label":        self.run_label,
            "started_at":       self.started_at.isoformat(),
            "finished_at":      finished_at.isoformat(),
            "duration_seconds": round(duration, 2),
            "inventory_counts": {
                "previous": len(self.previous),
                "current":  len(self.current),
            },
            "change_summary": {
                "added":     report.total_added,
                "removed":   report.total_removed,
                "modified":  report.total_modified,
                "unchanged": report.total_unchanged,
            },
            "alert_summary": summ,
            "alerts": [a.to_dict() for a in alerts],
            "added_assets":   report.added,
            "removed_assets": report.removed,
            "modified_assets": {
                asset_id: [
                    {"field": c.field, "old_value": c.old_value, "new_value": c.new_value}
                    for c in changes
                ]
                for asset_id, changes in report.modified.items()
            },
        }

        with open(file_path, "w") as f:
            json.dump(log_data, f, indent=2, default=str)

        return file_path

    # ── Supabase storage ──────────────────────────────────────────────────────

    def _push_to_supabase(self, report, alerts, summ, finished_at, duration):
        """Insert alerts and the monitoring run record into Supabase."""
        sb = self._supabase

        # ── Insert monitoring_run record ──────────────────────────────────────
        run_record = {
            "run_id":                self.run_id,
            "run_started_at":        self.started_at.isoformat(),
            "run_finished_at":       finished_at.isoformat(),
            "duration_seconds":      round(duration, 2),
            "previous_asset_count":  len(self.previous),
            "current_asset_count":   len(self.current),
            "total_added":           report.total_added,
            "total_removed":         report.total_removed,
            "total_modified":        report.total_modified,
            "total_unchanged":       report.total_unchanged,
            "total_alerts":          summ["total"],
            "critical_alerts":       summ["critical"],
            "warning_alerts":        summ["warning"],
            "info_alerts":           summ["info"],
            "status":                "completed",
        }
        sb.table("monitoring_runs").insert(run_record).execute()
        print(f"       ✔  Monitoring run recorded (run_id: {self.run_id[:8]}…)")

        # ── Insert alerts ─────────────────────────────────────────────────────
        if alerts:
            # Resolve asset names → asset IDs from the database for FK linking
            asset_id_map = self._resolve_asset_ids(alerts)

            rows = []
            for a in alerts:
                db_asset_id = asset_id_map.get(a.asset_id)  # may be None
                rows.append({
                    "asset_id":         db_asset_id,
                    "alert_type":       a.alert_type,
                    "severity":         a.severity,
                    "asset_name":       a.asset_name,
                    "message":          a.message,
                    "details":          a.details,
                    "monitoring_run_id": self.run_id,
                    "is_acknowledged":  False,
                })

            sb.table("alerts").insert(rows).execute()
            print(f"       ✔  {len(rows)} alert(s) stored in Supabase.")
        else:
            print("       ✔  No alerts to store.")

    def _resolve_asset_ids(self, alerts: list) -> dict:
        """
        Build a mapping from asset_id string → DB integer asset_id.
        Falls back gracefully if the asset isn't in the DB.
        """
        # Collect unique asset IDs mentioned in alerts
        asset_ids = list({a.asset_id for a in alerts if a.asset_id})
        if not asset_ids:
            return {}

        try:
            rows = (
                self._supabase.table("assets")
                .select("asset_id, asset_name")
                .execute()
                .data
            )
            # Map both by asset_name and asset_id (in case IDs differ)
            mapping = {}
            for row in rows:
                mapping[str(row["asset_id"])] = row["asset_id"]
            return mapping
        except Exception:
            return {}


# ─────────────────────────────────────────────────────────────────────────────
# Report Formatter
# ─────────────────────────────────────────────────────────────────────────────

def _format_monitoring_report(
    run_id, run_label, started_at, finished_at,
    duration, previous, current, report, alerts, log_path
) -> str:
    """Return the full monitoring summary report as a formatted string."""

    lines = []
    W = 64

    def line(t=""):       lines.append(t)
    def rule():           lines.append("─" * W)
    def double_rule():    lines.append("=" * W)

    double_rule()
    line(f"  CTEM ASSET MONITORING REPORT")
    double_rule()
    line(f"  Run Label  : {run_label}")
    line(f"  Run ID     : {run_id}")
    line(f"  Started    : {started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    line(f"  Finished   : {finished_at.strftime('%Y-%m-%d %H:%M:%S')}")
    line(f"  Duration   : {duration:.2f}s")
    line()

    # ── Inventory Summary ─────────────────────────────────────────────────────
    rule()
    line("  INVENTORY OVERVIEW")
    rule()
    line(f"  Previous inventory  : {len(previous):>4} asset(s)")
    line(f"  Current  inventory  : {len(current):>4} asset(s)")
    line(f"  Net change          : {len(current) - len(previous):>+4} asset(s)")
    line()

    # ── Change Summary ────────────────────────────────────────────────────────
    rule()
    line("  CHANGE SUMMARY")
    rule()
    line(f"  ✅  Added             : {report.total_added:>4}")
    line(f"  🗑️   Removed           : {report.total_removed:>4}")
    line(f"  ✏️   Modified          : {report.total_modified:>4}")
    line(f"  ➖  Unchanged          : {report.total_unchanged:>4}")
    line()

    # ── Alert Summary ─────────────────────────────────────────────────────────
    rule()
    line("  ALERT SUMMARY")
    rule()
    critical = [a for a in alerts if a.severity == "CRITICAL"]
    warnings = [a for a in alerts if a.severity == "WARNING"]
    infos    = [a for a in alerts if a.severity == "INFO"]
    line(f"  🔴  CRITICAL          : {len(critical):>4}")
    line(f"  🟡  WARNING           : {len(warnings):>4}")
    line(f"  🔵  INFO              : {len(infos):>4}")
    line(f"  ─────────────────────────────")
    line(f"  ⚡  TOTAL ALERTS      : {len(alerts):>4}")
    line()

    # ── Critical Alerts detail ────────────────────────────────────────────────
    if critical:
        rule()
        line("  🔴  CRITICAL ALERTS — Action Required Immediately")
        rule()
        for a in critical:
            line()
            line(f"  [{a.alert_type}]")
            line(f"  Asset   : {a.asset_name or a.asset_id}")
            line(f"  Message : {a.message}")
        line()

    # ── Warning Alerts detail ─────────────────────────────────────────────────
    if warnings:
        rule()
        line("  🟡  WARNING ALERTS — Please Review")
        rule()
        for a in warnings:
            line()
            line(f"  [{a.alert_type}]")
            line(f"  Asset   : {a.asset_name or a.asset_id}")
            line(f"  Message : {a.message}")
        line()

    # ── Info Alerts detail ────────────────────────────────────────────────────
    if infos:
        rule()
        line("  🔵  INFO ALERTS — For Audit Record")
        rule()
        for a in infos:
            line(f"  • [{a.alert_type}] {a.asset_name or a.asset_id} — {a.message}")
        line()

    # ── No alerts case ────────────────────────────────────────────────────────
    if not alerts:
        rule()
        line("  ✅  NO ALERTS — Inventory is stable, no action required.")
        line()

    # ── Storage info ──────────────────────────────────────────────────────────
    rule()
    line("  STORAGE")
    rule()
    if log_path:
        line(f"  Local log  : {os.path.basename(log_path)}")
    line(f"  Supabase   : alerts table + monitoring_runs table")
    line()
    double_rule()
    line("  END OF MONITORING REPORT")
    double_rule()

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Built-in Demo Data
# ─────────────────────────────────────────────────────────────────────────────

_DEMO_PREVIOUS = [
    {"asset_id": "SRV-001", "asset_name": "Web Server 01",     "asset_type": "server",         "ip_address": "192.168.1.10", "os": "Ubuntu 20.04", "owner": "Infra Team",    "criticality": "critical", "status": "active"},
    {"asset_id": "SRV-002", "asset_name": "Database Server",   "asset_type": "server",         "ip_address": "192.168.1.20", "os": "Win Server 2019","owner": "DB Team",    "criticality": "critical", "status": "active"},
    {"asset_id": "WRK-001", "asset_name": "HR Workstation",    "asset_type": "workstation",    "ip_address": "192.168.2.15", "os": "Windows 11",   "owner": "HR Dept",       "criticality": "medium",   "status": "active"},
    {"asset_id": "WRK-002", "asset_name": "Dev Laptop - Alice","asset_type": "workstation",    "ip_address": "192.168.3.5",  "os": "macOS Ventura","owner": "Engineering",   "criticality": "low",      "status": "active"},
    {"asset_id": "NET-001", "asset_name": "Core Switch",       "asset_type": "network_device", "ip_address": "192.168.1.1",  "os": "Cisco IOS 15","owner": "Network Team",  "criticality": "critical", "status": "active"},
    {"asset_id": "CLO-001", "asset_name": "Cloud API Gateway", "asset_type": "cloud_instance", "ip_address": "10.0.1.4",     "os": "Amazon Linux","owner": "DevOps Team",   "criticality": "high",     "status": "active"},
    {"asset_id": "SRV-003", "asset_name": "Old Backup Server", "asset_type": "server",         "ip_address": "192.168.1.99", "os": "CentOS 7",    "owner": "Infra Team",    "criticality": "medium",   "status": "active"},
]

_DEMO_CURRENT = [
    {"asset_id": "SRV-001", "asset_name": "Web Server 01",       "asset_type": "server",         "ip_address": "192.168.1.10", "os": "Ubuntu 22.04",  "owner": "Infra Team",   "criticality": "critical", "status": "active"},   # OS upgraded
    {"asset_id": "SRV-002", "asset_name": "Database Server",     "asset_type": "server",         "ip_address": "192.168.1.20", "os": "Win Server 2022","owner": "DB Team",     "criticality": "critical", "status": "active"},   # OS upgraded
    {"asset_id": "WRK-001", "asset_name": "HR Workstation",      "asset_type": "workstation",    "ip_address": "192.168.2.15", "os": "Windows 11",    "owner": "HR Dept",      "criticality": "medium",   "status": "inactive"}, # STATUS → inactive
    {"asset_id": "WRK-002", "asset_name": "Dev Laptop - Alice",  "asset_type": "workstation",    "ip_address": "192.168.3.5",  "os": "macOS Ventura", "owner": "Engineering",  "criticality": "high",     "status": "active"},   # criticality raised
    {"asset_id": "NET-001", "asset_name": "Core Switch",         "asset_type": "network_device", "ip_address": "192.168.1.1",  "os": "Cisco IOS 15", "owner": "Network Team", "criticality": "critical", "status": "active"},   # unchanged
    {"asset_id": "CLO-001", "asset_name": "Cloud API Gateway",   "asset_type": "cloud_instance", "ip_address": "10.0.1.5",     "os": "Amazon Linux", "owner": "DevOps Team",  "criticality": "high",     "status": "active"},   # IP changed
    # SRV-003 removed (decommissioned)
    {"asset_id": "CLO-002", "asset_name": "Cloud Storage Bucket","asset_type": "cloud_instance", "ip_address": "10.0.2.1",     "os": "N/A",          "owner": "DevOps Team",  "criticality": "high",     "status": "active"},   # new
    {"asset_id": "SRV-004", "asset_name": "New CI/CD Server",    "asset_type": "server",         "ip_address": "192.168.1.55", "os": "Ubuntu 22.04", "owner": "Engineering",  "criticality": "medium",   "status": "active"},   # new
]


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTEM Asset Monitor")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with built-in demo data instead of pulling from Supabase.",
    )
    args = parser.parse_args()

    if args.demo or not _SUPABASE_AVAILABLE:
        # ── Demo mode (no Supabase required) ─────────────────────────────────
        monitor = AssetMonitor(
            previous         = _DEMO_PREVIOUS,
            current          = _DEMO_CURRENT,
            run_label        = "Demo Monitor Run",
            save_locally     = True,
            push_to_supabase = False,
        )
    else:
        # ── Live Supabase mode ────────────────────────────────────────────────
        # Pull the full assets table as "current" inventory.
        # For a real system you'd compare against a previously saved snapshot;
        # here we simulate by using the DB current state as both (no changes).
        # Replace this with your own snapshot-loading logic as needed.
        try:
            sb      = create_client(SUPABASE_URL, SUPABASE_KEY)
            current = sb.table("assets").select("*").execute().data

            # Try to load the last monitoring log as "previous"
            log_files = sorted(
                [f for f in os.listdir(LOGS_DIR) if f.endswith(".json")]
            ) if os.path.exists(LOGS_DIR) else []

            if log_files:
                last_log = os.path.join(LOGS_DIR, log_files[-1])
                with open(last_log) as f:
                    previous = json.load(f).get("added_assets", []) + \
                               json.load(open(last_log)).get("current_inventory", current)
            else:
                print("  ℹ️  No previous log found — using current inventory as baseline.")
                previous = current

            monitor = AssetMonitor(
                previous         = previous,
                current          = current,
                run_label        = "Supabase Live Run",
                save_locally     = True,
                push_to_supabase = True,
            )
        except Exception as e:
            print(f"\n  ⚠️  Could not connect to Supabase: {e}")
            print("  Falling back to demo mode.\n")
            monitor = AssetMonitor(
                previous         = _DEMO_PREVIOUS,
                current          = _DEMO_CURRENT,
                run_label        = "Demo Monitor Run (fallback)",
                save_locally     = True,
                push_to_supabase = False,
            )

    report = monitor.run()
    print(report)
