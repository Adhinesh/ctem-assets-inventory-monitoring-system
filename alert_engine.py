"""
alert_engine.py
===============
Alert Generation Engine for the CTEM Asset Monitoring System.

Takes a ChangeReport (from change_detector.py) and applies a rule set
to produce a list of Alert objects — one per notable event.

Alert Types
-----------
  NEW_ASSET          An asset appeared that wasn't in the previous inventory.
  REMOVED_ASSET      An asset disappeared from the inventory.
  STATUS_CHANGE      The 'status' field changed (e.g. active → inactive).
  CRITICALITY_CHANGE The 'criticality' field changed.
  IP_CHANGE          The IP address changed (potential unauthorized move).
  OS_CHANGE          The operating system changed (patch or compromise?).
  OWNER_CHANGE       Ownership of the asset changed.
  FIELD_CHANGE       Any other field-level change not covered above.

Severity Levels
---------------
  CRITICAL   Immediate action required (e.g. critical asset removed, IP changed).
  WARNING    Should be reviewed soon (e.g. status went inactive, owner changed).
  INFO       Routine change, logged for audit purposes.

Usage
-----
    from change_detector import AssetChangeDetector
    from alert_engine import AlertEngine

    detector = AssetChangeDetector(previous, current)
    report   = detector.detect()

    engine = AlertEngine(report)
    alerts = engine.generate_alerts()
    for alert in alerts:
        print(alert)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import uuid

from change_detector import ChangeReport, AssetChange


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Map criticality label → severity of a "new asset" or "removed asset" alert
_CRITICALITY_TO_SEVERITY = {
    "critical": "CRITICAL",
    "high":     "WARNING",
    "medium":   "INFO",
    "low":      "INFO",
}

# Fields that get their own dedicated alert type
_FIELD_ALERT_TYPES = {
    "status":      "STATUS_CHANGE",
    "criticality": "CRITICALITY_CHANGE",
    "ip_address":  "IP_CHANGE",
    "os":          "OS_CHANGE",
    "owner":       "OWNER_CHANGE",
}

# Severity rules for specific field changes
_FIELD_SEVERITY = {
    "ip_address":  "WARNING",
    "status":      "WARNING",
    "criticality": "WARNING",
    "os":          "INFO",
    "owner":       "WARNING",
}

# Status values considered "risky" (trigger WARNING instead of INFO)
_RISKY_STATUS_VALUES = {"inactive", "decommissioned", "under_maintenance", "compromised"}

# Upward criticality transitions (lower → higher risk)
_CRITICALITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ─────────────────────────────────────────────────────────────────────────────
# Alert Data Class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    """Represents a single monitoring alert."""

    alert_type:       str                        # e.g. 'NEW_ASSET', 'IP_CHANGE'
    severity:         str                        # 'INFO' | 'WARNING' | 'CRITICAL'
    message:          str                        # human-readable description
    asset_id:         str   = None               # the affected asset's ID
    asset_name:       str   = None               # the affected asset's name
    details:          dict  = field(default_factory=dict)  # extra structured data
    alert_id:         str   = field(default_factory=lambda: str(uuid.uuid4()))
    created_at:       str   = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def __str__(self):
        icon = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(self.severity, "⚪")
        return f"[{self.severity}] {icon}  {self.alert_type} | {self.asset_name or self.asset_id} — {self.message}"

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation or Supabase insertion."""
        return {
            "alert_id":         self.alert_id,
            "alert_type":       self.alert_type,
            "severity":         self.severity,
            "asset_name":       self.asset_name,
            "message":          self.message,
            "details":          self.details,
            "created_at":       self.created_at,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Alert Engine
# ─────────────────────────────────────────────────────────────────────────────

class AlertEngine:
    """
    Applies a rule-based system to a ChangeReport to produce Alert objects.

    Parameters
    ----------
    report : ChangeReport
        The output of AssetChangeDetector.detect().
    id_field : str
        The field used as the asset's unique identifier. Default: 'asset_id'.
    """

    def __init__(self, report: ChangeReport, id_field: str = "asset_id"):
        self.report   = report
        self.id_field = id_field
        self._alerts  = []

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_alerts(self) -> list:
        """
        Process the ChangeReport and return a list of Alert objects.
        Alerts are sorted: CRITICAL first, then WARNING, then INFO.
        """
        self._alerts = []
        self._process_added()
        self._process_removed()
        self._process_modified()
        self._alerts.sort(key=lambda a: {"CRITICAL": 0, "WARNING": 1, "INFO": 2}[a.severity])
        return self._alerts

    def summary(self) -> dict:
        """Return a quick count of alerts by severity."""
        alerts = self._alerts or self.generate_alerts()
        return {
            "total":    len(alerts),
            "critical": sum(1 for a in alerts if a.severity == "CRITICAL"),
            "warning":  sum(1 for a in alerts if a.severity == "WARNING"),
            "info":     sum(1 for a in alerts if a.severity == "INFO"),
        }

    # ── Internal rule processors ──────────────────────────────────────────────

    def _add(self, alert: Alert):
        self._alerts.append(alert)

    def _get_name(self, asset: dict) -> str:
        return asset.get("asset_name") or asset.get(self.id_field, "Unknown")

    def _get_id(self, asset: dict) -> str:
        return str(asset.get(self.id_field, ""))

    def _process_added(self):
        """Rule: every new asset → NEW_ASSET alert. Severity based on criticality."""
        for asset in self.report.added:
            criticality = (asset.get("criticality") or "low").lower()
            severity    = _CRITICALITY_TO_SEVERITY.get(criticality, "INFO")
            name        = self._get_name(asset)
            asset_id    = self._get_id(asset)

            self._add(Alert(
                alert_type  = "NEW_ASSET",
                severity    = severity,
                asset_id    = asset_id,
                asset_name  = name,
                message     = (
                    f"New {criticality}-criticality asset '{name}' "
                    f"({asset.get('asset_type', 'unknown type')}) "
                    f"appeared at {asset.get('ip_address', 'unknown IP')}."
                ),
                details = {
                    "asset_type":   asset.get("asset_type"),
                    "ip_address":   asset.get("ip_address"),
                    "owner":        asset.get("owner"),
                    "environment":  asset.get("environment"),
                    "criticality":  criticality,
                },
            ))

    def _process_removed(self):
        """Rule: every removed asset → REMOVED_ASSET alert. Critical assets → CRITICAL."""
        for asset in self.report.removed:
            criticality = (asset.get("criticality") or "low").lower()
            # Critical or high assets disappearing = CRITICAL alert
            severity = "CRITICAL" if criticality in ("critical", "high") else "WARNING"
            name     = self._get_name(asset)
            asset_id = self._get_id(asset)

            self._add(Alert(
                alert_type  = "REMOVED_ASSET",
                severity    = severity,
                asset_id    = asset_id,
                asset_name  = name,
                message     = (
                    f"{criticality.upper()}-criticality asset '{name}' "
                    f"({asset.get('asset_type', 'unknown type')}, "
                    f"{asset.get('ip_address', 'unknown IP')}) "
                    f"has been removed from the inventory."
                ),
                details = {
                    "asset_type":   asset.get("asset_type"),
                    "ip_address":   asset.get("ip_address"),
                    "owner":        asset.get("owner"),
                    "environment":  asset.get("environment"),
                    "criticality":  criticality,
                    "last_status":  asset.get("status"),
                },
            ))

    def _process_modified(self):
        """Rule: inspect each field change and raise the appropriate alert."""
        for asset_id, changes in self.report.modified.items():
            for change in changes:
                self._evaluate_field_change(asset_id, change)

    def _evaluate_field_change(self, asset_id: str, change: AssetChange):
        """Apply field-specific rules to a single AssetChange."""
        field      = change.field
        old_val    = change.old_value
        new_val    = change.new_value
        alert_type = _FIELD_ALERT_TYPES.get(field, "FIELD_CHANGE")

        # ── STATUS CHANGE ──────────────────────────────────────────────────
        if field == "status":
            new_lower = str(new_val).lower() if new_val else ""
            severity  = "WARNING" if new_lower in _RISKY_STATUS_VALUES else "INFO"
            message   = f"Asset status changed from '{old_val}' → '{new_val}'."
            if new_lower in _RISKY_STATUS_VALUES:
                message += f" Asset is now {new_val.upper()} — verify this is intentional."

        # ── CRITICALITY CHANGE ─────────────────────────────────────────────
        elif field == "criticality":
            old_rank = _CRITICALITY_RANK.get(str(old_val).lower(), 0)
            new_rank = _CRITICALITY_RANK.get(str(new_val).lower(), 0)
            if new_rank > old_rank:
                severity = "CRITICAL" if new_val and str(new_val).lower() == "critical" else "WARNING"
                message  = f"Criticality RAISED from '{old_val}' → '{new_val}'. Verify risk posture."
            else:
                severity = "INFO"
                message  = f"Criticality lowered from '{old_val}' → '{new_val}'."

        # ── IP ADDRESS CHANGE ──────────────────────────────────────────────
        elif field == "ip_address":
            severity = "WARNING"
            message  = (
                f"IP address changed from {old_val} → {new_val}. "
                f"Verify this is an authorised change (redeployment, DHCP, etc.)."
            )

        # ── OS CHANGE ─────────────────────────────────────────────────────
        elif field == "os":
            severity = "INFO"
            message  = f"Operating system changed from '{old_val}' → '{new_val}'."

        # ── OWNER CHANGE ──────────────────────────────────────────────────
        elif field == "owner":
            severity = "WARNING"
            message  = f"Asset owner changed from '{old_val}' → '{new_val}'. Update access controls."

        # ── ALL OTHER FIELD CHANGES ────────────────────────────────────────
        else:
            severity = "INFO"
            message  = f"Field '{field}' changed from '{old_val}' → '{new_val}'."

        self._add(Alert(
            alert_type = alert_type,
            severity   = severity,
            asset_id   = str(asset_id),
            message    = message,
            details    = {
                "field":     field,
                "old_value": old_val,
                "new_value": new_val,
            },
        ))
