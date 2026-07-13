"""
change_detector.py
==================
Asset Change Detection System for CTEM (Continuous Threat Exposure Management).

Compares two asset inventories (previous vs. current) and detects:
  - Newly ADDED assets
  - REMOVED assets
  - MODIFIED assets (field-level changes)

Then generates a formatted summary report.

Usage:
    from change_detector import AssetChangeDetector

    detector = AssetChangeDetector(previous_inventory, current_inventory)
    report   = detector.generate_report()
    print(report)
"""

from datetime import datetime
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

class AssetChange:
    """Represents a single field-level change on an asset."""

    def __init__(self, asset_id: str, field: str, old_value: Any, new_value: Any):
        self.asset_id  = asset_id
        self.field     = field
        self.old_value = old_value
        self.new_value = new_value

    def __repr__(self):
        return (
            f"AssetChange(asset_id={self.asset_id!r}, field={self.field!r}, "
            f"old={self.old_value!r}, new={self.new_value!r})"
        )


class ChangeReport:
    """
    Holds the full result of a change detection run.

    Attributes:
        added     : list of asset dicts that are new in the current inventory.
        removed   : list of asset dicts that are missing from the current inventory.
        modified  : dict mapping asset_id → list of AssetChange objects.
        unchanged : list of asset dicts with no detected changes.
        generated_at : timestamp when this report was produced.
    """

    def __init__(self, added, removed, modified, unchanged):
        self.added        = added
        self.removed      = removed
        self.modified     = modified      # { asset_id: [AssetChange, ...] }
        self.unchanged    = unchanged
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Convenience counts ────────────────────────────────────────────────────
    @property
    def total_added(self):
        return len(self.added)

    @property
    def total_removed(self):
        return len(self.removed)

    @property
    def total_modified(self):
        return len(self.modified)

    @property
    def total_unchanged(self):
        return len(self.unchanged)

    @property
    def has_changes(self):
        return bool(self.added or self.removed or self.modified)


# ─────────────────────────────────────────────────────────────────────────────
# Core Detector
# ─────────────────────────────────────────────────────────────────────────────

class AssetChangeDetector:
    """
    Compares two asset inventories and produces a ChangeReport.

    Parameters
    ----------
    previous : list[dict]
        The older asset inventory snapshot.
    current  : list[dict]
        The latest asset inventory snapshot.
    id_field : str, optional
        The field used as a unique identifier for each asset.
        Defaults to "asset_id".
    ignore_fields : list[str], optional
        Fields that should be excluded from change comparison
        (e.g., timestamps that change every scan).
        Defaults to ["updated_at", "last_seen"].

    Example
    -------
    previous = [{"asset_id": "A1", "ip_address": "10.0.0.1", "status": "active"}]
    current  = [{"asset_id": "A1", "ip_address": "10.0.0.2", "status": "active"}]

    detector = AssetChangeDetector(previous, current)
    report   = detector.detect()
    """

    def __init__(
        self,
        previous: list,
        current: list,
        id_field: str = "asset_id",
        ignore_fields: list = None,
    ):
        self.previous      = previous
        self.current       = current
        self.id_field      = id_field
        self.ignore_fields = set(ignore_fields or ["updated_at", "last_seen"])

        # Build lookup dicts keyed by the id_field value
        self._prev_map = self._build_map(previous)
        self._curr_map = self._build_map(current)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_map(self, inventory: list) -> dict:
        """Convert a list of asset dicts into a dict keyed by id_field."""
        result = {}
        for asset in inventory:
            key = asset.get(self.id_field)
            if key is None:
                raise ValueError(
                    f"Asset is missing the id field '{self.id_field}': {asset}"
                )
            if key in result:
                raise ValueError(
                    f"Duplicate asset id '{key}' found in inventory."
                )
            result[key] = asset
        return result

    def _compare_assets(self, asset_id: str) -> list:
        """
        Compare two versions of the same asset and return a list
        of AssetChange objects for every field that differs.
        Fields listed in self.ignore_fields are skipped.
        """
        prev = self._prev_map[asset_id]
        curr = self._curr_map[asset_id]

        # Union of all field names from both versions
        all_fields = set(prev.keys()) | set(curr.keys())
        changes = []

        for field in sorted(all_fields):
            if field in self.ignore_fields:
                continue
            if field == self.id_field:
                continue  # the id itself is our key — not a meaningful change

            old_val = prev.get(field)
            new_val = curr.get(field)

            if old_val != new_val:
                changes.append(AssetChange(asset_id, field, old_val, new_val))

        return changes

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self) -> ChangeReport:
        """
        Run the full comparison and return a ChangeReport.

        Returns
        -------
        ChangeReport
            Contains .added, .removed, .modified, .unchanged lists.
        """
        prev_ids = set(self._prev_map.keys())
        curr_ids = set(self._curr_map.keys())

        # Added: exist in current but NOT in previous
        added_ids   = curr_ids - prev_ids
        added       = [self._curr_map[i] for i in sorted(added_ids)]

        # Removed: exist in previous but NOT in current
        removed_ids = prev_ids - curr_ids
        removed     = [self._prev_map[i] for i in sorted(removed_ids)]

        # Present in both — check for modifications
        common_ids  = prev_ids & curr_ids
        modified    = {}
        unchanged   = []

        for asset_id in sorted(common_ids):
            field_changes = self._compare_assets(asset_id)
            if field_changes:
                modified[asset_id] = field_changes
            else:
                unchanged.append(self._curr_map[asset_id])

        return ChangeReport(added, removed, modified, unchanged)

    def generate_report(self) -> str:
        """
        Run detection and return the full summary as a formatted string.
        This is the main method you'd call to get a printable report.
        """
        report = self.detect()
        return _format_report(report)


# ─────────────────────────────────────────────────────────────────────────────
# Report Formatter
# ─────────────────────────────────────────────────────────────────────────────

def _format_report(report: ChangeReport) -> str:
    """Render a ChangeReport as a human-readable string."""

    lines = []
    W = 64  # report width

    def line(text=""):
        lines.append(text)

    def header(title):
        lines.append("=" * W)
        lines.append(f"  {title}")
        lines.append("=" * W)

    def section(title, count, icon):
        lines.append("")
        lines.append(f"{'─' * W}")
        lines.append(f"  {icon}  {title}  ({count})")
        lines.append(f"{'─' * W}")

    # ── Title ─────────────────────────────────────────────────────────────────
    header("ASSET CHANGE DETECTION REPORT")
    line(f"  Generated : {report.generated_at}")
    line()
    line(f"  {'Summary':30} {'Count':>6}")
    line(f"  {'─'*30} {'─'*6}")
    line(f"  {'✅  Newly Added Assets':30} {report.total_added:>6}")
    line(f"  {'🗑️   Removed Assets':30} {report.total_removed:>6}")
    line(f"  {'✏️   Modified Assets':30} {report.total_modified:>6}")
    line(f"  {'➖  Unchanged Assets':30} {report.total_unchanged:>6}")
    line()
    if report.has_changes:
        line("  ⚠️  Changes detected — review details below.")
    else:
        line("  ✅  No changes detected. Inventories are identical.")
    line("=" * W)

    # ── Added ─────────────────────────────────────────────────────────────────
    section("ADDED ASSETS", report.total_added, "✅")
    if report.added:
        for asset in report.added:
            line()
            line(f"  + Asset ID  : {asset.get('asset_id', 'N/A')}")
            line(f"    Name      : {asset.get('asset_name', 'N/A')}")
            line(f"    Type      : {asset.get('asset_type', 'N/A')}")
            line(f"    IP        : {asset.get('ip_address', 'N/A')}")
            line(f"    Owner     : {asset.get('owner', 'N/A')}")
            line(f"    Criticality: {asset.get('criticality', 'N/A')}")
    else:
        line()
        line("  None.")

    # ── Removed ──────────────────────────────────────────────────────────────
    section("REMOVED ASSETS", report.total_removed, "🗑️")
    if report.removed:
        for asset in report.removed:
            line()
            line(f"  - Asset ID  : {asset.get('asset_id', 'N/A')}")
            line(f"    Name      : {asset.get('asset_name', 'N/A')}")
            line(f"    Type      : {asset.get('asset_type', 'N/A')}")
            line(f"    IP        : {asset.get('ip_address', 'N/A')}")
            line(f"    Owner     : {asset.get('owner', 'N/A')}")
            line(f"    Criticality: {asset.get('criticality', 'N/A')}")
    else:
        line()
        line("  None.")

    # ── Modified ─────────────────────────────────────────────────────────────
    section("MODIFIED ASSETS", report.total_modified, "✏️")
    if report.modified:
        for asset_id, changes in report.modified.items():
            line()
            line(f"  ~ Asset ID : {asset_id}  ({len(changes)} field(s) changed)")
            line(f"    {'Field':<25} {'Old Value':<22} {'New Value':<22}")
            line(f"    {'─'*25} {'─'*22} {'─'*22}")
            for ch in changes:
                old = str(ch.old_value)[:20] if ch.old_value is not None else "(none)"
                new = str(ch.new_value)[:20] if ch.new_value is not None else "(none)"
                line(f"    {ch.field:<25} {old:<22} {new:<22}")
    else:
        line()
        line("  None.")

    # ── Unchanged ─────────────────────────────────────────────────────────────
    section("UNCHANGED ASSETS", report.total_unchanged, "➖")
    if report.unchanged:
        for asset in report.unchanged:
            a_id   = asset.get("asset_id",   "N/A")
            a_name = asset.get("asset_name", "N/A")
            line(f"    {a_id:<15} {a_name}")
    else:
        line()
        line("  None.")

    line()
    line("=" * W)
    line("  END OF REPORT")
    line("=" * W)

    return "\n".join(lines)
