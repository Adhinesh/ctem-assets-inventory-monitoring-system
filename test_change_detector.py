"""
test_change_detector.py
=======================
Unit tests for the Asset Change Detection System.

Run with:
    python -m unittest test_change_detector.py -v

Or to save results to a file:
    python -m unittest test_change_detector.py -v 2>&1 | tee test_results.txt
"""

import unittest
from change_detector import AssetChangeDetector, ChangeReport, AssetChange


# ─────────────────────────────────────────────────────────────────────────────
# Shared test fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_asset(**kwargs):
    """Helper to quickly build an asset dict with sensible defaults."""
    defaults = {
        "asset_id":       "ASSET-001",
        "asset_name":     "Test Server",
        "asset_type":     "server",
        "ip_address":     "192.168.1.1",
        "os":             "Ubuntu 22.04",
        "owner":          "IT Team",
        "criticality":    "medium",
        "status":         "active",
    }
    defaults.update(kwargs)
    return defaults


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite 1: Added Assets
# ─────────────────────────────────────────────────────────────────────────────

class TestAddedAssets(unittest.TestCase):
    """Tests that the detector correctly identifies newly added assets."""

    def test_single_asset_added(self):
        """A new asset in current but not in previous is detected as added."""
        previous = [make_asset(asset_id="A1")]
        current  = [
            make_asset(asset_id="A1"),
            make_asset(asset_id="A2", asset_name="New Server"),
        ]
        report = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_added, 1)
        self.assertEqual(report.added[0]["asset_id"], "A2")

    def test_multiple_assets_added(self):
        """Multiple new assets are all correctly detected."""
        previous = []
        current  = [
            make_asset(asset_id="A1"),
            make_asset(asset_id="A2"),
            make_asset(asset_id="A3"),
        ]
        report = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_added, 3)

    def test_no_assets_added(self):
        """When both inventories are identical, no additions are reported."""
        inventory = [make_asset(asset_id="A1"), make_asset(asset_id="A2")]
        report = AssetChangeDetector(inventory, inventory).detect()
        self.assertEqual(report.total_added, 0)

    def test_added_from_empty_previous(self):
        """Starting from an empty previous inventory, everything in current is 'added'."""
        current = [make_asset(asset_id="A1"), make_asset(asset_id="A2")]
        report  = AssetChangeDetector([], current).detect()
        self.assertEqual(report.total_added, 2)
        added_ids = [a["asset_id"] for a in report.added]
        self.assertIn("A1", added_ids)
        self.assertIn("A2", added_ids)


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite 2: Removed Assets
# ─────────────────────────────────────────────────────────────────────────────

class TestRemovedAssets(unittest.TestCase):
    """Tests that the detector correctly identifies removed assets."""

    def test_single_asset_removed(self):
        """An asset missing from current (but in previous) is detected as removed."""
        previous = [
            make_asset(asset_id="A1"),
            make_asset(asset_id="A2"),
        ]
        current = [make_asset(asset_id="A1")]
        report  = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_removed, 1)
        self.assertEqual(report.removed[0]["asset_id"], "A2")

    def test_multiple_assets_removed(self):
        """Multiple removed assets are all detected."""
        previous = [
            make_asset(asset_id="A1"),
            make_asset(asset_id="A2"),
            make_asset(asset_id="A3"),
        ]
        current = []
        report  = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_removed, 3)

    def test_no_assets_removed(self):
        """When no assets are removed, the removed list is empty."""
        inventory = [make_asset(asset_id="A1")]
        report    = AssetChangeDetector(inventory, inventory).detect()
        self.assertEqual(report.total_removed, 0)

    def test_all_assets_decommissioned(self):
        """When current is empty, all previous assets show as removed."""
        previous = [make_asset(asset_id="A1"), make_asset(asset_id="A2")]
        report   = AssetChangeDetector(previous, []).detect()
        self.assertEqual(report.total_removed, 2)


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite 3: Modified Assets
# ─────────────────────────────────────────────────────────────────────────────

class TestModifiedAssets(unittest.TestCase):
    """Tests that the detector correctly identifies field-level changes."""

    def test_ip_address_changed(self):
        """A changed IP address is detected as a modification."""
        previous = [make_asset(asset_id="A1", ip_address="192.168.1.1")]
        current  = [make_asset(asset_id="A1", ip_address="10.0.0.5")]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_modified, 1)
        changes = report.modified["A1"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].field,     "ip_address")
        self.assertEqual(changes[0].old_value, "192.168.1.1")
        self.assertEqual(changes[0].new_value, "10.0.0.5")

    def test_os_changed(self):
        """A changed operating system is detected as a modification."""
        previous = [make_asset(asset_id="A1", os="Ubuntu 20.04")]
        current  = [make_asset(asset_id="A1", os="Ubuntu 22.04")]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_modified, 1)
        change = report.modified["A1"][0]
        self.assertEqual(change.field,     "os")
        self.assertEqual(change.old_value, "Ubuntu 20.04")
        self.assertEqual(change.new_value, "Ubuntu 22.04")

    def test_criticality_escalated(self):
        """Criticality changing from 'low' to 'critical' is detected."""
        previous = [make_asset(asset_id="A1", criticality="low")]
        current  = [make_asset(asset_id="A1", criticality="critical")]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_modified, 1)
        change = report.modified["A1"][0]
        self.assertEqual(change.field,     "criticality")
        self.assertEqual(change.old_value, "low")
        self.assertEqual(change.new_value, "critical")

    def test_multiple_fields_changed(self):
        """Multiple changed fields on the same asset are all detected."""
        previous = [make_asset(asset_id="A1", ip_address="10.0.0.1", status="active",   criticality="low")]
        current  = [make_asset(asset_id="A1", ip_address="10.0.0.9", status="inactive", criticality="high")]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_modified, 1)
        changed_fields = {c.field for c in report.modified["A1"]}
        self.assertIn("ip_address",  changed_fields)
        self.assertIn("status",      changed_fields)
        self.assertIn("criticality", changed_fields)

    def test_field_added_to_asset(self):
        """Adding a new field to an existing asset is detected as a modification."""
        previous = [{"asset_id": "A1", "asset_name": "Server"}]
        current  = [{"asset_id": "A1", "asset_name": "Server", "owner": "Infra Team"}]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_modified, 1)
        self.assertEqual(report.modified["A1"][0].field, "owner")

    def test_field_removed_from_asset(self):
        """Removing a field from an existing asset is detected as a modification."""
        previous = [{"asset_id": "A1", "asset_name": "Server", "owner": "Infra Team"}]
        current  = [{"asset_id": "A1", "asset_name": "Server"}]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_modified, 1)
        self.assertEqual(report.modified["A1"][0].field, "owner")
        self.assertIsNone(report.modified["A1"][0].new_value)

    def test_ignored_fields_not_reported(self):
        """Fields listed in ignore_fields are not reported as changes."""
        previous = [make_asset(asset_id="A1", updated_at="2024-01-01", last_seen="2024-01-01")]
        current  = [make_asset(asset_id="A1", updated_at="2024-06-01", last_seen="2024-06-01")]
        report   = AssetChangeDetector(previous, current).detect()
        # updated_at and last_seen are ignored by default
        self.assertEqual(report.total_modified, 0)
        self.assertEqual(report.total_unchanged, 1)

    def test_custom_ignore_fields(self):
        """Custom ignore_fields are respected."""
        previous = [make_asset(asset_id="A1", status="active")]
        current  = [make_asset(asset_id="A1", status="inactive")]
        report   = AssetChangeDetector(
            previous, current, ignore_fields=["status"]
        ).detect()
        self.assertEqual(report.total_modified, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite 4: Unchanged Assets
# ─────────────────────────────────────────────────────────────────────────────

class TestUnchangedAssets(unittest.TestCase):
    """Tests that genuinely unchanged assets are correctly classified."""

    def test_unchanged_asset(self):
        """An asset identical in both inventories is counted as unchanged."""
        asset    = make_asset(asset_id="A1")
        report   = AssetChangeDetector([asset], [asset]).detect()
        self.assertEqual(report.total_unchanged, 1)
        self.assertEqual(report.unchanged[0]["asset_id"], "A1")

    def test_no_changes_means_no_changes_flag(self):
        """has_changes is False when inventories are identical."""
        asset  = make_asset(asset_id="A1")
        report = AssetChangeDetector([asset], [asset]).detect()
        self.assertFalse(report.has_changes)

    def test_with_changes_flag_is_true(self):
        """has_changes is True when there is at least one addition."""
        previous = []
        current  = [make_asset(asset_id="A1")]
        report   = AssetChangeDetector(previous, current).detect()
        self.assertTrue(report.has_changes)


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite 5: Edge Cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """Tests for boundary conditions and unusual inputs."""

    def test_both_inventories_empty(self):
        """Two empty inventories produce a report with all zeros."""
        report = AssetChangeDetector([], []).detect()
        self.assertEqual(report.total_added,     0)
        self.assertEqual(report.total_removed,   0)
        self.assertEqual(report.total_modified,  0)
        self.assertEqual(report.total_unchanged, 0)
        self.assertFalse(report.has_changes)

    def test_custom_id_field(self):
        """The detector works correctly with a custom id_field like 'hostname'."""
        previous = [{"hostname": "web01", "ip_address": "10.0.0.1"}]
        current  = [
            {"hostname": "web01", "ip_address": "10.0.0.1"},
            {"hostname": "web02", "ip_address": "10.0.0.2"},
        ]
        report = AssetChangeDetector(previous, current, id_field="hostname").detect()
        self.assertEqual(report.total_added, 1)
        self.assertEqual(report.added[0]["hostname"], "web02")

    def test_duplicate_id_in_inventory_raises_error(self):
        """Duplicate asset IDs in the same inventory raise a ValueError."""
        inventory = [
            make_asset(asset_id="A1"),
            make_asset(asset_id="A1"),   # duplicate!
        ]
        with self.assertRaises(ValueError):
            AssetChangeDetector(inventory, []).detect()

    def test_missing_id_field_raises_error(self):
        """An asset missing the id field raises a ValueError."""
        inventory = [{"asset_name": "Server without ID"}]
        with self.assertRaises(ValueError):
            AssetChangeDetector(inventory, []).detect()

    def test_large_inventory_performance(self):
        """Smoke test: handles a large inventory (1000 assets) without crashing."""
        previous = [make_asset(asset_id=f"A{i}", ip_address=f"10.0.{i//256}.{i%256}") for i in range(1000)]
        # Modify 100 assets, add 50 new ones, remove 50
        current = [make_asset(asset_id=f"A{i}", ip_address=f"10.1.{i//256}.{i%256}") for i in range(100)]  # modified
        current += [make_asset(asset_id=f"A{i}", ip_address=f"10.0.{i//256}.{i%256}") for i in range(100, 950)]  # unchanged
        current += [make_asset(asset_id=f"NEW{i}") for i in range(50)]  # added 50 new

        report = AssetChangeDetector(previous, current).detect()
        self.assertEqual(report.total_added,   50)   # 50 new
        self.assertEqual(report.total_removed, 50)   # A950–A999 are gone
        self.assertEqual(report.total_modified, 100) # A0–A99 changed IP


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite 6: Report Generation
# ─────────────────────────────────────────────────────────────────────────────

class TestReportGeneration(unittest.TestCase):
    """Tests that the report output is correctly formatted."""

    def test_report_is_string(self):
        """generate_report() returns a string."""
        detector = AssetChangeDetector([], [])
        result   = detector.generate_report()
        self.assertIsInstance(result, str)

    def test_report_contains_summary_header(self):
        """The report contains the expected header text."""
        result = AssetChangeDetector([], []).generate_report()
        self.assertIn("ASSET CHANGE DETECTION REPORT", result)

    def test_report_shows_added_asset_name(self):
        """The report mentions the name of an added asset."""
        current  = [make_asset(asset_id="A1", asset_name="Brand New Server")]
        result   = AssetChangeDetector([], current).generate_report()
        self.assertIn("Brand New Server", result)

    def test_report_shows_removed_asset_name(self):
        """The report mentions the name of a removed asset."""
        previous = [make_asset(asset_id="A1", asset_name="Old Decommissioned Box")]
        result   = AssetChangeDetector(previous, []).generate_report()
        self.assertIn("Old Decommissioned Box", result)

    def test_report_shows_modified_field(self):
        """The report shows the field name and old/new values for a modified asset."""
        previous = [make_asset(asset_id="A1", ip_address="1.2.3.4")]
        current  = [make_asset(asset_id="A1", ip_address="9.9.9.9")]
        result   = AssetChangeDetector(previous, current).generate_report()
        self.assertIn("ip_address", result)
        self.assertIn("1.2.3.4",   result)
        self.assertIn("9.9.9.9",   result)

    def test_no_changes_message(self):
        """When there are no changes, the report says so clearly."""
        asset  = make_asset(asset_id="A1")
        result = AssetChangeDetector([asset], [asset]).generate_report()
        self.assertIn("No changes detected", result)

    def test_report_contains_generated_at(self):
        """The report contains a timestamp."""
        result = AssetChangeDetector([], []).generate_report()
        self.assertIn("Generated", result)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
