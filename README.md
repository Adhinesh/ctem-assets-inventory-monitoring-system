# CTEM Database & Asset Inventory 🛡️

A lightweight Continuous Threat Exposure Management (CTEM) prototype database built for PostgreSQL / Supabase, managed via a Python client.

## 🗄️ Database Tables (10-Table Schema)
- `assets` — Full IT asset inventory.
- `vulnerabilities` — CVE catalog with severity scores and exploit data.
- `open_ports` — Per-asset port state & service fingerprints.
- `dns_records` — DNS mapping and subdomain takeover risk tracking.
- `asset_changes` — Complete audit trail for any asset modification.
- `asset_logs` — Event stream (SIEM-lite) per asset.
- `scans` — Scan run history and metrics.
- `scan_snapshots` — Point-in-time security state captures.
- `asset_vulnerabilities` — Link table mapping CVEs to Assets with SLA tracking.
- `exposures` — Active CTEM threats mapped to business risk.

## 🚀 Getting Started

### 1. Database Setup
Copy the contents of `schema.sql` and run it in your PostgreSQL database or Supabase SQL Editor.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configuration
1. Copy `config.example.py` to `config.py`
2. Open `config.py` and replace the placeholder values with your actual Supabase URL and API Key.
*(Note: `config.py` is gitignored so you won't accidentally commit your secrets).*

### 4. Insert Sample Data
To populate the database with realistic CTEM sample data, run:
```bash
python insert_data.py
```
*(Need to reset the database? Run `python clear_data.py` before running the insert script again).*

### 5. Query the Data
To view your data nicely formatted in the terminal, run:
```bash
python queries.py
```

---

## 🔍 Asset Change Detection System

A standalone Python module that compares two asset inventory snapshots and detects every addition, removal, and field-level modification.

### How It Works

```
  Monday Inventory  ─┐
                     ├─▶  AssetChangeDetector  ─▶  ChangeReport  ─▶  Summary Report
  Friday Inventory  ─┘
```

1. Feed it a **previous** and **current** list of asset dictionaries.
2. It compares every asset by a unique `asset_id` field.
3. It produces a `ChangeReport` with four categories:
   - ✅ **Added** — assets present in current but not in previous.
   - 🗑️ **Removed** — assets present in previous but not in current.
   - ✏️ **Modified** — assets present in both, but with changed field values.
   - ➖ **Unchanged** — assets identical in both snapshots.

### Files

| File | Purpose |
|---|---|
| `change_detector.py` | Core module — `AssetChangeDetector` class and report formatter |
| `test_change_detector.py` | 31 unit tests covering all scenarios and edge cases |
| `demo.py` | Demo script simulating a realistic Monday→Friday inventory change |
| `test_results.txt` | Saved output of the test run |

### Running the Demo

```bash
python3 demo.py
```

This simulates a full week of asset changes and prints a formatted report to the terminal.

### Running the Tests

```bash
# Run all 31 tests with verbose output
python3 -m unittest test_change_detector.py -v

# Run and save results to a file
python3 -m unittest test_change_detector.py -v 2>&1 | tee test_results.txt
```

### Using the API in Your Own Code

```python
from change_detector import AssetChangeDetector

previous = [
    {"asset_id": "A1", "ip_address": "10.0.0.1", "os": "Ubuntu 20.04"},
]
current = [
    {"asset_id": "A1", "ip_address": "10.0.0.1", "os": "Ubuntu 22.04"},  # OS changed
    {"asset_id": "A2", "ip_address": "10.0.0.2", "os": "Windows 11"},    # new asset
]

detector = AssetChangeDetector(previous, current)
print(detector.generate_report())
```
