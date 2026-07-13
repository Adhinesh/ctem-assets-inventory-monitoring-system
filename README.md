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

### 2b. Run With Docker
Build and start the API with:
```bash
docker compose up --build
```

The container reads `SUPABASE_URL`, `SUPABASE_KEY`, and `CTEM_LOG_LEVEL` from the environment. If you want to override the defaults, export them before starting Compose.

### 3. Configuration
1. Set `SUPABASE_URL` and `SUPABASE_KEY` in your environment, or edit `config.py` if you need a local fallback.
2. Optionally set `CTEM_LOG_LEVEL` to control verbosity.

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

### 6. Run Continuous Monitoring
To keep monitoring running in the background 24/7, start:
```bash
python3 scheduler1.py
```

To change how often it checks for changes:
```bash
python3 scheduler1.py --interval-seconds 30
```

This runner:
- loads the previous asset snapshot from `monitoring_logs/latest_inventory_snapshot.json`
- loads the current asset inventory from Supabase
- detects added, removed, and modified assets
- stores monitoring alerts and saves the new snapshot for the next cycle

### 7. Poll Alerts From the Frontend
For near-real-time notifications, poll:
```bash
GET /alerts/changes?since=2026-07-10T12:00:00
```

The response includes:
- `data` → new alert/change rows
- `latest_changed_at` → use this value as the next `since`
- `server_time` → backend timestamp for sync/debugging

Recommended frontend loop:
1. Call `GET /alerts/changes` with no `since` on first load.
2. Store `latest_changed_at` from the response.
3. Poll every 3 to 5 seconds with `?since=<latest_changed_at>`.
4. Show any new rows in `data` as notifications.

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


### Rename the config example.py to config.py
```python

SUPABASE_URL = "https://eqlolqdgviakidyinwrt.supabase.co"  
SUPABASE_KEY = "" # for the KEY, kindly contact the team 2        
```
