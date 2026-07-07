"""
routers/monitor.py — Trigger and view monitoring runs via API.

Integrates directly with the existing monitor.py pipeline logic.
"""
from __future__ import annotations
import os
import sys
import json
import glob
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends, Query
from supabase import Client

from api.db import get_db

# Ensure project root is in path so monitor.py can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

router = APIRouter(prefix="/monitor", tags=["Monitor"])

# Where monitor.py saves its JSON run logs
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "monitoring_logs")


def _run_monitor_pipeline() -> dict:
    """
    Run the full monitoring pipeline: fetch assets, detect changes, generate alerts,
    save logs. Returns a summary dict.
    """
    try:
        from monitor import CTEMMonitor
        monitor = CTEMMonitor()
        result = monitor.run()
        return result if isinstance(result, dict) else {"status": "completed", "detail": str(result)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _list_log_files() -> list[dict]:
    """Return metadata for all monitoring run log files, newest first."""
    pattern = os.path.join(LOGS_DIR, "*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    runs = []
    for f in files:
        try:
            stat = os.stat(f)
            with open(f) as fp:
                data = json.load(fp)
            runs.append({
                "run_id": os.path.basename(f).replace(".json", ""),
                "file": f,
                "size_bytes": stat.st_size,
                "run_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "summary": {k: v for k, v in data.items() if k != "alerts"},
            })
        except Exception:
            pass
    return runs


@router.post("/run", summary="Trigger a full monitoring run")
def trigger_monitor_run(background_tasks: BackgroundTasks):
    """
    Kick off the full CTEM monitoring pipeline:
    1. Fetches current assets from Supabase
    2. Compares against previous snapshot to detect changes
    3. Generates alerts (new assets, removed assets, field changes)
    4. Saves monitoring log to monitoring_logs/

    The run happens synchronously and returns when complete.
    """
    result = _run_monitor_pipeline()
    return {
        "message": "Monitoring run completed",
        "result": result,
        "ran_at": datetime.utcnow().isoformat(),
    }


@router.get("/runs", summary="List past monitoring runs")
def list_monitor_runs(limit: int = Query(20, ge=1, le=100)):
    """Return metadata about previous monitoring run log files."""
    runs = _list_log_files()
    return {"total": len(runs), "data": runs[:limit]}


@router.get("/runs/{run_id}", summary="Get a specific monitoring run")
def get_monitor_run(run_id: str):
    """
    Return the full content of a monitoring run log, including all generated alerts.
    `run_id` is the filename without extension.
    """
    path = os.path.join(LOGS_DIR, f"{run_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    with open(path) as f:
        return json.load(f)


@router.get("/latest", summary="Get the most recent monitoring run result")
def get_latest_run():
    """Return the most recent monitoring run log file."""
    runs = _list_log_files()
    if not runs:
        raise HTTPException(status_code=404, detail="No monitoring runs found yet. POST /monitor/run to start one.")
    run = runs[0]
    path = run["file"]
    with open(path) as f:
        return json.load(f)
