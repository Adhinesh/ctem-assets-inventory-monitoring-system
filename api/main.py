"""
main.py — CTEM FastAPI Application Entry Point
===============================================
Run with:
    uvicorn api.main:app --reload

Or from the project root:
    python -m uvicorn api.main:app --reload --port 8000

Swagger UI:  http://127.0.0.1:8000/docs
ReDoc:       http://127.0.0.1:8000/redoc
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import (
    assets,
    vulnerabilities,
    ports,
    dns,
    scans,
    alerts,
    exposures,
    monitor,
    dashboard,
)

# ── App definition ────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTEM API",
    description="""
## Continuous Threat Exposure Management — REST API

This API exposes your full CTEM database and monitoring pipeline over HTTP.

### Core Resources
| Resource | Path | Description |
|---|---|---|
| **Assets** | `/assets` | IT asset inventory — servers, workstations, cloud |
| **Vulnerabilities** | `/vulnerabilities` | CVE catalog with CVSS/EPSS scores |
| **Open Ports** | `/ports` | Per-asset port discovery and rogue port detection |
| **DNS Records** | `/dns` | DNS records + dangling record detection |
| **Scans** | `/scans` | Scan run history and snapshots |
| **Exposures** | `/exposures` | Active CTEM threat exposures |
| **Alerts** | `/alerts` | Change alerts, exposure alerts, log-level alerts |
| **Monitor** | `/monitor` | Trigger monitoring runs and view run history |
| **Dashboard** | `/dashboard` | Summary statistics for dashboards |

### Quick Start
1. `GET /dashboard/summary` — overall security posture
2. `GET /assets?criticality=critical` — list critical assets
3. `GET /vulnerabilities?exploit_available=true` — exploitable CVEs
4. `POST /monitor/run` — run the full monitoring pipeline
5. `GET /alerts/summary` — alert headline numbers
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — allow all origins for development ──────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routers ──────────────────────────────────────────────────────────
app.include_router(assets.router)
app.include_router(vulnerabilities.router)
app.include_router(ports.router)
app.include_router(dns.router)
app.include_router(scans.router)
app.include_router(alerts.router)
app.include_router(exposures.router)
app.include_router(monitor.router)
app.include_router(dashboard.router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    """API health check — confirms the server is running."""
    return {
        "name": "CTEM API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Detailed health check — verifies Supabase connection."""
    from api.db import get_db
    try:
        db = get_db()
        # Quick ping — count assets table
        res = db.table("assets").select("asset_id", count="exact").limit(1).execute()
        return {
            "status": "healthy",
            "database": "connected",
            "assets_in_db": res.count,
        }
    except Exception as e:
        return {"status": "unhealthy", "database": "error", "detail": str(e)}
