# API Workflow Guide

This project exposes a FastAPI service for inserting and retrieving CTEM data from Supabase. The most common flow is:

1. Start the API server.
2. Insert data with `POST` endpoints.
3. Retrieve data with `GET` endpoints.
4. Use the audit and sub-resource routes to verify what changed.

## 1. Start the API

Run the server from the project root:

```bash
python run_api.py
```

Open the interactive docs:

- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/redoc`

## 2. Insert Data

The main insert endpoint for inventory data is `POST /assets/`.

### Asset insert payload

Required field:

- `asset_id`
- `asset_name`

Common fields you can send:

- `asset_type`
- `ip_address`
- `fqdn`
- `hostname`
- `operating_system`
- `owner`
- `department`
- `environment`
- `criticality`
- `status`
- `tags`

### Example: create an asset

```bash
curl -X POST "http://127.0.0.1:8000/assets/" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 101,
    "asset_name": "Web Server 01",
    "asset_type": "server",
    "ip_address": "10.0.0.10",
    "fqdn": "web01.example.com",
    "operating_system": "Ubuntu 22.04",
    "owner": "IT Operations",
    "environment": "production",
    "criticality": "high",
    "status": "active",
    "tags": {"role": "web", "tier": "frontend"}
  }'
```

### Important asset behavior

- If another asset already exists with the same `asset_name`, the API updates that record instead of creating a duplicate.
- Any change written through the asset endpoints is also recorded in `asset_changes`.

### Insert related data

Use these endpoints after the asset exists:

- `POST /ports/` to add open port records
- `POST /dns/` to add DNS records
- `POST /exposures/` to add exposure records
- `POST /scans/` to create a scan record

Example: insert a port record.

```bash
curl -X POST "http://127.0.0.1:8000/ports/" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 1,
    "port_number": 443,
    "protocol": "TCP",
    "state": "open",
    "service_name": "https",
    "service_version": "nginx",
    "is_expected": true,
    "risk_level": "low"
  }'
```

Example: insert a DNS record.

```bash
curl -X POST "http://127.0.0.1:8000/dns/" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 1,
    "domain": "example.com",
    "subdomain": "web01",
    "fqdn": "web01.example.com",
    "record_type": "A",
    "record_value": "10.0.0.10",
    "status": "active"
  }'
```

## 3. Retrieve Data

### List assets

Use query filters to narrow results:

```bash
curl "http://127.0.0.1:8000/assets/?criticality=high&status=active"
```

Useful filters:

- `criticality`
- `status`
- `environment`
- `asset_type`
- `search`
- `limit`
- `offset`

### Get one asset by ID

```bash
curl "http://127.0.0.1:8000/assets/1"
```

### Retrieve related asset data

Once you have an `asset_id`, use the sub-resource routes:

- `GET /assets/{asset_id}/ports`
- `GET /assets/{asset_id}/vulnerabilities`
- `GET /assets/{asset_id}/changes`
- `GET /assets/{asset_id}/logs`

Example:

```bash
curl "http://127.0.0.1:8000/assets/1/ports"
curl "http://127.0.0.1:8000/assets/1/changes"
```

### Retrieve other tables directly

The API also exposes top-level list and detail routes for other resources:

- `GET /ports/` and `GET /ports/{port_id}`
- `GET /dns/` and `GET /dns/{record_id}`
- `GET /scans/` and `GET /scans/{scan_id}`
- `GET /alerts/changes`
- `GET /alerts/exposures`
- `GET /dashboard/summary`

## 4. Recommended Workflow

For a clean insert-and-retrieve cycle, follow this order:

1. Create the asset with `POST /assets/`.
2. Capture the returned `asset_id`.
3. Insert child records such as ports and DNS using that `asset_id`.
4. Verify the asset with `GET /assets/{asset_id}`.
5. Review related data with `GET /assets/{asset_id}/ports` and `GET /assets/{asset_id}/changes`.
6. Use `GET /dashboard/summary` or `GET /alerts/summary` for a higher-level view.

## 5. Python Example

If you want to call the API from Python, use `requests`:

```python
import requests

base_url = "http://127.0.0.1:8000"

asset_payload = {
    "asset_id": 201,
    "asset_name": "Database Server 01",
    "asset_type": "server",
    "ip_address": "10.0.0.20",
    "operating_system": "Ubuntu 22.04",
    "owner": "Platform Team",
    "environment": "production",
    "criticality": "critical",
    "status": "active",
}

created = requests.post(f"{base_url}/assets/", json=asset_payload, timeout=30)
created.raise_for_status()
asset = created.json()

asset_id = asset["asset_id"]

ports = requests.get(f"{base_url}/assets/{asset_id}/ports", timeout=30)
ports.raise_for_status()
print(ports.json())
```

## 6. Notes

- The API server runs at `http://127.0.0.1:8000` by default.
- `POST /assets/` requires `asset_id` and updates that record if the ID already exists.
- `POST /ports/` upserts on `(asset_id, port_number, protocol)`.
- `POST /dns/` upserts on `(domain, subdomain, record_type, record_value)`.
- Use `/docs` when you want to inspect request schemas and try requests manually.
