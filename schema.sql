-- ================================================================
-- CTEM (Continuous Threat Exposure Management) — Full Schema
-- ================================================================
-- Tables:
--   1.  assets               → IT asset inventory (full detail)
--   2.  vulnerabilities      → CVE catalog with exploit metadata
--   3.  open_ports           → Per-asset open port tracking
--   4.  dns_records          → DNS records linked to assets
--   5.  asset_changes        → Audit trail of every asset change
--   6.  asset_logs           → Event / activity log stream
--   7.  scan_snapshots       → Point-in-time security snapshots
--   8.  scans                → Scan run history
--   9.  asset_vulnerabilities → Asset ↔ CVE link + remediation
--   10. exposures            → Active CTEM threat exposures
--
-- Run: psql -U your_user -d your_db -f schema.sql
--      OR paste into Supabase SQL Editor and click Run
-- ================================================================


-- ----------------------------------------------------------------
-- TABLE 1: assets
-- The central table — every device, server, or cloud resource
-- ----------------------------------------------------------------
CREATE TABLE assets (
    asset_id            SERIAL          PRIMARY KEY,

    -- Identity
    asset_name          VARCHAR(150)    NOT NULL,           -- "Web Server 01"
    asset_type          VARCHAR(60)     NOT NULL,           -- 'server' | 'workstation' | 'network_device' | 'cloud_instance' | 'container' | 'iot_device' | 'mobile'
    hostname            VARCHAR(150),                       -- web01
    fqdn                VARCHAR(255),                       -- web01.prod.company.com (fully qualified)
    mac_address         MACADDR,                            -- hardware address e.g. 08:00:2b:01:02:03

    -- Network
    ip_address          INET,                               -- primary IP (IPv4 or IPv6)
    secondary_ips       INET[],                             -- additional IPs (array)
    network_zone        VARCHAR(60),                        -- 'dmz' | 'internal' | 'external' | 'cloud_vpc'

    -- OS & Software
    operating_system    VARCHAR(150),                       -- "Ubuntu 22.04 LTS"
    os_version          VARCHAR(60),                        -- "22.04.3"
    os_architecture     VARCHAR(20),                        -- 'x86_64' | 'arm64' | 'i386'
    installed_software  JSONB           DEFAULT '[]',       -- [{"name":"nginx","version":"1.24.0"}, ...]

    -- Cloud / Physical Location
    cloud_provider      VARCHAR(50),                        -- 'aws' | 'azure' | 'gcp' | 'on_premise' | 'hybrid'
    cloud_region        VARCHAR(80),                        -- "us-east-1"
    cloud_instance_id   VARCHAR(150),                       -- "i-0abc1234def56789"
    physical_location   VARCHAR(150),                       -- "DC1 Rack 12 Unit 4" or "HQ Floor 2"

    -- Ownership
    owner               VARCHAR(100),                       -- "Infrastructure Team"
    department          VARCHAR(100),                       -- "Engineering"
    business_unit       VARCHAR(100),                       -- "Platform"
    contact_email       VARCHAR(150),                       -- "infra@company.com"

    -- Classification
    environment         VARCHAR(30)     DEFAULT 'production',  -- 'production' | 'staging' | 'development' | 'testing'
    criticality         VARCHAR(20)     DEFAULT 'medium',      -- 'low' | 'medium' | 'high' | 'critical'
    data_classification VARCHAR(30)     DEFAULT 'internal',    -- 'public' | 'internal' | 'confidential' | 'restricted'
    tags                JSONB           DEFAULT '{}',       -- {"team":"devops","project":"phoenix"}

    -- Lifecycle
    status              VARCHAR(30)     DEFAULT 'active',   -- 'active' | 'inactive' | 'decommissioned' | 'under_maintenance'
    first_seen          TIMESTAMP       DEFAULT NOW(),       -- when this asset was first discovered
    last_seen           TIMESTAMP       DEFAULT NOW(),       -- last time it responded to a scan
    decommissioned_at   TIMESTAMP,                          -- set when status = 'decommissioned'
    created_at          TIMESTAMP       DEFAULT NOW(),
    updated_at          TIMESTAMP       DEFAULT NOW(),

    -- Notes
    notes               TEXT                                -- any freeform notes
);


-- ----------------------------------------------------------------
-- TABLE 2: vulnerabilities
-- CVE catalog with full exploit and patch metadata
-- ----------------------------------------------------------------
CREATE TABLE vulnerabilities (
    vuln_id             SERIAL          PRIMARY KEY,

    -- CVE Identity
    cve_id              VARCHAR(25)     UNIQUE,             -- "CVE-2024-1234"
    title               VARCHAR(300)    NOT NULL,
    description         TEXT,

    -- Severity Scoring
    cvss_score          DECIMAL(3,1)    CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    cvss_vector         VARCHAR(100),                       -- "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    severity            VARCHAR(20),                        -- 'none' | 'low' | 'medium' | 'high' | 'critical'
    epss_score          DECIMAL(5,4),                       -- Exploit Prediction Score 0.0000–1.0000 (from FIRST.org)

    -- Affected Software
    affected_software   VARCHAR(200),                       -- "Apache Log4j"
    affected_versions   VARCHAR(200),                       -- "2.0-beta9 to 2.14.1"
    affected_platforms  VARCHAR(200),                       -- "Windows, Linux, macOS"

    -- Patch & Fix Info
    fix_available       BOOLEAN         DEFAULT FALSE,
    patch_details       TEXT,                               -- "Upgrade to Log4j 2.17.1 or later"
    workaround          TEXT,                               -- interim mitigation if no patch

    -- Exploit Info
    exploit_available   BOOLEAN         DEFAULT FALSE,
    exploit_maturity    VARCHAR(30),                        -- 'unproven' | 'poc' | 'functional' | 'weaponized'
    exploit_url         VARCHAR(500),                       -- link to PoC or exploit-db entry

    -- References
    vuln_references     JSONB           DEFAULT '[]',       -- [{"url":"https://nvd.nist.gov/...","label":"NVD"}]
    cwe_ids             VARCHAR(100),                       -- "CWE-502, CWE-917"

    -- Dates
    published_date      DATE,
    last_modified_date  DATE,
    created_at          TIMESTAMP       DEFAULT NOW()
);


-- ----------------------------------------------------------------
-- TABLE 3: open_ports
-- Every open port discovered on each asset, per scan
-- ----------------------------------------------------------------
CREATE TABLE open_ports (
    port_id             SERIAL          PRIMARY KEY,
    asset_id            INT             NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,

    -- Port Details
    port_number         INT             NOT NULL CHECK (port_number BETWEEN 1 AND 65535),
    protocol            VARCHAR(5)      NOT NULL DEFAULT 'TCP', -- 'TCP' | 'UDP' | 'SCTP'
    state               VARCHAR(15)     DEFAULT 'open',         -- 'open' | 'closed' | 'filtered' | 'open|filtered'

    -- Service Info (gathered from banner grabbing / fingerprinting)
    service_name        VARCHAR(80),                        -- "http" | "ssh" | "postgresql" | "unknown"
    service_version     VARCHAR(150),                       -- "OpenSSH 8.9p1 Ubuntu"
    service_product     VARCHAR(150),                       -- "Apache httpd"
    banner              TEXT,                               -- raw banner text returned by the service

    -- Risk
    is_expected         BOOLEAN         DEFAULT TRUE,       -- FALSE = unexpected/rogue port → alert!
    risk_level          VARCHAR(20)     DEFAULT 'low',      -- 'low' | 'medium' | 'high' | 'critical'
    notes               TEXT,

    -- Tracking
    first_detected      TIMESTAMP       DEFAULT NOW(),
    last_seen           TIMESTAMP       DEFAULT NOW(),

    UNIQUE (asset_id, port_number, protocol)               -- no duplicates per asset
);


-- ----------------------------------------------------------------
-- TABLE 4: dns_records
-- DNS records associated with assets or domains in your inventory
-- ----------------------------------------------------------------
CREATE TABLE dns_records (
    record_id           SERIAL          PRIMARY KEY,
    asset_id            INT             REFERENCES assets(asset_id) ON DELETE SET NULL, -- nullable: some DNS records may not map to an asset

    -- DNS Record Fields
    domain              VARCHAR(255)    NOT NULL,           -- "company.com"
    subdomain           VARCHAR(255),                       -- "api" (full name would be api.company.com)
    fqdn                VARCHAR(255),                       -- "api.company.com" (computed or stored directly)
    record_type         VARCHAR(10)     NOT NULL,           -- 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'PTR' | 'SRV' | 'CAA'
    record_value        TEXT            NOT NULL,           -- "192.168.1.10" or "backup.company.com"
    ttl                 INT,                                -- time to live in seconds

    -- Classification
    is_internal         BOOLEAN         DEFAULT FALSE,      -- TRUE = internal DNS, FALSE = public-facing
    is_wildcard         BOOLEAN         DEFAULT FALSE,      -- TRUE = *.company.com

    -- Health / Risk
    status              VARCHAR(30)     DEFAULT 'active',   -- 'active' | 'stale' | 'dangling' | 'expired'
    -- 'dangling' = points to a resource that no longer exists (subdomain takeover risk!)
    risk_notes          TEXT,                               -- e.g., "Dangling CNAME — subdomain takeover risk"

    -- Tracking
    registrar           VARCHAR(100),                       -- "GoDaddy" | "Cloudflare"
    dns_provider        VARCHAR(100),                       -- "AWS Route53" | "Cloudflare DNS"
    first_seen          TIMESTAMP       DEFAULT NOW(),
    last_seen           TIMESTAMP       DEFAULT NOW(),
    expires_at          TIMESTAMP,                          -- domain/cert expiry date

    UNIQUE (domain, subdomain, record_type, record_value)  -- prevent duplicate records
);


-- ----------------------------------------------------------------
-- TABLE 5: asset_changes
-- Audit trail — every time anything about an asset changes
-- ----------------------------------------------------------------
CREATE TABLE asset_changes (
    change_id           SERIAL          PRIMARY KEY,
    asset_id            INT             NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,

    -- What Changed
    change_type         VARCHAR(60)     NOT NULL,
    -- 'ip_change' | 'os_update' | 'port_opened' | 'port_closed'
    -- 'vuln_discovered' | 'vuln_remediated' | 'dns_change'
    -- 'owner_change' | 'status_change' | 'software_installed'
    -- 'software_removed' | 'config_change' | 'criticality_change'

    field_changed       VARCHAR(100),                       -- which field changed, e.g. "ip_address", "status"
    old_value           TEXT,                               -- value before the change
    new_value           TEXT,                               -- value after the change

    -- Who / What caused it
    changed_by          VARCHAR(100),                       -- "scanner_auto" | "admin_john" | "api_integration"
    source              VARCHAR(60),                        -- 'scanner' | 'manual' | 'api' | 'ci_cd_pipeline'
    change_reason       TEXT,                               -- why it was changed (optional)

    -- When
    changed_at          TIMESTAMP       DEFAULT NOW(),
    notes               TEXT
);


-- ----------------------------------------------------------------
-- TABLE 6: asset_logs
-- Streaming event log for each asset (like a SIEM feed per asset)
-- ----------------------------------------------------------------
CREATE TABLE asset_logs (
    log_id              BIGSERIAL       PRIMARY KEY,        -- BIGSERIAL for high-volume logging
    asset_id            INT             NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,

    -- Log Classification
    log_level           VARCHAR(15)     NOT NULL DEFAULT 'info',
    -- 'debug' | 'info' | 'warning' | 'error' | 'critical'

    event_type          VARCHAR(80)     NOT NULL,
    -- 'scan_started' | 'scan_completed' | 'vuln_detected' | 'port_opened'
    -- 'port_closed' | 'login_attempt' | 'config_change' | 'alert_triggered'
    -- 'compliance_check' | 'patch_applied' | 'reboot' | 'service_restart'

    -- Source
    event_source        VARCHAR(100),                       -- "Nessus" | "OpenVAS" | "SIEM" | "manual" | "AWS CloudTrail"

    -- Content
    message             TEXT            NOT NULL,           -- human-readable log message
    details             JSONB           DEFAULT '{}',       -- structured extra data (raw JSON)
    -- e.g. {"port": 22, "protocol": "TCP", "scanner": "nmap"}

    -- Timing
    logged_at           TIMESTAMP       DEFAULT NOW()
);


-- ----------------------------------------------------------------
-- TABLE 7: scans
-- One record per scan run (can target one or many assets)
-- ----------------------------------------------------------------
CREATE TABLE scans (
    scan_id             SERIAL          PRIMARY KEY,
    scan_name           VARCHAR(150),                       -- "Weekly Full Scan — June 2024"
    scan_type           VARCHAR(60),                        -- 'vulnerability' | 'port' | 'dns' | 'compliance' | 'pentest' | 'full'
    scanner_tool        VARCHAR(100),                       -- "Nessus" | "OpenVAS" | "Nmap" | "Qualys" | "Tenable"
    scanner_version     VARCHAR(50),                        -- "10.6.1"
    initiated_by        VARCHAR(100),                       -- "scheduler" | "admin_john" | "ci_cd"

    -- Scope
    target_range        VARCHAR(255),                       -- "192.168.1.0/24" or "all_production"
    assets_scanned      INT             DEFAULT 0,
    total_findings      INT             DEFAULT 0,

    -- Scan Results Summary
    critical_findings   INT             DEFAULT 0,
    high_findings       INT             DEFAULT 0,
    medium_findings     INT             DEFAULT 0,
    low_findings        INT             DEFAULT 0,
    new_assets_found    INT             DEFAULT 0,          -- assets discovered this scan that weren't in inventory

    -- Timing
    scan_started_at     TIMESTAMP       DEFAULT NOW(),
    scan_finished_at    TIMESTAMP,
    duration_seconds    INT,                                -- how long the scan took

    -- Status
    status              VARCHAR(30)     DEFAULT 'running',  -- 'running' | 'completed' | 'failed' | 'cancelled'
    error_message       TEXT,                               -- populated if status = 'failed'
    notes               TEXT
);


-- ----------------------------------------------------------------
-- TABLE 8: scan_snapshots
-- Point-in-time security snapshot of ONE asset from ONE scan
-- This is your historical record — compare snapshots over time
-- ----------------------------------------------------------------
CREATE TABLE scan_snapshots (
    snapshot_id         SERIAL          PRIMARY KEY,
    asset_id            INT             NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    scan_id             INT             NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Snapshot Timing
    snapshot_taken_at   TIMESTAMP       DEFAULT NOW(),

    -- Vulnerability Counts at this moment
    total_vulns         INT             DEFAULT 0,
    critical_vulns      INT             DEFAULT 0,
    high_vulns          INT             DEFAULT 0,
    medium_vulns        INT             DEFAULT 0,
    low_vulns           INT             DEFAULT 0,
    new_vulns           INT             DEFAULT 0,          -- vulns not seen in previous snapshot
    resolved_vulns      INT             DEFAULT 0,          -- vulns fixed since last snapshot

    -- Port Counts at this moment
    total_open_ports    INT             DEFAULT 0,
    unexpected_ports    INT             DEFAULT 0,          -- ports that are NOT in expected list

    -- Scores
    risk_score          INT             CHECK (risk_score BETWEEN 0 AND 100),
    compliance_score    INT             CHECK (compliance_score BETWEEN 0 AND 100),

    -- OS Info captured at scan time (may differ from asset record if it changed)
    os_detected         VARCHAR(150),

    -- Embedded Snapshots (JSONB for full history without joins)
    open_ports_snapshot JSONB           DEFAULT '[]',
    -- [{"port":80,"protocol":"TCP","service":"http","state":"open"}, ...]

    vuln_snapshot       JSONB           DEFAULT '[]',
    -- [{"cve_id":"CVE-2024-1234","cvss_score":9.8,"severity":"critical","status":"open"}, ...]

    dns_snapshot        JSONB           DEFAULT '[]',
    -- [{"record_type":"A","fqdn":"web01.company.com","value":"192.168.1.10"}, ...]

    -- Raw Data
    raw_scan_output     JSONB           DEFAULT '{}',       -- full raw output from scanner (optional)

    UNIQUE (asset_id, scan_id)                             -- one snapshot per asset per scan
);


-- ----------------------------------------------------------------
-- TABLE 9: asset_vulnerabilities
-- Links assets to vulnerabilities + tracks remediation
-- ----------------------------------------------------------------
CREATE TABLE asset_vulnerabilities (
    id                  SERIAL          PRIMARY KEY,
    asset_id            INT             NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    vuln_id             INT             NOT NULL REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    scan_id             INT             REFERENCES scans(scan_id),          -- which scan found this

    -- Remediation Status
    status              VARCHAR(30)     DEFAULT 'open',
    -- 'open' | 'in_progress' | 'remediated' | 'accepted_risk' | 'false_positive'

    priority            VARCHAR(20)     DEFAULT 'medium',   -- 'low' | 'medium' | 'high' | 'urgent'
    assigned_to         VARCHAR(100),                       -- who owns fixing this

    -- Dates
    detected_on         DATE            DEFAULT CURRENT_DATE,
    remediated_on       DATE,                               -- NULL until fixed
    due_date            DATE,                               -- SLA deadline for fix
    last_seen           DATE            DEFAULT CURRENT_DATE, -- last scan where it was still present

    -- Context
    affected_component  VARCHAR(200),                       -- which specific software/service on the asset
    proof_of_concept    TEXT,                               -- evidence / reproduction steps
    notes               TEXT,

    UNIQUE (asset_id, vuln_id)
);


-- ----------------------------------------------------------------
-- TABLE 10: exposures
-- Active CTEM exposures — confirmed, business-impacting risks
-- An exposure = asset + vuln + attack path = real danger
-- ----------------------------------------------------------------
CREATE TABLE exposures (
    exposure_id         SERIAL          PRIMARY KEY,
    asset_id            INT             REFERENCES assets(asset_id) ON DELETE CASCADE,  -- nullable: some exposures are DNS/org-level
    vuln_id             INT             REFERENCES vulnerabilities(vuln_id),

    -- Exposure Classification
    exposure_type       VARCHAR(60),
    -- 'external_attack_surface' | 'insider_threat' | 'misconfiguration'
    -- 'data_exposure' | 'supply_chain' | 'credential_exposure' | 'lateral_movement_path'

    attack_vector       VARCHAR(60),                        -- 'network' | 'adjacent' | 'local' | 'physical'
    attack_complexity   VARCHAR(20),                        -- 'low' | 'high'

    -- Risk
    risk_score          INT             CHECK (risk_score BETWEEN 1 AND 100),
    business_impact     TEXT,                               -- plain-English impact statement

    -- Status
    status              VARCHAR(30)     DEFAULT 'active',   -- 'active' | 'mitigated' | 'accepted' | 'closed'

    -- Ownership
    assigned_to         VARCHAR(100),
    escalated           BOOLEAN         DEFAULT FALSE,      -- has this been escalated to management?

    -- Timing
    identified_on       TIMESTAMP       DEFAULT NOW(),
    closed_on           TIMESTAMP,
    sla_deadline        TIMESTAMP,                          -- when it must be fixed by

    description         TEXT
);


-- ================================================================
-- INDEXES — speeds up the most common queries
-- ================================================================

-- Asset lookups
CREATE INDEX idx_assets_criticality    ON assets(criticality);
CREATE INDEX idx_assets_status         ON assets(status);
CREATE INDEX idx_assets_environment    ON assets(environment);
CREATE INDEX idx_assets_ip             ON assets(ip_address);

-- Vulnerability lookups
CREATE INDEX idx_vulns_cve             ON vulnerabilities(cve_id);
CREATE INDEX idx_vulns_severity        ON vulnerabilities(severity);
CREATE INDEX idx_vulns_exploit         ON vulnerabilities(exploit_available);

-- Open ports
CREATE INDEX idx_ports_asset           ON open_ports(asset_id);
CREATE INDEX idx_ports_unexpected      ON open_ports(is_expected) WHERE is_expected = FALSE;

-- DNS
CREATE INDEX idx_dns_domain            ON dns_records(domain);
CREATE INDEX idx_dns_status            ON dns_records(status);

-- Asset changes (audit trail — queried by asset and time)
CREATE INDEX idx_changes_asset         ON asset_changes(asset_id);
CREATE INDEX idx_changes_time          ON asset_changes(changed_at DESC);
CREATE INDEX idx_changes_type          ON asset_changes(change_type);

-- Asset logs (high volume — always query by asset + time)
CREATE INDEX idx_logs_asset            ON asset_logs(asset_id);
CREATE INDEX idx_logs_time             ON asset_logs(logged_at DESC);
CREATE INDEX idx_logs_level            ON asset_logs(log_level);
CREATE INDEX idx_logs_event_type       ON asset_logs(event_type);

-- Snapshots
CREATE INDEX idx_snapshots_asset       ON scan_snapshots(asset_id);
CREATE INDEX idx_snapshots_scan        ON scan_snapshots(scan_id);
CREATE INDEX idx_snapshots_time        ON scan_snapshots(snapshot_taken_at DESC);

-- Asset vulnerabilities
CREATE INDEX idx_av_status             ON asset_vulnerabilities(status);
CREATE INDEX idx_av_asset              ON asset_vulnerabilities(asset_id);
CREATE INDEX idx_av_priority           ON asset_vulnerabilities(priority);

-- Exposures
CREATE INDEX idx_exposures_status      ON exposures(status);
CREATE INDEX idx_exposures_risk        ON exposures(risk_score DESC);


-- ================================================================
-- DONE — Tables created:
--   1.  assets               ← full IT inventory
--   2.  vulnerabilities      ← CVE catalog with exploit info
--   3.  open_ports           ← per-asset port tracking
--   4.  dns_records          ← DNS records per domain/asset
--   5.  asset_changes        ← audit trail of all changes
--   6.  asset_logs           ← event log stream
--   7.  scans                ← scan run history
--   8.  scan_snapshots       ← point-in-time security state
--   9.  asset_vulnerabilities ← asset ↔ CVE + remediation
--   10. exposures            ← active CTEM threat exposures
-- ================================================================
