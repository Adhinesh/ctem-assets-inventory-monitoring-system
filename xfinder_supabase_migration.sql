-- ================================================================
-- XFinder → Supabase migration
-- ------------------------------------------------
-- Run this ONLY after your existing CTEM schema already exists.
-- Do NOT rerun schema.sql in a populated database, because that file
-- recreates base tables like `assets` and will fail with "relation
-- \"assets\" already exists".
-- ================================================================

ALTER TABLE vulnerabilities
    ALTER COLUMN cve_id TYPE VARCHAR(128);

CREATE TABLE IF NOT EXISTS xfinder_targets (
    id                  BIGSERIAL       PRIMARY KEY,
    domain              VARCHAR(253)    UNIQUE NOT NULL,
    created_at          TIMESTAMP       DEFAULT NOW(),
    is_active           BOOLEAN         DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS xfinder_scans (
    id                  BIGSERIAL       PRIMARY KEY,
    source_scan_id      BIGINT          UNIQUE,
    target_id           BIGINT          NOT NULL REFERENCES xfinder_targets(id) ON DELETE CASCADE,
    scan_type           VARCHAR(32)     NOT NULL,
    status              VARCHAR(16)     DEFAULT 'running',
    started_at          TIMESTAMP       DEFAULT NOW(),
    finished_at         TIMESTAMP,
    duration_seconds    FLOAT,
    error               TEXT,
    output_dir          VARCHAR(512)
);
CREATE INDEX IF NOT EXISTS idx_xfinder_scans_target_started ON xfinder_scans(target_id, started_at);

CREATE TABLE IF NOT EXISTS xfinder_subdomains (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    target_id           BIGINT          NOT NULL REFERENCES xfinder_targets(id) ON DELETE CASCADE,
    name                VARCHAR(253)    NOT NULL,
    is_resolved         BOOLEAN         DEFAULT FALSE,
    is_live_http        BOOLEAN         DEFAULT FALSE,
    source              VARCHAR(64),
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_subdomains_scan_name ON xfinder_subdomains(scan_id, name);

CREATE TABLE IF NOT EXISTS xfinder_dns_records (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    subdomain_id        BIGINT          NOT NULL REFERENCES xfinder_subdomains(id) ON DELETE CASCADE,
    record_type         VARCHAR(8)      NOT NULL,
    value               TEXT            NOT NULL,
    ttl                 INT,
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_dns_scan_sub_type ON xfinder_dns_records(scan_id, subdomain_id, record_type);

CREATE TABLE IF NOT EXISTS xfinder_http_information (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    subdomain_id        BIGINT          NOT NULL UNIQUE REFERENCES xfinder_subdomains(id) ON DELETE CASCADE,
    url                 VARCHAR(2048)   NOT NULL,
    final_url           VARCHAR(2048),
    status_code         INT,
    title               VARCHAR(512),
    server_header       VARCHAR(256),
    content_length      BIGINT,
    response_time_ms    INT,
    redirect_chain      TEXT,
    scheme              VARCHAR(8),
    webserver           VARCHAR(128),
    tech_blob           TEXT,
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_http_scan_status ON xfinder_http_information(scan_id, status_code);

CREATE TABLE IF NOT EXISTS xfinder_cloud_assets (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    subdomain_id        BIGINT          NOT NULL UNIQUE REFERENCES xfinder_subdomains(id) ON DELETE CASCADE,
    provider            VARCHAR(64),
    cdn                 VARCHAR(64),
    waf                 VARCHAR(64),
    is_cloud_hosted     BOOLEAN         DEFAULT FALSE,
    evidence            TEXT,
    created_at          TIMESTAMP       DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS xfinder_ip_addresses (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    subdomain_id        BIGINT          NOT NULL REFERENCES xfinder_subdomains(id) ON DELETE CASCADE,
    address             VARCHAR(64)     NOT NULL,
    version             INT,
    reverse_dns         VARCHAR(253),
    asn                 VARCHAR(32),
    asn_org             VARCHAR(256),
    country             VARCHAR(64),
    hosting_provider    VARCHAR(256),
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_ip_scan_addr ON xfinder_ip_addresses(scan_id, address);

CREATE TABLE IF NOT EXISTS xfinder_ports (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    ip_address_id       BIGINT          NOT NULL REFERENCES xfinder_ip_addresses(id) ON DELETE CASCADE,
    port                INT             NOT NULL,
    protocol            VARCHAR(8)      DEFAULT 'tcp',
    state               VARCHAR(16),
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_ports_scan_ip_port ON xfinder_ports(scan_id, ip_address_id, port);

CREATE TABLE IF NOT EXISTS xfinder_services (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    port_id             BIGINT          NOT NULL REFERENCES xfinder_ports(id) ON DELETE CASCADE,
    name                VARCHAR(64),
    product             VARCHAR(128),
    version             VARCHAR(128),
    os                  VARCHAR(128),
    extra               TEXT,
    created_at          TIMESTAMP       DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS xfinder_technologies (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    http_info_id        BIGINT          NOT NULL REFERENCES xfinder_http_information(id) ON DELETE CASCADE,
    category            VARCHAR(64),
    name                VARCHAR(128)    NOT NULL,
    version             VARCHAR(64),
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_tech_scan_http ON xfinder_technologies(scan_id, http_info_id);

CREATE TABLE IF NOT EXISTS xfinder_api_endpoints (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    source_host         VARCHAR(253)    NOT NULL,
    method              VARCHAR(8),
    url                 VARCHAR(2048)   NOT NULL,
    body                TEXT,
    tag                 VARCHAR(32),
    created_at          TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_api_scan_host ON xfinder_api_endpoints(scan_id, source_host);

CREATE TABLE IF NOT EXISTS xfinder_vulnerabilities (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    template_id         VARCHAR(128)    NOT NULL,
    name                VARCHAR(512),
    severity            VARCHAR(16),
    description         TEXT,
    matched_url         VARCHAR(2048),
    matched_at          VARCHAR(2048),
    evidence            TEXT,
    reference_urls      TEXT,
    tags                VARCHAR(256),
    cvss_score          FLOAT,
    discovered_at       TIMESTAMP       DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xfinder_vuln_scan_severity ON xfinder_vulnerabilities(scan_id, severity);

CREATE TABLE IF NOT EXISTS xfinder_scan_reports (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    source_scan_id      BIGINT,
    target              VARCHAR(253)    NOT NULL,
    scan_type           VARCHAR(32)     NOT NULL,
    timestamp           TIMESTAMP       NOT NULL,
    duration_seconds    DECIMAL(10,2),
    scanners            JSONB           DEFAULT '{}'::jsonb,
    raw_payload         JSONB           DEFAULT '{}'::jsonb,
    created_at          TIMESTAMP       DEFAULT NOW(),
    UNIQUE (scan_id)
);

CREATE TABLE IF NOT EXISTS xfinder_change_reports (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES xfinder_scans(id) ON DELETE CASCADE,
    source_scan_id      BIGINT,
    previous_scan_id    BIGINT,
    generated_at        TIMESTAMP       NOT NULL,
    new_subdomains      JSONB           DEFAULT '[]'::jsonb,
    removed_subdomains  JSONB           DEFAULT '[]'::jsonb,
    new_ports           JSONB           DEFAULT '[]'::jsonb,
    closed_ports        JSONB           DEFAULT '[]'::jsonb,
    new_technologies    JSONB           DEFAULT '[]'::jsonb,
    removed_technologies JSONB          DEFAULT '[]'::jsonb,
    dns_changes         JSONB           DEFAULT '[]'::jsonb,
    cloud_changes       JSONB           DEFAULT '[]'::jsonb,
    new_vulnerabilities JSONB           DEFAULT '[]'::jsonb,
    resolved_vulnerabilities JSONB      DEFAULT '[]'::jsonb,
    new_api_endpoints   JSONB           DEFAULT '[]'::jsonb,
    removed_api_endpoints JSONB         DEFAULT '[]'::jsonb,
    summary             JSONB           DEFAULT '{}'::jsonb,
    raw_payload         JSONB           DEFAULT '{}'::jsonb,
    created_at          TIMESTAMP       DEFAULT NOW(),
    UNIQUE (scan_id)
);
