# ================================================================
# insert_data.py — Insert CTEM sample data into Supabase
# ================================================================
# Run: python insert_data.py
# Requires: pip install supabase
# ================================================================

from insert_tool import SupabaseInserter

inserter = SupabaseInserter()
print("✅ Connected to Supabase (Safe Mode)\n")


# ── Helper using SupabaseInserter (Safe Upsert) ──────────────────
def insert(table, rows, label):
    results = []
    if not isinstance(rows, list):
        rows = [rows]
        
    for row in rows:
        if table == "assets":
            res = inserter.upsert_asset(row)
        elif table == "vulnerabilities":
            res = inserter.upsert_vuln(row)
        elif table == "open_ports":
            res = inserter.upsert_open_port(row)
        elif table == "dns_records":
            res = inserter.upsert_dns_record(row)
        elif table == "scans":
            res = inserter.upsert_scan(row)
        elif table == "scan_snapshots":
            res = inserter.upsert_scan_snapshot(row)
        elif table == "asset_vulnerabilities":
            res = inserter.upsert_asset_vuln(row)
        elif table == "exposures":
            res = inserter.upsert_exposure(row)
        elif table == "asset_changes":
            res = inserter.insert_change(row)
        elif table == "asset_logs":
            res = inserter.insert_log(row)
        else:
            res = inserter.supabase.table(table).insert(row).execute().data[0]
        results.append(res)
        
    print(f"  ✔  {label}: {len(results)} row(s) upserted/inserted")
    return results



# ================================================================
# 1. ASSETS
# ================================================================
print("📦  Inserting assets...")

assets_data = [
    {
        "asset_name": "Web Server 01",
        "asset_type": "server",
        "hostname": "web01",
        "fqdn": "web01.prod.company.com",
        "mac_address": "08:00:2b:01:02:03",
        "ip_address": "192.168.1.10",
        "network_zone": "dmz",
        "operating_system": "Ubuntu 22.04 LTS",
        "os_version": "22.04.3",
        "os_architecture": "x86_64",
        "installed_software": [
            {"name": "nginx",  "version": "1.24.0"},
            {"name": "log4j",  "version": "2.14.1"},
            {"name": "java",   "version": "17.0.8"}
        ],
        "cloud_provider": "on_premise",
        "physical_location": "DC1 Rack 12 Unit 4",
        "owner": "Infrastructure Team",
        "department": "Engineering",
        "contact_email": "infra@company.com",
        "environment": "production",
        "criticality": "critical",
        "data_classification": "confidential",
        "tags": {"team": "infra", "tier": "web"},
        "status": "active"
    },
    {
        "asset_name": "Database Server",
        "asset_type": "server",
        "hostname": "db01",
        "fqdn": "db01.prod.company.com",
        "mac_address": "08:00:2b:04:05:06",
        "ip_address": "192.168.1.20",
        "network_zone": "internal",
        "operating_system": "Windows Server 2022",
        "os_version": "21H2",
        "os_architecture": "x86_64",
        "installed_software": [
            {"name": "PostgreSQL", "version": "15.3"},
            {"name": "pgAgent",    "version": "4.2"}
        ],
        "cloud_provider": "on_premise",
        "physical_location": "DC1 Rack 08 Unit 2",
        "owner": "Database Team",
        "department": "Engineering",
        "contact_email": "dba@company.com",
        "environment": "production",
        "criticality": "critical",
        "data_classification": "restricted",
        "tags": {"team": "dba", "tier": "data"},
        "status": "active"
    },
    {
        "asset_name": "Cloud API Gateway",
        "asset_type": "cloud_instance",
        "hostname": "api-gw",
        "fqdn": "api.company.com",
        "ip_address": "10.0.1.5",
        "network_zone": "external",
        "operating_system": "Amazon Linux 2",
        "os_version": "2.0",
        "os_architecture": "x86_64",
        "cloud_provider": "aws",
        "cloud_region": "us-east-1",
        "cloud_instance_id": "i-0abc1234def56789",
        "owner": "DevOps Team",
        "department": "Platform",
        "contact_email": "devops@company.com",
        "environment": "production",
        "criticality": "high",
        "data_classification": "confidential",
        "tags": {"team": "devops", "project": "api-platform"},
        "status": "active"
    },
    {
        "asset_name": "HR Workstation",
        "asset_type": "workstation",
        "hostname": "hr-pc-01",
        "ip_address": "192.168.2.15",
        "network_zone": "internal",
        "operating_system": "Windows 11 Pro",
        "os_version": "23H2",
        "os_architecture": "x86_64",
        "cloud_provider": "on_premise",
        "physical_location": "HQ Floor 2",
        "owner": "HR Department",
        "department": "Human Resources",
        "contact_email": "hr-it@company.com",
        "environment": "production",
        "criticality": "medium",
        "data_classification": "confidential",
        "tags": {"team": "hr"},
        "status": "active"
    },
    {
        "asset_name": "Dev Laptop - Alice",
        "asset_type": "workstation",
        "hostname": "alice-mbp",
        "ip_address": "192.168.3.5",
        "network_zone": "internal",
        "operating_system": "macOS Ventura",
        "os_version": "13.5.2",
        "os_architecture": "arm64",
        "cloud_provider": "on_premise",
        "owner": "Engineering Team",
        "department": "Engineering",
        "contact_email": "alice@company.com",
        "environment": "development",
        "criticality": "low",
        "data_classification": "internal",
        "tags": {"team": "engineering", "user": "alice"},
        "status": "active"
    },
    {
        "asset_name": "Core Switch",
        "asset_type": "network_device",
        "hostname": "core-sw-01",
        "fqdn": "core-switch-01.infra.company.com",
        "mac_address": "00:1a:2b:3c:4d:5e",
        "ip_address": "192.168.1.1",
        "network_zone": "internal",
        "operating_system": "Cisco IOS",
        "os_version": "15.2(7)E5",
        "cloud_provider": "on_premise",
        "physical_location": "DC1 Rack 01 Unit 1",
        "owner": "Network Team",
        "department": "IT Operations",
        "contact_email": "netops@company.com",
        "environment": "production",
        "criticality": "critical",
        "data_classification": "restricted",
        "tags": {"team": "netops", "tier": "network"},
        "status": "active"
    },
    {
       "asset_name": "Core Switch",
        "asset_type": "network_device",
        "hostname": "core-sw-01",
        "fqdn": "core-switch-01.infra.company.com",
        "mac_address": "00:1a:2b:3c:4d:5e",
        "ip_address": "192.168.1.1",
        "network_zone": "internal",
        "operating_system": "Cisco IOS",
        "os_version": "15.2(7)E5",
        "cloud_provider": "on_premise",
        "physical_location": "DC1 Rack 01 Unit 1",
        "owner": "Network Team",
        "department": "IT Operations",
        "contact_email": "netops@company.com",
        "environment": "production",
        "criticality": "critical",
        "data_classification": "restricted",
        "tags": {"team": "netops", "tier": "network"},
        "status": "active" 
    },
    {
        "asset_name": "payment Server",
        "asset_type": "server",
        "hostname": "pyserver-01",
        "fqdn": "pyserver-01.prod.company.com",
        "mac_address": "08:00:2b:04:05:06",
        "ip_address": "192.168.1.105",
        "network_zone": "internal",
        "operating_system": "Windows Server 2022",
        "os_version": "21H2",
        "os_architecture": "x86_64",
        "installed_software": [
            {"name": "PostgreSQL", "version": "15.3"},
            {"name": "pgAgent",    "version": "4.2"}
        ],
        "cloud_provider": "on_premise",
        "physical_location": "DC1 Rack 08 Unit 2",
        "owner": "Database Team",
        "department": "Engineering",
        "contact_email": "dba@company.com",
        "environment": "production",
        "criticality": "critical",
        "data_classification": "restricted",
        "tags": {"team": "dba", "tier": "data"},
        "status": "active"
    }
]

inserted_assets = insert("assets", assets_data, "Assets")

# Build a name → ID map for use in subsequent inserts
asset_map = {a["asset_name"]: a["asset_id"] for a in inserted_assets}


# ================================================================
# 2. VULNERABILITIES
# ================================================================
print("\n🔓  Inserting vulnerabilities...")

vulns_data = [
    {
        "cve_id": "CVE-2024-1234",
        "title": "Apache Log4j Remote Code Execution (Log4Shell)",
        "description": "A remote attacker can execute arbitrary code via JNDI lookup in log messages. Affects Log4j 2.0-beta9 through 2.14.1.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "epss_score": 0.9752,
        "affected_software": "Apache Log4j",
        "affected_versions": "2.0-beta9 to 2.14.1",
        "affected_platforms": "Windows, Linux, macOS",
        "fix_available": True,
        "patch_details": "Upgrade to Log4j 2.17.1 or later. Set log4j2.formatMsgNoLookups=true as interim workaround.",
        "exploit_available": True,
        "exploit_maturity": "weaponized",
        "exploit_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
        "vuln_references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "label": "NVD"},
            {"url": "https://logging.apache.org/log4j/2.x/security.html", "label": "Apache Advisory"}
        ],
        "cwe_ids": "CWE-502",
        "published_date": "2024-01-15"
    },
    {
        "cve_id": "CVE-2024-5678",
        "title": "OpenSSL Buffer Overflow in X.509 Certificate Parsing",
        "description": "A buffer overflow in OpenSSL's certificate parsing allows an attacker to crash the process or potentially execute code.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "high",
        "epss_score": 0.3421,
        "affected_software": "OpenSSL",
        "affected_versions": "3.0.0 to 3.0.6",
        "affected_platforms": "Windows, Linux",
        "fix_available": True,
        "patch_details": "Upgrade OpenSSL to 3.0.7 or later.",
        "exploit_available": False,
        "exploit_maturity": "poc",
        "vuln_references": [
            {"url": "https://www.openssl.org/news/secadv/20221101.txt", "label": "OpenSSL Advisory"}
        ],
        "cwe_ids": "CWE-119",
        "published_date": "2024-03-10"
    },
    {
        "cve_id": "CVE-2023-9999",
        "title": "Windows SMB Authentication Bypass",
        "description": "Attackers on the same network segment can bypass SMB NTLM authentication and access network shares without valid credentials.",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "high",
        "epss_score": 0.5100,
        "affected_software": "Microsoft Windows SMB",
        "affected_versions": "Windows Server 2016, 2019, 2022; Windows 10, 11",
        "affected_platforms": "Windows",
        "fix_available": True,
        "patch_details": "Apply Microsoft Security Update KB5025885.",
        "exploit_available": True,
        "exploit_maturity": "functional",
        "vuln_references": [
            {"url": "https://msrc.microsoft.com/update-guide", "label": "Microsoft MSRC"}
        ],
        "cwe_ids": "CWE-287",
        "published_date": "2023-11-20"
    },
    {
        "cve_id": "CVE-2024-2200",
        "title": "Nginx HTTP Request Smuggling",
        "description": "Specially crafted HTTP/1.1 requests can cause Nginx to forward smuggled requests to backend servers, bypassing security controls.",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "medium",
        "epss_score": 0.1523,
        "affected_software": "Nginx",
        "affected_versions": "1.0.0 to 1.24.0",
        "affected_platforms": "Linux, Windows, macOS",
        "fix_available": True,
        "patch_details": "Upgrade to Nginx 1.25.1 or configure 'ignore_invalid_headers on'.",
        "exploit_available": False,
        "exploit_maturity": "poc",
        "vuln_references": [
            {"url": "https://nginx.org/en/security_advisories.html", "label": "Nginx Security"}
        ],
        "cwe_ids": "CWE-444",
        "published_date": "2024-02-05"
    },
    {
        "cve_id": "CVE-2023-8888",
        "title": "SSH Weak Key Exchange Algorithm Supported",
        "description": "The SSH server advertises deprecated diffie-hellman-group1-sha1 key exchange algorithms which are vulnerable to Logjam attacks.",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "medium",
        "epss_score": 0.0210,
        "affected_software": "OpenSSH",
        "affected_versions": "< 8.0",
        "affected_platforms": "Linux, macOS",
        "fix_available": True,
        "patch_details": "Update sshd_config: remove diffie-hellman-group1-sha1 from KexAlgorithms.",
        "workaround": "Add 'KexAlgorithms -diffie-hellman-group1-sha1' to /etc/ssh/sshd_config",
        "exploit_available": False,
        "exploit_maturity": "unproven",
        "vuln_references": [
            {"url": "https://weakdh.org/", "label": "Logjam Attack"}
        ],
        "cwe_ids": "CWE-326",
        "published_date": "2023-09-01"
    },
]

inserted_vulns = insert("vulnerabilities", vulns_data, "Vulnerabilities")
vuln_map = {v["cve_id"]: v["vuln_id"] for v in inserted_vulns}


# ================================================================
# 3. OPEN PORTS
# ================================================================
print("\n🔌  Inserting open ports...")

ports_data = [
    # Web Server 01
    {"asset_id": asset_map["Web Server 01"],   "port_number": 80,   "protocol": "TCP", "state": "open", "service_name": "http",       "service_version": "nginx/1.24.0",       "is_expected": True,  "risk_level": "low"},
    {"asset_id": asset_map["Web Server 01"],   "port_number": 443,  "protocol": "TCP", "state": "open", "service_name": "https",      "service_version": "nginx/1.24.0",       "is_expected": True,  "risk_level": "low"},
    {"asset_id": asset_map["Web Server 01"],   "port_number": 22,   "protocol": "TCP", "state": "open", "service_name": "ssh",        "service_version": "OpenSSH 8.9p1",      "is_expected": True,  "risk_level": "low"},
    {"asset_id": asset_map["Web Server 01"],   "port_number": 8080, "protocol": "TCP", "state": "open", "service_name": "http-proxy", "service_version": "Apache Tomcat 9.0",  "is_expected": False, "risk_level": "high",   "notes": "Unexpected! Not in approved port list — investigate."},

    # Database Server
    {"asset_id": asset_map["Database Server"], "port_number": 5432, "protocol": "TCP", "state": "open", "service_name": "postgresql", "service_version": "PostgreSQL 15.3",    "is_expected": True,  "risk_level": "medium", "notes": "Should only be accessible from internal network."},
    {"asset_id": asset_map["Database Server"], "port_number": 3389, "protocol": "TCP", "state": "open", "service_name": "rdp",        "service_version": "Microsoft RDP",       "is_expected": True,  "risk_level": "high"},
    {"asset_id": asset_map["Database Server"], "port_number": 445,  "protocol": "TCP", "state": "open", "service_name": "smb",        "service_version": "Windows SMB",        "is_expected": True,  "risk_level": "high"},

    # Cloud API Gateway
    {"asset_id": asset_map["Cloud API Gateway"],"port_number": 443,  "protocol": "TCP", "state": "open", "service_name": "https",     "service_version": "AWS API Gateway",    "is_expected": True,  "risk_level": "low"},
    {"asset_id": asset_map["Cloud API Gateway"],"port_number": 8443, "protocol": "TCP", "state": "open", "service_name": "https-alt", "service_version": "unknown",            "is_expected": False, "risk_level": "critical", "notes": "Unexpected open port on internet-facing host!"},
]

insert("open_ports", ports_data, "Open ports")


# ================================================================
# 4. DNS RECORDS
# ================================================================
print("\n🌐  Inserting DNS records...")

dns_data = [
    {"asset_id": asset_map["Web Server 01"],    "domain": "company.com", "subdomain": "web01",    "fqdn": "web01.company.com",    "record_type": "A",     "record_value": "192.168.1.10", "ttl": 300,  "is_internal": True,  "status": "active"},
    {"asset_id": asset_map["Cloud API Gateway"],"domain": "company.com", "subdomain": "api",      "fqdn": "api.company.com",      "record_type": "A",     "record_value": "10.0.1.5",    "ttl": 60,   "is_internal": False, "status": "active"},
    {"asset_id": None,                           "domain": "company.com", "subdomain": "mail",     "fqdn": "mail.company.com",     "record_type": "MX",    "record_value": "mail.google.com.", "ttl": 3600, "is_internal": False, "status": "active"},
    {"asset_id": None,                           "domain": "company.com", "subdomain": "vpn",      "fqdn": "vpn.company.com",      "record_type": "CNAME", "record_value": "old-vpn-host.provider.net.", "ttl": 300, "is_internal": False, "status": "dangling", "risk_notes": "CNAME points to a decommissioned provider host — subdomain takeover risk!"},
    {"asset_id": asset_map["Web Server 01"],    "domain": "company.com", "subdomain": "www",      "fqdn": "www.company.com",      "record_type": "CNAME", "record_value": "web01.company.com.", "ttl": 300, "is_internal": False, "status": "active"},
    {"asset_id": None,                           "domain": "company.com", "subdomain": None,       "fqdn": "company.com",          "record_type": "TXT",   "record_value": "v=spf1 include:_spf.google.com ~all", "ttl": 3600, "is_internal": False, "status": "active"},
]

insert("dns_records", dns_data, "DNS records")


# ================================================================
# 5. SCANS
# ================================================================
print("\n📡  Inserting scans...")

scans_data = [
    {
        "scan_name": "June 2024 Full Vulnerability Scan",
        "scan_type": "vulnerability",
        "scanner_tool": "Nessus Professional",
        "scanner_version": "10.6.1",
        "initiated_by": "scheduler",
        "target_range": "192.168.0.0/16, 10.0.0.0/8",
        "assets_scanned": 6,
        "total_findings": 9,
        "critical_findings": 2,
        "high_findings": 4,
        "medium_findings": 2,
        "low_findings": 1,
        "new_assets_found": 0,
        "scan_started_at": "2024-06-01T09:00:00",
        "scan_finished_at": "2024-06-01T10:45:00",
        "duration_seconds": 6300,
        "status": "completed"
    },
    {
        "scan_name": "June 2024 Port Scan",
        "scan_type": "port",
        "scanner_tool": "Nmap",
        "scanner_version": "7.94",
        "initiated_by": "admin_john",
        "target_range": "192.168.0.0/16",
        "assets_scanned": 6,
        "total_findings": 9,
        "scan_started_at": "2024-06-01T08:00:00",
        "scan_finished_at": "2024-06-01T08:22:00",
        "duration_seconds": 1320,
        "status": "completed"
    },
    {
        "scan_name": "Q2 Compliance Check",
        "scan_type": "compliance",
        "scanner_tool": "OpenSCAP",
        "scanner_version": "1.3.8",
        "initiated_by": "scheduler",
        "target_range": "all_production",
        "assets_scanned": 5,
        "total_findings": 3,
        "scan_started_at": "2024-06-15T14:00:00",
        "scan_finished_at": "2024-06-15T15:10:00",
        "duration_seconds": 4200,
        "status": "completed"
    },
]

inserted_scans = insert("scans", scans_data, "Scans")
scan_map = {s["scan_name"]: s["scan_id"] for s in inserted_scans}


# ================================================================
# 6. ASSET VULNERABILITIES (link table)
# ================================================================
print("\n🔗  Linking assets to vulnerabilities...")

av_data = [
    # Web Server 01
    {"asset_id": asset_map["Web Server 01"],    "vuln_id": vuln_map["CVE-2024-1234"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "open",        "priority": "urgent", "detected_on": "2024-06-01", "due_date": "2024-06-08", "assigned_to": "infra@company.com",   "affected_component": "Log4j 2.14.1",   "notes": "Critical! Externally reachable Java app."},
    {"asset_id": asset_map["Web Server 01"],    "vuln_id": vuln_map["CVE-2024-2200"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "in_progress", "priority": "high",   "detected_on": "2024-06-01", "due_date": "2024-06-15", "assigned_to": "devops@company.com",  "affected_component": "nginx 1.24.0",   "notes": "Config fix in review."},

    # Database Server
    {"asset_id": asset_map["Database Server"],  "vuln_id": vuln_map["CVE-2023-9999"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "open",        "priority": "urgent", "detected_on": "2024-06-01", "due_date": "2024-06-08", "assigned_to": "dba@company.com",     "affected_component": "Windows SMB",    "notes": "DB server SMB bypass — must patch immediately."},

    # Cloud API Gateway
    {"asset_id": asset_map["Cloud API Gateway"],"vuln_id": vuln_map["CVE-2024-1234"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "open",        "priority": "urgent", "detected_on": "2024-06-01", "due_date": "2024-06-05", "assigned_to": "devops@company.com",  "affected_component": "Log4j 2.14.1",   "notes": "Internet-facing! Highest priority fix."},

    # HR Workstation
    {"asset_id": asset_map["HR Workstation"],   "vuln_id": vuln_map["CVE-2024-5678"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "remediated",  "priority": "medium", "detected_on": "2024-05-01", "remediated_on": "2024-05-20",           "affected_component": "OpenSSL 3.0.5",  "notes": "OpenSSL upgraded to 3.0.7. Verified clean."},

    # Dev Laptop
    {"asset_id": asset_map["Dev Laptop - Alice"],"vuln_id": vuln_map["CVE-2023-8888"],"scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "in_progress", "priority": "low",    "detected_on": "2024-06-01",                             "assigned_to": "alice@company.com",   "affected_component": "OpenSSH 7.9",    "notes": "Alice updating SSH config."},
]

insert("asset_vulnerabilities", av_data, "Asset-vulnerability links")


# ================================================================
# 7. ASSET CHANGES (audit trail)
# ================================================================
print("\n📋  Inserting asset change records...")

changes_data = [
    {"asset_id": asset_map["Web Server 01"],    "change_type": "vuln_discovered",   "field_changed": "vulnerabilities", "old_value": None,              "new_value": "CVE-2024-1234 detected", "changed_by": "Nessus",        "source": "scanner",  "changed_at": "2024-06-01T10:00:00"},
    {"asset_id": asset_map["Web Server 01"],    "change_type": "port_opened",        "field_changed": "open_ports",      "old_value": None,              "new_value": "Port 8080/TCP now open", "changed_by": "Nmap",          "source": "scanner",  "changed_at": "2024-06-01T08:15:00", "notes": "Unexpected port — flagged for review."},
    {"asset_id": asset_map["Database Server"],  "change_type": "os_update",          "field_changed": "os_version",      "old_value": "21H1",            "new_value": "21H2",                   "changed_by": "admin_sarah",   "source": "manual",   "changed_at": "2024-05-15T14:30:00"},
    {"asset_id": asset_map["Cloud API Gateway"],"change_type": "ip_change",          "field_changed": "ip_address",      "old_value": "10.0.1.4",        "new_value": "10.0.1.5",               "changed_by": "ci_cd_pipeline","source": "api",      "changed_at": "2024-05-20T09:00:00", "change_reason": "Redeployment after scaling event."},
    {"asset_id": asset_map["HR Workstation"],   "change_type": "vuln_remediated",    "field_changed": "vulnerabilities", "old_value": "CVE-2024-5678 open","new_value": "CVE-2024-5678 remediated","changed_by": "admin_john", "source": "manual",   "changed_at": "2024-05-20T11:00:00"},
    {"asset_id": asset_map["Dev Laptop - Alice"],"change_type": "criticality_change","field_changed": "criticality",     "old_value": "low",             "new_value": "medium",                 "changed_by": "admin_john",    "source": "manual",   "changed_at": "2024-06-05T10:00:00", "change_reason": "Alice now has access to prod credentials."},
]

insert("asset_changes", changes_data, "Asset change records")


# ================================================================
# 8. ASSET LOGS (event stream)
# ================================================================
print("\n📝  Inserting asset logs...")

logs_data = [
    {"asset_id": asset_map["Web Server 01"],    "log_level": "critical", "event_type": "vuln_detected",    "event_source": "Nessus",        "message": "Critical vulnerability CVE-2024-1234 detected on Log4j 2.14.1.", "details": {"cve": "CVE-2024-1234", "cvss": 9.8, "component": "log4j"}},
    {"asset_id": asset_map["Web Server 01"],    "log_level": "warning",  "event_type": "port_opened",      "event_source": "Nmap",          "message": "Unexpected port 8080/TCP found open. Not in approved port list.", "details": {"port": 8080, "protocol": "TCP", "service": "http-proxy"}},
    {"asset_id": asset_map["Web Server 01"],    "log_level": "info",     "event_type": "scan_completed",   "event_source": "Nessus",        "message": "Vulnerability scan completed. 2 findings on this asset.",          "details": {"findings": 2, "scan": "June 2024 Full Vulnerability Scan"}},
    {"asset_id": asset_map["Database Server"],  "log_level": "critical", "event_type": "vuln_detected",    "event_source": "Nessus",        "message": "High-severity SMB bypass CVE-2023-9999 detected.",                 "details": {"cve": "CVE-2023-9999", "cvss": 8.1}},
    {"asset_id": asset_map["Database Server"],  "log_level": "info",     "event_type": "scan_started",     "event_source": "Nessus",        "message": "Vulnerability scan started on database server.",                   "details": {"scan_type": "vulnerability"}},
    {"asset_id": asset_map["Cloud API Gateway"],"log_level": "critical", "event_type": "alert_triggered",  "event_source": "SIEM",          "message": "CRITICAL: Internet-facing host has Log4Shell vulnerability!",      "details": {"cve": "CVE-2024-1234", "exposure": "external_attack_surface"}},
    {"asset_id": asset_map["Cloud API Gateway"],"log_level": "error",    "event_type": "port_opened",      "event_source": "Nmap",          "message": "Rogue port 8443/TCP found open on internet-facing host.",          "details": {"port": 8443, "risk": "critical"}},
    {"asset_id": asset_map["HR Workstation"],   "log_level": "info",     "event_type": "patch_applied",    "event_source": "manual",        "message": "OpenSSL upgraded from 3.0.5 to 3.0.7. CVE-2024-5678 resolved.",   "details": {"cve": "CVE-2024-5678", "action": "upgrade"}},
    {"asset_id": asset_map["Dev Laptop - Alice"],"log_level":"warning",  "event_type": "compliance_check", "event_source": "OpenSCAP",      "message": "SSH weak key exchange algorithm detected. Non-compliant.",         "details": {"cve": "CVE-2023-8888", "policy": "CIS Level 1"}},
]

insert("asset_logs", logs_data, "Asset logs")


# ================================================================
# 9. SCAN SNAPSHOTS (point-in-time state)
# ================================================================
print("\n📸  Inserting scan snapshots...")

snapshots_data = [
    {
        "asset_id": asset_map["Web Server 01"],
        "scan_id": scan_map["June 2024 Full Vulnerability Scan"],
        "snapshot_taken_at": "2024-06-01T10:45:00",
        "total_vulns": 2, "critical_vulns": 1, "high_vulns": 0, "medium_vulns": 1, "low_vulns": 0,
        "new_vulns": 2, "resolved_vulns": 0,
        "total_open_ports": 4, "unexpected_ports": 1,
        "risk_score": 88,
        "compliance_score": 60,
        "os_detected": "Ubuntu 22.04.3 LTS",
        "open_ports_snapshot": [
            {"port": 80,   "protocol": "TCP", "service": "http",        "state": "open", "expected": True},
            {"port": 443,  "protocol": "TCP", "service": "https",       "state": "open", "expected": True},
            {"port": 22,   "protocol": "TCP", "service": "ssh",         "state": "open", "expected": True},
            {"port": 8080, "protocol": "TCP", "service": "http-proxy",  "state": "open", "expected": False}
        ],
        "vuln_snapshot": [
            {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "critical", "status": "open"},
            {"cve_id": "CVE-2024-2200", "cvss_score": 6.5, "severity": "medium",   "status": "in_progress"}
        ],
        "dns_snapshot": [
            {"record_type": "A",     "fqdn": "web01.company.com", "value": "192.168.1.10"},
            {"record_type": "CNAME", "fqdn": "www.company.com",   "value": "web01.company.com."}
        ]
    },
    {
        "asset_id": asset_map["Cloud API Gateway"],
        "scan_id": scan_map["June 2024 Full Vulnerability Scan"],
        "snapshot_taken_at": "2024-06-01T10:50:00",
        "total_vulns": 1, "critical_vulns": 1, "high_vulns": 0, "medium_vulns": 0, "low_vulns": 0,
        "new_vulns": 1, "resolved_vulns": 0,
        "total_open_ports": 2, "unexpected_ports": 1,
        "risk_score": 97,
        "compliance_score": 45,
        "os_detected": "Amazon Linux 2",
        "open_ports_snapshot": [
            {"port": 443,  "protocol": "TCP", "service": "https",     "state": "open", "expected": True},
            {"port": 8443, "protocol": "TCP", "service": "https-alt", "state": "open", "expected": False}
        ],
        "vuln_snapshot": [
            {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "critical", "status": "open"}
        ],
        "dns_snapshot": [
            {"record_type": "A", "fqdn": "api.company.com", "value": "10.0.1.5"}
        ]
    },
]

insert("scan_snapshots", snapshots_data, "Scan snapshots")


# ================================================================
# 10. EXPOSURES (active CTEM threats)
# ================================================================
print("\n🚨  Inserting CTEM exposures...")

exposures_data = [
    {
        "asset_id": asset_map["Cloud API Gateway"],
        "vuln_id": vuln_map["CVE-2024-1234"],
        "exposure_type": "external_attack_surface",
        "attack_vector": "network",
        "attack_complexity": "low",
        "risk_score": 97,
        "business_impact": "Full RCE on internet-facing API gateway. Attacker could exfiltrate all API traffic and pivot to internal network.",
        "status": "active",
        "assigned_to": "devops@company.com",
        "escalated": True,
        "sla_deadline": "2024-06-05T18:00:00",
        "description": "Log4Shell on internet-exposed host. Weaponized exploits in the wild. Must patch immediately."
    },
    {
        "asset_id": asset_map["Web Server 01"],
        "vuln_id": vuln_map["CVE-2024-1234"],
        "exposure_type": "external_attack_surface",
        "attack_vector": "network",
        "attack_complexity": "low",
        "risk_score": 88,
        "business_impact": "Public web server with Log4Shell. Could lead to full server compromise and lateral movement.",
        "status": "active",
        "assigned_to": "infra@company.com",
        "escalated": True,
        "sla_deadline": "2024-06-08T18:00:00",
        "description": "Log4j RCE on public web server. Severity: Critical."
    },
    {
        "asset_id": asset_map["Database Server"],
        "vuln_id": vuln_map["CVE-2023-9999"],
        "exposure_type": "insider_threat",
        "attack_vector": "adjacent",
        "attack_complexity": "low",
        "risk_score": 80,
        "business_impact": "Any attacker who reaches the internal network can access all production database files without credentials.",
        "status": "active",
        "assigned_to": "dba@company.com",
        "escalated": False,
        "sla_deadline": "2024-06-08T18:00:00",
        "description": "SMB auth bypass on production database server. All database files at risk if internal network is breached."
    },
    {
        "asset_id": None,
        "vuln_id": None,
        "exposure_type": "data_exposure",
        "attack_vector": "network",
        "attack_complexity": "low",
        "risk_score": 70,
        "business_impact": "Dangling DNS CNAME for vpn.company.com could allow an attacker to register the old provider host and intercept VPN traffic.",
        "status": "active",
        "assigned_to": "netops@company.com",
        "escalated": False,
        "description": "vpn.company.com CNAME points to a decommissioned host. Subdomain takeover possible."
    },
]

insert("exposures", exposures_data, "CTEM exposures")

print("\n🎉  All data inserted successfully!")
print("    Run: python queries.py  to see the data")
