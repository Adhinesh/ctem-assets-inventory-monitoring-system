#!/usr/bin/env python3
"""
insert_tool.py
==============
A command-line tool and Python module for safe, robust, and easy data insertion
into the CTEM Supabase database.

Prevents duplicate key errors by using Upserts (Update-or-Insert) and provides
an interactive prompt interface for adding assets and vulnerabilities.

Usage:
    # 1. Show CLI options:
    python3 insert_tool.py --help

    # 2. Insert a single asset interactively:
    python3 insert_tool.py asset

    # 3. Insert a single vulnerability interactively:
    python3 insert_tool.py vuln

    # 4. Insert all default sample mock data safely:
    python3 insert_tool.py sample

    # 5. Clear all database tables:
    python3 insert_tool.py clear
"""

import sys
import argparse
from datetime import datetime
from supabase import create_client

try:
    from config import SUPABASE_URL, SUPABASE_KEY
except ImportError:
    print("❌ Error: config.py with SUPABASE_URL and SUPABASE_KEY is required.")
    sys.exit(1)


class SupabaseInserter:
    """
    Handles all connection and safe insertion/upsertion operations
    against the CTEM database in Supabase.
    """

    def __init__(self):
        try:
            self.supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            print(f"❌ Failed to connect to Supabase: {e}")
            sys.exit(1)

    # ── Core Upsert Implementations ──────────────────────────────────────────

    def upsert_asset(self, asset_data: dict) -> dict:
        """
        Inserts or updates an asset. Since there is no unique constraint
        on assets in the DB schema, we check by asset_name before inserting.
        """
        name = asset_data.get("asset_name")
        if not name:
            raise ValueError("asset_name is required for assets.")

        existing = (
            self.supabase.table("assets")
            .select("asset_id")
            .eq("asset_name", name)
            .execute()
            .data
        )

        if existing:
            asset_id = existing[0]["asset_id"]
            res = (
                self.supabase.table("assets")
                .update(asset_data)
                .eq("asset_id", asset_id)
                .execute()
            )
            return res.data[0]
        else:
            res = self.supabase.table("assets").insert(asset_data).execute()
            return res.data[0]

    def upsert_vuln(self, vuln_data: dict) -> dict:
        """
        Upserts a vulnerability using its UNIQUE cve_id constraint.
        """
        cve_id = vuln_data.get("cve_id")
        if not cve_id:
            raise ValueError("cve_id is required for vulnerabilities.")

        res = (
            self.supabase.table("vulnerabilities")
            .upsert(vuln_data, on_conflict="cve_id")
            .execute()
        )
        return res.data[0]

    def upsert_scan(self, scan_data: dict) -> dict:
        """
        Inserts or updates a scan record. Checks by scan_name.
        """
        name = scan_data.get("scan_name")
        if not name:
            raise ValueError("scan_name is required for scans.")

        existing = (
            self.supabase.table("scans")
            .select("scan_id")
            .eq("scan_name", name)
            .execute()
            .data
        )

        if existing:
            scan_id = existing[0]["scan_id"]
            res = (
                self.supabase.table("scans")
                .update(scan_data)
                .eq("scan_id", scan_id)
                .execute()
            )
            return res.data[0]
        else:
            res = self.supabase.table("scans").insert(scan_data).execute()
            return res.data[0]

    def upsert_open_port(self, port_data: dict) -> dict:
        """
        Upserts an open port based on (asset_id, port_number, protocol).
        """
        res = (
            self.supabase.table("open_ports")
            .upsert(port_data, on_conflict="asset_id,port_number,protocol")
            .execute()
        )
        return res.data[0]

    def upsert_dns_record(self, dns_data: dict) -> dict:
        """
        Upserts a DNS record based on (domain, subdomain, record_type, record_value).
        """
        res = (
            self.supabase.table("dns_records")
            .upsert(dns_data, on_conflict="domain,subdomain,record_type,record_value")
            .execute()
        )
        return res.data[0]

    def upsert_scan_snapshot(self, snapshot_data: dict) -> dict:
        """
        Upserts a scan snapshot based on (asset_id, scan_id).
        """
        res = (
            self.supabase.table("scan_snapshots")
            .upsert(snapshot_data, on_conflict="asset_id,scan_id")
            .execute()
        )
        return res.data[0]

    def upsert_asset_vuln(self, av_data: dict) -> dict:
        """
        Upserts an asset-vulnerability link based on (asset_id, vuln_id).
        """
        res = (
            self.supabase.table("asset_vulnerabilities")
            .upsert(av_data, on_conflict="asset_id,vuln_id")
            .execute()
        )
        return res.data[0]

    def upsert_exposure(self, exp_data: dict) -> dict:
        """
        Upserts an active exposure. We check by matching asset_id, vuln_id, and exposure_type.
        """
        asset_id = exp_data.get("asset_id")
        vuln_id = exp_data.get("vuln_id")
        exp_type = exp_data.get("exposure_type")

        query = self.supabase.table("exposures").select("exposure_id")
        if asset_id is not None:
            query = query.eq("asset_id", asset_id)
        else:
            query = query.is_("asset_id", "null")

        if vuln_id is not None:
            query = query.eq("vuln_id", vuln_id)
        else:
            query = query.is_("vuln_id", "null")

        query = query.eq("exposure_type", exp_type)
        existing = query.execute().data

        if existing:
            exp_id = existing[0]["exposure_id"]
            res = (
                self.supabase.table("exposures")
                .update(exp_data)
                .eq("exposure_id", exp_id)
                .execute()
            )
            return res.data[0]
        else:
            res = self.supabase.table("exposures").insert(exp_data).execute()
            return res.data[0]

    def insert_change(self, change_data: dict) -> dict:
        """Adds a change record (audit logs are append-only)."""
        res = self.supabase.table("asset_changes").insert(change_data).execute()
        return res.data[0]

    def insert_log(self, log_data: dict) -> dict:
        """Adds an event log (event streams are append-only)."""
        res = self.supabase.table("asset_logs").insert(log_data).execute()
        return res.data[0]

    # ── Database Cleaning ────────────────────────────────────────────────────

    def clear_database(self):
        """Clears all data from database tables in correct dependency order."""
        tables_to_clear = [
            ("exposures", "exposure_id"),
            ("asset_vulnerabilities", "id"),
            ("scan_snapshots", "snapshot_id"),
            ("scans", "scan_id"),
            ("asset_logs", "log_id"),
            ("asset_changes", "change_id"),
            ("dns_records", "record_id"),
            ("open_ports", "port_id"),
            ("vulnerabilities", "vuln_id"),
            ("assets", "asset_id")
        ]

        print("\n🗑️  Clearing all data from database tables...")
        for table, pk in tables_to_clear:
            try:
                # PostgREST delete needs a filter; id != 0 matches everything
                self.supabase.table(table).delete().neq(pk, 0).execute()
                print(f"  ✔ Cleared table: {table}")
            except Exception as e:
                print(f"  ⚠ Failed to clear {table}: {e}")
        print("🎉 Database tables successfully cleared!\n")


# ── Interactive Prompts (CLI helper functions) ───────────────────────────────

def prompt_input(field_name: str, default: str = None, required: bool = False) -> str:
    """Helper to get user input with a clean default format."""
    prompt_str = f"  👉 Enter {field_name}"
    if default is not None:
        prompt_str += f" [{default}]"
    prompt_str += ": "

    while True:
        value = input(prompt_str).strip()
        if not value:
            if default is not None:
                return default
            if required:
                print(f"     ⚠️  {field_name} is required. Please enter a value.")
                continue
            return None
        return value


def interactive_add_asset(inserter: SupabaseInserter, args=None):
    print("\n" + "═"*50)
    print("  🛡️  CTEM Asset Insertion Wizard")
    print("═"*50)

    asset_name = getattr(args, "name", None) or prompt_input("Asset Name (e.g., Web Server)", required=True)
    asset_type = getattr(args, "type", None) or prompt_input("Asset Type (server/workstation/network_device/cloud_instance)", default="server")
    hostname = getattr(args, "hostname", None) or prompt_input("Hostname (e.g., web01)")
    fqdn = getattr(args, "fqdn", None) or prompt_input("FQDN (e.g., web01.company.com)")
    ip_address = getattr(args, "ip", None) or prompt_input("IP Address (e.g., 192.168.1.10)")
    network_zone = getattr(args, "zone", None) or prompt_input("Network Zone (dmz/internal/external)", default="internal")
    operating_system = getattr(args, "os", None) or prompt_input("Operating System (e.g., Ubuntu 22.04 LTS)")
    owner = getattr(args, "owner", None) or prompt_input("Owner Team/Person (e.g., DevOps Team)")
    environment = getattr(args, "env", None) or prompt_input("Environment (production/staging/development)", default="production")
    criticality = getattr(args, "criticality", None) or prompt_input("Criticality (low/medium/high/critical)", default="medium")
    status = getattr(args, "status", None) or prompt_input("Status (active/inactive/under_maintenance)", default="active")
    
    asset_data = {
        "asset_name": asset_name,
        "asset_type": asset_type,
        "hostname": hostname,
        "fqdn": fqdn,
        "ip_address": ip_address,
        "network_zone": network_zone,
        "operating_system": operating_system,
        "owner": owner,
        "environment": environment,
        "criticality": criticality,
        "status": status
    }
    # Remove None values
    asset_data = {k: v for k, v in asset_data.items() if v is not None}

    print("\n⏳  Inserting asset into Supabase...")
    try:
        res = inserter.upsert_asset(asset_data)
        print(f"✅ Success! Asset inserted/updated. Database ID: {res['asset_id']}")
    except Exception as e:
        print(f"❌ Failed to insert asset: {e}")


def interactive_add_vuln(inserter: SupabaseInserter, args=None):
    print("\n" + "═"*50)
    print("  🔓  CTEM Vulnerability Insertion Wizard")
    print("═"*50)

    cve_id = getattr(args, "cve", None) or prompt_input("CVE ID (e.g., CVE-2024-9999)", required=True)
    title = getattr(args, "title", None) or prompt_input("Vulnerability Title", required=True)
    description = getattr(args, "desc", None) or prompt_input("Description")
    
    cvss_val = getattr(args, "cvss", None)
    if cvss_val is None:
        raw_cvss = prompt_input("CVSS Score (0.0 to 10.0)", default="7.5")
        cvss_val = float(raw_cvss) if raw_cvss else None
        
    severity = getattr(args, "severity", None) or prompt_input("Severity (low/medium/high/critical)", default="high")
    affected_software = getattr(args, "software", None) or prompt_input("Affected Software")
    affected_versions = getattr(args, "versions", None) or prompt_input("Affected Versions")
    
    fix_avail_raw = getattr(args, "fix_available", None)
    if fix_avail_raw is not None:
        fix_available = str(fix_avail_raw).lower() in ("true", "t", "1")
    else:
        fix_available = prompt_input("Is Fix Available? (True/False)", default="True").lower() in ("true", "t", "1")
        
    patch_details = getattr(args, "patch", None) or prompt_input("Patch/Fix Details")

    vuln_data = {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "cvss_score": cvss_val,
        "severity": severity,
        "affected_software": affected_software,
        "affected_versions": affected_versions,
        "fix_available": fix_available,
        "patch_details": patch_details
    }
    # Remove None values
    vuln_data = {k: v for k, v in vuln_data.items() if v is not None}

    print("\n⏳  Inserting vulnerability into Supabase...")
    try:
        res = inserter.upsert_vuln(vuln_data)
        print(f"✅ Success! Vulnerability inserted/updated. Database ID: {res['vuln_id']}")
    except Exception as e:
        print(f"❌ Failed to insert vulnerability: {e}")



# ── Sample Mock Data Insertion (Safely Replaces insert_data.py) ──────────────

def insert_sample_data(inserter: SupabaseInserter, clear_first: bool = False):
    """
    Inserts a comprehensive set of sample mock data safely using upserting,
    optionally clearing existing database records first.
    """
    if clear_first:
        inserter.clear_database()

    # 1. ASSETS
    print("📦  Upserting assets...")
    assets_raw = [
        {"asset_name": "Web Server 01", "asset_type": "server", "hostname": "web01", "fqdn": "web01.prod.company.com", "mac_address": "08:00:2b:01:02:03", "ip_address": "192.168.1.10", "network_zone": "dmz", "operating_system": "Ubuntu 22.04 LTS", "os_version": "22.04.3", "os_architecture": "x86_64", "cloud_provider": "on_premise", "physical_location": "DC1 Rack 12 Unit 4", "owner": "Infrastructure Team", "department": "Engineering", "contact_email": "infra@company.com", "environment": "production", "criticality": "critical", "data_classification": "confidential", "tags": {"team": "infra", "tier": "web"}, "status": "active"},
        {"asset_name": "Database Server", "asset_type": "server", "hostname": "db01", "fqdn": "db01.prod.company.com", "mac_address": "08:00:2b:04:05:06", "ip_address": "192.168.1.20", "network_zone": "internal", "operating_system": "Windows Server 2022", "os_version": "21H2", "os_architecture": "x86_64", "cloud_provider": "on_premise", "physical_location": "DC1 Rack 08 Unit 2", "owner": "Database Team", "department": "Engineering", "contact_email": "dba@company.com", "environment": "production", "criticality": "critical", "data_classification": "restricted", "tags": {"team": "dba", "tier": "data"}, "status": "active"},
        {"asset_name": "Cloud API Gateway", "asset_type": "cloud_instance", "hostname": "api-gw", "fqdn": "api.company.com", "ip_address": "10.0.1.5", "network_zone": "external", "operating_system": "Amazon Linux 2", "os_version": "2.0", "os_architecture": "x86_64", "cloud_provider": "aws", "cloud_region": "us-east-1", "cloud_instance_id": "i-0abc1234def56789", "owner": "DevOps Team", "department": "Platform", "contact_email": "devops@company.com", "environment": "production", "criticality": "high", "data_classification": "confidential", "tags": {"team": "devops", "project": "api-platform"}, "status": "active"},
        {"asset_name": "HR Workstation", "asset_type": "workstation", "hostname": "hr-pc-01", "ip_address": "192.168.2.15", "network_zone": "internal", "operating_system": "Windows 11 Pro", "os_version": "23H2", "os_architecture": "x86_64", "cloud_provider": "on_premise", "physical_location": "HQ Floor 2", "owner": "HR Department", "department": "Human Resources", "contact_email": "hr-it@company.com", "environment": "production", "criticality": "medium", "data_classification": "confidential", "tags": {"team": "hr"}, "status": "active"},
        {"asset_name": "Dev Laptop - Alice", "asset_type": "workstation", "hostname": "alice-mbp", "ip_address": "192.168.3.5", "network_zone": "internal", "operating_system": "macOS Ventura", "os_version": "13.5.2", "os_architecture": "arm64", "cloud_provider": "on_premise", "owner": "Engineering Team", "department": "Engineering", "contact_email": "alice@company.com", "environment": "development", "criticality": "low", "data_classification": "internal", "tags": {"team": "engineering", "user": "alice"}, "status": "active"},
        {"asset_name": "Core Switch", "asset_type": "network_device", "hostname": "core-sw-01", "fqdn": "core-switch-01.infra.company.com", "mac_address": "00:1a:2b:3c:4d:5e", "ip_address": "192.168.1.1", "network_zone": "internal", "operating_system": "Cisco IOS", "os_version": "15.2(7)E5", "cloud_provider": "on_premise", "physical_location": "DC1 Rack 01 Unit 1", "owner": "Network Team", "department": "IT Operations", "contact_email": "netops@company.com", "environment": "production", "criticality": "critical", "data_classification": "restricted", "tags": {"team": "netops", "tier": "network"}, "status": "active"},
        {"asset_name": "payment Server", "asset_type": "server", "hostname": "pyserver-01", "fqdn": "pyserver-01.prod.company.com", "mac_address": "08:00:2b:04:05:06", "ip_address": "192.168.1.105", "network_zone": "internal", "operating_system": "Windows Server 2022", "os_version": "21H2", "os_architecture": "x86_64", "cloud_provider": "on_premise", "physical_location": "DC1 Rack 08 Unit 2", "owner": "Database Team", "department": "Engineering", "contact_email": "dba@company.com", "environment": "production", "criticality": "critical", "data_classification": "restricted", "tags": {"team": "dba", "tier": "data"}, "status": "active"}
    ]
    
    asset_map = {}
    for raw in assets_raw:
        res = inserter.upsert_asset(raw)
        asset_map[res["asset_name"]] = res["asset_id"]
    print(f"  ✔ Upserted: {len(asset_map)} assets")

    # 2. VULNERABILITIES
    print("\n🔓  Upserting vulnerabilities...")
    vulns_raw = [
        {
            "cve_id": "CVE-2024-1234",
            "title": "Apache Log4j Remote Code Execution (Log4Shell)",
            "description": "A remote attacker can execute arbitrary code via JNDI lookup in log messages. Affects Log4j 2.0-beta9 through 2.14.1.",
            "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "critical", "epss_score": 0.9752, "affected_software": "Apache Log4j", "affected_versions": "2.0-beta9 to 2.14.1", "affected_platforms": "Windows, Linux, macOS", "fix_available": True, "patch_details": "Upgrade to Log4j 2.17.1 or later. Set log4j2.formatMsgNoLookups=true as interim workaround.", "exploit_available": True, "exploit_maturity": "weaponized", "exploit_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
            "vuln_references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "label": "NVD"}, {"url": "https://logging.apache.org/log4j/2.x/security.html", "label": "Apache Advisory"}],
            "cwe_ids": "CWE-502", "published_date": "2024-01-15"
        },
        {
            "cve_id": "CVE-2024-5678",
            "title": "OpenSSL Buffer Overflow in X.509 Certificate Parsing",
            "description": "A buffer overflow in OpenSSL's certificate parsing allows an attacker to crash the process or potentially execute code.",
            "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "severity": "high", "epss_score": 0.3421, "affected_software": "OpenSSL", "affected_versions": "3.0.0 to 3.0.6", "affected_platforms": "Windows, Linux", "fix_available": True, "patch_details": "Upgrade OpenSSL to 3.0.7 or later.", "exploit_available": False, "exploit_maturity": "poc",
            "vuln_references": [{"url": "https://www.openssl.org/news/secadv/20221101.txt", "label": "OpenSSL Advisory"}],
            "cwe_ids": "CWE-119", "published_date": "2024-03-10"
        },
        {
            "cve_id": "CVE-2023-9999",
            "title": "Windows SMB Authentication Bypass",
            "description": "Attackers on the same network segment can bypass SMB NTLM authentication and access network shares without valid credentials.",
            "cvss_score": 8.1, "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "severity": "high", "epss_score": 0.5100, "affected_software": "Microsoft Windows SMB", "affected_versions": "Windows Server 2016, 2019, 2022; Windows 10, 11", "affected_platforms": "Windows", "fix_available": True, "patch_details": "Apply Microsoft Security Update KB5025885.", "exploit_available": True, "exploit_maturity": "functional",
            "vuln_references": [{"url": "https://msrc.microsoft.com/update-guide", "label": "Microsoft MSRC"}],
            "cwe_ids": "CWE-287", "published_date": "2023-11-20"
        },
        {
            "cve_id": "CVE-2024-2200",
            "title": "Nginx HTTP Request Smuggling",
            "description": "Specially crafted HTTP/1.1 requests can cause Nginx to forward smuggled requests to backend servers, bypassing security controls.",
            "cvss_score": 6.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "severity": "medium", "epss_score": 0.1523, "affected_software": "Nginx", "affected_versions": "1.0.0 to 1.24.0", "affected_platforms": "Linux, Windows, macOS", "fix_available": True, "patch_details": "Upgrade to Nginx 1.25.1 or configure 'ignore_invalid_headers on'.", "exploit_available": False, "exploit_maturity": "poc",
            "vuln_references": [{"url": "https://nginx.org/en/security_advisories.html", "label": "Nginx Security"}],
            "cwe_ids": "CWE-444", "published_date": "2024-02-05"
        },
        {
            "cve_id": "CVE-2023-8888",
            "title": "SSH Weak Key Exchange Algorithm Supported",
            "description": "The SSH server advertises deprecated diffie-hellman-group1-sha1 key exchange algorithms which are vulnerable to Logjam attacks.",
            "cvss_score": 4.3, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "severity": "medium", "epss_score": 0.0210, "affected_software": "OpenSSH", "affected_versions": "< 8.0", "affected_platforms": "Linux, macOS",
            "vuln_references": [{"url": "https://weakdh.org", "label": "WeakDH Project Advisory"}],
            "cwe_ids": "CWE-327", "published_date": "2023-05-15"
        }
    ]

    vuln_map = {}
    for raw in vulns_raw:
        res = inserter.upsert_vuln(raw)
        vuln_map[res["cve_id"]] = res["vuln_id"]
    print(f"  ✔ Upserted: {len(vuln_map)} vulnerabilities")

    # 3. OPEN PORTS
    print("\n🔌  Upserting open ports...")
    ports_raw = [
        {"asset_id": asset_map["Web Server 01"], "port_number": 80, "protocol": "TCP", "state": "open", "service_name": "http", "service_version": "nginx 1.24.0", "is_expected": True, "risk_level": "low"},
        {"asset_id": asset_map["Web Server 01"], "port_number": 443, "protocol": "TCP", "state": "open", "service_name": "https", "service_version": "nginx 1.24.0", "is_expected": True, "risk_level": "low"},
        {"asset_id": asset_map["Web Server 01"], "port_number": 22, "protocol": "TCP", "state": "open", "service_name": "ssh", "service_version": "OpenSSH 8.9p1", "is_expected": True, "risk_level": "low"},
        {"asset_id": asset_map["Database Server"], "port_number": 5432, "protocol": "TCP", "state": "open", "service_name": "postgresql", "service_version": "PostgreSQL 15.3", "is_expected": True, "risk_level": "low"},
        {"asset_id": asset_map["Database Server"], "port_number": 3389, "protocol": "TCP", "state": "open", "service_name": "ms-wbt-server", "service_version": "Windows RDP", "is_expected": False, "risk_level": "medium", "notes": "RDP open internally - verify policy."},
        {"asset_id": asset_map["Cloud API Gateway"], "port_number": 443, "protocol": "TCP", "state": "open", "service_name": "https", "is_expected": True, "risk_level": "low"},
        {"asset_id": asset_map["Core Switch"], "port_number": 22, "protocol": "TCP", "state": "open", "service_name": "ssh", "is_expected": True, "risk_level": "low"},
        {"asset_id": asset_map["Core Switch"], "port_number": 161, "protocol": "UDP", "state": "open", "service_name": "snmp", "is_expected": True, "risk_level": "medium"}
    ]
    for port in ports_raw:
        inserter.upsert_open_port(port)
    print(f"  ✔ Upserted: {len(ports_raw)} open ports")

    # 4. DNS RECORDS
    print("\n🌐  Upserting DNS records...")
    dns_raw = [
        {"asset_id": asset_map["Web Server 01"], "domain": "company.com", "subdomain": "web01", "fqdn": "web01.company.com", "record_type": "A", "record_value": "192.168.1.10", "ttl": 3600, "is_internal": True},
        {"asset_id": asset_map["Web Server 01"], "domain": "company.com", "subdomain": "www", "fqdn": "www.company.com", "record_type": "CNAME", "record_value": "web01.company.com", "ttl": 3600, "is_internal": False},
        {"asset_id": asset_map["Database Server"], "domain": "company.com", "subdomain": "db01", "fqdn": "db01.company.com", "record_type": "A", "record_value": "192.168.1.20", "ttl": 3600, "is_internal": True},
        {"asset_id": asset_map["Cloud API Gateway"], "domain": "company.com", "subdomain": "api", "fqdn": "api.company.com", "record_type": "A", "record_value": "10.0.1.5", "ttl": 300, "is_internal": False},
        {"asset_id": None, "domain": "company.com", "subdomain": "vpn", "fqdn": "vpn.company.com", "record_type": "CNAME", "record_value": "decommissioned-provider.net", "ttl": 600, "status": "dangling", "risk_notes": "Dangling CNAME points to unregistered third-party host."}
    ]
    for record in dns_raw:
        inserter.upsert_dns_record(record)
    print(f"  ✔ Upserted: {len(dns_raw)} DNS records")

    # 5. SCANS
    print("\n🔬  Upserting scans...")
    scans_raw = [
        {"scan_name": "June 2024 Full Vulnerability Scan", "scan_type": "full", "scanner_tool": "Nessus", "scanner_version": "10.6.1", "initiated_by": "scheduler", "target_range": "192.168.0.0/16", "assets_scanned": 6, "total_findings": 9, "scan_started_at": "2024-06-01T08:00:00", "scan_finished_at": "2024-06-01T08:22:00", "duration_seconds": 1320, "status": "completed"},
        {"scan_name": "Q2 Compliance Check", "scan_type": "compliance", "scanner_tool": "OpenSCAP", "scanner_version": "1.3.8", "initiated_by": "scheduler", "target_range": "all_production", "assets_scanned": 5, "total_findings": 3, "scan_started_at": "2024-06-15T14:00:00", "scan_finished_at": "2024-06-15T15:10:00", "duration_seconds": 4200, "status": "completed"}
    ]
    scan_map = {}
    for s in scans_raw:
        res = inserter.upsert_scan(s)
        scan_map[res["scan_name"]] = res["scan_id"]
    print(f"  ✔ Upserted: {len(scan_map)} scans")

    # 6. ASSET VULNERABILITIES
    print("\n🔗  Upserting asset-vulnerability links...")
    av_raw = [
        {"asset_id": asset_map["Web Server 01"], "vuln_id": vuln_map["CVE-2024-1234"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "open", "priority": "urgent", "detected_on": "2024-06-01", "due_date": "2024-06-08", "assigned_to": "infra@company.com", "affected_component": "Log4j 2.14.1", "notes": "Critical! Externally reachable Java app."},
        {"asset_id": asset_map["Web Server 01"], "vuln_id": vuln_map["CVE-2024-2200"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "in_progress", "priority": "high", "detected_on": "2024-06-01", "due_date": "2024-06-15", "assigned_to": "devops@company.com", "affected_component": "nginx 1.24.0", "notes": "Config fix in review."},
        {"asset_id": asset_map["Database Server"], "vuln_id": vuln_map["CVE-2023-9999"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "open", "priority": "urgent", "detected_on": "2024-06-01", "due_date": "2024-06-08", "assigned_to": "dba@company.com", "affected_component": "Windows SMB", "notes": "DB server SMB bypass — must patch immediately."},
        {"asset_id": asset_map["Cloud API Gateway"], "vuln_id": vuln_map["CVE-2024-1234"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "open", "priority": "urgent", "detected_on": "2024-06-01", "due_date": "2024-06-05", "assigned_to": "devops@company.com", "affected_component": "Log4j 2.14.1", "notes": "Internet-facing! Highest priority fix."},
        {"asset_id": asset_map["HR Workstation"], "vuln_id": vuln_map["CVE-2024-5678"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "remediated", "priority": "medium", "detected_on": "2024-05-01", "remediated_on": "2024-05-20", "affected_component": "OpenSSL 3.0.5", "notes": "OpenSSL upgraded to 3.0.7. Verified clean."},
        {"asset_id": asset_map["Dev Laptop - Alice"], "vuln_id": vuln_map["CVE-2023-8888"], "scan_id": scan_map["June 2024 Full Vulnerability Scan"], "status": "in_progress", "priority": "low", "detected_on": "2024-06-01", "assigned_to": "alice@company.com", "affected_component": "OpenSSH 7.9", "notes": "Alice updating SSH config."}
    ]
    for av in av_raw:
        inserter.upsert_asset_vuln(av)
    print(f"  ✔ Upserted: {len(av_raw)} asset-vulnerability links")

    # 7. ASSET CHANGES (Appends new history record per insert)
    print("\n📋  Adding asset changes history records...")
    changes_raw = [
        {"asset_id": asset_map["Web Server 01"], "change_type": "vuln_discovered", "field_changed": "vulnerabilities", "old_value": None, "new_value": "CVE-2024-1234 detected", "changed_by": "Nessus", "source": "scanner", "changed_at": "2024-06-01T10:00:00"},
        {"asset_id": asset_map["Web Server 01"], "change_type": "port_opened", "field_changed": "open_ports", "old_value": None, "new_value": "Port 8080/TCP now open", "changed_by": "Nmap", "source": "scanner", "changed_at": "2024-06-01T08:15:00", "notes": "Unexpected port — flagged for review."},
        {"asset_id": asset_map["Database Server"], "change_type": "os_update", "field_changed": "os_version", "old_value": "21H1", "new_value": "21H2", "changed_by": "admin_sarah", "source": "manual", "changed_at": "2024-05-15T14:30:00"},
        {"asset_id": asset_map["Cloud API Gateway"], "change_type": "ip_change", "field_changed": "ip_address", "old_value": "10.0.1.4", "new_value": "10.0.1.5", "changed_by": "ci_cd_pipeline", "source": "api", "changed_at": "2024-05-20T09:00:00", "change_reason": "Redeployment after scaling event."},
        {"asset_id": asset_map["HR Workstation"], "change_type": "vuln_remediated", "field_changed": "vulnerabilities", "old_value": "CVE-2024-5678 open", "new_value": "CVE-2024-5678 remediated", "changed_by": "admin_john", "source": "manual", "changed_at": "2024-05-20T11:00:00"},
        {"asset_id": asset_map["Dev Laptop - Alice"], "change_type": "criticality_change", "field_changed": "criticality", "old_value": "low", "new_value": "medium", "changed_by": "admin_john", "source": "manual", "changed_at": "2024-06-05T10:00:00", "change_reason": "Alice now has access to prod credentials."}
    ]
    for change in changes_raw:
        inserter.insert_change(change)
    print(f"  ✔ Appended: {len(changes_raw)} change logs")

    # 8. ASSET LOGS
    print("\n📝  Adding asset event stream logs...")
    logs_raw = [
        {"asset_id": asset_map["Web Server 01"], "log_level": "critical", "event_type": "vuln_detected", "event_source": "Nessus", "message": "Critical vulnerability CVE-2024-1234 detected on Log4j 2.14.1.", "details": {"cve": "CVE-2024-1234", "cvss": 9.8, "component": "log4j"}},
        {"asset_id": asset_map["Web Server 01"], "log_level": "warning", "event_type": "port_opened", "event_source": "Nmap", "message": "Unexpected port 8080/TCP found open. Not in approved port list.", "details": {"port": 8080, "protocol": "TCP", "service": "http-proxy"}},
        {"asset_id": asset_map["Web Server 01"], "log_level": "info", "event_type": "scan_completed", "event_source": "Nessus", "message": "Vulnerability scan completed. 2 findings on this asset.", "details": {"findings": 2, "scan": "June 2024 Full Vulnerability Scan"}},
        {"asset_id": asset_map["Database Server"], "log_level": "critical", "event_type": "vuln_detected", "event_source": "Nessus", "message": "High-severity SMB bypass CVE-2023-9999 detected.", "details": {"cve": "CVE-2023-9999", "cvss": 8.1}},
        {"asset_id": asset_map["Database Server"], "log_level": "info", "event_type": "scan_started", "event_source": "Nessus", "message": "Vulnerability scan started on database server.", "details": {"scan_type": "vulnerability"}},
        {"asset_id": asset_map["Cloud API Gateway"], "log_level": "critical", "event_type": "alert_triggered", "event_source": "SIEM", "message": "CRITICAL: Internet-facing host has Log4Shell vulnerability!", "details": {"cve": "CVE-2024-1234", "exposure": "external_attack_surface"}},
        {"asset_id": asset_map["Cloud API Gateway"], "log_level": "error", "event_type": "port_opened", "event_source": "Nmap", "message": "Rogue port 8443/TCP found open on internet-facing host.", "details": {"port": 8443, "risk": "critical"}},
        {"asset_id": asset_map["HR Workstation"], "log_level": "info", "event_type": "patch_applied", "event_source": "manual", "message": "OpenSSL upgraded from 3.0.5 to 3.0.7. CVE-2024-5678 resolved.", "details": {"cve": "CVE-2024-5678", "action": "upgrade"}},
        {"asset_id": asset_map["Dev Laptop - Alice"], "log_level": "warning", "event_type": "compliance_check", "event_source": "OpenSCAP", "message": "SSH weak key exchange algorithm detected. Non-compliant.", "details": {"cve": "CVE-2023-8888", "policy": "CIS Level 1"}}
    ]
    for log in logs_raw:
        inserter.insert_log(log)
    print(f"  ✔ Appended: {len(logs_raw)} events")

    # 9. SCAN SNAPSHOTS
    print("\n📸  Upserting scan snapshots...")
    snapshots_raw = [
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
                {"port": 80, "protocol": "TCP", "service": "http", "state": "open", "expected": True},
                {"port": 443, "protocol": "TCP", "service": "https", "state": "open", "expected": True},
                {"port": 22, "protocol": "TCP", "service": "ssh", "state": "open", "expected": True},
                {"port": 8080, "protocol": "TCP", "service": "http-proxy", "state": "open", "expected": False}
            ],
            "vuln_snapshot": [
                {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "critical", "status": "open"},
                {"cve_id": "CVE-2024-2200", "cvss_score": 6.5, "severity": "medium", "status": "in_progress"}
            ],
            "dns_snapshot": [
                {"record_type": "A", "fqdn": "web01.company.com", "value": "192.168.1.10"},
                {"record_type": "CNAME", "fqdn": "www.company.com", "value": "web01.company.com."}
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
                {"port": 443, "protocol": "TCP", "service": "https", "state": "open", "expected": True},
                {"port": 8443, "protocol": "TCP", "service": "https-alt", "state": "open", "expected": False}
            ],
            "vuln_snapshot": [
                {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "critical", "status": "open"}
            ],
            "dns_snapshot": [
                {"record_type": "A", "fqdn": "api.company.com", "value": "10.0.1.5"}
            ]
        }
    ]
    for ss in snapshots_raw:
        inserter.upsert_scan_snapshot(ss)
    print(f"  ✔ Upserted: {len(snapshots_raw)} snapshots")

    # 10. EXPOSURES
    print("\n🚨  Upserting exposures...")
    exposures_raw = [
        {"asset_id": asset_map["Cloud API Gateway"], "vuln_id": vuln_map["CVE-2024-1234"], "exposure_type": "external_attack_surface", "attack_vector": "network", "attack_complexity": "low", "risk_score": 97, "business_impact": "Full RCE on internet-facing API gateway. Attacker could exfiltrate all API traffic and pivot to internal network.", "status": "active", "assigned_to": "devops@company.com", "escalated": True, "sla_deadline": "2024-06-05T18:00:00", "description": "Log4Shell on internet-exposed host. Weaponized exploits in the wild. Must patch immediately."},
        {"asset_id": asset_map["Web Server 01"], "vuln_id": vuln_map["CVE-2024-1234"], "exposure_type": "external_attack_surface", "attack_vector": "network", "attack_complexity": "low", "risk_score": 88, "business_impact": "Public web server with Log4Shell. Could lead to full server compromise and lateral movement.", "status": "active", "assigned_to": "infra@company.com", "escalated": True, "sla_deadline": "2024-06-08T18:00:00", "description": "Log4j RCE on public web server. Severity: Critical."},
        {"asset_id": asset_map["Database Server"], "vuln_id": vuln_map["CVE-2023-9999"], "exposure_type": "insider_threat", "attack_vector": "adjacent", "attack_complexity": "low", "risk_score": 80, "business_impact": "Any attacker who reaches the internal network can access all production database files without credentials.", "status": "active", "assigned_to": "dba@company.com", "escalated": False, "sla_deadline": "2024-06-08T18:00:00", "description": "SMB auth bypass on production database server. All database files at risk if internal network is breached."},
        {"asset_id": None, "vuln_id": None, "exposure_type": "data_exposure", "attack_vector": "network", "attack_complexity": "low", "risk_score": 70, "business_impact": "Dangling DNS CNAME for vpn.company.com could allow an attacker to register the old provider host and intercept VPN traffic.", "status": "active", "assigned_to": "netops@company.com", "escalated": False, "description": "vpn.company.com CNAME points to a decommissioned host. Subdomain takeover possible."}
    ]
    for exp in exposures_raw:
        inserter.upsert_exposure(exp)
    print(f"  ✔ Upserted: {len(exposures_raw)} exposures")

    print("\n🎉  All sample mock data inserted/updated successfully!")
    print("    Run:  python3 queries.py  to see the data in your database.")


# ── Main Runner ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTEM Database Insertion Tool & CLI"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available actions")

    # Command: asset
    asset_parser = subparsers.add_parser(
        "asset", help="Add/update a single asset in the database (CLI args or interactive prompt)."
    )
    asset_parser.add_argument("--name", help="Asset name")
    asset_parser.add_argument("--type", help="Asset type (server/workstation/network_device/cloud_instance)")
    asset_parser.add_argument("--hostname", help="Hostname")
    asset_parser.add_argument("--fqdn", help="FQDN")
    asset_parser.add_argument("--ip", help="IP address")
    asset_parser.add_argument("--zone", help="Network zone")
    asset_parser.add_argument("--os", help="Operating system")
    asset_parser.add_argument("--owner", help="Owner team/person")
    asset_parser.add_argument("--env", help="Environment")
    asset_parser.add_argument("--criticality", help="Criticality (low/medium/high/critical)")
    asset_parser.add_argument("--status", help="Status (active/inactive/...)")

    # Command: vuln
    vuln_parser = subparsers.add_parser(
        "vuln", help="Add/update a single vulnerability in the database (CLI args or interactive prompt)."
    )
    vuln_parser.add_argument("--cve", help="CVE ID (e.g., CVE-2024-9999)")
    vuln_parser.add_argument("--title", help="Vulnerability title")
    vuln_parser.add_argument("--desc", help="Vulnerability description")
    vuln_parser.add_argument("--cvss", type=float, help="CVSS score (0.0 to 10.0)")
    vuln_parser.add_argument("--severity", help="Severity (low/medium/high/critical)")
    vuln_parser.add_argument("--software", help="Affected software")
    vuln_parser.add_argument("--versions", help="Affected versions")
    vuln_parser.add_argument("--fix-available", help="Is fix available? (true/false)")
    vuln_parser.add_argument("--patch", help="Patch/fix details")

    # Command: sample
    sample_parser = subparsers.add_parser(
        "sample", help="Insert the full set of default CTEM sample mock data safely."
    )
    sample_parser.add_argument(
        "--clear", action="store_true", help="Clear all database tables first."
    )

    # Command: clear
    subparsers.add_parser(
        "clear", help="Erase all records from all CTEM database tables."
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Instantiate the inserter client
    inserter = SupabaseInserter()
    print("✅ Connected to Supabase")

    if args.command == "clear":
        confirm = input("⚠️  Are you sure you want to clear ALL tables? (y/N): ")
        if confirm.lower() in ("y", "yes"):
            inserter.clear_database()
        else:
            print("Operation cancelled.")
            
    elif args.command == "sample":
        insert_sample_data(inserter, clear_first=args.clear)
        
    elif args.command == "asset":
        interactive_add_asset(inserter, args)
        
    elif args.command == "vuln":
        interactive_add_vuln(inserter, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Wizard cancelled. Exiting.")
        sys.exit(0)
