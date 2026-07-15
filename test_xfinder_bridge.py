from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from xfinder_bridge import build_ctem_rows, build_xfinder_rows, load_bundle


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class XFinderBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.bundle_dir = Path(self.tempdir.name)

        write_json(
            self.bundle_dir / "subdomains.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "exported_at": "2026-07-09T13:38:00Z",
                "data": ["hackerone.com", "www.hackerone.com", "api.hackerone.com"],
            },
        )
        write_json(
            self.bundle_dir / "dns.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "exported_at": "2026-07-09T13:38:00Z",
                "data": [
                    {"host": "www.hackerone.com", "type": "A", "value": "104.16.185.53", "ttl": 300},
                    {"host": "api.hackerone.com", "type": "CNAME", "value": "hackerone.com", "ttl": 300},
                ],
            },
        )
        write_json(
            self.bundle_dir / "http.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "exported_at": "2026-07-09T13:38:00Z",
                "data": [
                    {
                        "url": "https://www.hackerone.com",
                        "host": "www.hackerone.com",
                        "final_url": "https://www.hackerone.com/",
                        "status_code": 200,
                        "title": "HackerOne",
                        "server_header": "cloudflare",
                        "content_length": 1,
                        "response_time_ms": 1,
                        "scheme": "https",
                        "webserver": "cloudflare",
                        "technologies": ["Cloudflare", "Next.js"],
                        "ips": ["104.16.185.53", "2606:4700::6810:b935"],
                        "cnames": ["hackerone.com"],
                    }
                ],
            },
        )
        write_json(
            self.bundle_dir / "ports.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "exported_at": "2026-07-09T13:38:00Z",
                "data": [{"host": "www.hackerone.com", "ip": "104.16.185.53", "port": 443, "protocol": "tcp"}],
            },
        )
        write_json(
            self.bundle_dir / "services.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "exported_at": "2026-07-09T13:38:00Z",
                "data": [
                    {
                        "ip": "104.16.185.53",
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "name": "https",
                        "product": "cloudflare",
                        "version": None,
                        "os": None,
                        "extra": None,
                    }
                ],
            },
        )
        write_json(
            self.bundle_dir / "vulnerabilities.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "exported_at": "2026-07-09T13:38:00Z",
                "data": [
                    {
                        "template_id": "graphql-alias-batching",
                        "name": "GraphQL Alias-based Batching",
                        "severity": "info",
                        "description": "GraphQL supports aliasing.",
                        "matched_url": "https://www.hackerone.com/graphql",
                        "matched_at": "https://www.hackerone.com/graphql",
                        "evidence": None,
                        "reference_urls": "https://example.com",
                        "tags": "graphql,misconfig,vuln",
                        "cvss_score": None,
                    }
                ],
            },
        )
        write_json(
            self.bundle_dir / "full_scan.json",
            {
                "scan_id": 42,
                "target": "hackerone.com",
                "scan_type": "full",
                "timestamp": "2026-07-09T13:38:00Z",
                "duration_seconds": 507.35,
                "scanners": {
                    "nuclei": {"success": True, "duration_seconds": 1, "summary": {"count": 1, "by_severity": {"info": 1}}},
                    "subfinder": {"success": True, "duration_seconds": 1, "summary": {"count": 3}},
                },
            },
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_load_bundle(self) -> None:
        bundle = load_bundle(self.bundle_dir)
        self.assertEqual(bundle["scan_id"], 42)
        self.assertEqual(bundle["target"], "hackerone.com")

    def test_build_ctem_rows(self) -> None:
        bundle = load_bundle(self.bundle_dir)
        ctem = build_ctem_rows(bundle)
        by_name = {row["asset_name"]: row for row in ctem["assets"]}

        self.assertEqual(len(ctem["assets"]), 3)
        self.assertEqual(by_name["www.hackerone.com"]["cloud_provider"], "cloudflare")
        self.assertEqual(by_name["www.hackerone.com"]["ip_address"], "104.16.185.53")
        self.assertEqual(ctem["scans"][0]["scanner_tool"], "XFinder")
        self.assertEqual(ctem["open_ports"][0]["service_name"], "https")
        self.assertEqual(ctem["vulnerabilities"][0]["cve_id"], "graphql-alias-batching")
        self.assertEqual(ctem["asset_vulnerabilities"][0]["asset_key"], "www.hackerone.com")

    def test_build_xfinder_rows(self) -> None:
        bundle = load_bundle(self.bundle_dir)
        xfinder = build_xfinder_rows(bundle)

        self.assertEqual(xfinder["targets"][0]["domain"], "hackerone.com")
        self.assertEqual(xfinder["scans"][0]["source_scan_id"], 42)
        self.assertEqual(xfinder["scan_report"]["scan_id"], 42)
        self.assertEqual(xfinder["change_report"]["summary"], {})


if __name__ == "__main__":
    unittest.main()
