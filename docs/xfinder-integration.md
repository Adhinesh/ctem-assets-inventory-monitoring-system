# XFinder ↔ CTEM Integration

This repository now supports Team 1's XFinder bundle as an import source.

## What is preserved

- `subdomains.json`, `dns.json`, `http.json`, `ports.json`, `services.json`, and `vulnerabilities.json` are translated into CTEM records.
- `full_scan.json` is stored in `xfinder_scan_reports`.
- `changes.json` is stored in `xfinder_change_reports`.

## What is derived

- CTEM assets are keyed by host name.
- `cloud_provider`, `network_zone`, `installed_software`, and `ip_address` are inferred from the XFinder bundle.
- CTEM vulnerability links are created when a vulnerability's `matched_url` hostname can be matched to an imported asset.
- Asset changes are only emitted for changes that can be resolved to a concrete host.

## Import

```bash
python import_xfinder_bundle.py --bundle-dir /path/to/sample_output
```

Use `--dry-run` to inspect the derived CTEM payloads without writing to Supabase.

## Notes

- `changes.json` contains upstream `subdomain_id` references that are not always recoverable from the exported JSON alone.
- The raw change report is preserved so those IDs are not lost.
