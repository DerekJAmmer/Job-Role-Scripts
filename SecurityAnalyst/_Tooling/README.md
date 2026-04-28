# _Tooling

Tools that don't belong to a single ATT&CK tactic — used across multiple stages of analysis.

## Scripts

- **Invoke-SysmonAudit** — validate a Sysmon configuration against a known-good baseline (SwiftOnSecurity / Olaf Hartong), deploy, and verify. *(planned)*
- **Get-IOCIntel** (Python) — threat-intel enrichment CLI. Takes hashes, IPs, or domains and queries VirusTotal, AbuseIPDB, and OTX with a local cache to avoid hammering APIs. *(planned)*
- **Invoke-PhishTriage** (Python) — parse `.eml` / `.msg` headers, URLs, and attachments. Sandbox-safe extraction. *(planned)*
- **mini-siem** (Python, capstone) — ingest Winlogbeat-style NDJSON to SQLite, run Sigma-ish YAML detection rules, and alert on matches via CLI. *(planned)*

See `SecurityAnalyst/README.md` for the full matrix.
