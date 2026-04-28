---
name: Get-SoftwareInventoryCVE
role: Compliance
tactic_folder: Inventory
language: Python
difficulty: medium
status: complete
entry_point: get_software_inventory_cve.py
requires:
  Python: "3.10+"
  Packages: []
  external_deps: none (stdlib only)
frameworks:
  nist_800_53: [SI-5, RA-5]
  cis_windows11: [2.3]
  mitre_attack: []
inputs:
  - --source: collection method — winget or registry
  - --output: CSV output file path (required)
  - --cache: JSON cache file for CVE lookups (default .cache/cve.json)
  - --rate-limit: NVD API requests per second (default 5.0)
  - --dry-run: collect inventory only; skip CVE lookups
  - --verbose: print progress to stderr
outputs:
  - CSV with columns: Name, Version, Publisher, CVE_IDs, MaxCVSS, MaxSeverity
---

# Get-SoftwareInventoryCVE

Enumerate all installed software on a Windows host — via `winget list` or the
HKLM Uninstall registry hive — then look up each package against the
**NVD 2.0 API** to surface known CVEs. Results are written to a CSV for import
into spreadsheets, SIEMs, or compliance platforms.

This tool is **stdlib-only** (Python 3.10+, no pip installs required) and
caches NVD responses locally so repeated runs do not re-query the API.

---

## Overview

1. **Collect** — runs `winget list` or a PowerShell one-liner against
   `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`.
2. **Enrich** — for each package, queries the NVD CVE 2.0 REST API using a
   keyword search (`name + version`). Results are cached in a local JSON file.
3. **Report** — writes a six-column CSV: package metadata plus highest CVSS
   score and severity out of all matched CVEs.

---

## Usage

**Dry-run first (no NVD calls, no API quota consumed):**

```bash
python get_software_inventory_cve.py --source winget --output report.csv --dry-run
python get_software_inventory_cve.py --source registry --output report.csv --dry-run
```

**Live run via winget:**

```bash
python get_software_inventory_cve.py --source winget --output report.csv
```

**Live run via registry (requires PowerShell):**

```bash
python get_software_inventory_cve.py --source registry --output report.csv
```

**With a custom cache location and verbose output:**

```bash
python get_software_inventory_cve.py \
    --source winget \
    --output report.csv \
    --cache C:\Temp\nvd_cache.json \
    --rate-limit 3 \
    --verbose
```

**Module invocation:**

```bash
python -m get_software_inventory_cve --source winget --output report.csv
```

---

## Output Schema

| Column | Description |
|---|---|
| `Name` | Installed software display name |
| `Version` | Installed version string |
| `Publisher` | Publisher / vendor name (empty if unavailable) |
| `CVE_IDs` | Semicolon-joined CVE identifiers (e.g. `CVE-2023-1234;CVE-2023-5678`) |
| `MaxCVSS` | Highest CVSS base score across all matched CVEs (empty if none) |
| `MaxSeverity` | Severity label for the highest-scoring CVE (CRITICAL / HIGH / MEDIUM / LOW) |

In `--dry-run` mode the last three columns (`CVE_IDs`, `MaxCVSS`, `MaxSeverity`) are empty strings.

---

## Caching

CVE results are cached in a JSON file (default: `.cache/cve.json`) keyed by
`"<name>::<version>"`. The cache is loaded at startup and written after each
successful NVD response. If the file is missing or unparseable, the tool starts
with an empty cache and emits a warning to stderr.

---

## Limitations

- **NVD keyword search is fuzzy.** A search for `7-Zip 22.01` may return CVEs
  for unrelated packages that happen to contain those words. Always validate
  findings before taking action or raising tickets.
- **No authenticated NVD key.** The unauthenticated NVD 2.0 rate limit is
  5 requests per second (configured via `--rate-limit`). If you register a
  free NVD API key you can raise this limit.
- **winget availability.** `winget` is not available on all Windows editions or
  Server SKUs; use `--source registry` as a fallback.
- **Version string matching.** NVD keyword search does not do semantic version
  matching; partial version strings may produce false positives or misses.
- **No external dependencies.** This tool is stdlib-only; no `pip install`
  is required.

---

## Running the Tests

```bash
cd "C:\MiscProjects\Windows\UsefulScripts\Compliance\Inventory\Get-SoftwareInventoryCVE"
python -m pytest -v
```

All tests are fully mocked — no real subprocess, no real HTTP calls.

## Lint

```bash
ruff check .
```
