---
name: Get-IOCIntel
role: SecurityAnalyst
tactic_folder: _Tooling
language: Python
difficulty: intermediate
status: in-progress
entry_point: get_ioc_intel.py
requires:
  Python: 3.10+
  Packages: [requests]
  Packages_optional: []
env:
  - VT_API_KEY        (optional — VirusTotal v3)
  - ABUSEIPDB_API_KEY (optional — AbuseIPDB v2)
  - OTX_API_KEY       (optional — AlienVault OTX)
frameworks:
  mitre_attack:
    tactic: TA0043
    techniques: [T1598]
  nist_800_53: [SI-4, SI-5, IR-4]
inputs:
  - --ioc: single IOC value (auto-detected type)
  - --batch: CSV with a 'value' column (and optional 'type')
  - --providers: comma list (default: all with keys set)
  - --dry-run: return canned data, no HTTP
  - --out: write JSON to file (else stdout)
outputs:
  - JSON object (single) or array (batch) on stdout, or to --out
---

# Get-IOCIntel

Enrich a single IOC or a batch of them against three public threat-intel sources:

- **VirusTotal v3** — multi-AV verdict stats for IPs, domains, URLs, and hashes
- **AbuseIPDB v2** — crowd-reported abuse score for IPv4 addresses
- **AlienVault OTX** — pulse count and reputation for IPs, domains, URLs, and hashes

No key is required. Any provider whose env var is unset gets skipped with a warning; the others still run. Use `--dry-run` to test offline or demo without burning API quota.

## Providers

| Provider | Env var | Supported types |
|---|---|---|
| VirusTotal v3 | `VT_API_KEY` | ipv4, domain, url, md5, sha1, sha256 |
| AbuseIPDB v2 | `ABUSEIPDB_API_KEY` | ipv4 only |
| AlienVault OTX | `OTX_API_KEY` | ipv4, domain, url, md5, sha1, sha256 |

## IOC types

Auto-detected in this order (most-specific first):

1. `sha256` — 64 hex chars
2. `sha1` — 40 hex chars
3. `md5` — 32 hex chars
4. `ipv4` — dotted-quad with valid octets (0–255)
5. `url` — starts with `http://` or `https://`
6. `domain` — everything else that looks like a hostname

## Setup

```bash
pip install requests
```

Set whichever API keys you have:

```bash
export VT_API_KEY="your-virustotal-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
export OTX_API_KEY="your-otx-key"
```

Free-tier accounts work fine for occasional lookups. VT free tier is rate-limited to 4 requests/minute.

## Usage

**Single IOC (type auto-detected):**

```bash
python get_ioc_intel.py --ioc 185.220.101.45
python get_ioc_intel.py --ioc evil-domain.ru
python get_ioc_intel.py --ioc https://phish.example.com/steal
python get_ioc_intel.py --ioc d41d8cd98f00b204e9800998ecf8427e
```

**Specific providers only:**

```bash
python get_ioc_intel.py --ioc 1.2.3.4 --providers vt,abuseipdb
```

**Batch from CSV:**

CSV must have a `value` column. Optionally include a `type` column to skip auto-detection.

```csv
value,type
185.220.101.45,ipv4
evil-domain.ru,domain
d41d8cd98f00b204e9800998ecf8427e,md5
```

```bash
python get_ioc_intel.py --batch iocs.csv
python get_ioc_intel.py --batch iocs.csv --out results.json
```

**Dry-run (no HTTP, canned responses):**

```bash
python get_ioc_intel.py --ioc 1.2.3.4 --dry-run
python get_ioc_intel.py --batch iocs.csv --dry-run --out dry.json
```

**Write output to file (suppresses stdout):**

```bash
python get_ioc_intel.py --ioc 1.2.3.4 --out /tmp/intel.json
```

## Output shape

Single IOC:

```json
{
  "ioc": "185.220.101.45",
  "type": "ipv4",
  "providers": [
    {
      "provider": "virustotal",
      "ioc": "185.220.101.45",
      "type": "ipv4",
      "stats": { "malicious": 12, "suspicious": 0, "harmless": 71, "undetected": 4 },
      "raw_status": 200
    },
    {
      "provider": "abuseipdb",
      "ioc": "185.220.101.45",
      "type": "ipv4",
      "abuseConfidenceScore": 100,
      "totalReports": 847,
      "lastReportedAt": "2024-06-01T10:22:00+00:00",
      "countryCode": "DE",
      "raw_status": 200
    },
    {
      "provider": "otx",
      "ioc": "185.220.101.45",
      "type": "ipv4",
      "pulse_count": 9,
      "reputation": 0,
      "raw_status": 200
    }
  ]
}
```

Batch mode emits a JSON array of these objects.

## Running the tests

```bash
pip install pytest responses
python -m pytest test_get_ioc_intel.py -v
```

Tests stub all HTTP with `responses`, so no real API keys or network access are needed.

## Known gaps

- No response caching — repeated lookups hit the API every time.
- Requests run sequentially; no concurrent enrichment for large batches.
- AbuseIPDB only supports IPv4, not IPv6.
- No URL normalization or domain-resolve for URLs containing bare domains.
- VT URL lookups require the exact URL string; redirected URLs are not followed.
