---
role: Compliance
language: Python
difficulty: medium
frameworks:
  mitre_attack: []
  nist_800_53: []
  nist_800_171: ["3.1","3.2","3.3","3.4","3.5","3.6","3.7","3.8","3.9","3.10","3.11","3.12","3.13","3.14"]
  cis_windows11: []
  stig: []
---

# Test-NIST80017Mapping

Map CIS Benchmark and DISA STIG findings to NIST SP 800-171 r2 controls and
produce a per-family coverage report in Markdown and/or HTML.

## Overview

Security assessors running `Test-CISBenchmark` and `Test-STIGCompliance`
produce per-control pass/fail results. This script consumes those JSON outputs,
joins each finding to one or more NIST 800-171 r2 controls via a configurable
mapping file, and aggregates results by the 14 NIST 800-171 families (3.1–3.14).
The output shows which families are well-covered, which have gaps, and which
controls require manual review.

## Usage

```powershell
# CIS only, write Markdown to stdout
python nist80017_mapping.py --cis cis-findings.json

# STIG only, write Markdown to a file
python nist80017_mapping.py --stig stig-findings.json --output report.md

# Both sources, Markdown + HTML
python nist80017_mapping.py --cis cis-findings.json --stig stig-findings.json `
    --output report.md --html report.html

# Preview without writing any files
python nist80017_mapping.py --cis cis-findings.json --dry-run

# Override the default mapping files
python nist80017_mapping.py --cis cis.json `
    --cis-map path/to/custom-cis-map.json `
    --stig-map path/to/custom-stig-map.json `
    --output report.md
```

### Generating findings files from PowerShell

```powershell
# CIS
Test-CISBenchmark -BenchmarkPath cis-win11-subset.json |
    ConvertTo-Json -Depth 5 |
    Set-Content cis-findings.json

# STIG
Test-STIGCompliance -BenchmarkPath stig-win11-subset.json |
    ConvertTo-Json -Depth 5 |
    Set-Content stig-findings.json
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--cis FILE` | One of --cis/--stig | CIS findings JSON |
| `--stig FILE` | One of --cis/--stig | STIG findings JSON |
| `--output FILE` | No | Markdown output path (default: stdout) |
| `--html FILE` | No | HTML output path |
| `--dry-run` | No | Preview only; write nothing |
| `--cis-map FILE` | No | Override CIS→800-171 mapping |
| `--stig-map FILE` | No | Override STIG→800-171 mapping |

## Mapping data

The bundled JSON maps live in `mapping/`:

- `cis_to_800171.json` — maps CIS control IDs (e.g. `"1.1.1"`) to lists of
  NIST 800-171 r2 control IDs (e.g. `["3.5.7"]`).
- `stig_to_800171.json` — maps STIG VulnIDs (e.g. `"V-253256"`) to lists of
  NIST 800-171 r2 control IDs.

> **Important:** These maps are shipped as a starting point — reviewers should
> adjust the JSON maps for their authorization boundary. The shipped entries
> correspond to the demonstration subset used in `Test-CISBenchmark` and
> `Test-STIGCompliance`. A production deployment should be reviewed against
> NIST SP 800-171A and the applicable CIS/STIG content for the environment.

CIS control IDs not present in the mapping file are excluded from family counts
and listed as warnings on stderr.

## Output formats

### Markdown (default)

A human-readable report with a summary table and per-family detail tables.
Suitable for committing to a wiki or viewing in any Markdown renderer.

### HTML (`--html`)

A single self-contained HTML file with inline CSS. No external dependencies.
All user-supplied content is HTML-escaped to prevent injection in audit reports
that contain unusual characters in finding titles.

### Dry-run

Prints what would be written and a one-line summary of finding counts. Nothing
is written to disk.

## Status mapping

| Source status | Counted as |
|---|---|
| CIS `Compliant` | Compliant |
| CIS `NonCompliant` | NonCompliant |
| CIS `Manual` | Manual |
| STIG `NotAFinding` | Compliant |
| STIG `Open` | NonCompliant |
| STIG `Manual` | Manual |
| STIG `NotApplicable` | Excluded |
| STIG `Error` | Excluded |

`NotApplicable` and `Error` statuses are excluded because they do not represent
an actual determination of compliance state. This is noted in the output
warnings when such statuses are encountered.

## Limitations

- The mapping files cover only the demonstration subset of CIS and STIG controls
  included in this portfolio. Full production mappings must be authored manually
  or sourced from the organisation's GRC tooling.
- `% Compliant` is computed as `Compliant / (Compliant + NonCompliant)` — Manual
  findings are excluded from the denominator.
- A single finding may map to multiple 800-171 controls (and thus contribute
  counts to multiple family cells). This is by design — one finding can satisfy
  or fail multiple controls.
- The script does not perform any automated control testing; it only consumes
  results produced by `Test-CISBenchmark` and `Test-STIGCompliance`.

## Running tests

```powershell
cd Compliance/Reporting/Test-NIST80017Mapping
python -m pytest test_nist80017_mapping.py -v
```
