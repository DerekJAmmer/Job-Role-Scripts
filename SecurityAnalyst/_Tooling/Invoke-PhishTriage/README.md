---
name: Invoke-PhishTriage
role: SecurityAnalyst
tactic_folder: _Tooling
language: Python
difficulty: intermediate
status: in-progress
entry_point: phish_triage.py
requires:
  Python: 3.10+
  Packages: []
  Packages_optional: []
frameworks:
  mitre_attack:
    tactic: TA0001
    techniques: [T1566, T1566.001, T1566.002]
  nist_800_53: [SI-3, SI-4, IR-4]
inputs:
  - <path-to-eml>: positional
  - --out: write JSON report to file (else stdout)
outputs:
  - JSON dict (headers, auth_results, urls, attachments, flags, summary)
---

# Invoke-PhishTriage

A Python CLI for triaging suspicious `.eml` email files. It parses message headers, extracts and defangs URLs, hashes attachments, evaluates SPF/DKIM/DMARC authentication results, and flags common phishing signals — all using Python stdlib only.

Designed to feed into SOC workflows: the JSON output pairs naturally with `Get-IOCIntel` for IOC enrichment of flagged URLs and attachment hashes.

## What it checks

| Check | Description |
|---|---|
| From / Return-Path domain mismatch | Sender domain spoofing indicator |
| From / Reply-To domain mismatch | Reply-hijacking indicator |
| SPF verdict | `fail` or `softfail` flags `spf_fail` |
| DKIM verdict | `fail` flags `dkim_fail` |
| DMARC verdict | `fail`, `reject`, or `quarantine` flags `dmarc_fail` |
| URL shorteners | `bit.ly`, `tinyurl.com`, `t.co`, and 7 others |
| Executable attachments | `.exe`, `.docm`, `.xlsm`, `.ps1`, `.iso`, and 12 others |
| Received chain | Hop count and first received timestamp |

## Red flags

Each flagged condition appends a string to the `flags` list:

- `from_returnpath_mismatch` — From and Return-Path domains differ
- `from_replyto_mismatch` — From and Reply-To domains differ
- `spf_fail` — SPF verdict is `fail` or `softfail`
- `dkim_fail` — DKIM verdict is `fail`
- `dmarc_fail` — DMARC verdict is `fail`, `reject`, or `quarantine`
- `url_shortener:<host>` — URL from a known shortener service
- `executable_attachment:<filename>` — attachment with a dangerous extension

## Usage

```bash
# Print JSON report to stdout
python phish_triage.py suspicious.eml

# Write JSON report to file, print summary line to stdout
python phish_triage.py suspicious.eml --out report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | File not found |
| 3 | Parse error |

## Output shape

```json
{
  "source": "suspicious.eml",
  "headers": {
    "from": "Bank Support <support@bank.com>",
    "from_domain": "bank.com",
    "return_path": "<evil@attacker.tld>",
    "return_path_domain": "attacker.tld",
    "reply_to": "support@another-domain.tld",
    "reply_to_domain": "another-domain.tld",
    "subject": "Urgent: Your account has been compromised",
    "received_chain_hops": 2,
    "first_received_at": "from localhost..."
  },
  "auth_results": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail",
    "raw": "mx.yourcompany.com; spf=fail ..."
  },
  "urls": [
    {
      "url": "https://bit.ly/x9k2",
      "defanged": "hxxps://bit[.]ly/x9k2",
      "is_shortener": true,
      "host": "bit.ly"
    }
  ],
  "attachments": [
    {
      "filename": "invoice.docm",
      "content_type": "application/vnd.ms-word.document.macroEnabled.12",
      "size": 18,
      "sha256": "abc123..."
    }
  ],
  "flags": [
    "from_returnpath_mismatch",
    "from_replyto_mismatch",
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "url_shortener:bit.ly",
    "executable_attachment:invoice.docm"
  ],
  "summary": "7 flag(s): from_returnpath_mismatch, from_replyto_mismatch, spf_fail, dkim_fail, dmarc_fail..."
}
```

## Running tests

```bash
cd SecurityAnalyst/_Tooling/Invoke-PhishTriage
python -m pytest test_phish_triage.py -v
```

Lint:

```bash
ruff check .
```

## Known gaps

- `.msg` (Outlook binary format) is not supported — use `extract-msg` separately if needed.
- HTML rendering is not performed; URL extraction uses regex over raw HTML text.
- URL redirects are not followed — shortener destinations are unknown without a live HTTP request.
- Authentication-Results parsing assumes the RFC 8601 `key=value` format; non-standard headers may produce `unknown` verdicts.
- Only the first `Authentication-Results` header is evaluated; messages with multiple instances (e.g. after re-delivery) may miss inner results.
