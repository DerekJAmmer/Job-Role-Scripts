---
role: Compliance
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [AU-2, AU-12]
  cis_windows11: [18.9.100]
  stig: []
---

# Get-LoggingCoverage

Reports local logging-stack coverage across five controls and emits a percent rollup.
The script is **local-only** and **read-only** — it never modifies any setting.

---

## Overview

`Get-LoggingCoverage` audits the five logging controls most relevant to NIST AU-2 / AU-12
and CIS Windows 11 benchmark section 18.9.100:

| # | Control | Source |
|---|---------|--------|
| 1 | PowerShell ScriptBlock Logging | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` — value `EnableScriptBlockLogging` |
| 2 | PowerShell Module Logging | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` — value `EnableModuleLogging`; also checks `ModuleNames` subkey |
| 3 | PowerShell Transcription (toggle) | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` — value `EnableTranscripting` |
| 3 | PowerShell Transcription (directory) | Same key — value `OutputDirectory` |
| 4 | Sysmon | Windows service `Sysmon*` presence and run state |
| 5 | WEF — Wecsvc service | Windows service `Wecsvc` run state |
| 5 | WEF — Subscription count | `wecutil es` output line count |

After all checks a special `__OverallScore` row is appended with the enabled fraction
expressed as an integer percentage.

---

## Parameters

| Parameter     | Type   | Required | Description |
|---------------|--------|----------|-------------|
| `-OutputPath` | string | No       | When supplied, all rows (including rollup) are exported as a UTF-8 CSV. |

---

## Output schema

Each row is a `PSCustomObject` with four properties:

| Property  | Type   | Description |
|-----------|--------|-------------|
| `Control` | string | Human-readable control name, or `__OverallScore` for the rollup. |
| `Setting` | string | Registry value name, service name, or sub-check label. |
| `Value`   | object | Raw value read (integer, path, service status, count), `NotSet`, or `NotInstalled`. |
| `Status`  | string | `Enabled`, `Disabled`, `Missing`, or `Unknown`. For the rollup row: integer percentage (e.g. `71%`). |

### Status semantics

| Status     | Meaning |
|------------|---------|
| `Enabled`  | Control is configured and active. |
| `Disabled` | Control is present but explicitly off or the service is stopped. |
| `Missing`  | Registry key/value absent, or service not installed. |
| `Unknown`  | Check could not complete (e.g. wecutil access denied). |

### Rollup row

The final row always has `Control = '__OverallScore'`:

```
Control          : __OverallScore
Setting          :
Value            : 5 / 7
Status           : 71%
```

Filter it out with `Where-Object { $_.Control -ne '__OverallScore' }`.

---

## Examples

```powershell
# Emit all logging-coverage rows to the pipeline.
Get-LoggingCoverage

# Show only controls that are not fully enabled.
Get-LoggingCoverage | Where-Object { $_.Status -ne 'Enabled' -and $_.Control -ne '__OverallScore' }

# Export results to CSV.
Get-LoggingCoverage -OutputPath .\logging-report.csv

# Display just the overall score.
Get-LoggingCoverage | Where-Object { $_.Control -eq '__OverallScore' }
```

---

## Notes

- **Local-only by design.** For fleet rollups invoke via `Invoke-Command` from an orchestration tool.
- The private helper `Get-GLCRegistryValue` wraps registry reads and returns `$null` on missing keys or values — no exceptions propagate from absent GPO paths.
- The private helper `Get-GLCService` wraps `Get-Service` and returns `$null` when a service is not installed.
- `Invoke-GLCWecutil` wraps `wecutil.exe es`; if it throws (e.g. access denied), the WEF Subscriptions row is emitted with `Status = 'Unknown'` and a warning is written.
- Module Logging bonus check: if `EnableModuleLogging = 1` but the `ModuleNames` subkey is empty, `Value` is set to `'Configured but ModuleNames empty'` (Status remains `Enabled`).
