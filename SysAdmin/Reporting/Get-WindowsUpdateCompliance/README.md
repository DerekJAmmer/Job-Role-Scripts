---
role: SysAdmin
language: PowerShell
difficulty: medium
frameworks:
  mitre_attack: []
  nist_800_53: [SI-2]
  cis_windows11: []
  stig: []
---

# Get-WindowsUpdateCompliance

Reports per-host Windows Update compliance: last install date, missing update count, reboot-required state, and days since last update.

## Overview

`Get-WindowsUpdateCompliance` queries one or more Windows hosts via the **Microsoft.Update.Session COM object** (primary) or a **registry fallback** when COM is unavailable. The function emits a structured PSCustomObject per host suitable for pipeline consumption, CSV export, and JSON reporting.

Designed for SysAdmins who need a quick, read-only snapshot of patch currency across a fleet — without requiring WSUS, Intune, or Windows Update for Business integration.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ComputerName` | `string[]` | `$env:COMPUTERNAME` | Target host names. FQDNs whose leftmost label matches the local machine name are treated as local. |
| `StaleDays` | `int` | `30` | Days after which a host is considered stale. Staleness is `DaysSinceLastUpdate > StaleDays` (strictly greater than). |
| `OutputPath` | `string` | _(none)_ | Optional CSV output path. A JSON sidecar is also written at the same path with `.json` extension. |

## Output Schema

| Field | Type | Notes |
|-------|------|-------|
| `ComputerName` | `string` | Target host |
| `LastInstalledDate` | `datetime` / `$null` | Date of last successful Windows Update install |
| `DaysSinceLastUpdate` | `int` / `$null` | Integer days since `LastInstalledDate`; `$null` when date is unknown |
| `MissingUpdateCount` | `int` / `'Unknown'` / `$null` | Integer when COM is available; `'Unknown'` in registry fallback; `$null` for unreachable hosts |
| `RebootRequired` | `bool` / `$null` | `$true`/`$false` if `Get-PendingReboot` is in scope; `$null` otherwise |
| `Source` | `string` | `COM`, `Registry`, or `Unreachable` |
| `IsStale` | `bool` / `$null` | `$true` when `DaysSinceLastUpdate > StaleDays`; `$null` when date is unknown |

## Sources

| Source | When Used | MissingUpdateCount | LastInstalledDate |
|--------|-----------|-------------------|-------------------|
| `COM` | `Microsoft.Update.Session` COM object is available | Integer count of pending updates | Read from registry helper |
| `Registry` | COM unavailable or blocked | `'Unknown'` | Read from `HKLM:\...\WindowsUpdate\Auto Update\Results\Install\LastSuccessTime` |
| `Unreachable` | Host does not respond to `Test-Connection` or `Invoke-Command` fails | `$null` | `$null` |

## Examples

```powershell
# Check local machine
Get-WindowsUpdateCompliance

# Check two servers with 14-day threshold, export CSV + JSON
Get-WindowsUpdateCompliance -ComputerName SRV01,SRV02 -StaleDays 14 -OutputPath C:\Reports\wu.csv

# Find all stale hosts
Get-WindowsUpdateCompliance -ComputerName (Get-ADComputer -Filter *).Name |
    Where-Object { $_.IsStale -eq $true }
```

## RebootRequired Integration

At runtime the function calls `Get-Command Get-PendingReboot -ErrorAction SilentlyContinue`. If found in the current session, it invokes `Get-PendingReboot` for the local host and populates `RebootRequired`. For remote hosts `RebootRequired` is always `$null` (the field is not populated via `Invoke-Command`). If `Get-PendingReboot` is not available, `RebootRequired` is `$null` for all hosts.

To enable: dot-source or import `Get-PendingReboot.ps1` before running this function.

## Limitations

- **WSUS / Intune / WUfB integration is out of scope.** This function delivers local-state visibility only, using the Windows Update Agent COM API and the registry. It does not query WSUS server-side approval data, Intune compliance policies, or Windows Update for Business ring assignments.
- Remote collection runs over WinRM via `Invoke-Command`. Hosts must have PSRemoting enabled and accessible.
- COM availability depends on the Windows Update Agent service (`wuauserv`) running on the target. In hardened or non-standard environments the COM path may be blocked.
- `MissingUpdateCount` in registry fallback is always `'Unknown'` — there is no pure registry path to enumerate pending updates.
