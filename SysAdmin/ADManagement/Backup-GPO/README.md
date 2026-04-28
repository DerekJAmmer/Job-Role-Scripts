---
role: SysAdmin
language: PowerShell
difficulty: medium
frameworks:
  mitre_attack: []
  nist_800_53: [CM-2]
  cis_windows11: []
  stig: []
---

# Backup-GPO

## Overview

`Backup-GPO` exports every Group Policy Object in the domain to a timestamped subfolder (`yyyy-MM-dd_HHmm`) under `-BackupRoot`. For each GPO it calls the GroupPolicy module to write a native backup archive and then produces an XML report and an HTML report. Optionally it compares the new XML reports against the previous backup folder to classify each GPO as Unchanged, Changed, Added, or Removed. **Active Directory is never modified**; the only write operations go to the local file system under `-BackupRoot`.

> **Note on naming.** The user-facing function is named `Backup-GPO` (matching the PORTFOLIO_PLAN entry). To avoid recursion when calling the underlying `GroupPolicy\Backup-GPO` cmdlet, the script uses private helper functions (`Invoke-PBGBackupGPO`, `Invoke-PBGGetGPO`, `Invoke-PBGGetGPOReport`). These helpers are also the mock surface used by Pester tests, so the GroupPolicy module does not need to be installed at test time.

---

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-BackupRoot` | `string` | Yes | Parent directory. Created automatically if it does not exist. A dated subfolder (`yyyy-MM-dd_HHmm`) is created inside it on each run. |
| `-CompareToPrevious` | `switch` | No | Diff the new backup's XML reports against the most recent prior timestamped folder under `-BackupRoot`. |
| `-OutputPath` | `string` | No | Path to write a JSON summary file. See schema below. |
| `-WhatIf` | `switch` | No | Preview mode — no folders or files are created, no backup cmdlets are called. |

---

## Output Schema

### Pipeline output

Each GPO produces one `PSCustomObject` row:

| Field | Type | Values |
|---|---|---|
| `DisplayName` | string | GPO display name |
| `Id` | Guid | GPO identifier |
| `Status` | string | `Success`, `Failed`, `WhatIf` |
| `Reason` | string | Error message on failure; empty on success |

### JSON summary (`-OutputPath`)

```json
{
  "BackupFolder":   "<full path to the timestamped subfolder>",
  "Timestamp":      "<ISO 8601 timestamp of the run>",
  "BackupResults":  [ ...per-GPO rows as above... ],
  "Comparison":     [ ...comparison rows (see below), or null... ],
  "CompareSkipped": true | false
}
```

### Comparison rows

| Field | Type | Description |
|---|---|---|
| `DisplayName` | string | GPO name (derived from XML file name) |
| `Status` | string | See table below |

---

## Comparison Statuses

| Status | Meaning |
|---|---|
| `Unchanged` | GPO XML hash matches the prior backup exactly |
| `Changed` | GPO XML hash differs from the prior backup |
| `Added` | GPO present in current backup but absent from prior backup |
| `Removed` | GPO present in prior backup but absent from current backup |

`CompareSkipped = true` is set when `-CompareToPrevious` is requested but no prior timestamped folder exists under `-BackupRoot` (e.g., first run). No error is raised.

---

## Examples

```powershell
# Preview without writing anything.
Backup-GPO -BackupRoot C:\GPOBackups -WhatIf

# Full backup with JSON summary.
Backup-GPO -BackupRoot C:\GPOBackups -OutputPath C:\GPOBackups\latest-summary.json

# Backup and compare against the previous run.
Backup-GPO -BackupRoot C:\GPOBackups -CompareToPrevious -OutputPath C:\GPOBackups\latest-summary.json
```

---

## Prerequisites

- PowerShell 7.2+
- RSAT Group Policy Management Tools (`Get-WindowsCapability -Name Rsat.GroupPolicy*` / `Add-WindowsCapability`)
- Domain connectivity and read access to Group Policy Objects

The script loads without the GroupPolicy module installed (stubs gate the helpers); all live operations require the module.
