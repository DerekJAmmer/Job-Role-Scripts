---
role: SysAdmin
language: PowerShell
difficulty: easy
frameworks:
  nist_800_53: [SI-12]
---

# Invoke-DiskCleanup

Deletes temporary files and old logs from common Windows locations. Supports
selective targets, a minimum-free-space threshold, and JSON reporting.

## Safety first

**This script will not delete anything unless you explicitly confirm it.**

The function uses PowerShell's `ShouldProcess` mechanism with a `ConfirmImpact`
of `High`. That means:

- Without any flags, PowerShell prompts you before each deletion.
- With `-WhatIf`, nothing is deleted. The script shows you what it *would*
  remove.
- With `-Confirm:$false`, all prompts are suppressed and files are deleted
  immediately. Use this for scheduled tasks or automation.

Always test with `-WhatIf` before running unattended.

## Requirements

- PowerShell 7.2 or later
- Run as Administrator for full access to system temp and log directories

## Parameters

| Parameter      | Type       | Default                                         | Description |
|----------------|------------|--------------------------------------------------|-------------|
| `-Targets`     | `string[]` | `UserTemp,WindowsTemp,IISLogs,OldLogs`          | Which categories to clean |
| `-OldLogDays`  | `int`      | `30`                                            | Age threshold for `OldLogs` target |
| `-MinFreeGB`   | `int`      | `0` (always run)                                | Skip cleanup if C: has at least this many GB free |
| `-OutputPath`  | `string`   | (none)                                          | Write JSON report to this path |

### Targets

| Name          | What it cleans |
|---------------|----------------|
| `UserTemp`    | `$env:TEMP` (current user) + all user profiles' `AppData\Local\Temp` |
| `WindowsTemp` | `C:\Windows\Temp` |
| `IISLogs`     | `C:\inetpub\logs\LogFiles\**\*.log` older than 7 days. Silently skipped if IIS is not installed. |
| `OldLogs`     | `C:\Windows\Logs`, `C:\Windows\Logs\CBS`, and `C:\ProgramData\Microsoft\Windows\WER` — files older than `-OldLogDays` days |

## Examples

```powershell
# Preview what would be deleted — nothing is removed
Invoke-DiskCleanup -WhatIf

# Run all targets, prompt before each file
Invoke-DiskCleanup

# Run without prompts (for scheduled tasks)
Invoke-DiskCleanup -Confirm:$false

# Clean only temp dirs, write a report
Invoke-DiskCleanup -Targets UserTemp,WindowsTemp -Confirm:$false -OutputPath C:\Logs\cleanup.json

# Only run if C: has less than 10 GB free
Invoke-DiskCleanup -MinFreeGB 10 -Confirm:$false

# Keep older log threshold at 90 days
Invoke-DiskCleanup -Targets OldLogs -OldLogDays 90 -Confirm:$false
```

## Output

The function always emits a report object to the pipeline. Use `-OutputPath`
to also write it as JSON.

```json
{
  "Host": "SERVER01",
  "Started": "2026-04-27T10:00:00",
  "Finished": "2026-04-27T10:00:05",
  "Targets": [
    {
      "Name": "WindowsTemp",
      "Files": ["C:\\Windows\\Temp\\abc.tmp"],
      "BytesReclaimed": 4096,
      "Skipped": ""
    }
  ],
  "TotalReclaimedMB": 0.004
}
```

When `MinFreeGB` is set and the drive is above the threshold, each target
entry will have `Skipped: "AboveThreshold"` and no files will be touched.

## Running tests

```powershell
Invoke-Pester -Path .\Invoke-DiskCleanup.Tests.ps1 -Output Detailed
```

## NIST mapping

See [docs/control-mapping.md](docs/control-mapping.md) for the SI-12 rationale.
