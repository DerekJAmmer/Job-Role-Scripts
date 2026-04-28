---
role: SysAdmin
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [CM-3]
  cis_windows11: []
  stig: []
---

# Get-PendingReboot

Standalone reboot-status reporter for one or more Windows hosts. Run it before a patching window, after a software deployment, or any time you need to know whether a host is waiting on a reboot before it is safe to hand back to production.

## What it checks

Five registry conditions indicate a pending reboot on Windows:

| # | Condition | Registry location |
|---|-----------|-------------------|
| 1 | Component Based Servicing | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending` |
| 2 | Windows Update | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired` |
| 3 | Pending File Rename Operations | `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager` (value: `PendingFileRenameOperations`) |
| 4 | SCCM Client | `HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData` |
| 5 | Computer Rename | Mismatch between `ActiveComputerName` and `ComputerName` under `HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\` |

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ComputerName` | `string[]` | Local machine | One or more host names to check. |
| `-OutputPath` | `string` | *(none)* | Optional path for a JSON report file. |

## Output

One `PSCustomObject` per host is emitted on the pipeline:

```
ComputerName   : SERVER01
RebootRequired : True
Reasons        : {Windows Update, SCCM Client}
QueriedAt      : 2026-04-27 09:15:32
Status         : OK
```

`Status` is `OK` for hosts that responded or `Unreachable` for hosts that could not be contacted.

## Examples

**Check the local machine:**

```powershell
.\Get-PendingReboot.ps1
Get-PendingReboot
```

**Check several servers and write a JSON report:**

```powershell
Get-PendingReboot -ComputerName SRV01, SRV02, SRV03 -OutputPath C:\Reports\reboot.json
```

## Requirements

- PowerShell 7.2 or later
- For remote checks: WinRM must be enabled on target hosts and the running account must have remote access

## Running tests

```powershell
Invoke-Pester -Path ./Get-PendingReboot.Tests.ps1 -Output Detailed
```
