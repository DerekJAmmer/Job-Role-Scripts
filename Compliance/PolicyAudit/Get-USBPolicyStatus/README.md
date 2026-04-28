---
role: Compliance
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: [T1091, T1052.001]
  nist_800_53: [AC-19, MP-7]
  cis_windows11: [18.9.x]
  stig: []
---

# Get-USBPolicyStatus

Read-only audit of USB removable storage restrictions and recent device history.

## Scope

Checks three registry surfaces that control USB removable storage access on Windows:

| Check | Registry Path | Value |
|-------|--------------|-------|
| Write protection | `HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies` | `WriteProtect` |
| Device installation block | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` | `DenyRemovableDevices` |
| Device class GUID deny-list | `…\DeviceInstall\Restrictions\DenyDeviceClasses` | GUID values |

USB device history is enumerated from `HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR`.
Last-connected timestamps are best-effort — they depend on the Windows build and may be `$null`
on systems that do not write the `{83da6326-…}\0064` property.

**This script never writes to the registry, modifies event logs, or installs devices.**

## Output

| RowType | Columns populated | Status values |
|---------|------------------|---------------|
| `Policy` | `WriteProtect`, `DenyRemovableDevices`, `DenyDeviceClasses`, `Status`, `Reason` | `Restricted` / `Unrestricted` / `Unknown` |
| `Device` | `FriendlyName`, `DeviceId`, `Service`, `LastConnected` | _(empty)_ |

Status definitions:

- **Restricted** — at least one policy control is enforced (write protection, device install block, or GUID deny-list match).
- **Unrestricted** — policy keys are readable and none indicate restriction.
- **Unknown** — unable to read the policy keys (key absent, ACL denied, etc.).

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-MaxDevices` | `int` | `50` | Maximum recent USB devices to enumerate. |
| `-PolicyOnly` | `switch` | off | Suppress device history; emit only the Policy row. |
| `-OutputPath` | `string` | — | Export all rows to a CSV file (UTF-8). |

## Usage

```powershell
# Quick policy check
Get-USBPolicyStatus -PolicyOnly

# Full report with device history
Get-USBPolicyStatus

# Export to CSV
Get-USBPolicyStatus -MaxDevices 20 -OutputPath .\usb-report.csv

# Filter to Restricted status
Get-USBPolicyStatus | Where-Object { $_.RowType -eq 'Policy' -and $_.Status -eq 'Restricted' }
```

## Interpretation

A result of `Unrestricted` means no GPO-enforced controls were found in the audited registry
keys. It does not account for hardware-level controls, third-party endpoint agents, or
BitLocker-to-Go policies. Pair with `Get-BitLockerStatus` for full removable media coverage.

## Test

```powershell
pwsh -NoProfile -Command "Invoke-Pester -Path 'Compliance/PolicyAudit/Get-USBPolicyStatus/Get-USBPolicyStatus.Tests.ps1' -CI"
```

## Lint

```powershell
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path 'Compliance/PolicyAudit/Get-USBPolicyStatus/Get-USBPolicyStatus.ps1' -Settings 'PSScriptAnalyzerSettings.psd1'"
```
