---
role: Compliance
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [SC-28, SC-12]
  cis_windows11: [18.9.11.x]
  stig: []
---

# Get-BitLockerStatus

Report per-volume BitLocker posture for one or more Windows computers.

## Summary

Collects BitLocker volume data (`Get-BitLockerVolume`), TPM state (`Get-Tpm`), and Secure Boot
state (`Confirm-SecureBootUEFI`) and classifies each fixed volume as **Compliant**,
**NonCompliant**, or **Unknown**.

## Scope

- **Read-only** — never calls `Enable-BitLocker`, `Initialize-Tpm`, or any other state-changing
  cmdlet.
- **No baseline file** — compliance rules are intrinsic (fully encrypted + TPM ready + Secure Boot
  on). There is no samples folder because there is nothing to baseline against; the policy is
  self-defining.
- **Graceful degradation** — TPM and Secure Boot helpers handle non-UEFI machines and older
  clients that lack the relevant cmdlets; affected fields are reported as `$null` rather than
  causing a failure.
- **Fixed volumes only** — `OperatingSystem` and `Data` volume types are evaluated.
  `Removable` and `Network` volumes are excluded.

## Parameters

| Parameter      | Type       | Default | Description                                          |
|----------------|------------|---------|------------------------------------------------------|
| `ComputerName` | `string[]` | `@('.')` | Target host names. Use `.` or `localhost` for local. |
| `OutputPath`   | `string`   | —       | Optional CSV export path (UTF-8).                    |

## Compliance logic

A volume is **Compliant** when **all** of the following are true:

| Check                    | Condition                  |
|--------------------------|----------------------------|
| `ProtectionStatus`       | `On`                       |
| `EncryptionPercentage`   | `100`                      |
| `TpmPresent`             | `$true`                    |
| `TpmReady`               | `$true`                    |
| `SecureBootEnabled`      | `$true`                    |

Any failing check is listed in the `Reasons` field. When `Get-BitLockerVolume` is unavailable
(module not installed) the row has `Status=Unknown` and `Reasons='Get-BitLockerVolume not available'`.

## Output columns

| Column                | Description                                               |
|-----------------------|-----------------------------------------------------------|
| `ComputerName`        | Target host                                               |
| `MountPoint`          | Drive letter / volume path (empty for Unknown rows)       |
| `ProtectionStatus`    | `On` or `Off`                                             |
| `EncryptionPercentage`| 0–100                                                     |
| `EncryptionMethod`    | Algorithm (e.g. `XtsAes256`)                              |
| `VolumeStatus`        | `FullyEncrypted`, `EncryptionInProgress`, etc.            |
| `KeyProtectorTypes`   | Semicolon-joined protector types                          |
| `TpmPresent`          | `$true`/`$false`/`$null`                                  |
| `TpmReady`            | `$true`/`$false`/`$null`                                  |
| `SecureBootEnabled`   | `$true`/`$false`/`$null` (`$null` on non-UEFI)           |
| `Status`              | `Compliant` / `NonCompliant` / `Unknown`                  |
| `Reasons`             | Semicolon-joined failure reasons, or empty                |

## Usage

```powershell
# Local machine
Get-BitLockerStatus

# Remote hosts
Get-BitLockerStatus -ComputerName SRV01, WK02

# Export to CSV
Get-BitLockerStatus -ComputerName SRV01, WK02 -OutputPath .\bitlocker-report.csv
```

## Remote execution

Remote hosts are queried via `Invoke-Command` (WS-Man / PowerShell remoting). Ensure the target
has PSRemoting enabled (`Enable-PSRemoting`). FQDN-aware local detection means a name like
`WK01.corp.local` is treated as local when the script runs on `WK01`.

## Testing

```powershell
pwsh -NoProfile -Command "Invoke-Pester -Path 'Compliance/Inventory/Get-BitLockerStatus/Get-BitLockerStatus.Tests.ps1' -CI"
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path 'Compliance/Inventory/Get-BitLockerStatus/Get-BitLockerStatus.ps1' -Settings 'PSScriptAnalyzerSettings.psd1'"
```

## Framework references

See [`docs/control-mapping.md`](docs/control-mapping.md) for the full control mapping table.
