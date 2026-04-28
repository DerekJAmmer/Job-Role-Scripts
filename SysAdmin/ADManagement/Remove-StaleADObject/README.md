---
role: SysAdmin
language: PowerShell
difficulty: medium
frameworks:
  mitre_attack: []
  nist_800_53: [AC-2]
  cis_windows11: []
  stig: []
---

# Remove-StaleADObject

Finds stale Active Directory users and/or computers — accounts with no logon activity for a configurable number of days — and quarantines them by disabling the account and moving it to a designated OU. **Nothing is ever deleted.** The only destructive actions are Disable + Move.

## Safety

> **This script disables real accounts. Always run with `-WhatIf` first.**

```powershell
# Preview — no changes made to AD, QuarantineOU is not required
Remove-StaleADObject -WhatIf
```

When `-WhatIf` is active the script scans AD, builds the full result report with `Action = 'WhatIf'`, and emits it to the pipeline — but never calls `Disable-ADAccount` or `Move-ADObject`. Review the output, confirm the scope, and only then run without `-WhatIf`.

`-QuarantineOU` is required when making real changes. The script will throw if it is omitted and `-WhatIf` is not in effect.

## Requirements

- PowerShell 7.2+
- ActiveDirectory module (RSAT) installed and imported
- Sufficient AD privileges to disable accounts and move objects between OUs

## Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-Mode` | string | No | `Both` | Object types to scan: `User`, `Computer`, or `Both` |
| `-StaleDays` | int | No | `90` | Days since last logon before an object is stale (30–730) |
| `-QuarantineOU` | string | Yes* | — | Distinguished name of the destination OU. *Required unless `-WhatIf` is used. |
| `-IncludeDisabled` | switch | No | `False` | Process already-disabled objects instead of skipping them |
| `-OutputPath` | string | No | — | Optional path to write the result report as a UTF-8 CSV |

## Status / Action values

| Action | Meaning |
|---|---|
| `Disable+Move` | Account was successfully disabled and moved to the quarantine OU |
| `Skipped:AlreadyDisabled` | Account was already disabled; skipped (override with `-IncludeDisabled`) |
| `WhatIf` | `-WhatIf` was active; no changes made |
| `Failed` | An error occurred during Disable or Move; see the `Reason` column |

## Failure modes

### Disable succeeds but Move fails

If `Disable-ADAccount` succeeds and `Move-ADObject` then throws, the row `Action` is set to `Failed` and the error is captured in `Reason`. The account is now **disabled in its original OU** — it did not reach the quarantine OU. On the next run with `-IncludeDisabled`, the script will attempt to move it again.

To recover manually:

```powershell
Move-ADObject -Identity 'CN=user,OU=Staff,DC=corp,DC=local' -TargetPath 'OU=Quarantine,DC=corp,DC=local'
```

### Get-ADUser / Get-ADComputer throws

If the initial AD query fails the exception is re-thrown immediately. No partial results are emitted. Investigate connectivity, module availability, and AD permissions.

## Usage examples

```powershell
# WhatIf first — always
Remove-StaleADObject -WhatIf

# WhatIf scoped to users, custom staleness window
Remove-StaleADObject -Mode User -StaleDays 60 -WhatIf

# Real run — users and computers, default 90-day threshold
Remove-StaleADObject -QuarantineOU 'OU=Quarantine,DC=corp,DC=local'

# Real run — users only, write CSV report
Remove-StaleADObject -Mode User -StaleDays 60 `
    -QuarantineOU 'OU=Quarantine,DC=corp,DC=local' `
    -OutputPath .\stale-users-report.csv

# Include accounts that are already disabled (e.g. prior partial run)
Remove-StaleADObject -QuarantineOU 'OU=Quarantine,DC=corp,DC=local' -IncludeDisabled
```

## Per-object logic

1. Build cutoff date: `(Get-Date).AddDays(-StaleDays)`.
2. Query all users/computers and filter client-side to those with `LastLogonDate < cutoff`.
3. For each candidate:
   - Skip with `Action = Skipped:AlreadyDisabled` if already disabled (unless `-IncludeDisabled` is set).
   - Gate on `ShouldProcess`; if `-WhatIf`, record `Action = WhatIf` and continue.
   - Call `Disable-ADAccount`, then `Move-ADObject`. On any error, set `Action = Failed` and record the exception message; continue to the next object.
4. Emit each row to the pipeline.
5. If `-OutputPath` is set, write all rows to a CSV.

## Output report columns

| Column | Description |
|---|---|
| `ObjectType` | `User` or `Computer` |
| `SamAccountName` | AD account name |
| `DistinguishedName` | Full DN at time of processing |
| `LastLogonDate` | Last logon timestamp from AD |
| `OriginalOU` | Parent OU extracted from the DN |
| `Action` | One of: `Disable+Move`, `Skipped:AlreadyDisabled`, `WhatIf`, `Failed` |
| `Reason` | Error message (Failed rows) or skip reason |

## Framework mapping

See `docs/control-mapping.md` for NIST 800-53 AC-2 rationale.
