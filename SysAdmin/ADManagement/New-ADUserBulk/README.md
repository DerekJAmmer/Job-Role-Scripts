---
role: SysAdmin
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [AC-2, IA-4]
  cis_windows11: []
  stig: []
---

# New-ADUserBulk

Bulk-create Active Directory users from a CSV file.

## WARNING — live directory

This script writes to Active Directory. A mistake can create hundreds of accounts instantly. **Always run with `-WhatIf` first** to confirm the intended accounts before making any real changes.

```powershell
New-ADUserBulk -CsvPath .\users.csv -WhatIf
```

## Requirements

- PowerShell 7.2+
- ActiveDirectory module (RSAT) installed and imported on the machine running the script
- Sufficient AD privileges to create users and modify group membership

## Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-CsvPath` | string | Yes | — | Path to the input CSV file |
| `-DefaultOU` | string | No | `''` | Fallback OU DN when a row has no OU value |
| `-PasswordLength` | int | No | 16 | Length of generated passwords (min 8) |
| `-OutputPath` | string | No | — | Path to write the result report as CSV |
| `-IncludePlainTextPasswords` | switch | No | `False` | Keep plain-text passwords in the exported CSV. Off by default — redacted unless this is set. |

## CSV schema

Required columns: `SamAccountName`, `UserPrincipalName`.
Optional columns: `GivenName`, `Surname`, `OU`, `Groups`, `Department`, `Title`.

Groups is semicolon-delimited. OU must be a full distinguished name.

Example row:

```
GivenName,Surname,SamAccountName,UserPrincipalName,OU,Groups,Department,Title
Alice,Smith,asmith,asmith@corp.local,"OU=Staff,DC=corp,DC=local",HelpDesk;VPN-Users,IT,Support Analyst
```

See `samples/users-example.csv` for a three-row example.

## Security

### Password redaction (default behaviour)

By default, initial passwords are **redacted from the CSV report** — the `InitialPassword` column is blanked before the file is written. Objects emitted to the pipeline always carry the plain-text password in memory, so callers that process the pipeline directly are unaffected.

A warning is emitted when redaction occurs:

> Plain-text initial passwords were redacted from the CSV report. Re-run with -IncludePlainTextPasswords to include them, and protect the file accordingly.

### Opt-in: `-IncludePlainTextPasswords`

Passing `-IncludePlainTextPasswords` re-enables plain-text passwords in the CSV. When this switch is used:

- The `InitialPassword` column is written to the CSV in clear text.
- A warning is emitted naming the output path.
- **ACL hardening is applied automatically** — inheritance is disabled, all inherited ACEs are removed, and a single FullControl rule is added for the current user's Windows identity. This is best-effort: on non-NTFS volumes or paths where the caller lacks ACL write permission, hardening will fail with a warning but the CSV is still written.

### Operational guidance

Even with ACL hardening in place, treat the output CSV as a credential file:

- Deliver each initial password to the user through a secure channel (encrypted email, secure password portal, or similar).
- Store the report using `SecretManagement` or encrypt it at rest if it must be retained.
- Delete the report promptly once passwords have been distributed.
- Never commit the report to source control.

## Output report columns

| Column | Values |
|---|---|
| SamAccountName | Account name |
| UPN | User principal name |
| OU | Distinguished name used |
| Status | `Created`, `Skipped`, `Failed`, `WhatIf`, `Partial` (created but ≥1 group-add failed) |
| InitialPassword | Plain-text password (Created/Partial rows only; blank in CSV unless `-IncludePlainTextPasswords` is set) |
| Reason | Error or skip reason where applicable |

## Usage examples

```powershell
# Preview — no changes made to AD
New-ADUserBulk -CsvPath .\users.csv -WhatIf

# Create users, fall back to a default OU for rows with no OU
New-ADUserBulk -CsvPath .\users.csv -DefaultOU 'OU=NewHires,DC=corp,DC=local'

# Create users and save the result report (passwords redacted in the CSV)
New-ADUserBulk -CsvPath .\users.csv -OutputPath .\onboarding-report.csv

# Include plain-text passwords in the CSV and apply ACL hardening
New-ADUserBulk -CsvPath .\users.csv -OutputPath .\onboarding-report.csv -IncludePlainTextPasswords

# Longer passwords
New-ADUserBulk -CsvPath .\users.csv -PasswordLength 24 -OutputPath .\report.csv
```

## Per-row logic

1. Skip the row with `Status=Failed` if no OU is available (no row OU and no `-DefaultOU`).
2. Skip the row with `Status=Skipped` if the `SamAccountName` already exists in AD.
3. Generate a random password (upper + lower + digit + symbol, shuffled).
4. Create the user with `New-ADUser`.
5. Add the user to each semicolon-separated group in the `Groups` column.
6. If the user was created but one or more group-adds failed, `Status` is set to `Partial`.
7. Record result to the pipeline and optional CSV report.

## Framework mapping

See `docs/control-mapping.md` for NIST 800-53 AC-2 and IA-4 rationale.
