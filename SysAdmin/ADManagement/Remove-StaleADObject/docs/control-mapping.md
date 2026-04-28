# Control Mapping — Remove-StaleADObject

## NIST 800-53 Rev 5 — AC-2: Account Management

| Sub-control | Requirement | How this script addresses it |
|---|---|---|
| AC-2(3) | Disable accounts after an organization-defined inactivity period | Disables any user or computer account whose `LastLogonDate` exceeds the configured `-StaleDays` threshold |
| AC-2(7) | Review privileged accounts at a defined frequency | The `ObjectType` and `SamAccountName` columns allow reviewers to identify stale privileged accounts in the result report |
| AC-2 (base) | Remove or disable accounts no longer required | Accounts are disabled and moved to a quarantine OU; nothing is deleted, supporting audit and recovery requirements |

## Supporting controls

| Control | Notes |
|---|---|
| AU-9 (Protection of Audit Information) | The `-OutputPath` CSV report provides an auditable record of every quarantine action with timestamps and original OU |
| CM-6 (Configuration Settings) | `-StaleDays` is configurable to match organizational policy (default 90 days, range 30–730) |

## Usage in a compliance workflow

1. Run with `-WhatIf` and review the report to confirm scope before any changes.
2. Run without `-WhatIf` to quarantine stale accounts.
3. Archive the `-OutputPath` CSV as evidence for the next audit cycle.
4. After a defined retention period in the quarantine OU, accounts may be reviewed and permanently removed by an authorized administrator.
