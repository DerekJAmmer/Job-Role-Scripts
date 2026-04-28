# Control Mapping — New-ADUserBulk

## NIST 800-53 Rev 5

### AC-2 — Account Management

AC-2 requires organizations to define account types, establish conditions for account membership, approve account creation, and review accounts periodically.

**How this script supports AC-2:**

- Accounts are created only from an authorized, audited CSV prepared by an account manager or HR system. The CSV acts as the documented approval artifact.
- The output report provides a record of every account created, skipped, or failed — supporting the account inventory requirement.
- `-WhatIf` mode lets reviewers confirm the full list of accounts before any are created, supporting the approval step before account provisioning.
- Group membership is declared explicitly in the CSV, tying each account to its approved access level at creation time.

### IA-4 — Identifier Management

IA-4 requires that identifiers (user account names) be unique, managed, and assigned only to authorized individuals.

**How this script supports IA-4:**

- Before creating any account, the script checks whether the `SamAccountName` already exists in AD. Duplicate identifiers are blocked and logged as `Skipped: AlreadyExists`, preventing identifier reuse.
- `SamAccountName` and `UserPrincipalName` are both validated as present in the CSV before any processing begins, ensuring each account has the identifiers required by the directory.
- The generated initial password uses cryptographically random bytes (`System.Security.Cryptography.RandomNumberGenerator`), satisfying the expectation that initial credentials are unpredictable.
