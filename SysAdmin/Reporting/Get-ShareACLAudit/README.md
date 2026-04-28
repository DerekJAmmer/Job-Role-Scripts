---
role: SysAdmin
language: PowerShell
difficulty: medium
frameworks:
  mitre_attack: []
  nist_800_53: [AC-3, AC-6]
  cis_windows11: []
  stig: []
---

# Get-ShareACLAudit

## Overview

`Get-ShareACLAudit` walks one or more directory paths recursively (up to a
configurable depth) and flags any access rule that combines a risky principal
with a risky file-system right.  The script is **strictly read-only**: it
enumerates and reports ACL entries but never modifies permissions, ownership,
or any file-system object.  Partial audits are preferred over failed ones —
access-denied errors on individual directories emit a warning and are skipped
rather than halting the entire run.

---

## Parameters

| Parameter          | Type       | Default                                                                                                          | Description                                                                                       |
|--------------------|------------|------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `-Path`            | `string[]` | *(required)*                                                                                                     | One or more root paths (local or UNC) to audit.  Missing paths emit a warning and are skipped.    |
| `-MaxDepth`        | `int`      | `5`                                                                                                              | Maximum subdirectory recursion depth.                                                             |
| `-RiskyPrincipals` | `string[]` | `Everyone`, `BUILTIN\Users`, `NT AUTHORITY\Authenticated Users`, `Domain Users`                                 | Identity strings to flag.  Case-insensitive exact match.  **Customizable.**                       |
| `-RiskyRights`     | `string[]` | `Modify`, `Write`, `FullControl`                                                                                 | FileSystemRights token names to flag.  Matched against the comma-split of the rights enum string. **Customizable.** |
| `-OutputPath`      | `string`   | *(none)*                                                                                                         | Optional CSV output path.  Written with UTF-8 encoding and no type information header.            |

### Customising the risky lists

Both `-RiskyPrincipals` and `-RiskyRights` are fully customisable:

```powershell
# Flag only 'Domain Admins' and only for 'FullControl'
Get-ShareACLAudit -Path '\\srv\finance' `
    -RiskyPrincipals @('Domain Admins') `
    -RiskyRights     @('FullControl')
```

---

## Output Schema

Each finding is a `PSCustomObject` with the following properties:

| Property            | Type     | Description                                               |
|---------------------|----------|-----------------------------------------------------------|
| `Path`              | `string` | Full path of the directory whose ACL contains the rule.   |
| `Principal`         | `string` | `IdentityReference.Value` from the access rule.           |
| `Rights`            | `string` | `FileSystemRights.ToString()` from the access rule.       |
| `AccessControlType` | `string` | `Allow` or `Deny`.                                        |
| `IsInherited`       | `bool`   | Whether the rule is inherited from a parent object.       |

---

## Why Both Allow and Deny Rules Appear

The script intentionally reports **both Allow and Deny rules** for risky
principals.  A Deny entry for `Everyone` or `BUILTIN\Users` may seem
protective at first glance, but it is equally worthy of operator attention:

- A blanket Deny can indicate that an overly-permissive Allow higher in the
  ACL inheritance chain was "patched" with a compensating Deny rather than
  corrected at the source — a fragile and often misunderstood configuration.
- Deny rules applied at the wrong scope can inadvertently block legitimate
  administrative access or break application service accounts.

Operators should review all flagged rules — both Allow and Deny — and confirm
the intent is correct and documented.

---

## Examples

```powershell
# Audit a UNC share with all defaults
Get-ShareACLAudit -Path '\\fileserver\shares'

# Limit depth and save findings to CSV
Get-ShareACLAudit -Path 'D:\Data','E:\Dept' -MaxDepth 3 -OutputPath .\findings.csv

# Custom principal and right lists
Get-ShareACLAudit -Path 'C:\Shares' `
    -RiskyPrincipals @('Domain Users','Everyone') `
    -RiskyRights     @('Write','FullControl')
```

---

## Notes

- This script is **read-only**.  It does not modify ACLs, permissions,
  ownership, audit policies, or any file-system object.
- Access-denied errors on individual directories are non-fatal.  A warning
  is written and the next directory is processed.
- Missing input paths are also non-fatal and emit a warning.
- See `docs/control-mapping.md` for NIST 800-53 control alignment.
