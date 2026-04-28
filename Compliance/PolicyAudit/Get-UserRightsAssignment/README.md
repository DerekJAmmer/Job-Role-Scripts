---
role: Compliance
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [AC-3, AC-6]
  cis_windows11: [2.2.x]
  stig: []
---

# Get-UserRightsAssignment

Exports local user-rights assignments by running `secedit /export`, parsing the
`[Privilege Rights]` section, and resolving SIDs to friendly NTAccount names.
When `-BaselinePath` is supplied the script diffs the live assignments against a
CIS-style JSON baseline and marks each row **Compliant**, **Drift**, or **Missing**.
Without `-BaselinePath` every row has `Status = Unknown`.

**Read-only** — the script never calls `secedit /import` or modifies any policy setting.

---

## Parameters

| Parameter       | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `-BaselinePath` | string | No       | Path to a JSON baseline file (see `samples/cis-user-rights-baseline.json`). Enables compliance comparison. |
| `-OutputPath`   | string | No       | When supplied, all result rows are exported as a UTF-8 CSV (no type information). |

---

## Output schema

Each row emitted to the pipeline is a `PSCustomObject` with the following properties:

| Property       | Type   | Description |
|----------------|--------|-------------|
| `Privilege`    | string | Windows privilege constant (e.g. `SeDebugPrivilege`). |
| `AccountSids`  | string | Semicolon-joined raw SID strings as exported by secedit (with `*` prefix). |
| `AccountNames` | string | Semicolon-joined friendly NTAccount names resolved from the SIDs. Unresolvable SIDs appear as-is. |
| `Status`       | string | `Compliant`, `Drift`, `Missing`, or `Unknown` (see below). |
| `Expected`     | string | Semicolon-joined expected account names from the baseline. `$null` when no baseline is loaded. |
| `Actual`       | string | Semicolon-joined actual resolved account names. `$null` for Missing rows. |
| `Reason`       | string | Human-readable diff for Drift rows (e.g. `Added: DOMAIN\User; Removed: BUILTIN\Guests`). Empty otherwise. |

---

## Status meanings

| Status      | Meaning |
|-------------|---------|
| `Compliant` | Baseline supplied; live account set matches the expected set (case-insensitive). |
| `Drift`     | Baseline supplied; live account set differs from the expected set. `Reason` describes the delta. |
| `Missing`   | Baseline supplied; privilege defined in the baseline is absent from the live secedit output. |
| `Unknown`   | No baseline supplied; no comparison performed. |

---

## Examples

```powershell
# Enumerate all user-rights assignments with no baseline (Status = Unknown).
Get-UserRightsAssignment

# Compare against the shipped CIS 2.2.x baseline.
Get-UserRightsAssignment -BaselinePath .\samples\cis-user-rights-baseline.json

# Compare and export results to CSV.
Get-UserRightsAssignment -BaselinePath .\samples\cis-user-rights-baseline.json -OutputPath .\rights-report.csv

# Show only non-compliant privileges.
Get-UserRightsAssignment -BaselinePath .\samples\cis-user-rights-baseline.json |
    Where-Object { $_.Status -in 'Drift','Missing' } |
    Format-Table Privilege, Expected, Actual, Status, Reason -AutoSize
```

---

## Sample baseline

A ready-to-use CIS 2.2.x baseline covering 10 high-risk privileges is included at:

```
samples/cis-user-rights-baseline.json
```

Pass it directly via `-BaselinePath`:

```powershell
Get-UserRightsAssignment -BaselinePath "$PSScriptRoot\samples\cis-user-rights-baseline.json"
```

---

## Notes

- Requires the script to run as a local Administrator (secedit /export requires elevation).
- The private helper `Invoke-GURASecedit` wraps the external `secedit.exe` call and writes
  a temporary INF file that is always cleaned up in a `finally` block.
- `Get-GURAResolveSid` wraps SID-to-NTAccount translation; unresolvable SIDs are returned as-is
  rather than throwing.
- See `docs/control-mapping.md` for privilege-to-CIS/NIST mappings.
