---
role: Compliance
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [AU-2]
  cis_windows11: [17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8, 17.9]
  stig: []
---

# Get-AuditPolicy

Wraps `auditpol.exe /get /category:* /r`, parses the CSV output, and emits one row per
audit subcategory. When `-BaselinePath` is supplied the script diffs the live settings
against a CIS-style JSON baseline and marks each row **Compliant**, **Drift**, or
**Missing**. Without `-BaselinePath` every row has `Status = Unknown`.

**Read-only** — the script never calls `auditpol /set` or modifies any policy setting.

---

## Parameters

| Parameter      | Type   | Required | Description |
|----------------|--------|----------|-------------|
| `-BaselinePath`| string | No       | Path to a JSON baseline file (see `samples/cis-audit-baseline.json`). Enables compliance comparison. |
| `-OutputPath`  | string | No       | When supplied, all result rows are exported as a UTF-8 CSV (no type information). |

---

## Output schema

Each row emitted to the pipeline is a `PSCustomObject` with the following properties:

| Property     | Type   | Description |
|--------------|--------|-------------|
| `Category`   | string | Derived from a built-in subcategory lookup (e.g. `Logon/Logoff`, `Account Management`). Unknown subcategories resolve to `Other`. |
| `Subcategory`| string | Audit subcategory name as reported by `auditpol`. |
| `Setting`    | string | Current inclusion setting: `Success`, `Failure`, `Success and Failure`, or `No Auditing`. |
| `Status`     | string | `Compliant`, `Drift`, `Missing`, or `Unknown` (see below). |
| `Expected`   | string | Baseline expected value. Populated when a baseline is loaded and `Status != Unknown`. |
| `Actual`     | string | Live setting at comparison time. Populated when `Status` is `Drift`. |

---

## Status meanings

| Status      | Meaning |
|-------------|---------|
| `Compliant` | Baseline supplied; live setting matches the expected value. |
| `Drift`     | Baseline supplied; live setting differs from the expected value. |
| `Missing`   | Baseline supplied; subcategory defined in the baseline is absent from live `auditpol` output. |
| `Unknown`   | No baseline supplied; no comparison performed. |

---

## Examples

```powershell
# Enumerate all audit subcategories with no baseline (Status = Unknown).
Get-AuditPolicy

# Compare against the shipped CIS 17.x baseline.
Get-AuditPolicy -BaselinePath .\samples\cis-audit-baseline.json

# Compare and export results to CSV.
Get-AuditPolicy -BaselinePath .\samples\cis-audit-baseline.json -OutputPath .\audit-report.csv

# Pipe results to the console, filtering for non-compliant subcategories only.
Get-AuditPolicy -BaselinePath .\samples\cis-audit-baseline.json |
    Where-Object { $_.Status -in 'Drift','Missing' } |
    Format-Table Category, Subcategory, Expected, Actual, Status -AutoSize
```

---

## Sample baseline

A ready-to-use CIS 17.1-17.9 baseline is included at:

```
samples/cis-audit-baseline.json
```

Pass it directly via `-BaselinePath`:

```powershell
Get-AuditPolicy -BaselinePath "$PSScriptRoot\samples\cis-audit-baseline.json"
```

---

## Notes

- Requires no elevated privileges to read audit policy (standard user access to `auditpol` is sufficient on most configurations).
- The private helper `Invoke-GAPAuditPol` wraps the external `auditpol.exe` call. Pester tests mock this helper to avoid a real `auditpol` dependency.
- Category derivation uses a built-in lookup covering the ~60 most common subcategories. Subcategories not in the lookup are labelled `Other`.
