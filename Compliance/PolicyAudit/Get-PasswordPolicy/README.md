---
role: Compliance
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [IA-5]
  cis_windows11: [1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.2.1, 1.2.2]
  stig: []
---

# Get-PasswordPolicy

Reports Windows password-policy settings from the Active Directory default domain policy, the local machine policy, and (optionally) AD Fine-Grained Password Policies (FGPPs). Optionally compares each source against a JSON baseline and marks rows **Compliant** or **NonCompliant**.

**Read-only — this script never modifies any policy setting.**

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-IncludeDomain` | `[bool]` | `$true` | Collect the AD default domain password policy. Pass `-IncludeDomain:$false` to suppress. Requires RSAT. |
| `-IncludeLocal` | `[bool]` | `$true` | Collect local machine policy via `net accounts`. Works without RSAT. Pass `-IncludeLocal:$false` to suppress. |
| `-IncludeFGPP` | `[switch]` | off | Collect AD Fine-Grained Password Policies. Opt-in because enumeration can be slow in large forests. Requires RSAT. |
| `-BaselinePath` | `[string]` | — | Path to a JSON baseline file. When supplied, each row is compared and `Status` is set to `Compliant` or `NonCompliant`. |
| `-OutputPath` | `[string]` | — | Optional path to export all result rows as a CSV (UTF-8, no type information). |

> **Note:** `-IncludeDomain` and `-IncludeLocal` use `[bool]` rather than `[switch]` so callers can explicitly pass `$false` with the `:$false` syntax. A `[switch]` can only be omitted or set to `$true`.

---

## Output schema

Each pipeline object has the following properties:

| Property | Type | Description |
|----------|------|-------------|
| `Source` | `string` | `'Domain'`, `'Local'`, or `'FGPP:<Name>'` |
| `MinLength` | `int` | Minimum password length |
| `ComplexityEnabled` | `bool` / `$null` | Complexity requirement; `$null` when not determinable (e.g., local policy via `net accounts`) |
| `HistoryCount` | `int` | Password history count |
| `MaxAgeDays` | `int` | Maximum password age in days |
| `MinAgeDays` | `int` / `$null` | Minimum password age in days; `$null` when not reported |
| `LockoutThreshold` | `int` | Failed-logon lockout threshold (0 = never lockout) |
| `LockoutDurationMinutes` | `int` | Account lockout duration in minutes |
| `Status` | `string` | `'Unknown'` (no baseline), `'Compliant'`, or `'NonCompliant'` |
| `Deltas` | `object[]` | List of `{ Field, Expected, Actual }` objects for each mismatch; empty when compliant or no baseline |

---

## Policy sources

### Domain

Queries `Get-ADDefaultDomainPasswordPolicy` from the ActiveDirectory module.

**Requires:** RSAT feature `RSAT.ActiveDirectory` (or the ActiveDirectory PowerShell module on a domain controller).

### Local

Calls `cmd.exe /c net accounts` and parses the colon-delimited output. `ComplexityEnabled` is not exposed by `net accounts` and is reported as `$null`. For complexity status on local policy, use `secedit /export` separately.

**Requires:** Nothing beyond a standard Windows installation.

### FGPP (Fine-Grained Password Policies)

Queries `Get-ADFineGrainedPasswordPolicy -Filter '*'`. Each FGPP appears as a separate row with `Source = 'FGPP:<Name>'`.

**Requires:** RSAT.ActiveDirectory + an AD domain that has FGPPs configured.

---

## Baseline JSON shape

The baseline file is a flat JSON object. Keys must match the property names above (case-sensitive for comparison). All keys are optional; only keys present in the baseline are compared.

```json
{
  "MinLength": 14,
  "ComplexityEnabled": true,
  "HistoryCount": 24,
  "MaxAgeDays": 60,
  "MinAgeDays": 1,
  "LockoutThreshold": 5,
  "LockoutDurationMinutes": 15
}
```

A CIS-aligned example is shipped at [`samples/baseline-example.json`](samples/baseline-example.json).

---

## Examples

```powershell
# Default: collect Domain + Local, no baseline.
Get-PasswordPolicy

# Compare against a CIS baseline.
Get-PasswordPolicy -BaselinePath .\samples\baseline-example.json

# Suppress domain; compare and export.
Get-PasswordPolicy -IncludeDomain:$false -BaselinePath .\baseline.json -OutputPath .\audit.csv

# Include FGPPs (AD-joined machines only).
Get-PasswordPolicy -IncludeFGPP

# Pipe into Write-ComplianceReport (from Compliance.Common module).
Get-PasswordPolicy -BaselinePath .\baseline.json | Write-ComplianceReport -OutFile .\report.html -Title 'Password Policy Audit'
```

---

## Requirements

- PowerShell 7.2+
- RSAT.ActiveDirectory (for Domain / FGPP sources)
- No elevated rights required for read-only collection
