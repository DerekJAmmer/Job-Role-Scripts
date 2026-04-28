---
role: Compliance
language: PowerShell
difficulty: hard
frameworks:
  mitre_attack: []
  nist_800_53: [CM-6, CM-7, AU-2]
  cis_windows11: [1.1.x, 2.3.x, 17.x, 18.x, 5.x]
  stig: []
---

# Test-CISBenchmark

Loads a JSON benchmark file containing a subset of CIS Windows 10/11 controls and evaluates each one locally. For every control it emits a row with a `Status` of `Compliant`, `NonCompliant`, `Manual`, `Error`, or `Unknown`, along with `Expected` and `Actual` values so you can immediately see where drift occurred. A `SUMMARY` row closes the output with totals for each status bucket.

**Read-only** — the script never calls `Set-*` or modifies any system setting.

---

## Scope

This is a **subset** benchmark runner intended for portfolio demonstration and ad-hoc audit, not a certified CIS-CAT replacement. The shipped sample covers ~13 controls across five sections (Account Policies, Security Options, System Services, Advanced Audit Policy, Administrative Templates). It is deliberately narrow so each control type is exercised without creating a multi-hundred-line JSON file that nobody will maintain. For a production environment use the official CIS-CAT Pro tool or a full benchmark JSON covering all relevant controls.

---

## Parameters

| Parameter        | Type       | Required | Description |
|------------------|------------|----------|-------------|
| `-BenchmarkPath` | string     | Yes      | Path to the JSON benchmark file. See `samples/cis-win11-subset.json` for the expected shape. |
| `-ComputerName`  | string[]   | No       | Target(s). Only the local machine is currently supported; other values emit a warning and are skipped. Default: `@('.')`. |
| `-OutputPath`    | string     | No       | When supplied, all result rows are exported as a UTF-8 CSV. |
| `-HtmlPath`      | string     | No       | When supplied, an HTML report is written via `Write-ComplianceReport`. |
| `-Section`       | string[]   | No       | Restrict evaluation to controls whose `section` matches one of these values. |
| `-IncludeManual` | switch     | No       | Include `Manual` controls in output. Excluded by default because they cannot be checked programmatically. |

---

## Output schema

Each row emitted to the pipeline is a `PSCustomObject`:

| Property      | Type   | Description |
|---------------|--------|-------------|
| `ControlId`   | string | CIS control identifier (e.g. `2.3.7.1`). `SUMMARY` for the final row. |
| `Title`       | string | Full CIS control title. |
| `Section`     | string | CIS section name (e.g. `Account Policies`). |
| `Type`        | string | Control type: `RegistryValue`, `AuditPolicy`, `ServiceState`, `SecurityPolicy`, `Manual`. |
| `Status`      | string | `Compliant`, `NonCompliant`, `Manual`, `Error`, or `Unknown`. |
| `Expected`    | object | Expected value from the benchmark definition. |
| `Actual`      | object | Live value retrieved from the system. |
| `Reason`      | string | Human-readable explanation for non-Compliant rows, or the SUMMARY string for the last row. |
| `Remediation` | string | Remediation guidance from the benchmark file. |

---

## Status meanings

| Status         | Meaning |
|----------------|---------|
| `Compliant`    | Live value matches the benchmark expected value. |
| `NonCompliant` | Live value differs from expected, or the registry key / service is missing. |
| `Manual`       | Control cannot be checked programmatically; requires human review. Only emitted with `-IncludeManual`. |
| `Error`        | The check threw an exception or the data source (auditpol, net accounts) did not contain the expected entry. |
| `Unknown`      | The `type` field in the benchmark JSON was not recognised. |

---

## Supported control types

| Type             | Data source           | What it checks |
|------------------|-----------------------|----------------|
| `RegistryValue`  | `Get-ItemProperty`    | DWord or string registry value at a specified path/name. |
| `AuditPolicy`    | `auditpol.exe /r`     | Inclusion Setting for a named audit subcategory. |
| `ServiceState`   | `Get-Service`         | Service `StartType` (Disabled, Manual, Automatic). |
| `SecurityPolicy` | `net accounts`        | Password and lockout policy values. |
| `Manual`         | —                     | Human review required; emits the remediation text as `Reason`. |

---

## Examples

```powershell
# Run all non-manual controls against the shipped sample benchmark.
Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json

# Restrict to Account Policies section and export CSV.
Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json `
    -Section 'Account Policies' -OutputPath .\account-policies.csv

# Include manual controls and emit an HTML report.
Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json `
    -IncludeManual -HtmlPath .\cis-report.html

# Pipe to Format-Table to see non-compliant rows at a glance.
Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json |
    Where-Object { $_.Status -in 'NonCompliant','Error' } |
    Format-Table ControlId, Title, Expected, Actual, Status -AutoSize
```

---

## Benchmark JSON shape

```json
{
  "name": "My Benchmark",
  "version": "1.0",
  "controls": [
    {
      "id": "2.3.7.1",
      "title": "Human-readable title",
      "section": "Security Options",
      "type": "RegistryValue",
      "expected": {
        "Path": "HKLM:\\SOFTWARE\\...",
        "Name": "ValueName",
        "Value": 0,
        "ValueType": "DWord"
      },
      "remediation": "How to fix this if non-compliant."
    }
  ]
}
```

See `samples/cis-win11-subset.json` for a complete working example with all five control types.

---

## Limitations

- **Remote execution not implemented.** Passing values other than `.` to `-ComputerName` logs a warning and skips that target. Remote checks would require PowerShell Remoting and are not in scope for this portfolio tool.
- **SecurityPolicy via net accounts only.** `net accounts` exposes password-policy and lockout settings. It does not cover the full `secedit` / `Security Policy` surface. Controls outside that scope would need a `secedit /export` based parser.
- **auditpol requires local execution context.** The script invokes `auditpol.exe` directly; it will not work over a remote session without `Invoke-Command`.
- **Not a CIS-CAT replacement.** This tool is for spot-checks and demonstration. CIS-CAT Pro performs a certified, complete audit.

---

## Notes

- Private wrappers (`Invoke-TCBAuditPol`, `Get-TCBRegValue`, `Get-TCBService`, `Invoke-TCBNetAccounts`) are the Pester mock surface — tests mock these rather than the underlying system calls.
- `auditpol` and `net accounts` are each called once per `Test-CISBenchmark` invocation; the parsed results are cached and passed to per-control dispatch functions so multi-control runs do not hit the OS repeatedly.
