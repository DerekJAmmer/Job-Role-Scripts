---
role: Compliance
language: PowerShell
difficulty: hard
frameworks:
  mitre_attack: []
  nist_800_53: [CM-6, CM-7]
  cis_windows11: []
  stig: [V-253256, V-253257, V-253265, V-253283, V-253386, V-253399, V-253428, V-253260, V-253474, V-253466, V-253505, V-253506]
---

# Test-STIGCompliance

Loads a JSON STIG file containing a subset of DISA STIG Windows 11 V1R6 controls and evaluates each one locally. For every control it emits a row with a `Status` of `NotAFinding`, `Open`, `NotApplicable`, `Manual`, or `Error`, along with `Expected` and `Actual` values so you can immediately see where drift occurred. A `SUMMARY` row closes the output with totals for each status bucket and a `WouldFailGate` indicator.

**Read-only** — the script never calls `Set-*` or modifies any system setting.

---

## Scope

This is a **subset** STIG auditor intended for portfolio demonstration and ad-hoc audit, not a certified STIG-Viewer or Evaluate-STIG replacement. The shipped sample covers 12 controls across five types (RegistryValue, AuditPolicy, ServiceState, SecurityPolicy, BitLockerStatus) plus two Manual controls. It is deliberately narrow so each control type is exercised without creating a multi-hundred-line JSON file that nobody will maintain. For a production environment use the official DISA Evaluate-STIG tool or STIG-Viewer with a complete XCCDF benchmark.

Domain controller STIGs, browser STIGs (Edge, Chrome), and application-specific STIGs (IIS, SQL Server, Office) are explicitly out of scope — see `docs/control-mapping.md` for details.

---

## Architecture

This script intentionally duplicates `Test-CISBenchmark`'s dispatch shape rather than sharing code. The CIS and STIG schemas drift independently: CIS controls have `id`/`section` whereas STIG controls have `vulnId`/`severity`; CIS statuses are `Compliant`/`NonCompliant` whereas STIG statuses are `NotAFinding`/`Open`/`NotApplicable`; STIG adds `applicabilityCheck`, `BitLockerStatus`, and a `FailOnSeverity` gate that have no CIS equivalents. A shared base module would create a coupling tax — every STIG-specific feature would need to be shimmed, hidden, or conditionally activated in CIS paths. Two near-identical implementations is deliberate: each file is self-contained, each can evolve independently, and a reader only needs to understand one file at a time.

Private helpers use the `TSC` prefix (`Invoke-TSCAuditPol`, `Get-TSCRegValue`, `Get-TSCService`, `Invoke-TSCNetAccount`, `Invoke-TSCManageBde`). Pester tests mock these helpers rather than the underlying system calls, keeping tests fast and side-effect-free.

---

## Parameters

| Parameter         | Type     | Required | Description |
|-------------------|----------|----------|-------------|
| `-STIGPath`       | string   | Yes      | Path to the JSON STIG file. See `samples/stig-win11-subset.json` for the expected shape. |
| `-ComputerName`   | string[] | No       | Target(s). Only the local machine is currently supported; other values emit a warning and are skipped. Default: `@('.')`. |
| `-OutputPath`     | string   | No       | When supplied, all result rows are exported as a UTF-8 CSV. |
| `-HtmlPath`       | string   | No       | When supplied, an HTML report is written via `Write-ComplianceReport`. |
| `-Severity`       | string[] | No       | Restrict evaluation to controls whose `severity` matches one of these values (e.g. `'CAT I'`). |
| `-IncludeManual`  | switch   | No       | Include `Manual` controls in output. Excluded by default. |
| `-FailOnSeverity` | string   | No       | Comma-separated severity categories (e.g. `'CAT I,CAT II'`). The SUMMARY row `WouldFailGate` is `true` if any `Open` result matches. Default: `'CAT I,CAT II'`. |

---

## Output schema

Each row emitted to the pipeline is a `PSCustomObject`:

| Property   | Type   | Description |
|------------|--------|-------------|
| `VulnId`   | string | STIG Vulnerability ID (e.g. `V-253256`). `SUMMARY` for the final row. |
| `Title`    | string | Full STIG control title. |
| `Severity` | string | `CAT I`, `CAT II`, or `CAT III`. |
| `Type`     | string | Control type: `RegistryValue`, `AuditPolicy`, `ServiceState`, `SecurityPolicy`, `BitLockerStatus`, `Manual`. |
| `Status`   | string | `NotAFinding`, `Open`, `NotApplicable`, `Manual`, or `Error`. |
| `Expected` | object | Expected value from the STIG definition. |
| `Actual`   | object | Live value retrieved from the system. |
| `Reason`   | string | Explanation for non-NotAFinding rows, or the SUMMARY string for the last row. |
| `Fix`      | string | Remediation guidance from the STIG file. |

---

## Status meanings

| Status           | Meaning |
|------------------|---------|
| `NotAFinding`    | Live value satisfies the STIG requirement. |
| `Open`           | Live value does not satisfy the requirement, or the registry key / service is missing. |
| `NotApplicable`  | The control's `applicabilityCheck` did not match the local system (e.g. domain-only control on a standalone machine). The main check is skipped entirely. |
| `Manual`         | Control cannot be checked programmatically; requires human review. Only emitted with `-IncludeManual`. |
| `Error`          | The check threw an exception, the data source did not contain the expected entry, or the control type is unrecognised. |

---

## Supported control types

| Type              | Data source             | What it checks |
|-------------------|-------------------------|----------------|
| `RegistryValue`   | `Get-ItemProperty`      | DWord or string registry value at a specified path/name. |
| `AuditPolicy`     | `auditpol.exe /r`       | Inclusion Setting for a named audit subcategory. |
| `ServiceState`    | `Get-Service`           | Service `StartType`, or absence of the service when `NotPresent=true`. |
| `SecurityPolicy`  | `net accounts`          | Password and lockout policy values, with optional `LessThanOrEqual` operator. |
| `BitLockerStatus` | `manage-bde -status`    | Checks for "Conversion Status: Fully Encrypted" and "Protection Status: Protection On" on the specified mount point. |
| `Manual`          | —                       | Human review required; emits the `fix` text as `Reason`. |

### applicabilityCheck

Each control may include an optional `applicabilityCheck` field with shape:

```json
{
  "applicabilityCheck": {
    "type": "RegistryValue",
    "Path": "HKLM:\\...",
    "Name": "ValueName",
    "Value": 1
  }
}
```

Only `RegistryValue` is supported in this version. If the live registry value does not match the check value (or the key is absent), the control is emitted with `Status=NotApplicable` and the main test is skipped. This is useful for domain-only controls that are not relevant on standalone workstations.

### BitLocker note

`V-253474` (BitLocker on system drive) does not use an `applicabilityCheck` — the check assumes drive encryption is required by organisational policy. If encryption is not required in your environment, filter this control out with `-Severity` or omit it from the JSON.

---

## WouldFailGate

The `-FailOnSeverity` parameter (default: `'CAT I,CAT II'`) determines whether the SUMMARY row's `Reason` field includes `WouldFailGate=True`. If any `Open` result's `Severity` matches one of the listed categories, the gate is set. The script does **not** exit with a non-zero code — the gate is informational, so it is safe for unattended/CI use.

---

## Examples

```powershell
# Run all non-manual controls against the shipped sample STIG file.
Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json

# Restrict to CAT I controls only.
Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json -Severity 'CAT I'

# Export CSV and include manual controls.
Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json `
    -IncludeManual -OutputPath .\stig-report.csv

# CI gate: fail if any CAT I or CAT II control is Open.
$results = Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json -FailOnSeverity 'CAT I,CAT II'
$summary = $results | Where-Object { $_.VulnId -eq 'SUMMARY' }
if ($summary.Reason -match 'WouldFailGate=True') { exit 1 }
```

---

## STIG JSON shape

```json
{
  "name": "My STIG Subset",
  "version": "1.0",
  "controls": [
    {
      "vulnId": "V-253256",
      "title": "Human-readable STIG title",
      "severity": "CAT I",
      "type": "RegistryValue",
      "expected": {
        "Path": "HKLM:\\...",
        "Name": "ValueName",
        "Value": 4,
        "ValueType": "DWord"
      },
      "fix": "How to remediate if Open."
    }
  ]
}
```

See `samples/stig-win11-subset.json` for a working example covering all six control types.

---

## Limitations

- **Remote execution not implemented.** Passing values other than `.` to `-ComputerName` logs a warning and skips that target.
- **SecurityPolicy via net accounts only.** `net accounts` exposes password-policy and lockout settings only. Controls requiring `secedit /export` or User Rights Assignment are not supported.
- **BitLocker requires local elevation.** `manage-bde` requires an elevated session; if run without admin rights the check will surface as `Error`.
- **applicabilityCheck supports RegistryValue only.** WMI, domain-membership, or OS-version applicability checks are not implemented in this version.
- **Not a STIG-Viewer replacement.** This tool is for spot-checks and portfolio demonstration. Official DISA Evaluate-STIG performs a certified, complete evaluation against the full XCCDF benchmark.

---

## Notes

- Private wrappers (`Invoke-TSCAuditPol`, `Get-TSCRegValue`, `Get-TSCService`, `Invoke-TSCNetAccount`, `Invoke-TSCManageBde`) are the Pester mock surface — tests mock these rather than underlying system calls.
- `auditpol` and `net accounts` are each called once per `Test-STIGCompliance` invocation; parsed results are cached and passed to per-control dispatch functions.
