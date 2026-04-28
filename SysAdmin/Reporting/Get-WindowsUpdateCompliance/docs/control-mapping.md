# Control Mapping — Get-WindowsUpdateCompliance

## NIST 800-53 SI-2: Flaw Remediation

| Control | Requirement | How This Script Supports It |
|---------|------------|----------------------------|
| SI-2(a) | Identify, report, and correct information system flaws | Enumerates missing Windows updates (pending flaws) per host via the WUA COM API |
| SI-2(b) | Test software and firmware updates before installation | Out of scope (read-only); script provides visibility into what has or hasn't been applied |
| SI-2(c) | Install security-relevant updates within organizationally-defined time periods | `DaysSinceLastUpdate` and `IsStale` flag hosts that exceed the configured `StaleDays` threshold, enabling enforcement of patch SLAs |
| SI-2(d) | Incorporate flaw remediation into organizational configuration management | `MissingUpdateCount` and `LastInstalledDate` feed into compliance reports and change-management workflows |

## Coverage Notes

- `MissingUpdateCount` (COM path) directly surfaces the count of unapplied updates, supporting SI-2(a) identification and reporting.
- `IsStale` (derived from `DaysSinceLastUpdate` vs. `StaleDays`) operationalizes the SI-2(c) time-period requirement — set `StaleDays` to your organization's patch SLA (e.g. 30 days for standard, 7 days for critical).
- `Source = 'Unreachable'` rows identify hosts that could not be assessed, which themselves represent a gap in SI-2 compliance posture.
- Output CSV + JSON sidecar supports audit trail and integration with SIEM or GRC tooling.

## Related Controls

| Control | Relation |
|---------|---------|
| CM-6 (Configuration Settings) | Patch state is a key configuration attribute; feeds CM-6 assessments |
| RA-5 (Vulnerability Scanning) | Complements scanner output with real-time WUA pending-update counts |
| AU-6 (Audit Review) | CSV/JSON output can be ingested into audit log review workflows |
