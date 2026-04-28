# Control Mapping — Test-CISBenchmark

## NIST SP 800-53 Rev 5

| Control | Title | Relevance |
|---------|-------|-----------|
| CM-6    | Configuration Settings | Requires organizations to establish configuration settings for IT products in use. `Test-CISBenchmark` checks registry values, service states, and policy settings against CIS benchmark expected values — directly supporting CM-6 verification. |
| CM-7    | Least Functionality | Requires disabling unnecessary functions, ports, and services. The ServiceState checks (BTAGService, bthserv) verify that Bluetooth services are disabled where not required. |
| AU-2    | Event Logging | Requires identification of event types the system must log. The AuditPolicy checks verify that critical audit subcategories (Credential Validation, Account Lockout, Audit Policy Change) are configured at the required level. |

---

## CIS Microsoft Windows 11 Enterprise Benchmark v2.0.0 — Covered Controls

| CIS ID       | Title (abbreviated)                                        | Section                  | Type            |
|--------------|------------------------------------------------------------|--------------------------|-----------------|
| 1.1.1        | Enforce password history >= 24                             | Account Policies         | SecurityPolicy  |
| 1.1.2        | Maximum password age <= 365                                | Account Policies         | SecurityPolicy  |
| 2.3.1.1      | Block Microsoft accounts (NoConnectedUser = 3)             | Security Options         | RegistryValue   |
| 2.3.7.1      | Do not require CTRL+ALT+DEL (DisableCAD = 0)               | Security Options         | RegistryValue   |
| 2.3.10.5     | Restrict anonymous access to Named Pipes/Shares            | Security Options         | RegistryValue   |
| 2.3.11.5     | Microsoft network server: Digitally sign always            | Security Options         | RegistryValue   |
| 5.10         | Bluetooth Audio Gateway Service (BTAGService) = Disabled   | System Services          | ServiceState    |
| 5.11         | Bluetooth Support Service (bthserv) = Disabled             | System Services          | ServiceState    |
| 17.1.1       | Audit Credential Validation = Success and Failure          | Advanced Audit Policy    | AuditPolicy     |
| 17.5.1       | Audit Account Lockout = Failure                            | Advanced Audit Policy    | AuditPolicy     |
| 17.7.1       | Audit Audit Policy Change = Success                        | Advanced Audit Policy    | AuditPolicy     |
| 18.9.47.2    | Configure Attack Surface Reduction rules (manual)          | Administrative Templates | Manual          |
| 18.3.2       | LAPS installed and configured (manual)                     | Administrative Templates | Manual          |

---

## Sections Explicitly NOT Covered

The following CIS Windows 11 sections are outside the scope of this tool. This is a deliberate choice to keep the portfolio sample focused and maintainable.

| Section / ID Range | Reason not covered |
|--------------------|--------------------|
| Section 9 — Windows Firewall | Firewall rule auditing requires `Get-NetFirewallRule` and rule-set comparison logic that warrants a dedicated script. |
| Section 18.x (full Admin Templates) | The full Section 18 contains 200+ controls covering nearly every Windows component. Only two representative Manual controls are included here. |
| Section 19 — User Configuration | User-scoped GPO settings apply per-user, not per-machine, making automated collection significantly more complex. |
| Section 2.2 — User Rights Assignment | Requires `secedit /export` parsing and SID-to-account resolution; out of scope for this initial implementation. |
| Sections 3–4 — Event Log / Network | Event log size/retention (Section 3) and network settings (Section 4) are covered by other scripts in this portfolio (`Get-AuditPolicy`, planned NetworkAdmin scripts). |
| Section 5 (partial) | Only two Bluetooth services are included. The full Section 5 lists ~40 services; a complete ServiceState scan is more appropriate as a bulk automation task. |

Full CIS-CAT coverage requires the licensed CIS-CAT Pro tool. This script is intended for targeted spot-checks and portfolio demonstration.
