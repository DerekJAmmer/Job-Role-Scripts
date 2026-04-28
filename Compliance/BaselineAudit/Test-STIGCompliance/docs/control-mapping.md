# Control Mapping — Test-STIGCompliance

## NIST SP 800-53 Rev 5

| Control | Title | Relevance |
|---------|-------|-----------|
| CM-6    | Configuration Settings | Requires organizations to establish configuration settings for IT products in use. `Test-STIGCompliance` checks registry values, service states, and policy settings against STIG-required values — directly supporting CM-6 verification. |
| CM-7    | Least Functionality | Requires disabling unnecessary functions, ports, protocols, and services. The SMBv1 checks (V-253256, V-253257), Telnet Client check (V-253260), and BitLocker check (V-253474) all enforce minimal attack surface. |

---

## DISA STIG Windows 11 V1R6 — Covered Controls

| VulnId    | Title (abbreviated)                                               | Severity | Type              | NIST 800-53 |
|-----------|-------------------------------------------------------------------|----------|-------------------|-------------|
| V-253256  | SMBv1 client disabled (mrxsmb10 Start = 4)                        | CAT I    | RegistryValue     | CM-6, CM-7  |
| V-253257  | SMBv1 server disabled (SMB1 = 0)                                  | CAT I    | RegistryValue     | CM-6, CM-7  |
| V-253265  | LSA Protection enabled (RunAsPPL = 1)                             | CAT II   | RegistryValue     | CM-6        |
| V-253283  | Account lockout threshold <= 3 invalid attempts                   | CAT II   | SecurityPolicy    | CM-6        |
| V-253386  | Audit Credential Validation = Success and Failure                 | CAT II   | AuditPolicy       | CM-6        |
| V-253399  | Audit Account Lockout = Success and Failure                       | CAT III  | AuditPolicy       | CM-6        |
| V-253428  | Defender real-time monitoring enabled (DisableRealtimeMonitoring = 0) | CAT II | RegistryValue  | CM-6, CM-7  |
| V-253260  | Telnet Client not installed (TlntSvr service absent)              | CAT III  | ServiceState      | CM-7        |
| V-253474  | BitLocker enabled on system drive (C:)                            | CAT II   | BitLockerStatus   | CM-6        |
| V-253466  | PowerShell ScriptBlock Logging enabled                            | CAT III  | RegistryValue     | CM-6        |
| V-253505  | AppLocker policy configured and reviewed (manual)                 | CAT II   | Manual            | CM-7        |
| V-253506  | Software inventory reviewed annually (manual)                     | CAT III  | Manual            | CM-7        |

---

## Sections Explicitly NOT Covered

The following STIG categories and control families are outside the scope of this tool. This is a deliberate choice to keep the portfolio sample focused and maintainable.

| Out-of-scope area | Reason not covered |
|-------------------|--------------------|
| Domain Controller STIGs | DC-specific controls (e.g. SYSVOL permissions, replication audit, DC-only services) require an Active Directory environment; not applicable to standalone workstations. |
| Browser STIGs (Edge, Chrome) | Browser STIGs have their own STIG IDs and rely on browser-specific registry paths and Group Policy extensions; a separate script is more appropriate. |
| Application STIGs (IIS, SQL Server, Office 365) | Application-level STIGs vary significantly by product version and configuration. Each warrants a dedicated auditor. |
| Windows Server STIGs | Server-variant controls (IIS roles, DNS, DHCP, AD roles) do not apply to Windows 11 workstations. |
| STIG controls requiring secedit export | User Rights Assignment and Security Options not exposed by `net accounts` require `secedit /export` with SID-to-account resolution; out of scope for this version. |
| IPv6 and network adapter STIGs | Network configuration controls depend heavily on site-specific topology and cannot be meaningfully spot-checked with static expected values. |
| FIPS compliance controls | FIPS algorithm enforcement impacts application compatibility and warrants careful change management; not checked automatically in this tool. |
| Full CAT I/II/III coverage | This subset covers 10 automatable controls and 2 manual controls. The full DISA STIG Windows 11 V1R6 contains over 250 rules. Complete coverage requires DISA Evaluate-STIG. |

Full STIG compliance evaluation requires the official DISA Evaluate-STIG tool and a current XCCDF benchmark package from https://public.cyber.mil/stigs/. This script is intended for targeted spot-checks and portfolio demonstration.
